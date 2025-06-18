/**
 * security-integration.test.js
 * IPAガイドライン準拠セキュリティ統合テスト
 * 
 * @author Kei-Adachi0709
 * @version 1.0.0
 * @date 2025-06-19
 */

const SecureHashManager = require('../../src/js/security/SecureHashManager');
const InputValidator = require('../../src/js/security/InputValidator');
const SecurityConfig = require('../../src/js/security/SecurityConfig');

describe('IPAガイドライン準拠セキュリティ統合テスト', () => {
  let hashManager;
  let validator;
  let securityConfig;

  beforeEach(() => {
    securityConfig = new SecurityConfig('test_master_password');
    hashManager = new SecureHashManager({
      iterations: 100000,
      saltLength: 32,
      pepper: 'test_pepper_value_2025'
    });
    validator = new InputValidator();
  });

  describe('SecureHashManager', () => {
    test('ICカード番号のハッシュ化が正常に動作する', () => {
      const cardNumber = 'TO1234567890123456';
      const result = hashManager.hashICCardNumber(cardNumber);
      
      expect(result).toHaveProperty('hash');
      expect(result).toHaveProperty('salt');
      expect(result).toHaveProperty('maskedNumber');
      expect(result.iterations).toBe(100000);
      expect(result.algorithm).toBe('PBKDF2-SHA512');
    });

    test('名古屋圏ICカード検証が正常に動作する', () => {
      const testCards = [
        'TO1234567890123456', // TOICA
        'MA9876543210987654', // manaca
        'JE123456789012345',  // Suica
        'IC1111222233334444', // ICOCA
      ];

      testCards.forEach(cardNumber => {
        const validation = hashManager.validateNagoyaICCard(cardNumber);
        expect(validation.valid).toBe(true);
        expect(validation.type).toBeDefined();
        expect(validation.name).toBeDefined();
      });
    });
  });

  describe('InputValidator', () => {
    test('ICカード番号検証が正常に動作する', () => {
      const validCard = 'TO1234567890123456';
      const result = validator.validateICCardNumber(validCard);
      
      expect(result.valid).toBe(true);
      expect(result.cardType).toBe('TOICA');
      expect(result.cardName).toBe('TOICA（JR東海）');
    });

    test('XSS攻撃パターンを適切に検出・無害化する', () => {
      const xssPatterns = [
        '<script>alert("xss")</script>',
        'javascript:alert("xss")',
        '<img src="x" onerror="alert(1)">',
      ];

      xssPatterns.forEach(xssInput => {
        const result = validator.validateBasicInput(xssInput);
        expect(result.valid).toBe(false);
        expect(result.errors).toContain('危険なパターンが検出されました');
      });
    });
  });

  describe('SecurityConfig', () => {
    test('セキュリティヘルスチェックが正常に動作する', () => {
      const healthCheck = securityConfig.performSecurityHealthCheck();
      
      expect(healthCheck).toHaveProperty('score');
      expect(healthCheck).toHaveProperty('grade');
      expect(healthCheck).toHaveProperty('checks');
      expect(healthCheck.score).toBeGreaterThan(0);
    });

    test('監査ログが正常に記録される', () => {
      const auditLog = securityConfig.getAuditLog();
      expect(Array.isArray(auditLog)).toBe(true);
    });
  });

  describe('統合セキュリティテスト', () => {
    test('ICカード紛失報告フロー全体が安全に動作する', () => {
      const reportData = {
        icCardNumber: 'TO1234567890123456',
        employeeId: 'EMP123456',
        email: 'test@example.com',
        phoneNumber: '052-123-4567'
      };

      // 1. 入力値検証
      const validationResult = validator.validateBulkData(reportData);
      expect(validationResult.valid).toBe(true);

      // 2. ICカード番号ハッシュ化
      const hashedCard = hashManager.hashICCardNumber(
        validationResult.results.icCardNumber.sanitized
      );
      expect(hashedCard.hash).toBeDefined();
      expect(hashedCard.maskedNumber).toBeDefined();

      // 3. セキュリティ設定確認
      const config = hashManager.getSecurityConfig();
      expect(config.iterations).toBeGreaterThanOrEqual(100000);
    });
  });
});
