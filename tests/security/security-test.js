/**
 * security-test.js
 * セキュリティクラステスト・ベンチマークスイート
 * 
 * @author Kei-Adachi0709
 * @version 1.0.0
 * @date 2025-06-19
 */

const SecureHashManager = require('../../src/js/security/SecureHashManager');
const InputValidator = require('../../src/js/security/InputValidator');
const SecurityConfig = require('../../src/js/security/SecurityConfig');

/**
 * セキュリティテスト実行
 */
async function runSecurityTests() {
  console.log('🔒 IPAガイドライン準拠セキュリティテスト開始\n');

  // 1. SecureHashManager テスト
  console.log('1. SecureHashManager テスト');
  await testSecureHashManager();

  // 2. InputValidator テスト
  console.log('\n2. InputValidator テスト');
  testInputValidator();

  // 3. SecurityConfig テスト
  console.log('\n3. SecurityConfig テスト');
  testSecurityConfig();

  // 4. パフォーマンステスト
  console.log('\n4. パフォーマンステスト');
  await performanceTests();

  console.log('\n✅ 全セキュリティテスト完了');
}

/**
 * SecureHashManager テスト
 */
async function testSecureHashManager() {
  try {
    const hashManager = new SecureHashManager({
      iterations: 100000,
      saltLength: 32,
      pepper: 'test_pepper_value_2025'
    });

    // 名古屋圏ICカードテストデータ
    const testCards = [
      'TO1234567890123456', // TOICA
      'MA9876543210987654', // manaca
      'JE123456789012345678', // Suica (17桁)
      'IC1111222233334444', // ICOCA
      'SG5555666677778888', // SUGOCA
      'PA9999888877776666'  // PASMO
    ];

    console.log('  📋 ICカード番号ハッシュ化テスト:');
    
    for (const cardNumber of testCards) {
      const result = hashManager.hashICCardNumber(cardNumber);
      const validation = hashManager.validateNagoyaICCard(cardNumber);
      
      console.log(`    ${validation.name || 'UNKNOWN'}: ${result.maskedNumber} ✅`);
      
      // 検証テスト
      const isValid = hashManager.verifyICCardNumber(cardNumber, result.hash, result.salt);
      console.log(`    検証結果: ${isValid ? '✅ 成功' : '❌ 失敗'}`);
    }

    // セキュリティ設定確認
    const config = hashManager.getSecurityConfig();
    console.log('  🔧 セキュリティ設定:');
    console.log(`    反復回数: ${config.iterations.toLocaleString()}回`);
    console.log(`    ソルト長: ${config.saltLength}バイト`);
    console.log(`    アルゴリズム: PBKDF2-${config.algorithm}`);

  } catch (error) {
    console.error('  ❌ SecureHashManager テストエラー:', error.message);
  }
}

/**
 * InputValidator テスト
 */
function testInputValidator() {
  try {
    const validator = new InputValidator();

    console.log('  📋 入力値検証テスト:');

    // ICカード番号検証テスト
    const icCardTests = [
      { input: 'TO1234567890123456', expected: true, name: 'TOICA正常' },
      { input: 'MA9876543210987654', expected: true, name: 'manaca正常' },
      { input: 'INVALID123456', expected: false, name: '無効形式' },
      { input: '<script>alert("xss")</script>', expected: false, name: 'XSS攻撃' },
      { input: 'TO123456789012345678901234567890', expected: false, name: '長すぎる入力' }
    ];

    icCardTests.forEach(test => {
      const result = validator.validateICCardNumber(test.input);
      const status = result.valid === test.expected ? '✅' : '❌';
      console.log(`    ${test.name}: ${status}`);
      if (!result.valid && result.errors.length > 0) {
        console.log(`      エラー: ${result.errors.join(', ')}`);
      }
    });

    // 包括検証テスト
    console.log('  📋 包括検証テスト:');
    const bulkData = {
      icCardNumber: 'TO1234567890123456',
      employeeId: 'EMP123456',
      email: 'test@example.com',
      phoneNumber: '052-123-4567'
    };

    const bulkResult = validator.validateBulkData(bulkData);
    console.log(`    全体検証: ${bulkResult.valid ? '✅ 成功' : '❌ 失敗'}`);

    // XSS対策テスト
    const xssTests = [
      '<script>alert("xss")</script>',
      'javascript:alert("xss")',
      '<img src="x" onerror="alert(1)">',
      'data:text/html,<script>alert("xss")</script>'
    ];

    console.log('  🛡️ XSS対策テスト:');
    xssTests.forEach((xssInput, index) => {
      const sanitized = validator.sanitizeInput(xssInput);
      const isClean = !sanitized.includes('script') && !sanitized.includes('javascript');
      console.log(`    XSSパターン${index + 1}: ${isClean ? '✅ 無害化' : '❌ 危険'}`);
    });

  } catch (error) {
    console.error('  ❌ InputValidator テストエラー:', error.message);
  }
}

/**
 * SecurityConfig テスト
 */
function testSecurityConfig() {
  try {
    const securityConfig = new SecurityConfig('test_master_password');

    console.log('  📋 セキュリティ設定テスト:');

    // 設定ロード/保存テスト
    const testConfig = {
      hash: {
        iterations: 150000,
        saltLength: 64
      },
      session: {
        timeoutMinutes: 30
      }
    };

    const loadResult = securityConfig.loadConfig(testConfig);
    console.log(`    設定ロード: ${loadResult ? '✅ 成功' : '❌ 失敗'}`);

    // セキュリティヘルスチェック
    const healthCheck = securityConfig.performSecurityHealthCheck();
    console.log(`    ヘルスチェック: グレード ${healthCheck.grade} (${healthCheck.score}点)`);
    
    if (healthCheck.recommendations.length > 0) {
      console.log('    推奨事項:');
      healthCheck.recommendations.forEach(rec => {
        console.log(`      - ${rec}`);
      });
    }

    // 監査ログテスト
    const auditLog = securityConfig.getAuditLog(5);
    console.log(`    監査ログ: ${auditLog.length}件記録`);

  } catch (error) {
    console.error('  ❌ SecurityConfig テストエラー:', error.message);
  }
}

/**
 * パフォーマンステスト
 */
async function performanceTests() {
  try {
    console.log('  ⚡ ハッシュ化パフォーマンステスト:');

    // 異なる反復回数でのテスト
    const iterationTests = [100000, 150000, 200000];
    
    for (const iterations of iterationTests) {
      const hashManager = new SecureHashManager({
        iterations,
        saltLength: 32,
        pepper: 'performance_test'
      });

      const testData = 'TO1234567890123456';
      const startTime = Date.now();
      
      // 10回実行して平均算出
      for (let i = 0; i < 10; i++) {
        await hashManager.hashICCardNumber(testData);
      }
      
      const avgTime = (Date.now() - startTime) / 10;
      console.log(`    ${iterations.toLocaleString()}回反復: ${avgTime.toFixed(2)}ms/回`);
    }

    // メモリ使用量テスト
    console.log('  💾 メモリ使用量テスト:');
    const memBefore = process.memoryUsage();
    
    const hashManager = new SecureHashManager();
    const validator = new InputValidator();
    
    // 大量処理テスト
    for (let i = 0; i < 100; i++) {
      await hashManager.hashICCardNumber(`TO${String(i).padStart(14, '0')}`);
      validator.validateICCardNumber(`TO${String(i).padStart(14, '0')}`);
    }
    
    const memAfter = process.memoryUsage();
    const memDiff = (memAfter.heapUsed - memBefore.heapUsed) / 1024 / 1024;
    console.log(`    メモリ増加: ${memDiff.toFixed(2)}MB`);

  } catch (error) {
    console.error('  ❌ パフォーマンステストエラー:', error.message);
  }
}

/**
 * サンプル使用例生成
 */
function generateUsageExamples() {
  console.log('\n📖 セキュリティクラス使用例:\n');

  console.log('// 1. SecureHashManager 使用例');
  console.log(`const hashManager = new SecureHashManager({
  iterations: 100000,
  saltLength: 32,
  pepper: 'your_pepper_value'
});

const result = hashManager.hashICCardNumber('TO1234567890123456');
console.log('ハッシュ値:', result.hash);
console.log('マスク番号:', result.maskedNumber);`);

  console.log('\n// 2. InputValidator 使用例');
  console.log(`const validator = new InputValidator();

const icResult = validator.validateICCardNumber('TO1234567890123456');
if (icResult.valid) {
  console.log('カード種別:', icResult.cardName);
} else {
  console.log('エラー:', icResult.errors);
}`);

  console.log('\n// 3. SecurityConfig 使用例');
  console.log(`const securityConfig = new SecurityConfig('master_password');

const healthCheck = securityConfig.performSecurityHealthCheck();
console.log('セキュリティスコア:', healthCheck.score);`);
}

// テスト実行
if (require.main === module) {
  runSecurityTests()
    .then(() => {
      generateUsageExamples();
    })
    .catch(error => {
      console.error('テスト実行エラー:', error);
    });
}

module.exports = {
  runSecurityTests,
  testSecureHashManager,
  testInputValidator,
  testSecurityConfig,
  performanceTests
};
