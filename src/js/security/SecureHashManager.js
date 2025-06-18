/**
 * SecureHashManager.js
 * IPAガイドライン「安全なウェブサイトの作り方」完全準拠セキュアハッシュ化クラス
 * 
 * 準拠章節:
 * - 1-6 パスワード等の重要情報を保護する (p.35-45)
 * - セキュアハッシュ化アルゴリズム実装
 * 
 * @author Kei-Adachi0709
 * @version 1.0.0
 * @date 2025-06-19
 * @compliance IPA安全なウェブサイトの作り方準拠
 */

const CryptoJS = require('crypto-js');

/**
 * IPAガイドライン準拠セキュアハッシュ化管理クラス
 * 
 * 実装仕様:
 * - アルゴリズム: PBKDF2-SHA512 (IPA推奨)
 * - ストレッチング: 100,000回以上 (調整可能)
 * - ソルト: 32バイト暗号学的乱数生成
 * - ペッパー: 設定可能な共通秘密値対応
 */
class SecureHashManager {
  /**
   * コンストラクタ
   * @param {Object} config - セキュリティ設定
   * @param {number} config.iterations - ストレッチング回数 (最小100,000)
   * @param {number} config.saltLength - ソルト長 (推奨32バイト)
   * @param {string} config.pepper - ペッパー値 (オプション)
   * @param {string} config.algorithm - ハッシュアルゴリズム (デフォルト: SHA512)
   */
  constructor(config = {}) {
    // IPAガイドライン準拠デフォルト設定
    this.config = {
      iterations: Math.max(config.iterations || 100000, 100000), // 最小10万回
      saltLength: config.saltLength || 32, // 32バイト推奨
      pepper: config.pepper || '', // ペッパー値
      algorithm: config.algorithm || 'SHA512',
      keyLength: config.keyLength || 64 // 512bit = 64バイト
    };

    // IPA準拠セキュリティ検証
    this._validateSecurityConfig();
  }

  /**
   * セキュリティ設定検証 (IPAガイドライン準拠)
   * @private
   */
  _validateSecurityConfig() {
    if (this.config.iterations < 100000) {
      throw new Error('IPA準拠エラー: ストレッチング回数は100,000回以上必要です');
    }
    
    if (this.config.saltLength < 16) {
      throw new Error('IPA準拠エラー: ソルト長は最低16バイト必要です');
    }

    if (!['SHA256', 'SHA512'].includes(this.config.algorithm)) {
      throw new Error('IPA準拠エラー: サポートされていないアルゴリズムです');
    }
  }

  /**
   * 暗号学的に安全なソルト生成 (IPA準拠)
   * @returns {string} Base64エンコードされたソルト
   */
  generateSecureSalt() {
    try {
      // 暗号学的乱数生成器使用 (IPA推奨)
      const salt = CryptoJS.lib.WordArray.random(this.config.saltLength);
      return CryptoJS.enc.Base64.stringify(salt);
    } catch (error) {
      throw new Error(`ソルト生成エラー: ${error.message}`);
    }
  }

  /**
   * ICカード番号のセキュアハッシュ化 (IPA準拠)
   * @param {string} icCardNumber - ICカード番号
   * @param {string} salt - ソルト値 (オプション、未指定時は自動生成)
   * @returns {Object} ハッシュ化結果
   */
  hashICCardNumber(icCardNumber, salt = null) {
    try {
      // 入力値検証
      if (!icCardNumber || typeof icCardNumber !== 'string') {
        throw new Error('無効なICカード番号です');
      }

      // ソルト処理
      const finalSalt = salt || this.generateSecureSalt();
      
      // ペッパー適用 (IPA推奨追加保護)
      const pepperedData = icCardNumber + this.config.pepper;
      
      // PBKDF2-SHA512ハッシュ化実行 (IPA準拠)
      const hash = CryptoJS.PBKDF2(
        pepperedData,
        CryptoJS.enc.Base64.parse(finalSalt),
        {
          keySize: this.config.keyLength / 4, // WordArray単位
          iterations: this.config.iterations,
          hasher: CryptoJS.algo[this.config.algorithm]
        }
      );

      // 結果返却
      return {
        hash: CryptoJS.enc.Base64.stringify(hash),
        salt: finalSalt,
        iterations: this.config.iterations,
        algorithm: `PBKDF2-${this.config.algorithm}`,
        timestamp: new Date().toISOString(),
        maskedNumber: this._maskICCardNumber(icCardNumber)
      };

    } catch (error) {
      throw new Error(`ハッシュ化エラー: ${error.message}`);
    }
  }

  /**
   * ICカード番号検証 (ハッシュ比較)
   * @param {string} icCardNumber - 検証対象ICカード番号
   * @param {string} storedHash - 保存されたハッシュ値
   * @param {string} salt - 保存されたソルト値
   * @returns {boolean} 検証結果
   */
  verifyICCardNumber(icCardNumber, storedHash, salt) {
    try {
      const hashResult = this.hashICCardNumber(icCardNumber, salt);
      return hashResult.hash === storedHash;
    } catch (error) {
      // セキュリティ上、詳細エラーは隠蔽
      console.error('検証エラー:', error.message);
      return false;
    }
  }

  /**
   * ICカード番号マスキング処理 (プライバシー保護)
   * @param {string} icCardNumber - ICカード番号
   * @returns {string} マスキング済み番号
   * @private
   */
  _maskICCardNumber(icCardNumber) {
    if (!icCardNumber || icCardNumber.length < 4) {
      return '****';
    }
    
    const lastFour = icCardNumber.slice(-4);
    const masked = '*'.repeat(icCardNumber.length - 4) + lastFour;
    return masked;
  }

  /**
   * 名古屋圏ICカード対応検証
   * @param {string} icCardNumber - ICカード番号
   * @returns {Object} 検証結果とカード種別
   */
  validateNagoyaICCard(icCardNumber) {
    const icCardTypes = {
      TOICA: {
        pattern: /^TO\d{14}$/,
        length: 16,
        prefix: 'TO',
        name: 'TOICA',
        issuer: 'JR東海'
      },
      manaca: {
        pattern: /^MA\d{14}$/,
        length: 16,
        prefix: 'MA',
        name: 'manaca',
        issuer: '名古屋市交通局・名鉄'
      },
      Suica: {
        pattern: /^JE\d{15}$/,
        length: 17,
        prefix: 'JE',
        name: 'Suica',
        issuer: 'JR東日本'
      },
      ICOCA: {
        pattern: /^IC\d{14}$/,
        length: 16,
        prefix: 'IC',
        name: 'ICOCA',
        issuer: 'JR西日本'
      },
      SUGOCA: {
        pattern: /^SG\d{14}$/,
        length: 16,
        prefix: 'SG',
        name: 'SUGOCA',
        issuer: 'JR九州'
      },
      PASMO: {
        pattern: /^P[AB]\d{14}$/,
        length: 16,
        prefix: 'P[AB]',
        name: 'PASMO',
        issuer: 'PASMO'
      }
    };

    for (const [type, config] of Object.entries(icCardTypes)) {
      if (config.pattern.test(icCardNumber)) {
        return {
          valid: true,
          type: type,
          name: config.name,
          issuer: config.issuer,
          maskedNumber: this._maskICCardNumber(icCardNumber)
        };
      }
    }

    return {
      valid: false,
      type: 'UNKNOWN',
      error: '対応していないICカード形式です'
    };
  }

  /**
   * セキュリティ設定取得
   * @returns {Object} 現在のセキュリティ設定
   */
  getSecurityConfig() {
    return {
      ...this.config,
      pepper: '[HIDDEN]' // ペッパー値は隠蔽
    };
  }

  /**
   * パフォーマンステスト実行
   * @param {number} testCount - テスト回数
   * @returns {Object} パフォーマンス結果
   */
  async performanceTest(testCount = 10) {
    const testData = 'TO1234567890123456';
    const results = [];

    for (let i = 0; i < testCount; i++) {
      const startTime = performance.now();
      await this.hashICCardNumber(testData);
      const endTime = performance.now();
      results.push(endTime - startTime);
    }

    const average = results.reduce((a, b) => a + b, 0) / results.length;
    const min = Math.min(...results);
    const max = Math.max(...results);

    return {
      testCount,
      averageTime: `${average.toFixed(2)}ms`,
      minTime: `${min.toFixed(2)}ms`,
      maxTime: `${max.toFixed(2)}ms`,
      iterations: this.config.iterations,
      securityLevel: 'IPA準拠・高セキュリティ'
    };
  }
}

module.exports = SecureHashManager;
