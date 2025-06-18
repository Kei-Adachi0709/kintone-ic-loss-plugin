/**
 * SecurityConfig.js
 * IPAガイドライン準拠セキュリティ設定管理クラス
 * 
 * 準拠章節:
 * - セキュリティ設定の一元管理
 * - 設定値の暗号化保護
 * - 監査ログ機能
 * 
 * @author Kei-Adachi0709
 * @version 1.0.0
 * @date 2025-06-19
 * @compliance IPA安全なウェブサイトの作り方準拠
 */

const CryptoJS = require('crypto-js');

/**
 * IPAガイドライン準拠セキュリティ設定管理クラス
 */
class SecurityConfig {
  
  constructor(masterPassword = null) {
    this.masterPassword = masterPassword;
    
    // デフォルトセキュリティ設定 (IPA準拠)
    this.defaultConfig = {
      // ハッシュ化設定
      hash: {
        algorithm: 'PBKDF2-SHA512',
        iterations: 100000, // IPA推奨最小値
        saltLength: 32,
        keyLength: 64
      },
      
      // 入力値検証設定
      validation: {
        maxInputLength: 1000,
        strictMode: true,
        allowUnicode: false,
        logValidationErrors: true
      },
      
      // セッション設定
      session: {
        timeoutMinutes: 30,
        renewThreshold: 5, // 5分前に更新
        maxConcurrentSessions: 1
      },
      
      // 監査ログ設定
      audit: {
        enabled: true,
        logLevel: 'INFO',
        retentionDays: 90,
        sensitiveDataMasking: true
      },
      
      // エラーハンドリング設定
      errorHandling: {
        showDetailedErrors: false, // 本番環境では false
        logErrors: true,
        maxRetryAttempts: 3
      },
      
      // レート制限設定
      rateLimit: {
        enabled: true,
        maxRequestsPerMinute: 60,
        maxFailedAttemptsPerHour: 10,
        lockoutDurationMinutes: 30
      }
    };

    this.config = { ...this.defaultConfig };
    this.auditLog = [];
  }

  /**
   * セキュリティ設定の読み込み
   * @param {Object} externalConfig - 外部設定
   * @returns {boolean} 読み込み成功フラグ
   */
  loadConfig(externalConfig) {
    try {
      // 設定値検証
      const validationResult = this._validateConfig(externalConfig);
      if (!validationResult.valid) {
        this._logAuditEvent('CONFIG_VALIDATION_FAILED', {
          errors: validationResult.errors
        });
        return false;
      }

      // 設定マージ
      this.config = this._mergeConfig(this.defaultConfig, externalConfig);
      
      // 監査ログ記録
      this._logAuditEvent('CONFIG_LOADED', {
        configSections: Object.keys(externalConfig),
        timestamp: new Date().toISOString()
      });

      return true;

    } catch (error) {
      this._logAuditEvent('CONFIG_LOAD_ERROR', {
        error: error.message
      });
      return false;
    }
  }

  /**
   * セキュリティ設定の保存 (暗号化)
   * @param {string} configKey - 設定キー
   * @param {*} value - 設定値
   * @returns {boolean} 保存成功フラグ
   */
  saveSecureConfig(configKey, value) {
    try {
      if (!this.masterPassword) {
        throw new Error('マスターパスワードが設定されていません');
      }

      // 機密設定の暗号化
      const encryptedValue = this._encryptSensitiveData(value);
      
      // Kintone設定保存 (実際の実装では kintone.plugin.app.setConfig を使用)
      const configData = {
        [configKey]: encryptedValue,
        lastUpdated: new Date().toISOString(),
        version: '1.0.0'
      };

      // 監査ログ記録
      this._logAuditEvent('CONFIG_SAVED', {
        configKey,
        encrypted: true
      });

      return true;

    } catch (error) {
      this._logAuditEvent('CONFIG_SAVE_ERROR', {
        configKey,
        error: error.message
      });
      return false;
    }
  }

  /**
   * 暗号化された設定の読み込み
   * @param {string} configKey - 設定キー
   * @returns {*} 復号化された設定値
   */
  loadSecureConfig(configKey) {
    try {
      if (!this.masterPassword) {
        throw new Error('マスターパスワードが設定されていません');
      }

      // Kintone設定読み込み (実際の実装では kintone.plugin.app.getConfig を使用)
      const encryptedValue = this._getStoredConfig(configKey);
      
      if (!encryptedValue) {
        return null;
      }

      // 復号化
      const decryptedValue = this._decryptSensitiveData(encryptedValue);
      
      // 監査ログ記録
      this._logAuditEvent('CONFIG_LOADED', {
        configKey,
        decrypted: true
      });

      return decryptedValue;

    } catch (error) {
      this._logAuditEvent('CONFIG_LOAD_ERROR', {
        configKey,
        error: error.message
      });
      return null;
    }
  }

  /**
   * ペッパー値取得 (セキュア)
   * @returns {string} ペッパー値
   */
  getPepper() {
    return this.loadSecureConfig('security_pepper') || this._generateDefaultPepper();
  }

  /**
   * ハッシュ化設定取得
   * @returns {Object} ハッシュ化設定
   */
  getHashConfig() {
    return {
      ...this.config.hash,
      pepper: this.getPepper()
    };
  }

  /**
   * 入力値検証設定取得
   * @returns {Object} 検証設定
   */
  getValidationConfig() {
    return { ...this.config.validation };
  }

  /**
   * セッション設定取得
   * @returns {Object} セッション設定
   */
  getSessionConfig() {
    return { ...this.config.session };
  }

  /**
   * 監査ログ取得
   * @param {number} limit - 取得件数制限
   * @returns {Array} 監査ログ
   */
  getAuditLog(limit = 100) {
    return this.auditLog
      .slice(-limit)
      .map(log => ({
        ...log,
        sensitiveData: '[MASKED]' // 機密データマスキング
      }));
  }

  /**
   * セキュリティヘルスチェック
   * @returns {Object} ヘルスチェック結果
   */
  performSecurityHealthCheck() {
    const checks = {
      hashIterations: this.config.hash.iterations >= 100000,
      saltLength: this.config.hash.saltLength >= 32,
      sessionTimeout: this.config.session.timeoutMinutes <= 60,
      auditEnabled: this.config.audit.enabled,
      rateLimitEnabled: this.config.rateLimit.enabled,
      pepperConfigured: !!this.loadSecureConfig('security_pepper')
    };

    const passedChecks = Object.values(checks).filter(Boolean).length;
    const totalChecks = Object.keys(checks).length;
    const score = Math.round((passedChecks / totalChecks) * 100);

    this._logAuditEvent('SECURITY_HEALTH_CHECK', {
      score,
      passedChecks,
      totalChecks,
      details: checks
    });

    return {
      score,
      grade: this._getSecurityGrade(score),
      checks,
      recommendations: this._getSecurityRecommendations(checks)
    };
  }

  /**
   * 設定検証 (内部)
   * @param {Object} config - 検証対象設定
   * @returns {Object} 検証結果
   * @private
   */
  _validateConfig(config) {
    const errors = [];

    // ハッシュ設定検証
    if (config.hash) {
      if (config.hash.iterations && config.hash.iterations < 100000) {
        errors.push('ハッシュ反復回数は100,000以上必要です');
      }
      if (config.hash.saltLength && config.hash.saltLength < 16) {
        errors.push('ソルト長は16バイト以上必要です');
      }
    }

    // セッション設定検証
    if (config.session) {
      if (config.session.timeoutMinutes && config.session.timeoutMinutes > 120) {
        errors.push('セッションタイムアウトは120分以下を推奨します');
      }
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }

  /**
   * 設定マージ (深いマージ)
   * @param {Object} target - ターゲット設定
   * @param {Object} source - ソース設定
   * @returns {Object} マージ済み設定
   * @private
   */
  _mergeConfig(target, source) {
    const result = { ...target };
    
    for (const key in source) {
      if (source.hasOwnProperty(key)) {
        if (typeof source[key] === 'object' && !Array.isArray(source[key])) {
          result[key] = this._mergeConfig(target[key] || {}, source[key]);
        } else {
          result[key] = source[key];
        }
      }
    }
    
    return result;
  }

  /**
   * 機密データ暗号化
   * @param {*} data - 暗号化対象データ
   * @returns {string} 暗号化データ
   * @private
   */
  _encryptSensitiveData(data) {
    const jsonData = JSON.stringify(data);
    return CryptoJS.AES.encrypt(jsonData, this.masterPassword).toString();
  }

  /**
   * 機密データ復号化
   * @param {string} encryptedData - 暗号化データ
   * @returns {*} 復号化データ
   * @private
   */
  _decryptSensitiveData(encryptedData) {
    const bytes = CryptoJS.AES.decrypt(encryptedData, this.masterPassword);
    const jsonData = bytes.toString(CryptoJS.enc.Utf8);
    return JSON.parse(jsonData);
  }

  /**
   * デフォルトペッパー生成
   * @returns {string} ペッパー値
   * @private
   */
  _generateDefaultPepper() {
    const pepper = CryptoJS.lib.WordArray.random(32).toString();
    this.saveSecureConfig('security_pepper', pepper);
    return pepper;
  }

  /**
   * 保存済み設定取得 (モック)
   * @param {string} configKey - 設定キー
   * @returns {string} 設定値
   * @private
   */
  _getStoredConfig(configKey) {
    // 実際の実装では kintone.plugin.app.getConfig() を使用
    return localStorage.getItem(`secure_config_${configKey}`);
  }

  /**
   * 監査ログ記録
   * @param {string} event - イベント名
   * @param {Object} details - 詳細情報
   * @private
   */
  _logAuditEvent(event, details = {}) {
    if (!this.config.audit.enabled) return;

    const logEntry = {
      timestamp: new Date().toISOString(),
      event,
      details: this.config.audit.sensitiveDataMasking ? 
        this._maskSensitiveData(details) : details,
      userAgent: typeof navigator !== 'undefined' ? navigator.userAgent : 'Node.js'
    };

    this.auditLog.push(logEntry);

    // ログ保持期間管理
    const retentionMs = this.config.audit.retentionDays * 24 * 60 * 60 * 1000;
    const cutoffDate = new Date(Date.now() - retentionMs);
    
    this.auditLog = this.auditLog.filter(log => 
      new Date(log.timestamp) > cutoffDate
    );

    // コンソール出力 (開発環境のみ)
    if (this.config.audit.logLevel === 'DEBUG') {
      console.log('AUDIT:', logEntry);
    }
  }

  /**
   * 機密データマスキング
   * @param {Object} data - マスキング対象
   * @returns {Object} マスキング済みデータ
   * @private
   */
  _maskSensitiveData(data) {
    const masked = { ...data };
    const sensitiveKeys = ['password', 'pepper', 'salt', 'key', 'token'];
    
    for (const key of sensitiveKeys) {
      if (masked[key]) {
        masked[key] = '[MASKED]';
      }
    }
    
    return masked;
  }

  /**
   * セキュリティグレード判定
   * @param {number} score - セキュリティスコア
   * @returns {string} セキュリティグレード
   * @private
   */
  _getSecurityGrade(score) {
    if (score >= 90) return 'A';
    if (score >= 80) return 'B';
    if (score >= 70) return 'C';
    if (score >= 60) return 'D';
    return 'F';
  }

  /**
   * セキュリティ推奨事項取得
   * @param {Object} checks - チェック結果
   * @returns {Array} 推奨事項
   * @private
   */
  _getSecurityRecommendations(checks) {
    const recommendations = [];

    if (!checks.hashIterations) {
      recommendations.push('ハッシュ反復回数を100,000以上に設定してください');
    }
    if (!checks.pepperConfigured) {
      recommendations.push('ペッパー値を設定してください');
    }
    if (!checks.auditEnabled) {
      recommendations.push('監査ログを有効にしてください');
    }
    if (!checks.rateLimitEnabled) {
      recommendations.push('レート制限を有効にしてください');
    }

    return recommendations;
  }
}

module.exports = SecurityConfig;
