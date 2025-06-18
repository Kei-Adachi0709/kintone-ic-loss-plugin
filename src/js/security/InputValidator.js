/**
 * InputValidator.js
 * IPAガイドライン「安全なウェブサイトの作り方」章節1-4準拠入力値検証クラス
 * 
 * 準拠章節:
 * - 1-4 入力値の検証 (p.15-25)
 * - XSS対策・サニタイゼーション実装
 * - 入力値検証アーキテクチャ
 * 
 * @author Kei-Adachi0709
 * @version 1.0.0
 * @date 2025-06-19
 * @compliance IPA安全なウェブサイトの作り方準拠
 */

/**
 * IPAガイドライン準拠入力値検証クラス
 * 
 * 実装仕様:
 * - 文字種制限 (IPA章節1-4準拠)
 * - 長さ制限 (セキュリティ考慮)
 * - エスケープ処理 (XSS対策完全実装)
 * - サニタイゼーション (包括的実装)
 */
class InputValidator {
  
  constructor() {
    // IPA準拠セキュリティ設定
    this.config = {
      maxInputLength: 1000,
      allowedICCardFormats: [
        'TOICA', 'manaca', 'Suica', 'ICOCA', 'SUGOCA', 'PASMO'
      ],
      dangerousPatterns: [
        /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
        /javascript:/gi,
        /on\w+\s*=/gi,
        /data:text\/html/gi,
        /vbscript:/gi
      ]
    };
  }

  /**
   * 基本入力値検証 (IPA準拠)
   * @param {string} input - 検証対象文字列
   * @param {Object} options - 検証オプション
   * @returns {Object} 検証結果
   */
  validateBasicInput(input, options = {}) {
    const config = { ...this.config, ...options };
    const errors = [];
    
    try {
      // null/undefined チェック
      if (input === null || input === undefined) {
        errors.push('入力値が空です');
        return { valid: false, errors, sanitized: '' };
      }

      // 型チェック
      if (typeof input !== 'string') {
        input = String(input);
      }

      // 長さチェック (IPA推奨)
      if (input.length > config.maxInputLength) {
        errors.push(`入力値が長すぎます (最大${config.maxInputLength}文字)`);
      }

      // 危険なパターンチェック (XSS対策)
      for (const pattern of this.config.dangerousPatterns) {
        if (pattern.test(input)) {
          errors.push('危険なパターンが検出されました');
          break;
        }
      }

      // サニタイゼーション実行
      const sanitized = this.sanitizeInput(input);

      return {
        valid: errors.length === 0,
        errors,
        sanitized,
        originalLength: input.length,
        sanitizedLength: sanitized.length
      };

    } catch (error) {
      return {
        valid: false,
        errors: ['検証処理エラー'],
        sanitized: '',
        error: error.message
      };
    }
  }

  /**
   * ICカード番号専用検証 (名古屋圏対応)
   * @param {string} icCardNumber - ICカード番号
   * @returns {Object} 検証結果
   */
  validateICCardNumber(icCardNumber) {
    const basicValidation = this.validateBasicInput(icCardNumber, {
      maxInputLength: 20 // ICカード番号用制限
    });

    if (!basicValidation.valid) {
      return {
        ...basicValidation,
        cardType: null,
        formatValid: false
      };
    }

    // ICカード形式検証
    const icCardFormats = {
      TOICA: {
        pattern: /^TO\d{14}$/,
        length: 16,
        name: 'TOICA（JR東海）'
      },
      manaca: {
        pattern: /^MA\d{14}$/,
        length: 16,
        name: 'manaca（名古屋市交通局・名鉄）'
      },
      Suica: {
        pattern: /^JE\d{15}$/,
        length: 17,
        name: 'Suica（JR東日本）'
      },
      ICOCA: {
        pattern: /^IC\d{14}$/,
        length: 16,
        name: 'ICOCA（JR西日本）'
      },
      SUGOCA: {
        pattern: /^SG\d{14}$/,
        length: 16,
        name: 'SUGOCA（JR九州）'
      },
      PASMO: {
        pattern: /^P[AB]\d{14}$/,
        length: 16,
        name: 'PASMO'
      }
    };

    const sanitized = basicValidation.sanitized.toUpperCase();
    
    for (const [type, format] of Object.entries(icCardFormats)) {
      if (format.pattern.test(sanitized)) {
        return {
          valid: true,
          errors: [],
          sanitized,
          cardType: type,
          cardName: format.name,
          formatValid: true,
          maskedNumber: this._maskCardNumber(sanitized)
        };
      }
    }

    return {
      valid: false,
      errors: ['対応していないICカード形式です'],
      sanitized,
      cardType: null,
      formatValid: false,
      supportedFormats: Object.keys(icCardFormats)
    };
  }

  /**
   * 社員証番号検証
   * @param {string} employeeId - 社員証番号
   * @returns {Object} 検証結果
   */
  validateEmployeeId(employeeId) {
    const basicValidation = this.validateBasicInput(employeeId, {
      maxInputLength: 20
    });

    if (!basicValidation.valid) {
      return basicValidation;
    }

    const sanitized = basicValidation.sanitized;
    
    // 社員証番号形式チェック (例: 英数字のみ、6-12文字)
    const employeeIdPattern = /^[A-Za-z0-9]{6,12}$/;
    
    if (!employeeIdPattern.test(sanitized)) {
      return {
        valid: false,
        errors: ['社員証番号は英数字6-12文字で入力してください'],
        sanitized
      };
    }

    return {
      valid: true,
      errors: [],
      sanitized: sanitized.toUpperCase(),
      maskedId: this._maskEmployeeId(sanitized)
    };
  }

  /**
   * メールアドレス検証 (緊急連絡先用)
   * @param {string} email - メールアドレス
   * @returns {Object} 検証結果
   */
  validateEmail(email) {
    const basicValidation = this.validateBasicInput(email, {
      maxInputLength: 254 // RFC 5321準拠
    });

    if (!basicValidation.valid) {
      return basicValidation;
    }

    const sanitized = basicValidation.sanitized.toLowerCase();
    
    // RFC 5322準拠メールアドレスパターン (簡易版)
    const emailPattern = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    
    if (!emailPattern.test(sanitized)) {
      return {
        valid: false,
        errors: ['有効なメールアドレスを入力してください'],
        sanitized
      };
    }

    return {
      valid: true,
      errors: [],
      sanitized,
      domain: sanitized.split('@')[1]
    };
  }

  /**
   * 電話番号検証 (緊急連絡先用)
   * @param {string} phoneNumber - 電話番号
   * @returns {Object} 検証結果
   */
  validatePhoneNumber(phoneNumber) {
    const basicValidation = this.validateBasicInput(phoneNumber, {
      maxInputLength: 20
    });

    if (!basicValidation.valid) {
      return basicValidation;
    }

    // 数字、ハイフン、括弧のみ許可
    const sanitized = basicValidation.sanitized.replace(/[^\d\-\(\)\+\s]/g, '');
    
    // 日本の電話番号パターン
    const phonePatterns = [
      /^0\d{1,4}-\d{1,4}-\d{4}$/, // 固定電話
      /^0[789]0-\d{4}-\d{4}$/, // 携帯電話
      /^050-\d{4}-\d{4}$/, // IP電話
      /^\+81-\d{1,4}-\d{1,4}-\d{4}$/ // 国際形式
    ];

    const isValidFormat = phonePatterns.some(pattern => pattern.test(sanitized));

    if (!isValidFormat) {
      return {
        valid: false,
        errors: ['有効な電話番号形式で入力してください (例: 052-123-4567)'],
        sanitized
      };
    }

    return {
      valid: true,
      errors: [],
      sanitized,
      maskedNumber: this._maskPhoneNumber(sanitized)
    };
  }

  /**
   * HTMLエスケープ処理 (XSS対策)
   * @param {string} input - エスケープ対象文字列
   * @returns {string} エスケープ済み文字列
   */
  escapeHtml(input) {
    if (typeof input !== 'string') {
      return '';
    }

    const htmlEscapeMap = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#x27;',
      '/': '&#x2F;',
      '`': '&#x60;',
      '=': '&#x3D;'
    };

    return input.replace(/[&<>"'`=\/]/g, char => htmlEscapeMap[char]);
  }

  /**
   * 包括的サニタイゼーション (IPA準拠)
   * @param {string} input - サニタイゼーション対象
   * @returns {string} サニタイゼーション済み文字列
   */
  sanitizeInput(input) {
    if (typeof input !== 'string') {
      return '';
    }

    let sanitized = input;

    // 制御文字除去
    sanitized = sanitized.replace(/[\x00-\x1F\x7F]/g, '');

    // 危険なHTMLタグ除去
    sanitized = sanitized.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
    sanitized = sanitized.replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, '');
    sanitized = sanitized.replace(/<object\b[^<]*(?:(?!<\/object>)<[^<]*)*<\/object>/gi, '');

    // イベントハンドラ除去
    sanitized = sanitized.replace(/on\w+\s*=\s*[^>\s]+/gi, '');

    // JavaScript/VBScript URL除去
    sanitized = sanitized.replace(/javascript:/gi, '');
    sanitized = sanitized.replace(/vbscript:/gi, '');

    // 前後の空白除去
    sanitized = sanitized.trim();

    return sanitized;
  }

  /**
   * ICカード番号マスキング
   * @param {string} cardNumber - カード番号
   * @returns {string} マスク済み番号
   * @private
   */
  _maskCardNumber(cardNumber) {
    if (!cardNumber || cardNumber.length < 4) {
      return '****';
    }
    const prefix = cardNumber.substring(0, 2);
    const lastFour = cardNumber.slice(-4);
    const middle = '*'.repeat(cardNumber.length - 6);
    return prefix + middle + lastFour;
  }

  /**
   * 社員証番号マスキング
   * @param {string} employeeId - 社員証番号
   * @returns {string} マスク済み番号
   * @private
   */
  _maskEmployeeId(employeeId) {
    if (!employeeId || employeeId.length < 4) {
      return '****';
    }
    const first = employeeId.substring(0, 1);
    const last = employeeId.slice(-1);
    const middle = '*'.repeat(employeeId.length - 2);
    return first + middle + last;
  }

  /**
   * 電話番号マスキング
   * @param {string} phoneNumber - 電話番号
   * @returns {string} マスク済み番号
   * @private
   */
  _maskPhoneNumber(phoneNumber) {
    return phoneNumber.replace(/(\d{3})-(\d{4})-(\d{4})/, '$1-****-$3');
  }

  /**
   * バルクバリデーション (複数項目一括検証)
   * @param {Object} data - 検証対象データ
   * @returns {Object} 検証結果
   */
  validateBulkData(data) {
    const results = {};
    let allValid = true;

    // ICカード番号検証
    if (data.icCardNumber) {
      results.icCardNumber = this.validateICCardNumber(data.icCardNumber);
      if (!results.icCardNumber.valid) allValid = false;
    }

    // 社員証番号検証
    if (data.employeeId) {
      results.employeeId = this.validateEmployeeId(data.employeeId);
      if (!results.employeeId.valid) allValid = false;
    }

    // メールアドレス検証
    if (data.email) {
      results.email = this.validateEmail(data.email);
      if (!results.email.valid) allValid = false;
    }

    // 電話番号検証
    if (data.phoneNumber) {
      results.phoneNumber = this.validatePhoneNumber(data.phoneNumber);
      if (!results.phoneNumber.valid) allValid = false;
    }

    return {
      valid: allValid,
      results,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * 検証設定取得
   * @returns {Object} 現在の検証設定
   */
  getValidationConfig() {
    return { ...this.config };
  }
}

module.exports = InputValidator;
