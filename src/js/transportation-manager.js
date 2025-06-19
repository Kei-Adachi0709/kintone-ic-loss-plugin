/**
 * transportation-manager.js
 * 交通機関データ管理クラス - IPAガイドライン準拠実装
 * 
 * 準拠章節:
 * - PDF章節1-1: SQLインジェクション対策
 * - PDF章節1-4: 入力値の検証
 * - PDF章節1-3: OSコマンドインジェクション対策
 * 
 * @author Kei-Adachi0709
 * @version 1.0.0
 * @date 2025-06-19
 * @compliance IPA安全なウェブサイトの作り方準拠
 */

// Phase 1・2セキュリティクラス統合
const InputValidator = require('./security/InputValidator');
const SecureHashManager = require('./security/SecureHashManager');
const { CommonUtils } = require('./common');

/**
 * IPAガイドライン準拠交通機関データ管理クラス
 * PDF章節1-1・1-4準拠設計
 */
class TransportationManager {
  constructor() {
    // Phase 1・2のセキュリティクラス統合
    this.validator = new InputValidator();
    this.securityManager = new SecureHashManager();
    
    // 交通機関データキャッシュ
    this.transportationData = null;
    this.lastLoadTime = null;
    this.cacheExpiry = 300000; // 5分キャッシュ
    
    // IPA準拠セキュリティ設定
    this.securityConfig = {
      maxQueryLength: 100,
      allowedTransportationIds: [
        'jr_tokai', 'kintetsu', 'nagoya_subway', 
        'meitetsu', 'nagoya_bus', 'meitetsu_bus'
      ],
      dangerousPatterns: [
        /['"`;\\\\]/g, // SQL Injection patterns
        /--/g,         // SQL comments
        /\/\*/g,       // SQL block comments
        /<script/gi,   // XSS patterns
        /javascript:/gi
      ]
    };
  }

  /**
   * PDF章節1-4準拠: 交通機関ID検証
   * @param {string} id - 交通機関ID
   * @returns {Object} 検証結果
   */
  validateTransportationId(id) {
    // 基本入力値検証
    const basicValidation = this.validator.validateBasicInput(id, {
      type: 'string',
      required: true,
      minLength: 1,
      maxLength: 50
    });

    if (!basicValidation.isValid) {
      return {
        isValid: false,
        errors: ['交通機関IDの形式が不正です: ' + basicValidation.errors.join(', ')]
      };
    }

    // 文字種制限 (英数字・ハイフン・アンダースコアのみ)
    const allowedPattern = /^[a-zA-Z0-9\-_]+$/;
    if (!allowedPattern.test(id)) {
      return {
        isValid: false,
        errors: ['交通機関IDは英数字、ハイフン、アンダースコアのみ使用可能です']
      };
    }

    // 危険パターンチェック (SQL Injection対策)
    for (const pattern of this.securityConfig.dangerousPatterns) {
      if (pattern.test(id)) {
        return {
          isValid: false,
          errors: ['セキュリティ上禁止された文字が含まれています']
        };
      }
    }

    // 許可リストチェック
    if (!this.securityConfig.allowedTransportationIds.includes(id)) {
      return {
        isValid: false,
        errors: ['指定された交通機関IDは対応していません'],
        allowedIds: this.securityConfig.allowedTransportationIds
      };
    }

    return { isValid: true, errors: [] };
  }

  /**
   * PDF章節1-1準拠: セキュアなデータ取得
   * SQLインジェクション対策（将来のDB連携対応）
   * @param {string} id - 交通機関ID
   * @returns {Promise<Object>} 交通機関データ
   */
  async getTransportationData(id) {
    try {
      // 入力値検証
      const validation = this.validateTransportationId(id);
      if (!validation.isValid) {
        throw new Error(`Invalid transportation ID: ${validation.errors.join(', ')}`);
      }

      // プリペアードステートメント相当の実装
      // 現在はJSONファイルからの読み込み、将来DB対応時の準備
      const sanitizedId = this.sanitizeForQuery(id);
      const queryLog = {
        query: 'SELECT * FROM transportation WHERE id = ?',
        params: [sanitizedId],
        timestamp: new Date().toISOString(),
        clientIP: this.getClientIP()
      };

      // セキュリティログ記録
      console.log('Transportation data query:', queryLog);

      // 現在はJSONファイルから読み込み
      const data = await this.loadFromConfig(sanitizedId);
      
      if (!data) {
        throw new Error(`Transportation data not found for ID: ${sanitizedId}`);
      }

      return data;

    } catch (error) {
      // エラーログ記録（機密情報除外）
      console.error('Transportation data retrieval error:', {
        message: error.message,
        timestamp: new Date().toISOString(),
        // ID等の機密情報は記録しない
      });
      throw error;
    }
  }

  /**
   * 全交通機関データ取得（キャッシュ機能付き）
   * @returns {Promise<Object>} 全交通機関データ
   */
  async getAllTransportationData() {
    try {
      // キャッシュチェック
      if (this.isCacheValid()) {
        return this.transportationData;
      }

      // JSONファイル読み込み
      const configPath = 'src/data/transportation-config.json';
      const data = await this.loadConfigFile(configPath);

      // データ整合性チェック
      this.validateConfigData(data);

      // キャッシュ更新
      this.transportationData = data;
      this.lastLoadTime = Date.now();

      return data;

    } catch (error) {
      console.error('Failed to load transportation data:', error);
      throw new Error('交通機関データの読み込みに失敗しました');
    }
  }

  /**
   * 交通機関とICカードの対応確認
   * @param {string} transportationId - 交通機関ID
   * @param {string} icCardType - ICカード種別
   * @returns {Object} 対応確認結果
   */
  async validateICCardForTransportation(transportationId, icCardType) {
    try {
      // 入力値検証
      const idValidation = this.validateTransportationId(transportationId);
      const cardValidation = this.validateICCardType(icCardType);

      if (!idValidation.isValid) {
        return {
          isValid: false,
          errors: idValidation.errors
        };
      }

      if (!cardValidation.isValid) {
        return {
          isValid: false,
          errors: cardValidation.errors
        };
      }

      // 交通機関データ取得
      const transportData = await this.getTransportationData(transportationId);

      if (!transportData.icCards.includes(icCardType)) {
        return {
          isValid: false,
          errors: [`${transportData.name}では${icCardType}はご利用いただけません`],
          supportedCards: transportData.icCards,
          transportationInfo: {
            name: transportData.name,
            contact: transportData.contact.phone
          }
        };
      }

      return {
        isValid: true,
        isPrimary: transportData.primaryIC === icCardType,
        transportationInfo: transportData,
        cardFormat: transportData.cardNumberFormats[icCardType] || null
      };

    } catch (error) {
      console.error('IC card validation error:', error);
      return {
        isValid: false,
        errors: ['ICカード対応確認中にエラーが発生しました']
      };
    }
  }

  /**
   * ICカード種別検証
   * @param {string} cardType - ICカード種別
   * @returns {Object} 検証結果
   */
  validateICCardType(cardType) {
    const allowedCardTypes = [
      'TOICA', 'manaca', 'Suica', 'ICOCA', 'PASMO', 
      'PiTaPa', 'SUGOCA', 'nimoca', 'Kitaca'
    ];

    if (!cardType || typeof cardType !== 'string') {
      return {
        isValid: false,
        errors: ['ICカード種別が指定されていません']
      };
    }

    if (!allowedCardTypes.includes(cardType)) {
      return {
        isValid: false,
        errors: ['対応していないICカード種別です'],
        allowedTypes: allowedCardTypes
      };
    }

    return { isValid: true, errors: [] };
  }

  /**
   * 緊急度レベル取得
   * @param {string} transportationId - 交通機関ID
   * @returns {Promise<string>} 緊急度レベル
   */
  async getUrgencyLevel(transportationId) {
    try {
      const data = await this.getTransportationData(transportationId);
      return data.stopProcedure.urgencyLevel || 'MEDIUM';
    } catch (error) {
      console.warn('Failed to get urgency level:', error);
      return 'MEDIUM'; // デフォルト値
    }
  }

  /**
   * 対応手順情報取得
   * @param {string} transportationId - 交通機関ID
   * @returns {Promise<Object>} 対応手順情報
   */
  async getStopProcedure(transportationId) {
    try {
      const data = await this.getTransportationData(transportationId);
      return {
        method: data.stopProcedure.method,
        requiredInfo: data.stopProcedure.requiredInfo,
        urgencyLevel: data.stopProcedure.urgencyLevel,
        processingTime: data.stopProcedure.processingTime,
        notes: data.stopProcedure.notes,
        additionalSteps: data.stopProcedure.additionalSteps || []
      };
    } catch (error) {
      console.error('Failed to get stop procedure:', error);
      throw new Error('対応手順の取得に失敗しました');
    }
  }

  /**
   * PDF章節1-1準拠: クエリのサニタイゼーション
   * @param {string} input - 入力値
   * @returns {string} サニタイズ済み値
   */
  sanitizeForQuery(input) {
    if (!input || typeof input !== 'string') {
      return '';
    }

    // SQL Injection対策: 危険文字のエスケープ
    let sanitized = input
      .replace(/'/g, "''")     // シングルクォートのエスケープ
      .replace(/"/g, '""')     // ダブルクォートのエスケープ
      .replace(/\\/g, '\\\\')  // バックスラッシュのエスケープ
      .replace(/;/g, '\\;')    // セミコロンのエスケープ
      .replace(/--/g, '\\-\\-') // SQLコメントのエスケープ
      .replace(/\/\*/g, '\\/\\*'); // SQLブロックコメントのエスケープ

    // 長さ制限
    if (sanitized.length > this.securityConfig.maxQueryLength) {
      sanitized = sanitized.substring(0, this.securityConfig.maxQueryLength);
    }

    return sanitized;
  }

  /**
   * PDF章節1-3準拠: ファイルパスの検証
   * OSコマンドインジェクション対策
   * @param {string} filePath - ファイルパス
   * @returns {boolean} 安全性確認結果
   */
  validateFilePath(filePath) {
    if (!filePath || typeof filePath !== 'string') {
      return false;
    }

    // 危険なパターンのチェック
    const dangerousPatterns = [
      /\.\./,           // ディレクトリトラバーサル
      /[|&;`]/,         // コマンドインジェクション
      /\$\(/,           // コマンド置換
      /[<>]/,           // リダイレクト
      /[*?]/,           // ワイルドカード
      /^\/|^[a-zA-Z]:\\/  // 絶対パス
    ];

    for (const pattern of dangerousPatterns) {
      if (pattern.test(filePath)) {
        return false;
      }
    }

    // 許可されたファイル拡張子
    const allowedExtensions = ['.json', '.txt', '.csv'];
    const hasValidExtension = allowedExtensions.some(ext => 
      filePath.toLowerCase().endsWith(ext)
    );

    return hasValidExtension;
  }

  /**
   * 設定ファイル読み込み（セキュア実装）
   * @param {string} configPath - 設定ファイルパス
   * @returns {Promise<Object>} 設定データ
   */
  async loadConfigFile(configPath) {
    // ファイルパス検証
    if (!this.validateFilePath(configPath)) {
      throw new Error('Invalid file path for security reasons');
    }

    try {
      // Node.js環境では fs.readFile、ブラウザ環境では fetch
      let data;
      if (typeof require !== 'undefined') {
        // Node.js環境
        const fs = require('fs').promises;
        const content = await fs.readFile(configPath, 'utf8');
        data = JSON.parse(content);
      } else {
        // ブラウザ環境
        const response = await fetch(configPath);
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        data = await response.json();
      }

      return data;

    } catch (error) {
      if (error instanceof SyntaxError) {
        throw new Error('Configuration file contains invalid JSON');
      }
      throw error;
    }
  }

  /**
   * 個別交通機関データ読み込み
   * @param {string} id - 交通機関ID
   * @returns {Promise<Object>} 交通機関データ
   */
  async loadFromConfig(id) {
    const allData = await this.getAllTransportationData();
    return allData.transportationProviders[id] || null;
  }

  /**
   * 設定データ整合性チェック
   * @param {Object} data - 設定データ
   */
  validateConfigData(data) {
    if (!data || typeof data !== 'object') {
      throw new Error('Invalid configuration data structure');
    }

    if (!data.transportationProviders || typeof data.transportationProviders !== 'object') {
      throw new Error('Missing transportation providers data');
    }

    // 各交通機関データの必須フィールドチェック
    for (const [id, provider] of Object.entries(data.transportationProviders)) {
      this.validateProviderData(id, provider);
    }
  }

  /**
   * 個別事業者データ検証
   * @param {string} id - 事業者ID
   * @param {Object} provider - 事業者データ
   */
  validateProviderData(id, provider) {
    const requiredFields = ['name', 'icCards', 'contact', 'stopProcedure'];
    
    for (const field of requiredFields) {
      if (!provider[field]) {
        throw new Error(`Missing required field '${field}' for provider '${id}'`);
      }
    }

    // ICカード配列の検証
    if (!Array.isArray(provider.icCards) || provider.icCards.length === 0) {
      throw new Error(`Invalid icCards data for provider '${id}'`);
    }

    // 連絡先情報の検証
    if (!provider.contact.phone || !provider.contact.businessHours) {
      throw new Error(`Invalid contact data for provider '${id}'`);
    }
  }

  /**
   * キャッシュ有効性チェック
   * @returns {boolean} キャッシュ有効性
   */
  isCacheValid() {
    return this.transportationData && 
           this.lastLoadTime && 
           (Date.now() - this.lastLoadTime) < this.cacheExpiry;
  }

  /**
   * クライアントIP取得（ログ用）
   * @returns {string} クライアントIP
   */
  getClientIP() {
    try {
      // ブラウザ環境では取得不可のため、プレースホルダー
      return 'browser-client';
    } catch (error) {
      return 'unknown';
    }
  }

  /**
   * セキュリティ統計取得
   * @returns {Object} セキュリティ統計
   */
  getSecurityStats() {
    return {
      allowedTransportationCount: this.securityConfig.allowedTransportationIds.length,
      cacheStatus: this.isCacheValid(),
      lastLoadTime: this.lastLoadTime,
      securityLevel: 'HIGH' // IPA準拠実装
    };
  }
}

module.exports = TransportationManager;
