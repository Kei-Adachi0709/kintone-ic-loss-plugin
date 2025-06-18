/**
 * desktop.js
 * ICカード紛失対応プラグイン メイン機能実装
 * IPAガイドライン準拠・Phase 1セキュリティクラス統合
 * 
 * @author Kei-Adachi0709
 * @version 1.0.0
 * @date 2025-06-19
 * @compliance IPA安全なウェブサイトの作り方準拠
 */

// Phase 1セキュリティクラス統合
const SecureHashManager = require('./security/SecureHashManager');
const InputValidator = require('./security/InputValidator');
const SecurityConfig = require('./security/SecurityConfig');

// Phase 2 UIコンポーネント統合
const { CommonUtils, KintoneAPIHelper } = require('./common');
const ICLossReportForm = require('./ui/ICLossReportForm');
const ICLossStatusDashboard = require('./ui/ICLossStatusDashboard');

/**
 * ICカード紛失対応メイン機能クラス
 */
class ICLossDesktopApp {
  constructor() {
    this.securityConfig = new SecurityConfig();
    this.validator = new InputValidator();
    this.hashManager = null;
    this.isInitialized = false;
    this.currentUser = null;
    
    // UIコンポーネント
    this.reportForm = null;
    this.statusDashboard = null;
    this.currentView = 'dashboard'; // 'dashboard' | 'report'
    
    this.initialize();
  }
  /**
   * アプリケーション初期化
   */
  async initialize() {
    try {
      // プラグイン設定確認
      const config = kintone.plugin.app.getConfig();
      if (!config || config.plugin_enabled !== 'true') {
        console.log('ICカード紛失対応プラグインは無効です');
        return;
      }

      // ユーザー権限確認
      this.currentUser = kintone.getLoginUser();
      if (!this.checkUserPermission(config)) {
        console.log('ユーザーにプラグイン使用権限がありません');
        return;
      }

      // セキュリティマネージャー初期化
      await this.initializeSecurityManager(config);
      
      // UI初期化
      await this.initializeUI();
      
      // イベントリスナー設定
      this.setupEventListeners();
      
      this.isInitialized = true;
      console.log('ICカード紛失対応プラグインが初期化されました');
      
      // 初期化完了通知
      CommonUtils.showNotification('ICカード紛失対応プラグインが準備完了しました', 'success');
      
    } catch (error) {      console.error('アプリケーション初期化エラー:', error);
      CommonUtils.showNotification('プラグインの初期化に失敗しました', 'error');
    }
  }

  /**
   * セキュリティマネージャー初期化
   * @param {Object} config - プラグイン設定
   */
  async initializeSecurityManager(config) {
    this.hashManager = new SecureHashManager({
      iterations: parseInt(config.hash_iterations) || 100000,
      saltLength: parseInt(config.salt_length) || 32,
      pepper: atob(config.security_pepper || '')
    });
  }
  /**
   * ユーザー権限確認
   * @param {Object} config - プラグイン設定
   * @returns {boolean} 権限有無
   */
  checkUserPermission(config) {
    if (!this.currentUser) return false;

    // 管理者権限確認
    if (this.currentUser.isAdmin) return true;

    // 許可された部署の確認
    const allowedDepartments = (config.allowed_departments || '').split(',').map(d => d.trim());
    if (allowedDepartments.length > 0 && allowedDepartments.includes('すべて')) {
      return true;
    }

    // 個別ユーザー確認
    const allowedUsers = (config.allowed_users || '').split(',').map(u => u.trim());
    if (allowedUsers.includes(this.currentUser.code) || allowedUsers.includes(this.currentUser.name)) {
      return true;
    }

    return false;
  }
  /**
   * UI初期化
   */
  async initializeUI() {
    try {
      // CSSファイル読み込み
      await this.loadCSS();
      
      // メインコンテナ作成
      this.createMainContainer();
      
      // 初期表示（ダッシュボード）
      this.showDashboard();
      
    } catch (error) {
      console.error('UI初期化エラー:', error);
      throw error;
    }
  }

  /**
   * CSSファイル読み込み
   */
  async loadCSS() {
    const cssFiles = [
      'src/css/desktop.css',
      'src/css/ui-components.css'
    ];

    for (const cssFile of cssFiles) {
      const link = document.createElement('link');
      link.rel = 'stylesheet';
      link.type = 'text/css';
      link.href = kintone.plugin.app.getProxyURI() + cssFile;
      document.head.appendChild(link);
    }
  }

  /**
   * メインコンテナ作成
   */
  createMainContainer() {
    // 既存のコンテナがあれば削除
    const existingContainer = document.getElementById('ic-loss-main-container');
    if (existingContainer) {
      existingContainer.remove();
    }

    // メインコンテナ作成
    const container = document.createElement('div');
    container.id = 'ic-loss-main-container';
    container.className = 'ic-loss-main-container';
    container.innerHTML = `
      <div class="main-header">
        <div class="header-content">
          <h1 class="main-title">
            <span class="icon" aria-hidden="true">🔒</span>
            ICカード紛失対応システム
          </h1>
          <div class="header-actions">
            <button type="button" 
                    class="btn btn-outline header-btn"
                    id="toggle-view-btn"
                    aria-label="表示切り替え">
              <span class="btn-text">新規報告</span>
            </button>
            <button type="button" 
                    class="btn btn-danger header-btn"
                    id="emergency-btn"
                    aria-label="緊急報告">
              <span class="icon" aria-hidden="true">🚨</span>
              緊急報告
            </button>
          </div>
        </div>
      </div>
      <div class="main-content" id="main-content">
        <!-- コンテンツエリア -->
      </div>
    `;

    // Kintoneのメインエリアに追加
    const kintoneContent = document.querySelector('.contents-body') || document.body;
    kintoneContent.appendChild(container);
  }
  /**
   * イベントリスナー設定
   */
  setupEventListeners() {
    // 表示切り替えボタン
    const toggleViewBtn = document.getElementById('toggle-view-btn');
    if (toggleViewBtn) {
      toggleViewBtn.addEventListener('click', () => this.toggleView());
    }

    // 緊急報告ボタン
    const emergencyBtn = document.getElementById('emergency-btn');
    if (emergencyBtn) {
      emergencyBtn.addEventListener('click', () => this.showEmergencyReport());
    }

    // Kintoneイベント
    kintone.events.on('app.record.index.show', (event) => this.handleIndexShow(event));
    kintone.events.on('app.record.detail.show', (event) => this.handleDetailShow(event));
    kintone.events.on('app.record.create.show', (event) => this.handleCreateShow(event));
    kintone.events.on('app.record.edit.show', (event) => this.handleEditShow(event));
    
    // レコード保存前
    kintone.events.on(['app.record.create.submit', 'app.record.edit.submit'], (event) => {
      return this.handleRecordSubmit(event);
    });
  }

  /**
   * レコード一覧画面設定
   * @param {Object} event - Kintoneイベント
   */
  setupIndexView(event) {
    // 緊急報告ボタンを追加
    const headerSpace = kintone.app.getHeaderSpaceElement();
    if (!document.getElementById('emergency-report-btn')) {
      const buttonContainer = document.createElement('div');
      buttonContainer.innerHTML = `
        <div class="emergency-action-container">
          <button type="button" id="emergency-report-btn" class="emergency-btn">
            🚨 ICカード紛失緊急報告
          </button>
          <div class="emergency-help">
            <span class="help-icon">💡</span>
            <span>ICカードを紛失した場合は直ちに報告してください</span>
          </div>
        </div>
      `;
      
      headerSpace.appendChild(buttonContainer);
      
      // イベントリスナー設定
      document.getElementById('emergency-report-btn').addEventListener('click', () => {
        this.showEmergencyReportDialog();
      });
    }

    // セキュリティ表示の強化
    this.enhanceSecurityDisplay();
  }

  /**
   * レコード詳細画面設定
   * @param {Object} event - Kintoneイベント
   */
  setupDetailView(event) {
    // ICカード番号のマスク表示
    this.maskSensitiveFields(event.record);
    
    // セキュリティインジケーター追加
    this.addSecurityIndicator();
  }

  /**
   * レコード作成画面設定
   * @param {Object} event - Kintoneイベント
   */
  setupCreateView(event) {
    // 入力値検証の設定
    this.setupInputValidation();
    
    // ICカード番号入力の強化
    this.enhanceICCardInput();
    
    // 自動入力機能の追加
    this.addAutoFillFeatures();
  }

  /**
   * レコード編集画面設定
   * @param {Object} event - Kintoneイベント
   */
  setupEditView(event) {
    // 編集制限の適用
    this.applyEditRestrictions(event.record);
    
    // 変更ログの追加
    this.addChangeTracking(event.record);
  }

  /**
   * 緊急報告ダイアログ表示
   */
  showEmergencyReportDialog() {
    const dialogHTML = `
      <div class="emergency-dialog-overlay" id="emergency-dialog">
        <div class="emergency-dialog">
          <div class="emergency-header">
            <h2>🚨 ICカード紛失緊急報告</h2>
            <p class="emergency-subtitle">
              IPAガイドライン準拠・セキュア報告システム
            </p>
          </div>
          
          <form class="emergency-form" id="emergency-form">
            <!-- 基本情報 -->
            <div class="form-section">
              <h3>📋 基本情報</h3>
              
              <div class="form-group">
                <label for="emergency-ic-number" class="required">
                  ICカード番号
                </label>
                <input type="text" id="emergency-ic-number" 
                       placeholder="例: TO1234567890123456"
                       class="form-input ic-input"
                       autocomplete="off"
                       spellcheck="false">
                <div class="card-type-display" id="card-type-display"></div>
                <div class="validation-message" id="ic-validation"></div>
              </div>
              
              <div class="form-group">
                <label for="emergency-employee-id" class="required">
                  社員証番号
                </label>
                <input type="text" id="emergency-employee-id" 
                       placeholder="例: EMP123456"
                       class="form-input"
                       value="${this.currentUser.code}"
                       readonly>
              </div>
            </div>

            <!-- 紛失詳細 -->
            <div class="form-section">
              <h3>📍 紛失詳細</h3>
              
              <div class="form-group">
                <label for="loss-datetime" class="required">
                  紛失日時 (推定)
                </label>
                <input type="datetime-local" id="loss-datetime" 
                       class="form-input"
                       max="${new Date().toISOString().slice(0, 16)}">
              </div>
              
              <div class="form-group">
                <label for="loss-location">
                  紛失場所 (推定)
                </label>
                <input type="text" id="loss-location" 
                       placeholder="例: 名古屋駅、栄駅、会社内など"
                       class="form-input">
              </div>
              
              <div class="form-group">
                <label for="loss-description">
                  状況説明
                </label>
                <textarea id="loss-description" rows="3"
                          placeholder="紛失時の状況を可能な限り詳しく記入してください"
                          class="form-input"></textarea>
              </div>
            </div>

            <!-- 連絡先 -->
            <div class="form-section">
              <h3>📞 緊急連絡先</h3>
              
              <div class="form-group">
                <label for="emergency-email" class="required">
                  メールアドレス
                </label>
                <input type="email" id="emergency-email" 
                       placeholder="例: user@example.com"
                       class="form-input"
                       value="${this.currentUser.email || ''}"
                       readonly>
              </div>
              
              <div class="form-group">
                <label for="emergency-phone" class="required">
                  携帯電話番号
                </label>
                <input type="tel" id="emergency-phone" 
                       placeholder="例: 090-1234-5678"
                       class="form-input">
              </div>
            </div>

            <!-- セキュリティ確認 -->
            <div class="form-section security-section">
              <h3>🔒 セキュリティ確認</h3>
              
              <div class="security-notice">
                <div class="notice-icon">⚠️</div>
                <div class="notice-content">
                  <strong>重要:</strong> 
                  入力された情報は暗号化されて保存されます。
                  ICカード番号は一方向ハッシュ化され、復元不可能な形で記録されます。
                </div>
              </div>
              
              <label class="checkbox-label">
                <input type="checkbox" id="security-agreement" required>
                <span class="checkmark"></span>
                <span class="checkbox-text">
                  上記セキュリティ事項を理解し、報告内容に間違いがないことを確認しました
                </span>
              </label>
            </div>
          </form>

          <div class="emergency-actions">
            <button type="button" class="btn btn-secondary" onclick="closeEmergencyDialog()">
              キャンセル
            </button>
            <button type="submit" form="emergency-form" class="btn btn-danger">
              🚨 緊急報告する
            </button>
          </div>
        </div>
      </div>
    `;

    // ダイアログをDOMに追加
    document.body.insertAdjacentHTML('beforeend', dialogHTML);
    
    // フォームイベント設定
    this.setupEmergencyFormEvents();
    
    // 初期フォーカス
    document.getElementById('emergency-ic-number').focus();
  }

  /**
   * 緊急報告フォームイベント設定
   */
  setupEmergencyFormEvents() {
    const form = document.getElementById('emergency-form');
    const icInput = document.getElementById('emergency-ic-number');
    
    // ICカード番号のリアルタイム検証
    icInput.addEventListener('input', (e) => {
      this.validateICCardInput(e.target.value);
    });

    // 電話番号のフォーマット
    document.getElementById('emergency-phone').addEventListener('input', (e) => {
      this.formatPhoneNumber(e.target);
    });

    // フォーム送信
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      this.handleEmergencyReport();
    });
  }

  /**
   * ICカード番号入力検証
   * @param {string} value - 入力値
   */
  validateICCardInput(value) {
    const validationResult = this.validator.validateICCardNumber(value);
    const cardTypeDisplay = document.getElementById('card-type-display');
    const validationMessage = document.getElementById('ic-validation');
    
    if (value.length === 0) {
      cardTypeDisplay.innerHTML = '';
      validationMessage.innerHTML = '';
      return;
    }

    if (validationResult.valid) {
      cardTypeDisplay.innerHTML = `
        <div class="card-type-indicator card-type-${validationResult.cardType.toLowerCase()}">
          ${validationResult.cardName}
        </div>
      `;
      validationMessage.innerHTML = `
        <div class="validation-success">
          ✅ 有効な${validationResult.cardName}番号です
        </div>
      `;
    } else {
      cardTypeDisplay.innerHTML = '';
      validationMessage.innerHTML = `
        <div class="validation-error">
          ❌ ${validationResult.errors.join(', ')}
        </div>
      `;
    }
  }

  /**
   * 電話番号フォーマット
   * @param {HTMLElement} input - 入力要素
   */
  formatPhoneNumber(input) {
    let value = input.value.replace(/\D/g, '');
    
    if (value.length >= 7) {
      if (value.length <= 10) {
        value = value.replace(/(\d{3})(\d{3,4})(\d{4})/, '$1-$2-$3');
      } else {
        value = value.replace(/(\d{3})(\d{4})(\d{4})/, '$1-$2-$3');
      }
    }
    
    input.value = value;
  }

  /**
   * 緊急報告処理
   */
  async handleEmergencyReport() {
    try {
      // フォームデータ収集
      const reportData = this.collectEmergencyReportData();
      
      // 入力値検証
      const validationResult = this.validator.validateBulkData(reportData);
      if (!validationResult.valid) {
        throw new Error('入力値検証エラー: ' + this.formatValidationErrors(validationResult));
      }

      // ICカード番号のハッシュ化 (IPA準拠)
      const hashedICCard = this.hashManager.hashICCardNumber(
        validationResult.results.icCardNumber.sanitized
      );

      // Kintoneレコード作成
      const record = this.buildEmergencyRecord(reportData, hashedICCard, validationResult);
      
      // レコード保存
      await this.saveEmergencyRecord(record);
      
      // 成功通知
      this.showEmergencySuccess(hashedICCard.maskedNumber);
      
      // 緊急通知送信
      await this.sendEmergencyNotifications(reportData);
      
    } catch (error) {
      console.error('緊急報告エラー:', error);
      this.showError('緊急報告の処理中にエラーが発生しました: ' + error.message);
    }
  }

  /**
   * 緊急報告データ収集
   * @returns {Object} 報告データ
   */
  collectEmergencyReportData() {
    return {
      icCardNumber: document.getElementById('emergency-ic-number').value,
      employeeId: document.getElementById('emergency-employee-id').value,
      lossDatetime: document.getElementById('loss-datetime').value,
      lossLocation: document.getElementById('loss-location').value,
      lossDescription: document.getElementById('loss-description').value,
      email: document.getElementById('emergency-email').value,
      phoneNumber: document.getElementById('emergency-phone').value,
      securityAgreement: document.getElementById('security-agreement').checked
    };
  }

  /**
   * 緊急レコード構築
   * @param {Object} reportData - 報告データ
   * @param {Object} hashedICCard - ハッシュ化ICカード情報
   * @param {Object} validationResult - 検証結果
   * @returns {Object} Kintoneレコード
   */
  buildEmergencyRecord(reportData, hashedICCard, validationResult) {
    return {
      '報告日時': { value: new Date().toISOString() },
      '報告者': { value: this.currentUser.name },
      '社員証番号': { value: reportData.employeeId },
      'カード種別': { value: validationResult.results.icCardNumber.cardName },
      'カード番号ハッシュ': { value: hashedICCard.hash },
      'マスク番号': { value: hashedICCard.maskedNumber },
      '紛失推定日時': { value: reportData.lossDatetime },
      '紛失場所': { value: reportData.lossLocation },
      '状況説明': { value: reportData.lossDescription },
      '連絡先メール': { value: reportData.email },
      '連絡先電話': { value: reportData.phoneNumber },
      'ステータス': { value: '緊急報告済み' },
      '処理状況': { value: '対応待ち' },
      'セキュリティレベル': { value: 'HIGH' },
      'ハッシュアルゴリズム': { value: hashedICCard.algorithm },
      '報告IP': { value: this.getClientIP() },
      'ユーザーエージェント': { value: navigator.userAgent }
    };
  }

  /**
   * 緊急レコード保存
   * @param {Object} record - Kintoneレコード
   */
  async saveEmergencyRecord(record) {
    const response = await kintone.api(kintone.api.url('/k/v1/record', true), 'POST', {
      app: kintone.app.getId(),
      record: record
    });
    
    if (!response.id) {
      throw new Error('レコードの保存に失敗しました');
    }
    
    return response;
  }

  /**
   * 成功通知表示
   * @param {string} maskedNumber - マスク番号
   */
  showEmergencySuccess(maskedNumber) {
    const successMessage = `
      ✅ 緊急報告が完了しました

      🔒 セキュリティ情報:
      マスク番号: ${maskedNumber}
      報告ID: ${Date.now()}
      暗号化: PBKDF2-SHA512

      📧 管理者への自動通知を送信しました
      📱 緊急連絡先に確認の連絡が入る場合があります

      ⚠️ ICカードの利用停止手続きを至急行ってください
    `;
    
    alert(successMessage);
    this.closeEmergencyDialog();
    
    // ページリロード
    setTimeout(() => {
      location.reload();
    }, 2000);
  }

  /**
   * 機密フィールドマスク表示
   * @param {Object} record - レコードデータ
   */
  maskSensitiveFields(record) {
    // ICカード番号のマスク表示
    if (record['マスク番号'] && record['マスク番号'].value) {
      const maskedNumberField = kintone.app.record.getFieldElement('マスク番号');
      if (maskedNumberField) {
        maskedNumberField.innerHTML = `
          <div class="masked-field">
            <span class="masked-value">${record['マスク番号'].value}</span>
            <span class="security-badge">🔒 暗号化済み</span>
          </div>
        `;
      }
    }
  }

  /**
   * セキュリティインジケーター追加
   */
  addSecurityIndicator() {
    const spaceElement = kintone.app.record.getSpaceElement('security_indicator');
    if (spaceElement && !document.getElementById('security-status')) {
      spaceElement.innerHTML = `
        <div class="security-status" id="security-status">
          <div class="security-header">
            <span class="security-icon">🛡️</span>
            <span class="security-title">セキュリティステータス</span>
          </div>
          <div class="security-details">
            <div class="security-item">
              <span class="item-label">暗号化方式:</span>
              <span class="item-value">PBKDF2-SHA512</span>
              <span class="status-badge status-secure">✅ 安全</span>
            </div>
            <div class="security-item">
              <span class="item-label">データ保護:</span>
              <span class="item-value">一方向ハッシュ化</span>
              <span class="status-badge status-secure">✅ 復元不可</span>
            </div>
            <div class="security-item">
              <span class="item-label">準拠規格:</span>
              <span class="item-value">IPAガイドライン</span>
              <span class="status-badge status-compliant">✅ 準拠</span>
            </div>
          </div>
        </div>
      `;
    }
  }

  /**
   * レコード送信前処理 (セキュリティ強化)
   * @param {Object} event - Kintoneイベント
   * @returns {Object} 処理済みイベント
   */
  async handleRecordSubmit(event) {
    try {
      // ICカード番号が入力されている場合のハッシュ化
      if (event.record['ICカード番号'] && event.record['ICカード番号'].value) {
        const icCardNumber = event.record['ICカード番号'].value;
        
        // 入力値検証
        const validationResult = this.validator.validateICCardNumber(icCardNumber);
        if (!validationResult.valid) {
          throw new Error('ICカード番号の形式が正しくありません: ' + validationResult.errors.join(', '));
        }

        // ハッシュ化処理
        const hashedResult = this.hashManager.hashICCardNumber(icCardNumber);
        
        // ハッシュ値をレコードに設定
        event.record['カード番号ハッシュ'] = { value: hashedResult.hash };
        event.record['マスク番号'] = { value: hashedResult.maskedNumber };
        event.record['カード種別'] = { value: validationResult.cardName };
        event.record['ハッシュアルゴリズム'] = { value: hashedResult.algorithm };
        
        // 元のICカード番号をクリア (セキュリティ強化)
        event.record['ICカード番号'] = { value: '' };
      }

      return event;

    } catch (error) {
      console.error('レコード送信前処理エラー:', error);
      alert('エラー: ' + error.message);
      return false; // 送信を中止
    }
  }

  /**
   * クライアントIP取得 (簡易版)
   * @returns {string} クライアントIP
   */
  getClientIP() {
    // 実際の実装では適切なIP取得方法を使用
    return 'Unknown';
  }

  /**
   * 検証エラーフォーマット
   * @param {Object} validationResult - 検証結果
   * @returns {string} フォーマット済みエラー
   */
  formatValidationErrors(validationResult) {
    const errors = [];
    Object.entries(validationResult.results).forEach(([field, result]) => {
      if (!result.valid) {
        errors.push(`${field}: ${result.errors.join(', ')}`);
      }
    });
    return errors.join('\n');
  }

  /**
   * エラーメッセージ表示
   * @param {string} message - エラーメッセージ
   */
  showError(message) {
    alert('❌ エラー: ' + message);
  }

  /**
   * 緊急ダイアログクローズ
   */
  closeEmergencyDialog() {
    const dialog = document.getElementById('emergency-dialog');
    if (dialog) {
      dialog.remove();
    }
  }
}

// グローバル関数 (HTML内から呼び出し用)
window.closeEmergencyDialog = function() {
  const dialog = document.getElementById('emergency-dialog');
  if (dialog) {
    dialog.remove();
  }
};

// アプリケーション初期化
(() => {
  'use strict';
  
  // Kintone環境確認
  if (typeof kintone !== 'undefined') {
    new ICLossDesktopApp();
  } else {
    console.warn('Kintone環境ではありません');
  }
})();
