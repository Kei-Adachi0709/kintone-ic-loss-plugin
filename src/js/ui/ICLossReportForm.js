/**
 * ICLossReportForm.js
 * ICカード紛失報告フォームコンポーネント
 * IPAガイドライン準拠・アクセシビリティ対応
 * 
 * @author Kei-Adachi0709
 * @version 1.0.0
 * @date 2025-06-19
 * @compliance IPA安全なウェブサイトの作り方準拠
 */

// 依存関係インポート
const { CommonUtils, KintoneAPIHelper } = require('../common');
const InputValidator = require('../security/InputValidator');
const SecureHashManager = require('../security/SecureHashManager');

/**
 * ICカード紛失報告フォームクラス
 */
class ICLossReportForm {
  constructor(container, options = {}) {
    this.container = typeof container === 'string' ? document.getElementById(container) : container;
    this.options = {
      autoSave: false,
      enableValidation: true,
      showProgress: true,
      ...options
    };
    
    this.validator = new InputValidator();
    this.hashManager = null;
    this.formData = {};
    this.isSubmitting = false;
    this.currentStep = 1;
    this.totalSteps = 4;
    
    this.initialize();
  }

  /**
   * フォーム初期化
   */
  async initialize() {
    try {
      await this.loadPluginConfig();
      this.render();
      this.setupEventListeners();
      this.setupAccessibility();
      
      if (this.options.autoSave) {
        this.setupAutoSave();
      }
      
      console.log('ICカード紛失報告フォームが初期化されました');
    } catch (error) {
      console.error('フォーム初期化エラー:', error);
      this.showError('フォームの初期化に失敗しました');
    }
  }

  /**
   * プラグイン設定読み込み
   */
  async loadPluginConfig() {
    const config = kintone.plugin.app.getConfig();
    if (!config || config.plugin_enabled !== 'true') {
      throw new Error('プラグインが無効です');
    }

    // セキュリティマネージャー初期化
    this.hashManager = new SecureHashManager({
      iterations: parseInt(config.hash_iterations) || 100000,
      saltLength: parseInt(config.salt_length) || 32,
      pepper: config.security_pepper || ''
    });
  }

  /**
   * フォームHTML生成
   */
  render() {
    if (!this.container) {
      throw new Error('フォームコンテナが見つかりません');
    }

    this.container.innerHTML = `
      <div class="ic-loss-form" role="form" aria-labelledby="form-title">
        <header class="form-header">
          <h2 id="form-title" class="form-title">
            <span class="icon" aria-hidden="true">🔒</span>
            ICカード紛失報告
          </h2>
          ${this.options.showProgress ? this.renderProgressBar() : ''}
        </header>

        <div class="form-body">
          <div class="alert alert-info" role="alert">
            <span class="alert-icon" aria-hidden="true">ℹ</span>
            <div class="alert-content">
              <strong>重要:</strong> ICカードの紛失を発見した場合は、速やかに報告してください。
              セキュリティ保護のため、一部の情報は暗号化されて保存されます。
            </div>
          </div>

          <form id="ic-loss-report-form" novalidate aria-describedby="form-description">
            <div id="form-description" class="sr-only">
              ICカード紛失報告フォーム。4つのステップで入力してください。
            </div>

            <!-- ステップ1: 基本情報 -->
            <div id="step-1" class="form-step ${this.currentStep === 1 ? 'active' : 'hidden'}" 
                 aria-hidden="${this.currentStep !== 1}">
              <fieldset>
                <legend class="step-title">
                  <span class="step-number">1</span>
                  基本情報の入力
                </legend>

                <div class="form-group">
                  <label for="reporter-name" class="required">報告者名</label>
                  <input type="text" 
                         id="reporter-name" 
                         name="reporter_name"
                         class="form-control"
                         required
                         aria-required="true"
                         aria-describedby="reporter-name-help reporter-name-error"
                         autocomplete="name"
                         maxlength="100">
                  <div id="reporter-name-help" class="form-help">
                    あなたのフルネームを入力してください
                  </div>
                  <div id="reporter-name-error" class="form-error" role="alert" aria-live="polite"></div>
                </div>

                <div class="form-group">
                  <label for="reporter-department" class="required">所属部署</label>
                  <select id="reporter-department" 
                          name="reporter_department"
                          class="form-control"
                          required
                          aria-required="true"
                          aria-describedby="reporter-department-help reporter-department-error">
                    <option value="">選択してください</option>
                    <option value="総務部">総務部</option>
                    <option value="人事部">人事部</option>
                    <option value="経理部">経理部</option>
                    <option value="営業部">営業部</option>
                    <option value="開発部">開発部</option>
                    <option value="企画部">企画部</option>
                    <option value="その他">その他</option>
                  </select>
                  <div id="reporter-department-help" class="form-help">
                    所属している部署を選択してください
                  </div>
                  <div id="reporter-department-error" class="form-error" role="alert" aria-live="polite"></div>
                </div>

                <div class="form-group">
                  <label for="reporter-employee-id" class="required">社員番号</label>
                  <input type="text" 
                         id="reporter-employee-id" 
                         name="reporter_employee_id"
                         class="form-control"
                         required
                         aria-required="true"
                         aria-describedby="reporter-employee-id-help reporter-employee-id-error"
                         pattern="[A-Z0-9]{4,10}"
                         maxlength="10">
                  <div id="reporter-employee-id-help" class="form-help">
                    社員番号（4-10桁の英数字）を入力してください
                  </div>
                  <div id="reporter-employee-id-error" class="form-error" role="alert" aria-live="polite"></div>
                </div>

                <div class="form-group">
                  <label for="contact-phone" class="required">連絡先電話番号</label>
                  <input type="tel" 
                         id="contact-phone" 
                         name="contact_phone"
                         class="form-control"
                         required
                         aria-required="true"
                         aria-describedby="contact-phone-help contact-phone-error"
                         autocomplete="tel"
                         pattern="[0-9-+() ]{10,15}"
                         maxlength="15">
                  <div id="contact-phone-help" class="form-help">
                    緊急連絡用の電話番号を入力してください
                  </div>
                  <div id="contact-phone-error" class="form-error" role="alert" aria-live="polite"></div>
                </div>
              </fieldset>
            </div>

            <!-- ステップ2: カード情報 -->
            <div id="step-2" class="form-step ${this.currentStep === 2 ? 'active' : 'hidden'}" 
                 aria-hidden="${this.currentStep !== 2}">
              <fieldset>
                <legend class="step-title">
                  <span class="step-number">2</span>
                  紛失したカード情報
                </legend>

                <div class="form-group">
                  <fieldset class="radio-group">
                    <legend class="required">カードの種類</legend>
                    <div class="radio-options">
                      <div class="radio-option">
                        <input type="radio" 
                               id="card-type-suica" 
                               name="card_type" 
                               value="Suica"
                               required
                               aria-describedby="card-type-error">
                        <label for="card-type-suica">Suica</label>
                      </div>
                      <div class="radio-option">
                        <input type="radio" 
                               id="card-type-pasmo" 
                               name="card_type" 
                               value="PASMO">
                        <label for="card-type-pasmo">PASMO</label>
                      </div>
                      <div class="radio-option">
                        <input type="radio" 
                               id="card-type-icoca" 
                               name="card_type" 
                               value="ICOCA">
                        <label for="card-type-icoca">ICOCA</label>
                      </div>
                      <div class="radio-option">
                        <input type="radio" 
                               id="card-type-employee" 
                               name="card_type" 
                               value="社員証">
                        <label for="card-type-employee">社員証</label>
                      </div>
                      <div class="radio-option">
                        <input type="radio" 
                               id="card-type-other" 
                               name="card_type" 
                               value="その他">
                        <label for="card-type-other">その他</label>
                      </div>
                    </div>
                    <div id="card-type-error" class="form-error" role="alert" aria-live="polite"></div>
                  </fieldset>
                </div>

                <div class="form-group">
                  <label for="card-number">カード番号・ID</label>
                  <input type="text" 
                         id="card-number" 
                         name="card_number"
                         class="form-control"
                         aria-describedby="card-number-help card-number-error"
                         maxlength="20">
                  <div id="card-number-help" class="form-help">
                    分かる範囲でカード番号やIDを入力してください（任意）
                  </div>
                  <div id="card-number-error" class="form-error" role="alert" aria-live="polite"></div>
                </div>

                <div class="form-group">
                  <label for="card-balance">残高（概算）</label>
                  <div class="input-group">
                    <input type="number" 
                           id="card-balance" 
                           name="card_balance"
                           class="form-control"
                           aria-describedby="card-balance-help card-balance-error"
                           min="0"
                           max="100000"
                           step="100">
                    <span class="input-group-text">円</span>
                  </div>
                  <div id="card-balance-help" class="form-help">
                    おおよその残高を入力してください（任意）
                  </div>
                  <div id="card-balance-error" class="form-error" role="alert" aria-live="polite"></div>
                </div>

                <div class="form-group">
                  <fieldset class="checkbox-group">
                    <legend>付帯機能</legend>
                    <div class="checkbox-options">
                      <div class="checkbox-option">
                        <input type="checkbox" 
                               id="auto-charge" 
                               name="card_features" 
                               value="オートチャージ">
                        <label for="auto-charge">オートチャージ機能</label>
                      </div>
                      <div class="checkbox-option">
                        <input type="checkbox" 
                               id="credit-function" 
                               name="card_features" 
                               value="クレジット機能">
                        <label for="credit-function">クレジット機能</label>
                      </div>
                      <div class="checkbox-option">
                        <input type="checkbox" 
                               id="point-service" 
                               name="card_features" 
                               value="ポイントサービス">
                        <label for="point-service">ポイントサービス</label>
                      </div>
                    </div>
                  </fieldset>
                </div>
              </fieldset>
            </div>

            <!-- ステップ3: 紛失詳細 -->
            <div id="step-3" class="form-step ${this.currentStep === 3 ? 'active' : 'hidden'}" 
                 aria-hidden="${this.currentStep !== 3}">
              <fieldset>
                <legend class="step-title">
                  <span class="step-number">3</span>
                  紛失の詳細情報
                </legend>

                <div class="form-group">
                  <label for="loss-date" class="required">紛失日時</label>
                  <input type="datetime-local" 
                         id="loss-date" 
                         name="loss_date"
                         class="form-control"
                         required
                         aria-required="true"
                         aria-describedby="loss-date-help loss-date-error">
                  <div id="loss-date-help" class="form-help">
                    カードを紛失した（気づいた）日時を入力してください
                  </div>
                  <div id="loss-date-error" class="form-error" role="alert" aria-live="polite"></div>
                </div>

                <div class="form-group">
                  <label for="loss-location" class="required">紛失場所</label>
                  <input type="text" 
                         id="loss-location" 
                         name="loss_location"
                         class="form-control"
                         required
                         aria-required="true"
                         aria-describedby="loss-location-help loss-location-error"
                         maxlength="200">
                  <div id="loss-location-help" class="form-help">
                    紛失した場所を詳しく入力してください（駅名、建物名など）
                  </div>
                  <div id="loss-location-error" class="form-error" role="alert" aria-live="polite"></div>
                </div>

                <div class="form-group">
                  <label for="loss-circumstances" class="required">紛失状況</label>
                  <textarea id="loss-circumstances" 
                            name="loss_circumstances"
                            class="form-control"
                            required
                            aria-required="true"
                            aria-describedby="loss-circumstances-help loss-circumstances-error"
                            rows="4"
                            maxlength="1000"></textarea>
                  <div id="loss-circumstances-help" class="form-help">
                    紛失した時の状況を詳しく記述してください（1000文字以内）
                  </div>
                  <div id="loss-circumstances-error" class="form-error" role="alert" aria-live="polite"></div>
                </div>

                <div class="form-group">
                  <fieldset class="radio-group">
                    <legend class="required">発見の経緯</legend>
                    <div class="radio-options">
                      <div class="radio-option">
                        <input type="radio" 
                               id="discovery-immediate" 
                               name="discovery_timing" 
                               value="すぐに気づいた"
                               required>
                        <label for="discovery-immediate">すぐに気づいた</label>
                      </div>
                      <div class="radio-option">
                        <input type="radio" 
                               id="discovery-hours" 
                               name="discovery_timing" 
                               value="数時間後">
                        <label for="discovery-hours">数時間後</label>
                      </div>
                      <div class="radio-option">
                        <input type="radio" 
                               id="discovery-next-day" 
                               name="discovery_timing" 
                               value="翌日">
                        <label for="discovery-next-day">翌日</label>
                      </div>
                      <div class="radio-option">
                        <input type="radio" 
                               id="discovery-later" 
                               name="discovery_timing" 
                               value="それ以降">
                        <label for="discovery-later">それ以降</label>
                      </div>
                    </div>
                  </fieldset>
                </div>

                <div class="form-group">
                  <fieldset class="checkbox-group">
                    <legend>既に実施した対応</legend>
                    <div class="checkbox-options">
                      <div class="checkbox-option">
                        <input type="checkbox" 
                               id="action-search" 
                               name="actions_taken" 
                               value="周辺を探した">
                        <label for="action-search">周辺を探した</label>
                      </div>
                      <div class="checkbox-option">
                        <input type="checkbox" 
                               id="action-inquiry" 
                               name="actions_taken" 
                               value="駅・施設に問い合わせた">
                        <label for="action-inquiry">駅・施設に問い合わせた</label>
                      </div>
                      <div class="checkbox-option">
                        <input type="checkbox" 
                               id="action-police" 
                               name="actions_taken" 
                               value="警察に届け出た">
                        <label for="action-police">警察に届け出た</label>
                      </div>
                      <div class="checkbox-option">
                        <input type="checkbox" 
                               id="action-card-company" 
                               name="actions_taken" 
                               value="カード会社に連絡した">
                        <label for="action-card-company">カード会社に連絡した</label>
                      </div>
                    </div>
                  </fieldset>
                </div>
              </fieldset>
            </div>

            <!-- ステップ4: 確認・送信 -->
            <div id="step-4" class="form-step ${this.currentStep === 4 ? 'active' : 'hidden'}" 
                 aria-hidden="${this.currentStep !== 4}">
              <fieldset>
                <legend class="step-title">
                  <span class="step-number">4</span>
                  入力内容の確認
                </legend>

                <div class="confirmation-content" id="confirmation-content">
                  <!-- 確認内容はJavaScriptで動的生成 -->
                </div>

                <div class="form-group">
                  <div class="checkbox-option">
                    <input type="checkbox" 
                           id="agree-terms" 
                           name="agree_terms" 
                           required
                           aria-required="true"
                           aria-describedby="agree-terms-error">
                    <label for="agree-terms" class="required">
                      上記の内容に間違いがなく、プライバシーポリシーに同意します
                    </label>
                  </div>
                  <div id="agree-terms-error" class="form-error" role="alert" aria-live="polite"></div>
                </div>

                <div class="alert alert-warning" role="alert">
                  <span class="alert-icon" aria-hidden="true">⚠</span>
                  <div class="alert-content">
                    送信後、セキュリティ担当者が迅速に対応します。
                    緊急の場合は、直接セキュリティ部門までお電話ください。
                  </div>
                </div>
              </fieldset>
            </div>

            <!-- フォームナビゲーション -->
            <div class="form-navigation" role="navigation" aria-label="フォームナビゲーション">
              <button type="button" 
                      id="prev-button" 
                      class="btn btn-secondary ${this.currentStep === 1 ? 'hidden' : ''}"
                      aria-label="前のステップに戻る">
                <span aria-hidden="true">←</span> 前へ
              </button>
              
              <button type="button" 
                      id="next-button" 
                      class="btn btn-primary ${this.currentStep === this.totalSteps ? 'hidden' : ''}"
                      aria-label="次のステップに進む">
                次へ <span aria-hidden="true">→</span>
              </button>
              
              <button type="submit" 
                      id="submit-button" 
                      class="btn btn-danger ${this.currentStep !== this.totalSteps ? 'hidden' : ''}"
                      aria-label="報告を送信する">
                <span class="submit-icon" aria-hidden="true">🚨</span>
                緊急報告を送信
              </button>
            </div>
          </form>
        </div>

        <!-- 送信状況表示 -->
        <div id="submission-status" class="submission-status hidden" role="status" aria-live="polite">
          <!-- 送信結果はJavaScriptで動的生成 -->
        </div>
      </div>
    `;
  }

  /**
   * プログレスバー生成
   */
  renderProgressBar() {
    const progressPercentage = (this.currentStep / this.totalSteps) * 100;
    
    return `
      <div class="progress-container" role="progressbar" 
           aria-valuemin="0" 
           aria-valuemax="${this.totalSteps}" 
           aria-valuenow="${this.currentStep}"
           aria-label="フォーム進行状況">
        <div class="progress-bar">
          <div class="progress-fill" style="width: ${progressPercentage}%"></div>
        </div>
        <div class="progress-text">
          ステップ ${this.currentStep} / ${this.totalSteps}
        </div>
      </div>
    `;
  }

  /**
   * イベントリスナー設定
   */
  setupEventListeners() {
    const form = this.container.querySelector('#ic-loss-report-form');
    const nextButton = this.container.querySelector('#next-button');
    const prevButton = this.container.querySelector('#prev-button');
    const submitButton = this.container.querySelector('#submit-button');

    // フォーム送信
    form.addEventListener('submit', (e) => this.handleSubmit(e));

    // ナビゲーションボタン
    if (nextButton) {
      nextButton.addEventListener('click', () => this.nextStep());
    }
    
    if (prevButton) {
      prevButton.addEventListener('click', () => this.prevStep());
    }

    // リアルタイムバリデーション
    if (this.options.enableValidation) {
      this.setupRealTimeValidation();
    }

    // キーボードナビゲーション
    form.addEventListener('keydown', (e) => this.handleKeyNavigation(e));
  }

  /**
   * リアルタイムバリデーション設定
   */
  setupRealTimeValidation() {
    const inputs = this.container.querySelectorAll('input, select, textarea');
    
    inputs.forEach(input => {
      input.addEventListener('blur', () => this.validateField(input));
      input.addEventListener('input', CommonUtils.debounce(() => this.validateField(input), 300));
    });
  }

  /**
   * フィールドバリデーション
   * @param {HTMLElement} field - バリデーション対象フィールド
   */
  validateField(field) {
    const value = field.value.trim();
    const fieldName = field.name;
    const errorElement = this.container.querySelector(`#${field.id}-error`);
    
    let isValid = true;
    let errorMessage = '';

    // 必須チェック
    if (field.hasAttribute('required') && !value) {
      isValid = false;
      errorMessage = 'この項目は必須です';
    }

    // タイプ別バリデーション
    if (isValid && value) {
      switch (fieldName) {
        case 'reporter_name':
          const nameValidation = this.validator.validate(value, 'name');
          if (!nameValidation.isValid) {
            isValid = false;
            errorMessage = nameValidation.message;
          }
          break;

        case 'reporter_employee_id':
          if (!/^[A-Z0-9]{4,10}$/.test(value)) {
            isValid = false;
            errorMessage = '社員番号は4-10桁の英数字で入力してください';
          }
          break;

        case 'contact_phone':
          const phoneValidation = this.validator.validate(value, 'phone');
          if (!phoneValidation.isValid) {
            isValid = false;
            errorMessage = phoneValidation.message;
          }
          break;

        case 'card_number':
          if (value && !/^[A-Z0-9\-]{4,20}$/.test(value)) {
            isValid = false;
            errorMessage = 'カード番号は英数字とハイフンで入力してください';
          }
          break;

        case 'loss_location':
          if (value.length < 3) {
            isValid = false;
            errorMessage = '紛失場所をより詳しく入力してください（3文字以上）';
          }
          break;

        case 'loss_circumstances':
          if (value.length < 10) {
            isValid = false;
            errorMessage = '紛失状況をより詳しく記述してください（10文字以上）';
          }
          break;
      }
    }

    // UI更新
    this.updateFieldValidation(field, isValid, errorMessage);
    return isValid;
  }

  /**
   * フィールドバリデーション結果UI更新
   * @param {HTMLElement} field - 対象フィールド
   * @param {boolean} isValid - バリデーション結果
   * @param {string} errorMessage - エラーメッセージ
   */
  updateFieldValidation(field, isValid, errorMessage) {
    const errorElement = this.container.querySelector(`#${field.id}-error`);
    
    if (isValid) {
      field.classList.remove('error');
      field.classList.add('valid');
      field.setAttribute('aria-invalid', 'false');
      if (errorElement) {
        errorElement.textContent = '';
        errorElement.classList.remove('visible');
      }
    } else {
      field.classList.remove('valid');
      field.classList.add('error');
      field.setAttribute('aria-invalid', 'true');
      if (errorElement) {
        errorElement.textContent = errorMessage;
        errorElement.classList.add('visible');
      }
    }
  }

  /**
   * 次のステップに進む
   */
  async nextStep() {
    if (this.currentStep >= this.totalSteps) return;

    // 現在のステップをバリデーション
    if (!await this.validateCurrentStep()) {
      return;
    }

    this.currentStep++;
    this.updateStepDisplay();
    
    // ステップ4（確認画面）の場合は確認内容を生成
    if (this.currentStep === 4) {
      this.generateConfirmationContent();
    }
  }

  /**
   * 前のステップに戻る
   */
  prevStep() {
    if (this.currentStep <= 1) return;

    this.currentStep--;
    this.updateStepDisplay();
  }

  /**
   * ステップ表示更新
   */
  updateStepDisplay() {
    // ステップコンテンツの表示切り替え
    for (let i = 1; i <= this.totalSteps; i++) {
      const stepElement = this.container.querySelector(`#step-${i}`);
      if (stepElement) {
        if (i === this.currentStep) {
          stepElement.classList.remove('hidden');
          stepElement.classList.add('active');
          stepElement.setAttribute('aria-hidden', 'false');
        } else {
          stepElement.classList.remove('active');
          stepElement.classList.add('hidden');
          stepElement.setAttribute('aria-hidden', 'true');
        }
      }
    }

    // ナビゲーションボタンの表示制御
    const prevButton = this.container.querySelector('#prev-button');
    const nextButton = this.container.querySelector('#next-button');
    const submitButton = this.container.querySelector('#submit-button');

    if (prevButton) {
      prevButton.classList.toggle('hidden', this.currentStep === 1);
    }
    
    if (nextButton) {
      nextButton.classList.toggle('hidden', this.currentStep === this.totalSteps);
    }
    
    if (submitButton) {
      submitButton.classList.toggle('hidden', this.currentStep !== this.totalSteps);
    }

    // プログレスバー更新
    if (this.options.showProgress) {
      this.updateProgressBar();
    }

    // アクセシビリティ: フォーカス管理
    const activeStep = this.container.querySelector('.form-step.active');
    if (activeStep) {
      const firstInput = activeStep.querySelector('input, select, textarea');
      if (firstInput) {
        CommonUtils.setAccessibleFocus(firstInput);
      }
    }
  }

  /**
   * プログレスバー更新
   */
  updateProgressBar() {
    const progressBar = this.container.querySelector('.progress-fill');
    const progressText = this.container.querySelector('.progress-text');
    const progressContainer = this.container.querySelector('.progress-container');
    
    if (progressBar && progressText && progressContainer) {
      const progressPercentage = (this.currentStep / this.totalSteps) * 100;
      progressBar.style.width = `${progressPercentage}%`;
      progressText.textContent = `ステップ ${this.currentStep} / ${this.totalSteps}`;
      
      progressContainer.setAttribute('aria-valuenow', this.currentStep);
    }
  }

  /**
   * 現在のステップのバリデーション
   * @returns {Promise<boolean>} バリデーション結果
   */
  async validateCurrentStep() {
    const currentStepElement = this.container.querySelector(`#step-${this.currentStep}`);
    if (!currentStepElement) return false;

    const requiredFields = currentStepElement.querySelectorAll('[required]');
    let allValid = true;

    for (const field of requiredFields) {
      if (!this.validateField(field)) {
        allValid = false;
      }
    }

    // ラジオボタンとチェックボックスの特別処理
    const radioGroups = this.getRadioGroups(currentStepElement);
    for (const groupName of radioGroups) {
      const radioInputs = currentStepElement.querySelectorAll(`input[name="${groupName}"][required]`);
      if (radioInputs.length > 0) {
        const isChecked = Array.from(radioInputs).some(input => input.checked);
        if (!isChecked) {
          allValid = false;
          const errorElement = currentStepElement.querySelector(`#${groupName.replace('_', '-')}-error`);
          if (errorElement) {
            errorElement.textContent = 'この項目は必須です';
            errorElement.classList.add('visible');
          }
        }
      }
    }

    if (!allValid) {
      CommonUtils.showNotification('入力に不備があります。エラーを修正してください。', 'error');
      
      // 最初のエラーフィールドにフォーカス
      const firstErrorField = currentStepElement.querySelector('.error, [aria-invalid="true"]');
      if (firstErrorField) {
        CommonUtils.setAccessibleFocus(firstErrorField);
      }
    }

    return allValid;
  }

  /**
   * ラジオボタングループ取得
   * @param {HTMLElement} container - 検索対象要素
   * @returns {Array} ラジオボタングループ名の配列
   */
  getRadioGroups(container) {
    const radioInputs = container.querySelectorAll('input[type="radio"]');
    const groups = new Set();
    radioInputs.forEach(input => {
      if (input.name) {
        groups.add(input.name);
      }
    });
    return Array.from(groups);
  }

  /**
   * 確認内容生成
   */
  generateConfirmationContent() {
    const formData = this.getFormData();
    const confirmationContent = this.container.querySelector('#confirmation-content');
    
    if (!confirmationContent) return;

    const sections = [
      {
        title: '基本情報',
        fields: [
          { label: '報告者名', value: formData.reporter_name },
          { label: '所属部署', value: formData.reporter_department },
          { label: '社員番号', value: formData.reporter_employee_id },
          { label: '連絡先電話番号', value: formData.contact_phone }
        ]
      },
      {
        title: 'カード情報',
        fields: [
          { label: 'カードの種類', value: formData.card_type },
          { label: 'カード番号・ID', value: formData.card_number || '未入力' },
          { label: '残高', value: formData.card_balance ? `${formData.card_balance}円` : '未入力' },
          { label: '付帯機能', value: this.getCheckboxValues('card_features').join(', ') || '未選択' }
        ]
      },
      {
        title: '紛失詳細',
        fields: [
          { label: '紛失日時', value: this.formatDateTime(formData.loss_date) },
          { label: '紛失場所', value: formData.loss_location },
          { label: '紛失状況', value: formData.loss_circumstances },
          { label: '発見の経緯', value: formData.discovery_timing },
          { label: '実施した対応', value: this.getCheckboxValues('actions_taken').join(', ') || '未選択' }
        ]
      }
    ];

    let html = '<div class="confirmation-sections">';
    
    sections.forEach(section => {
      html += `
        <div class="confirmation-section">
          <h4 class="confirmation-section-title">${CommonUtils.escapeHtml(section.title)}</h4>
          <dl class="confirmation-list">
      `;
      
      section.fields.forEach(field => {
        html += `
          <dt class="confirmation-label">${CommonUtils.escapeHtml(field.label)}</dt>
          <dd class="confirmation-value">${CommonUtils.escapeHtml(field.value || '未入力')}</dd>
        `;
      });
      
      html += `
          </dl>
        </div>
      `;
    });
    
    html += '</div>';
    
    confirmationContent.innerHTML = html;
  }

  /**
   * チェックボックスの選択値取得
   * @param {string} name - チェックボックス名
   * @returns {Array} 選択された値の配列
   */
  getCheckboxValues(name) {
    const checkboxes = this.container.querySelectorAll(`input[name="${name}"]:checked`);
    return Array.from(checkboxes).map(cb => cb.value);
  }

  /**
   * 日時フォーマット
   * @param {string} dateTimeString - 日時文字列
   * @returns {string} フォーマット済み日時
   */
  formatDateTime(dateTimeString) {
    if (!dateTimeString) return '未入力';
    
    try {
      const date = new Date(dateTimeString);
      return CommonUtils.formatDate(date, 'YYYY年MM月DD日 HH:mm');
    } catch (error) {
      console.error('日時フォーマットエラー:', error);
      return dateTimeString;
    }
  }

  /**
   * フォームデータ取得
   * @returns {Object} フォームデータ
   */
  getFormData() {
    const formData = {};
    const form = this.container.querySelector('#ic-loss-report-form');
    
    if (!form) return formData;

    // テキスト入力、選択、ラジオボタン
    const inputs = form.querySelectorAll('input[type="text"], input[type="tel"], input[type="number"], input[type="datetime-local"], select, textarea, input[type="radio"]:checked');
    inputs.forEach(input => {
      if (input.name && input.value) {
        formData[input.name] = input.value.trim();
      }
    });

    // チェックボックス
    const checkboxGroups = new Set();
    form.querySelectorAll('input[type="checkbox"]').forEach(cb => {
      if (cb.name) checkboxGroups.add(cb.name);
    });

    checkboxGroups.forEach(groupName => {
      formData[groupName] = this.getCheckboxValues(groupName);
    });

    return formData;
  }

  /**
   * フォーム送信処理
   * @param {Event} event - 送信イベント
   */
  async handleSubmit(event) {
    event.preventDefault();
    
    if (this.isSubmitting) return;

    try {
      this.isSubmitting = true;
      
      // 最終バリデーション
      if (!await this.validateCurrentStep()) {
        return;
      }

      // 利用規約同意確認
      const agreeTerms = this.container.querySelector('#agree-terms');
      if (!agreeTerms || !agreeTerms.checked) {
        CommonUtils.showNotification('プライバシーポリシーへの同意が必要です', 'error');
        CommonUtils.setAccessibleFocus(agreeTerms);
        return;
      }

      // フォームデータ取得
      const formData = this.getFormData();
      
      // データの暗号化処理 (IPA準拠)
      const secureData = await this.encryptSensitiveData(formData);
      
      // 送信処理
      await this.submitData(secureData);
      
    } catch (error) {
      console.error('フォーム送信エラー:', error);
      this.showSubmissionError(error.message || 'フォームの送信に失敗しました');
    } finally {
      this.isSubmitting = false;
    }
  }

  /**
   * 機密データの暗号化 (IPA準拠)
   * @param {Object} data - フォームデータ
   * @returns {Promise<Object>} 暗号化済みデータ
   */
  async encryptSensitiveData(data) {
    if (!this.hashManager) {
      throw new Error('セキュリティマネージャーが初期化されていません');
    }

    const secureData = { ...data };
    
    // 機密情報の暗号化
    const sensitiveFields = ['reporter_employee_id', 'contact_phone', 'card_number'];
    
    for (const field of sensitiveFields) {
      if (secureData[field]) {
        try {
          const encrypted = await this.hashManager.hashWithPepper(secureData[field]);
          secureData[`${field}_hash`] = encrypted.hash;
          secureData[`${field}_salt`] = encrypted.salt;
          
          // 元データは削除（ログ対策）
          delete secureData[field];
        } catch (error) {
          console.error(`${field}の暗号化エラー:`, error);
          throw new Error(`データの暗号化に失敗しました: ${field}`);
        }
      }
    }

    // タイムスタンプ追加
    secureData.submitted_at = new Date().toISOString();
    secureData.submission_id = CommonUtils.generateCSRFToken();

    return secureData;
  }

  /**
   * データ送信処理
   * @param {Object} data - 送信データ
   * @returns {Promise<void>}
   */
  async submitData(data) {
    CommonUtils.showLoading(true, '緊急報告を送信中...');
    
    try {
      // Kintoneレコードとして保存
      const records = [{
        report_type: { value: 'ICカード紛失' },
        reporter_name: { value: data.reporter_name },
        reporter_department: { value: data.reporter_department },
        reporter_employee_id_hash: { value: data.reporter_employee_id_hash },
        reporter_employee_id_salt: { value: data.reporter_employee_id_salt },
        contact_phone_hash: { value: data.contact_phone_hash },
        contact_phone_salt: { value: data.contact_phone_salt },
        card_type: { value: data.card_type },
        card_number_hash: { value: data.card_number_hash || '' },
        card_number_salt: { value: data.card_number_salt || '' },
        card_balance: { value: data.card_balance || '0' },
        card_features: { value: (data.card_features || []).join(', ') },
        loss_date: { value: data.loss_date },
        loss_location: { value: data.loss_location },
        loss_circumstances: { value: data.loss_circumstances },
        discovery_timing: { value: data.discovery_timing },
        actions_taken: { value: (data.actions_taken || []).join(', ') },
        status: { value: '報告受付' },
        priority: { value: '緊急' },
        submitted_at: { value: data.submitted_at },
        submission_id: { value: data.submission_id }
      }];

      const result = await KintoneAPIHelper.saveRecordsSecurely(records);
      
      if (result.success) {
        this.showSubmissionSuccess(result.ids[0], data.submission_id);
      } else {
        throw new Error(result.error);
      }
      
    } catch (error) {
      console.error('データ送信エラー:', error);
      throw error;
    } finally {
      CommonUtils.showLoading(false);
    }
  }

  /**
   * 送信成功時の処理
   * @param {string} recordId - レコードID
   * @param {string} submissionId - 送信ID
   */
  showSubmissionSuccess(recordId, submissionId) {
    const statusContainer = this.container.querySelector('#submission-status');
    if (!statusContainer) return;

    statusContainer.innerHTML = `
      <div class="submission-success" role="alert" aria-live="assertive">
        <div class="success-icon">✅</div>
        <h3 class="success-title">ICカード紛失報告が受理されました</h3>
        <div class="success-content">
          <p><strong>受付番号:</strong> <code>${CommonUtils.escapeHtml(submissionId)}</code></p>
          <p><strong>レコードID:</strong> <code>${CommonUtils.escapeHtml(recordId)}</code></p>
          <p>セキュリティ担当者が速やかに対応いたします。</p>
          <p>緊急の場合は、以下の連絡先まで直接お電話ください：</p>
          <p class="emergency-contact">
            <strong>セキュリティ緊急ダイヤル:</strong> 
            <a href="tel:03-1234-5678" class="phone-link">03-1234-5678</a>
          </p>
        </div>
        <div class="success-actions">
          <button type="button" class="btn btn-primary" onclick="location.reload()">
            新しい報告を作成
          </button>
        </div>
      </div>
    `;
    
    statusContainer.classList.remove('hidden');
    
    // フォームを非表示
    const formContainer = this.container.querySelector('.form-body');
    if (formContainer) {
      formContainer.style.display = 'none';
    }

    // 成功通知
    CommonUtils.showNotification('ICカード紛失報告が正常に送信されました', 'success', 10000);
    
    // フォーカス管理
    CommonUtils.setAccessibleFocus(statusContainer);
  }

  /**
   * 送信エラー時の処理
   * @param {string} errorMessage - エラーメッセージ
   */
  showSubmissionError(errorMessage) {
    const statusContainer = this.container.querySelector('#submission-status');
    if (!statusContainer) return;

    statusContainer.innerHTML = `
      <div class="submission-error" role="alert" aria-live="assertive">
        <div class="error-icon">❌</div>
        <h3 class="error-title">送信に失敗しました</h3>
        <div class="error-content">
          <p class="error-message">${CommonUtils.escapeHtml(errorMessage)}</p>
          <p>申し訳ございませんが、しばらく経ってから再度お試しください。</p>
          <p>問題が続く場合は、以下の連絡先まで直接お電話ください：</p>
          <p class="emergency-contact">
            <strong>セキュリティ緊急ダイヤル:</strong> 
            <a href="tel:03-1234-5678" class="phone-link">03-1234-5678</a>
          </p>
        </div>
        <div class="error-actions">
          <button type="button" class="btn btn-primary" onclick="this.closest('.submission-status').classList.add('hidden')">
            フォームに戻る
          </button>
        </div>
      </div>
    `;
    
    statusContainer.classList.remove('hidden');

    // エラー通知
    CommonUtils.showNotification(errorMessage, 'error', 8000);
    
    // フォーカス管理
    CommonUtils.setAccessibleFocus(statusContainer);
  }

  /**
   * エラー表示
   * @param {string} message - エラーメッセージ
   */
  showError(message) {
    CommonUtils.showNotification(message, 'error');
  }

  /**
   * キーボードナビゲーション処理
   * @param {KeyboardEvent} event - キーボードイベント
   */
  handleKeyNavigation(event) {
    // Ctrl+Enterで次のステップまたは送信
    if (event.ctrlKey && event.key === 'Enter') {
      event.preventDefault();
      if (this.currentStep < this.totalSteps) {
        this.nextStep();
      } else {
        const submitButton = this.container.querySelector('#submit-button');
        if (submitButton && !submitButton.disabled) {
          submitButton.click();
        }
      }
    }

    // Escapeでフォームリセット確認
    if (event.key === 'Escape') {
      this.confirmReset();
    }
  }

  /**
   * フォームリセット確認
   */
  confirmReset() {
    if (confirm('フォームをリセットしますか？入力内容は失われます。')) {
      this.resetForm();
    }
  }

  /**
   * フォームリセット
   */
  resetForm() {
    const form = this.container.querySelector('#ic-loss-report-form');
    if (form) {
      form.reset();
    }
    
    this.currentStep = 1;
    this.formData = {};
    this.updateStepDisplay();
    
    // バリデーション状態をクリア
    const errorElements = this.container.querySelectorAll('.form-error');
    errorElements.forEach(el => {
      el.textContent = '';
      el.classList.remove('visible');
    });
    
    const fieldElements = this.container.querySelectorAll('.form-control');
    fieldElements.forEach(el => {
      el.classList.remove('error', 'valid');
      el.removeAttribute('aria-invalid');
    });

    CommonUtils.showNotification('フォームがリセットされました', 'info');
  }

  /**
   * アクセシビリティ設定
   */
  setupAccessibility() {
    // ARIA属性の動的設定
    const form = this.container.querySelector('#ic-loss-report-form');
    if (form) {
      form.setAttribute('aria-label', 'ICカード紛失報告フォーム');
    }

    // スクリーンリーダー用のライブリージョン
    if (!document.getElementById('sr-live-region')) {
      const liveRegion = document.createElement('div');
      liveRegion.id = 'sr-live-region';
      liveRegion.className = 'sr-only';
      liveRegion.setAttribute('aria-live', 'polite');
      liveRegion.setAttribute('aria-atomic', 'true');
      document.body.appendChild(liveRegion);
    }
  }

  /**
   * オートセーブ設定
   */
  setupAutoSave() {
    if (!this.options.autoSave) return;

    const autoSaveInterval = setInterval(() => {
      if (this.isSubmitting) return;
      
      try {
        const formData = this.getFormData();
        CommonUtils.setSecureLocalStorage('ic-loss-form-draft', formData);
        console.log('フォームデータが自動保存されました');
      } catch (error) {
        console.error('オートセーブエラー:', error);
      }
    }, 30000); // 30秒間隔

    // クリーンアップ用
    this.autoSaveInterval = autoSaveInterval;
  }

  /**
   * 下書きデータ復元
   */
  restoreDraft() {
    try {
      const draft = CommonUtils.getSecureLocalStorage('ic-loss-form-draft');
      if (draft) {
        // フォームに値を復元
        Object.keys(draft).forEach(key => {
          const field = this.container.querySelector(`[name="${key}"]`);
          if (field) {
            if (field.type === 'radio') {
              const radioOption = this.container.querySelector(`[name="${key}"][value="${draft[key]}"]`);
              if (radioOption) {
                radioOption.checked = true;
              }
            } else if (field.type === 'checkbox') {
              if (Array.isArray(draft[key])) {
                draft[key].forEach(value => {
                  const checkbox = this.container.querySelector(`[name="${key}"][value="${value}"]`);
                  if (checkbox) {
                    checkbox.checked = true;
                  }
                });
              }
            } else {
              field.value = draft[key];
            }
          }
        });

        CommonUtils.showNotification('下書きが復元されました', 'info');
        return true;
      }
    } catch (error) {
      console.error('下書き復元エラー:', error);
    }
    return false;
  }

  /**
   * 下書きデータクリア
   */
  clearDraft() {
    try {
      localStorage.removeItem('ic-loss-form-draft');
    } catch (error) {
      console.error('下書きクリアエラー:', error);
    }
  }

  /**
   * コンポーネント破棄
   */
  destroy() {
    // オートセーブの停止
    if (this.autoSaveInterval) {
      clearInterval(this.autoSaveInterval);
    }

    // イベントリスナーの削除
    if (this.container) {
      this.container.innerHTML = '';
    }

    // 下書きクリア
    this.clearDraft();
  }
}

// エクスポート
if (typeof module !== 'undefined' && module.exports) {
  module.exports = ICLossReportForm;
}

// ブラウザ環境でのグローバル変数設定
if (typeof window !== 'undefined') {
  window.ICLossReportForm = ICLossReportForm;
}
