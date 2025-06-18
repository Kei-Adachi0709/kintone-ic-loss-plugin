/**
 * index.js
 * Kintone ICカード紛失対応プラグイン メインファイル
 * 
 * @author Kei-Adachi0709
 * @version 1.0.0
 * @date 2025-06-19
 * @compliance IPA安全なウェブサイトの作り方準拠
 */

// セキュリティクラス読み込み
const SecureHashManager = require('../security/SecureHashManager');
const InputValidator = require('../security/InputValidator');
const SecurityConfig = require('../security/SecurityConfig');

/**
 * Kintone ICカード紛失対応プラグイン メインクラス
 */
class ICLossPlugin {
  
  constructor() {
    this.securityConfig = new SecurityConfig();
    this.hashManager = null;
    this.validator = new InputValidator();
    this.isInitialized = false;
  }

  /**
   * プラグイン初期化
   */
  async initialize() {
    try {
      // セキュリティ設定読み込み
      const hashConfig = this.securityConfig.getHashConfig();
      this.hashManager = new SecureHashManager(hashConfig);

      // プラグイン設定取得
      const config = kintone.plugin.app.getConfig();
      
      // セキュリティヘルスチェック実行
      const healthCheck = this.securityConfig.performSecurityHealthCheck();
      console.log('セキュリティヘルスチェック:', healthCheck);

      this.isInitialized = true;
      console.log('ICカード紛失対応プラグインが初期化されました');

    } catch (error) {
      console.error('プラグイン初期化エラー:', error.message);
      this.isInitialized = false;
    }
  }

  /**
   * ICカード紛失報告処理
   * @param {Object} reportData - 報告データ
   */
  async reportLostCard(reportData) {
    try {
      if (!this.isInitialized) {
        throw new Error('プラグインが初期化されていません');
      }

      // 入力値検証
      const validationResult = this.validator.validateBulkData(reportData);
      if (!validationResult.valid) {
        throw new Error('入力値検証エラー: ' + JSON.stringify(validationResult.results));
      }

      // ICカード番号ハッシュ化
      const hashedCard = await this.hashManager.hashICCardNumber(
        validationResult.results.icCardNumber.sanitized
      );

      // Kintoneレコード作成
      const record = {
        '報告日時': { value: new Date().toISOString() },
        'カード種別': { value: validationResult.results.icCardNumber.cardName },
        'カード番号ハッシュ': { value: hashedCard.hash },
        'マスク番号': { value: hashedCard.maskedNumber },
        '社員証番号': { value: validationResult.results.employeeId?.sanitized },
        '連絡先メール': { value: validationResult.results.email?.sanitized },
        '連絡先電話': { value: validationResult.results.phoneNumber?.sanitized },
        'ステータス': { value: '報告済み' }
      };

      // レコード登録
      await kintone.api(kintone.api.url('/k/v1/record', true), 'POST', {
        app: kintone.app.getId(),
        record: record
      });

      return {
        success: true,
        message: 'ICカード紛失報告が正常に登録されました',
        maskedNumber: hashedCard.maskedNumber
      };

    } catch (error) {
      console.error('紛失報告エラー:', error.message);
      return {
        success: false,
        message: '報告処理中にエラーが発生しました',
        error: error.message
      };
    }
  }
}

// Kintoneイベント処理
(() => {
  'use strict';

  const plugin = new ICLossPlugin();

  // アプリ表示時の初期化
  kintone.events.on('app.record.index.show', async (event) => {
    await plugin.initialize();
    
    // カスタムUIボタン追加
    if (!document.getElementById('ic-loss-report-btn')) {
      const headerSpace = kintone.app.getHeaderSpaceElement();
      const button = document.createElement('button');
      button.id = 'ic-loss-report-btn';
      button.textContent = 'ICカード紛失報告';
      button.className = 'kintoneplugin-button-normal';
      button.onclick = () => showLossReportDialog();
      headerSpace.appendChild(button);
    }

    return event;
  });

  /**
   * 紛失報告ダイアログ表示
   */
  function showLossReportDialog() {
    const dialog = document.createElement('div');
    dialog.innerHTML = `
      <div class="ic-loss-dialog">
        <h3>ICカード紛失報告</h3>
        <form id="ic-loss-form">
          <div class="form-group">
            <label for="ic-card-number">ICカード番号:</label>
            <input type="text" id="ic-card-number" placeholder="例: TO1234567890123456" required>
            <small>対応: TOICA, manaca, Suica, ICOCA, SUGOCA, PASMO</small>
          </div>
          
          <div class="form-group">
            <label for="employee-id">社員証番号:</label>
            <input type="text" id="employee-id" placeholder="例: EMP123456" required>
          </div>
          
          <div class="form-group">
            <label for="contact-email">連絡先メール:</label>
            <input type="email" id="contact-email" placeholder="例: user@example.com" required>
          </div>
          
          <div class="form-group">
            <label for="contact-phone">連絡先電話:</label>
            <input type="tel" id="contact-phone" placeholder="例: 052-123-4567" required>
          </div>
          
          <div class="form-actions">
            <button type="submit">報告する</button>
            <button type="button" onclick="closeLossReportDialog()">キャンセル</button>
          </div>
        </form>
      </div>
    `;
    
    document.body.appendChild(dialog);
    
    // フォーム送信処理
    document.getElementById('ic-loss-form').onsubmit = async (e) => {
      e.preventDefault();
      
      const formData = {
        icCardNumber: document.getElementById('ic-card-number').value,
        employeeId: document.getElementById('employee-id').value,
        email: document.getElementById('contact-email').value,
        phoneNumber: document.getElementById('contact-phone').value
      };
      
      const result = await plugin.reportLostCard(formData);
      
      if (result.success) {
        alert(`報告完了: ${result.message}\nマスク番号: ${result.maskedNumber}`);
        closeLossReportDialog();
        location.reload();
      } else {
        alert(`エラー: ${result.message}`);
      }
    };
  }

  /**
   * ダイアログクローズ
   */
  window.closeLossReportDialog = function() {
    const dialog = document.querySelector('.ic-loss-dialog');
    if (dialog) {
      dialog.parentElement.remove();
    }
  };

})();

module.exports = ICLossPlugin;
