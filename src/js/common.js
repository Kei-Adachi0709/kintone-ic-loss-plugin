/**
 * common.js
 * 共通ユーティリティとヘルパー関数
 * IPAガイドライン準拠共通処理
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

/**
 * 共通ユーティリティクラス
 */
class CommonUtils {
  static validator = new InputValidator();
  
  /**
   * 安全な日付フォーマット (IPA準拠)
   * @param {Date} date - フォーマット対象日付
   * @param {string} format - フォーマット形式
   * @returns {string} フォーマット済み日付
   */
  static formatDate(date, format = 'YYYY-MM-DD HH:mm:ss') {
    if (!date || !(date instanceof Date)) return '';
    
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    const seconds = String(date.getSeconds()).padStart(2, '0');
    
    return format
      .replace('YYYY', year)
      .replace('MM', month)
      .replace('DD', day)
      .replace('HH', hours)
      .replace('mm', minutes)
      .replace('ss', seconds);
  }

  /**
   * 安全なHTML表示 (XSS対策・IPA準拠)
   * @param {string} text - 表示テキスト
   * @returns {string} サニタイズ済みテキスト
   */
  static escapeHtml(text) {
    if (!text) return '';
    
    const map = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#x27;',
      '/': '&#x2F;'
    };
    
    return text.replace(/[&<>"'\/]/g, (s) => map[s]);
  }

  /**
   * バリデーション済み文字列取得
   * @param {string} input - 入力文字列
   * @param {string} type - バリデーションタイプ
   * @returns {string|null} バリデーション済み文字列またはnull
   */
  static getSafeString(input, type = 'text') {
    try {
      if (!this.validator.validate(input, type).isValid) {
        return null;
      }
      return this.escapeHtml(input.trim());
    } catch (error) {
      console.error('文字列バリデーションエラー:', error);
      return null;
    }
  }

  /**
   * セキュアな数値取得
   * @param {any} input - 入力値
   * @param {number} min - 最小値
   * @param {number} max - 最大値
   * @returns {number|null} バリデーション済み数値またはnull
   */
  static getSafeNumber(input, min = null, max = null) {
    const num = parseInt(input, 10);
    if (isNaN(num)) return null;
    if (min !== null && num < min) return null;
    if (max !== null && num > max) return null;
    return num;
  }

  /**
   * セキュアなURL生成 (IPA準拠)
   * @param {string} baseUrl - ベースURL
   * @param {Object} params - パラメータ
   * @returns {string} セキュアなURL
   */
  static buildSecureUrl(baseUrl, params = {}) {
    try {
      const url = new URL(baseUrl);
      Object.keys(params).forEach(key => {
        const value = this.getSafeString(params[key], 'text');
        if (value !== null) {
          url.searchParams.set(key, value);
        }
      });
      return url.toString();
    } catch (error) {
      console.error('URL構築エラー:', error);
      return baseUrl;
    }
  }

  /**
   * CSRFトークン生成 (IPA準拠)
   * @returns {string} CSRFトークン
   */
  static generateCSRFToken() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  /**
   * ローディング表示制御
   * @param {boolean} show - 表示/非表示
   * @param {string} message - ローディングメッセージ
   */
  static showLoading(show = true, message = '処理中...') {
    let loader = document.getElementById('global-loader');
    
    if (show && !loader) {
      loader = document.createElement('div');
      loader.id = 'global-loader';
      loader.className = 'loading-overlay';
      loader.innerHTML = `
        <div class="loading-content">
          <div class="loading-spinner" role="progressbar" aria-label="読み込み中">
            <div class="spinner-ring"></div>
            <div class="spinner-ring"></div>
            <div class="spinner-ring"></div>
          </div>
          <p class="loading-message">${this.escapeHtml(message)}</p>
        </div>
      `;
      loader.setAttribute('aria-live', 'polite');
      document.body.appendChild(loader);
    } else if (!show && loader) {
      loader.remove();
    } else if (show && loader) {
      const messageEl = loader.querySelector('.loading-message');
      if (messageEl) {
        messageEl.textContent = message;
      }
    }
  }

  /**
   * 通知メッセージ表示 (アクセシビリティ対応)
   * @param {string} message - メッセージ
   * @param {string} type - メッセージタイプ (success, error, warning, info)
   * @param {number} duration - 表示時間(ms)
   */
  static showNotification(message, type = 'info', duration = 5000) {
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.setAttribute('role', 'alert');
    notification.setAttribute('aria-live', 'assertive');
    
    const iconMap = {
      success: '✓',
      error: '✗',
      warning: '⚠',
      info: 'ℹ'
    };
    
    notification.innerHTML = `
      <div class="notification-content">
        <span class="notification-icon" aria-hidden="true">${iconMap[type] || iconMap.info}</span>
        <span class="notification-message">${this.escapeHtml(message)}</span>
        <button class="notification-close" aria-label="通知を閉じる" type="button">×</button>
      </div>
    `;
    
    // 通知エリアに追加
    let notificationArea = document.getElementById('notification-area');
    if (!notificationArea) {
      notificationArea = document.createElement('div');
      notificationArea.id = 'notification-area';
      notificationArea.className = 'notification-area';
      notificationArea.setAttribute('aria-live', 'polite');
      document.body.appendChild(notificationArea);
    }
    
    notificationArea.appendChild(notification);
    
    // 閉じるボタンのイベント
    const closeBtn = notification.querySelector('.notification-close');
    closeBtn.addEventListener('click', () => {
      notification.remove();
    });
    
    // 自動削除
    if (duration > 0) {
      setTimeout(() => {
        if (notification.parentNode) {
          notification.remove();
        }
      }, duration);
    }
    
    return notification;
  }

  /**
   * アクセシビリティ準拠フォーカス管理
   * @param {HTMLElement} element - フォーカス対象要素
   */
  static setAccessibleFocus(element) {
    if (!element) return;
    
    element.focus();
    element.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }

  /**
   * セキュアなCookie操作 (IPA準拠)
   * @param {string} name - Cookie名
   * @param {string} value - Cookie値
   * @param {number} days - 有効期限(日)
   */
  static setSecureCookie(name, value, days = 1) {
    const expires = new Date();
    expires.setTime(expires.getTime() + (days * 24 * 60 * 60 * 1000));
    
    const cookieOptions = [
      `${encodeURIComponent(name)}=${encodeURIComponent(value)}`,
      `expires=${expires.toUTCString()}`,
      'path=/',
      'SameSite=Strict'
    ];
    
    // HTTPSの場合はSecureフラグを追加
    if (location.protocol === 'https:') {
      cookieOptions.push('Secure');
    }
    
    document.cookie = cookieOptions.join('; ');
  }

  /**
   * セキュアなCookie取得
   * @param {string} name - Cookie名
   * @returns {string|null} Cookie値またはnull
   */
  static getSecureCookie(name) {
    const nameEQ = encodeURIComponent(name) + '=';
    const cookies = document.cookie.split(';');
    
    for (let cookie of cookies) {
      let c = cookie.trim();
      if (c.indexOf(nameEQ) === 0) {
        return decodeURIComponent(c.substring(nameEQ.length));
      }
    }
    return null;
  }

  /**
   * Cookie削除
   * @param {string} name - Cookie名
   */
  static deleteCookie(name) {
    this.setSecureCookie(name, '', -1);
  }

  /**
   * レスポンシブ画面サイズ判定
   * @returns {string} 画面サイズ (mobile, tablet, desktop)
   */
  static getScreenSize() {
    const width = window.innerWidth;
    if (width < 768) return 'mobile';
    if (width < 1024) return 'tablet';
    return 'desktop';
  }

  /**
   * セキュアなローカルストレージ操作
   * @param {string} key - キー
   * @param {any} value - 値
   */
  static setSecureLocalStorage(key, value) {
    try {
      const data = {
        value: value,
        timestamp: Date.now(),
        checksum: this.generateCSRFToken()
      };
      localStorage.setItem(key, JSON.stringify(data));
    } catch (error) {
      console.error('ローカルストレージ保存エラー:', error);
    }
  }

  /**
   * セキュアなローカルストレージ取得
   * @param {string} key - キー
   * @param {number} maxAge - 最大保持時間(ms)
   * @returns {any|null} 値またはnull
   */
  static getSecureLocalStorage(key, maxAge = 24 * 60 * 60 * 1000) {
    try {
      const stored = localStorage.getItem(key);
      if (!stored) return null;
      
      const data = JSON.parse(stored);
      if (!data.timestamp || !data.checksum) return null;
      
      // 有効期限チェック
      if (Date.now() - data.timestamp > maxAge) {
        localStorage.removeItem(key);
        return null;
      }
      
      return data.value;
    } catch (error) {
      console.error('ローカルストレージ取得エラー:', error);
      return null;
    }
  }

  /**
   * デバウンス処理
   * @param {Function} func - 実行関数
   * @param {number} wait - 待機時間(ms)
   * @returns {Function} デバウンス済み関数
   */
  static debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
      const later = () => {
        clearTimeout(timeout);
        func(...args);
      };
      clearTimeout(timeout);
      timeout = setTimeout(later, wait);
    };
  }

  /**
   * スロットル処理
   * @param {Function} func - 実行関数
   * @param {number} limit - 制限時間(ms)
   * @returns {Function} スロットル済み関数
   */
  static throttle(func, limit) {
    let inThrottle;
    return function executedFunction(...args) {
      if (!inThrottle) {
        func.apply(this, args);
        inThrottle = true;
        setTimeout(() => inThrottle = false, limit);
      }
    };
  }
}

/**
 * Kintone APIヘルパークラス
 */
class KintoneAPIHelper {
  static validator = new InputValidator();

  /**
   * セキュアなレコード取得
   * @param {Object} params - 取得パラメータ
   * @returns {Promise<Object>} レコードデータ
   */
  static async getRecordsSecurely(params = {}) {
    try {
      // パラメータバリデーション
      const query = CommonUtils.getSafeString(params.query || '', 'text');
      const fields = Array.isArray(params.fields) ? params.fields : [];
      
      const requestParams = {
        app: kintone.app.getId(),
        query: query,
        fields: fields
      };

      CommonUtils.showLoading(true, 'データ取得中...');
      const response = await kintone.api(kintone.api.url('/k/v1/records', true), 'GET', requestParams);
      
      return {
        success: true,
        records: response.records || [],
        totalCount: response.totalCount || 0
      };
    } catch (error) {
      console.error('レコード取得エラー:', error);
      return {
        success: false,
        error: error.message || 'データの取得に失敗しました'
      };
    } finally {
      CommonUtils.showLoading(false);
    }
  }

  /**
   * セキュアなレコード保存
   * @param {Array} records - 保存レコード
   * @returns {Promise<Object>} 保存結果
   */
  static async saveRecordsSecurely(records) {
    try {
      if (!Array.isArray(records) || records.length === 0) {
        throw new Error('有効なレコードデータが指定されていません');
      }

      // レコードデータのバリデーション
      const validatedRecords = records.map(record => {
        const validatedRecord = {};
        Object.keys(record).forEach(key => {
          const value = record[key];
          if (value && typeof value === 'object' && value.value !== undefined) {
            validatedRecord[key] = {
              value: CommonUtils.getSafeString(value.value, 'text')
            };
          }
        });
        return validatedRecord;
      });

      const requestParams = {
        app: kintone.app.getId(),
        records: validatedRecords
      };

      CommonUtils.showLoading(true, 'データ保存中...');
      const response = await kintone.api(kintone.api.url('/k/v1/records', true), 'POST', requestParams);
      
      return {
        success: true,
        ids: response.ids || [],
        revisions: response.revisions || []
      };
    } catch (error) {
      console.error('レコード保存エラー:', error);
      return {
        success: false,
        error: error.message || 'データの保存に失敗しました'
      };
    } finally {
      CommonUtils.showLoading(false);
    }
  }

  /**
   * セキュアなレコード更新
   * @param {Array} records - 更新レコード
   * @returns {Promise<Object>} 更新結果
   */
  static async updateRecordsSecurely(records) {
    try {
      if (!Array.isArray(records) || records.length === 0) {
        throw new Error('有効なレコードデータが指定されていません');
      }

      // レコードデータのバリデーション
      const validatedRecords = records.map(record => {
        if (!record.id || !record.revision) {
          throw new Error('レコードIDとリビジョンが必要です');
        }

        const validatedRecord = {
          id: CommonUtils.getSafeNumber(record.id),
          revision: CommonUtils.getSafeNumber(record.revision)
        };

        Object.keys(record).forEach(key => {
          if (key !== 'id' && key !== 'revision') {
            const value = record[key];
            if (value && typeof value === 'object' && value.value !== undefined) {
              validatedRecord[key] = {
                value: CommonUtils.getSafeString(value.value, 'text')
              };
            }
          }
        });

        return validatedRecord;
      });

      const requestParams = {
        app: kintone.app.getId(),
        records: validatedRecords
      };

      CommonUtils.showLoading(true, 'データ更新中...');
      const response = await kintone.api(kintone.api.url('/k/v1/records', true), 'PUT', requestParams);
      
      return {
        success: true,
        records: response.records || []
      };
    } catch (error) {
      console.error('レコード更新エラー:', error);
      return {
        success: false,
        error: error.message || 'データの更新に失敗しました'
      };
    } finally {
      CommonUtils.showLoading(false);
    }
  }

  /**
   * セキュアなファイルアップロード
   * @param {File} file - アップロードファイル
   * @returns {Promise<Object>} アップロード結果
   */
  static async uploadFileSecurely(file) {
    try {
      if (!file || !(file instanceof File)) {
        throw new Error('有効なファイルが指定されていません');
      }

      // ファイルタイプ制限 (セキュリティ対策)
      const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf', 'text/plain'];
      if (!allowedTypes.includes(file.type)) {
        throw new Error(`許可されていないファイルタイプです: ${file.type}`);
      }

      // ファイルサイズ制限 (10MB)
      const maxSize = 10 * 1024 * 1024;
      if (file.size > maxSize) {
        throw new Error('ファイルサイズが上限(10MB)を超えています');
      }

      const formData = new FormData();
      formData.append('file', file);

      CommonUtils.showLoading(true, 'ファイルアップロード中...');
      const response = await kintone.api(kintone.api.url('/k/v1/file', true), 'POST', formData);
      
      return {
        success: true,
        fileKey: response.fileKey
      };
    } catch (error) {
      console.error('ファイルアップロードエラー:', error);
      return {
        success: false,
        error: error.message || 'ファイルのアップロードに失敗しました'
      };
    } finally {
      CommonUtils.showLoading(false);
    }
  }
}

// グローバルエクスポート
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { CommonUtils, KintoneAPIHelper };
}

// ブラウザ環境でのグローバル変数設定
if (typeof window !== 'undefined') {
  window.CommonUtils = CommonUtils;
  window.KintoneAPIHelper = KintoneAPIHelper;
}
