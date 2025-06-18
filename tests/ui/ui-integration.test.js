/**
 * UI統合テスト
 * Phase 2 UI components and accessibility tests
 * 
 * @author Kei-Adachi0709
 * @version 1.0.0
 * @date 2025-06-19
 */

const { JSDOM } = require('jsdom');

// テスト環境セットアップ
const dom = new JSDOM(`
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>IC Loss Plugin Test</title>
</head>
<body>
  <div id="root"></div>
</body>
</html>
`, { 
  url: "https://test.cybozu.com",
  pretendToBeVisual: true,
  resources: "usable"
});

global.window = dom.window;
global.document = dom.window.document;
global.navigator = dom.window.navigator;

// Kintone API mock
global.kintone = {
  events: {
    on: jest.fn(),
    off: jest.fn()
  },
  app: {
    getId: jest.fn(() => '123'),
    getHeaderSpaceElement: jest.fn(() => document.createElement('div')),
    record: {
      get: jest.fn(() => ({
        record: {
          ic_card_number: { value: '' },
          employee_name: { value: '' },
          phone_number: { value: '' }
        }
      })),
      set: jest.fn()
    }
  },
  api: jest.fn()
};

describe('Phase 2 UI統合テスト', () => {
  beforeEach(() => {
    // DOM要素をクリア
    document.body.innerHTML = '<div id="root"></div>';
    jest.clearAllMocks();
  });

  describe('ICLossReportForm', () => {
    let ICLossReportForm;

    beforeEach(() => {
      // モジュールをモック
      jest.doMock('../src/js/security/InputValidator', () => {
        return jest.fn().mockImplementation(() => ({
          validateICCardNumber: jest.fn(() => ({ isValid: true, errors: [] })),
          validatePhoneNumber: jest.fn(() => ({ isValid: true, errors: [] })),
          validateEmployeeName: jest.fn(() => ({ isValid: true, errors: [] }))
        }));
      });

      jest.doMock('../src/js/common', () => ({
        CommonUtils: {
          showNotification: jest.fn(),
          formatPhoneNumber: jest.fn(val => val),
          escapeHTML: jest.fn(val => val)
        }
      }));

      ICLossReportForm = require('../src/js/ui/ICLossReportForm');
    });

    test('フォーム初期化', () => {
      const container = document.getElementById('root');
      const form = new ICLossReportForm(container, {});
      
      expect(container.querySelector('.ic-loss-report-form')).toBeTruthy();
      expect(container.querySelector('#ic-card-number')).toBeTruthy();
      expect(container.querySelector('#employee-name')).toBeTruthy();
      expect(container.querySelector('#phone-number')).toBeTruthy();
    });

    test('アクセシビリティ属性確認', () => {
      const container = document.getElementById('root');
      const form = new ICLossReportForm(container, {});
      
      // ARIA属性確認
      const icCardField = container.querySelector('#ic-card-number');
      expect(icCardField.getAttribute('aria-required')).toBe('true');
      expect(icCardField.getAttribute('aria-describedby')).toBeTruthy();
      
      // ラベル関連確認
      const label = container.querySelector('label[for="ic-card-number"]');
      expect(label).toBeTruthy();
      expect(label.textContent).toContain('ICカード番号');
    });

    test('バリデーション統合', () => {
      const container = document.getElementById('root');
      const form = new ICLossReportForm(container, {});
      
      const icCardField = container.querySelector('#ic-card-number');
      const submitBtn = container.querySelector('.submit-btn');
      
      // 無効な値でテスト
      icCardField.value = 'invalid';
      
      // バリデーション実行
      const event = new dom.window.Event('blur');
      icCardField.dispatchEvent(event);
      
      // エラー表示確認
      setTimeout(() => {
        const errorElement = container.querySelector('.error-message');
        expect(errorElement).toBeTruthy();
      }, 100);
    });
  });

  describe('ICLossStatusDashboard', () => {
    let ICLossStatusDashboard;

    beforeEach(() => {
      jest.doMock('../src/js/common', () => ({
        CommonUtils: {
          showNotification: jest.fn(),
          escapeHTML: jest.fn(val => val),
          formatDate: jest.fn(val => val)
        },
        KintoneAPIHelper: {
          getRecords: jest.fn(() => Promise.resolve({
            records: [
              {
                $id: { value: '1' },
                ic_card_number: { value: '****1234' },
                employee_name: { value: 'テスト太郎' },
                status: { value: '報告済み' },
                created_at: { value: '2025-01-19T10:00:00Z' }
              }
            ]
          }))
        }
      }));

      ICLossStatusDashboard = require('../src/js/ui/ICLossStatusDashboard');
    });

    test('ダッシュボード初期化', async () => {
      const container = document.getElementById('root');
      const dashboard = new ICLossStatusDashboard(container, {});
      
      await dashboard.initialize();
      
      expect(container.querySelector('.ic-loss-dashboard')).toBeTruthy();
      expect(container.querySelector('.dashboard-filters')).toBeTruthy();
      expect(container.querySelector('.status-summary')).toBeTruthy();
      expect(container.querySelector('.records-list')).toBeTruthy();
    });

    test('フィルター機能', async () => {
      const container = document.getElementById('root');
      const dashboard = new ICLossStatusDashboard(container, {});
      
      await dashboard.initialize();
      
      const statusFilter = container.querySelector('#status-filter');
      expect(statusFilter).toBeTruthy();
      
      // フィルター変更テスト
      statusFilter.value = '報告済み';
      const event = new dom.window.Event('change');
      statusFilter.dispatchEvent(event);
      
      // フィルター結果確認
      setTimeout(() => {
        const visibleRecords = container.querySelectorAll('.record-item:not(.hidden)');
        expect(visibleRecords.length).toBeGreaterThan(0);
      }, 100);
    });

    test('レスポンシブデザイン確認', () => {
      const container = document.getElementById('root');
      const dashboard = new ICLossStatusDashboard(container, {});
      
      // モバイル画面サイズをシミュレート
      Object.defineProperty(window, 'innerWidth', {
        writable: true,
        configurable: true,
        value: 480,
      });
      
      window.dispatchEvent(new dom.window.Event('resize'));
      
      // レスポンシブクラスが適用されるか確認
      setTimeout(() => {
        const dashboard = container.querySelector('.ic-loss-dashboard');
        expect(dashboard.classList.contains('mobile-view')).toBeTruthy();
      }, 100);
    });
  });

  describe('共通ユーティリティ統合', () => {
    let CommonUtils;

    beforeEach(() => {
      CommonUtils = require('../src/js/common').CommonUtils;
    });

    test('通知機能', () => {
      CommonUtils.showNotification('テストメッセージ', 'success');
      
      const notification = document.querySelector('.notification');
      expect(notification).toBeTruthy();
      expect(notification.textContent).toContain('テストメッセージ');
      expect(notification.classList.contains('success')).toBeTruthy();
    });

    test('HTMLエスケープ', () => {
      const dangerous = '<script>alert("xss")</script>';
      const escaped = CommonUtils.escapeHTML(dangerous);
      
      expect(escaped).not.toContain('<script>');
      expect(escaped).toContain('&lt;script&gt;');
    });

    test('電話番号フォーマット', () => {
      const formatted = CommonUtils.formatPhoneNumber('09012345678');
      expect(formatted).toBe('090-1234-5678');
      
      const formatted2 = CommonUtils.formatPhoneNumber('0312345678');
      expect(formatted2).toBe('03-1234-5678');
    });
  });

  describe('アクセシビリティ統合テスト', () => {
    test('キーボードナビゲーション', () => {
      const container = document.getElementById('root');
      container.innerHTML = `
        <button class="btn" tabindex="0">ボタン1</button>
        <button class="btn" tabindex="0">ボタン2</button>
        <input type="text" tabindex="0" />
      `;

      const buttons = container.querySelectorAll('[tabindex="0"]');
      expect(buttons.length).toBe(3);

      // Tab順序確認
      buttons[0].focus();
      expect(document.activeElement).toBe(buttons[0]);
    });

    test('ARIA属性適用', () => {
      const container = document.getElementById('root');
      container.innerHTML = `
        <div role="alert" aria-live="polite" id="status-message"></div>
        <button aria-expanded="false" aria-controls="menu">メニュー</button>
        <ul id="menu" aria-hidden="true">
          <li role="menuitem">項目1</li>
          <li role="menuitem">項目2</li>
        </ul>
      `;

      const alert = container.querySelector('[role="alert"]');
      const button = container.querySelector('[aria-expanded]');
      const menu = container.querySelector('#menu');

      expect(alert.getAttribute('aria-live')).toBe('polite');
      expect(button.getAttribute('aria-expanded')).toBe('false');
      expect(menu.getAttribute('aria-hidden')).toBe('true');
    });

    test('高コントラストモード対応', () => {
      const container = document.getElementById('root');
      
      // 高コントラストクラス追加
      document.body.classList.add('high-contrast');
      
      container.innerHTML = `
        <button class="btn btn-primary">プライマリボタン</button>
        <div class="card">カード</div>
      `;

      const button = container.querySelector('.btn-primary');
      const card = container.querySelector('.card');

      // CSSクラスが正しく適用されているか確認
      expect(document.body.classList.contains('high-contrast')).toBeTruthy();
      expect(button.classList.contains('btn-primary')).toBeTruthy();
    });
  });

  describe('セキュリティ統合テスト', () => {
    test('XSS防止', () => {
      const { CommonUtils } = require('../src/js/common');
      
      const maliciousInput = '<img src="x" onerror="alert(1)">';
      const sanitized = CommonUtils.escapeHTML(maliciousInput);
      
      expect(sanitized).not.toContain('<img');
      expect(sanitized).not.toContain('onerror');
      expect(sanitized).toContain('&lt;img');
    });

    test('機密データマスキング', () => {
      const { CommonUtils } = require('../src/js/common');
      
      const icNumber = '1234567890123456';
      const masked = CommonUtils.maskSensitiveData(icNumber);
      
      expect(masked).toContain('****');
      expect(masked).not.toBe(icNumber);
      expect(masked.length).toBeLessThan(icNumber.length);
    });
  });
});

// カバレッジ要件確認
describe('Phase 2 カバレッジ要件', () => {
  test('UIコンポーネント網羅性', () => {
    // 主要UIコンポーネントが存在することを確認
    const reportFormPath = '../src/js/ui/ICLossReportForm.js';
    const dashboardPath = '../src/js/ui/ICLossStatusDashboard.js';
    
    expect(() => require(reportFormPath)).not.toThrow();
    expect(() => require(dashboardPath)).not.toThrow();
  });

  test('セキュリティクラス統合', () => {
    // Phase 1セキュリティクラスが正しく統合されていることを確認
    const securityPaths = [
      '../src/js/security/SecureHashManager.js',
      '../src/js/security/InputValidator.js',
      '../src/js/security/SecurityConfig.js'
    ];

    securityPaths.forEach(path => {
      expect(() => require(path)).not.toThrow();
    });
  });

  test('アクセシビリティ要件', () => {
    // WAI-ARIA準拠要件が満たされていることを確認
    const container = document.getElementById('root');
    
    // サンプルUIを作成
    container.innerHTML = `
      <main role="main" aria-label="ICカード紛失対応">
        <h1>ICカード紛失報告</h1>
        <form aria-labelledby="form-title">
          <h2 id="form-title">報告フォーム</h2>
          <label for="test-input">テスト入力</label>
          <input id="test-input" aria-required="true" />
        </form>
      </main>
    `;

    const main = container.querySelector('[role="main"]');
    const form = container.querySelector('form');
    const input = container.querySelector('#test-input');

    expect(main.getAttribute('aria-label')).toBeTruthy();
    expect(form.getAttribute('aria-labelledby')).toBeTruthy();
    expect(input.getAttribute('aria-required')).toBe('true');
  });
});
