/**
 * setup.js
 * Jest テストセットアップファイル
 * 
 * @author Kei-Adachi0709
 * @version 1.0.0
 * @date 2025-06-19
 */

// グローバルテスト設定
global.console = {
  ...console,
  // ログ出力制御 (テスト時は簡潔に)
  log: jest.fn(),
  debug: jest.fn(),
  info: jest.fn(),
  warn: console.warn,
  error: console.error,
};

// セキュリティテスト用のモック設定
global.mockKintoneAPI = {
  app: {
    getId: () => 1,
    getConfig: () => ({
      security_pepper: 'test_pepper_value',
      admin_email: 'admin@example.com'
    })
  },
  api: jest.fn()
};

// Kintone APIのモック (テスト環境用)
if (typeof kintone === 'undefined') {
  global.kintone = global.mockKintoneAPI;
}

// Performance API のモック (Node.js環境用)
if (typeof performance === 'undefined') {
  global.performance = {
    now: () => Date.now()
  };
}

// テスト前の初期化
beforeEach(() => {
  // モックのリセット
  jest.clearAllMocks();
});
