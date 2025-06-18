/**
 * jest.config.js
 * Jest設定ファイル - IPAガイドライン準拠セキュリティテスト用
 * 
 * @author Kei-Adachi0709
 * @version 1.0.0
 * @date 2025-06-19
 */

module.exports = {
  // テスト環境
  testEnvironment: 'jsdom',
  
  // テストファイルのパターン
  testMatch: [
    '**/tests/**/*.test.js',
    '**/tests/**/*.spec.js',
    '**/tests/**/*-test.js'
  ],
  
  // カバレッジ設定
  collectCoverageFrom: [
    'src/**/*.js',
    '!src/**/*.test.js',
    '!src/**/*.spec.js'
  ],
  
  // カバレッジ出力ディレクトリ
  coverageDirectory: 'coverage',
  
  // カバレッジレポート形式
  coverageReporters: [
    'text',
    'lcov',
    'html'
  ],
  
  // セットアップファイル
  setupFilesAfterEnv: ['<rootDir>/tests/setup.js'],
  
  // モジュール解決
  moduleFileExtensions: ['js', 'json'],
  
  // テストタイムアウト
  testTimeout: 30000,
  
  // 詳細出力
  verbose: true,
  
  // セキュリティテスト用設定
  projects: [
    {
      displayName: 'Security Tests',
      testMatch: ['<rootDir>/tests/security/**/*.js'],
      testEnvironment: 'node'
    },
    {
      displayName: 'UI Integration Tests',
      testMatch: ['<rootDir>/tests/ui/**/*.js'],
      testEnvironment: 'jsdom'
    },
    {
      displayName: 'Unit Tests',
      testMatch: ['<rootDir>/tests/unit/**/*.js'],
      testEnvironment: 'node'
    }
  ],
  
  // カバレッジ閾値
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80, 
      lines: 80,      statements: 80
    },
    './src/js/security/': {
      branches: 90,
      functions: 90,
      lines: 90,
      statements: 90
    }
  }
};
