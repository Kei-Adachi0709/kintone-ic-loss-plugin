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
  testEnvironment: 'node',
  
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
      displayName: 'Unit Tests',
      testMatch: ['<rootDir>/tests/unit/**/*.js'],
      testEnvironment: 'node'
    },
    {
      displayName: 'Integration Tests',
      testMatch: ['<rootDir>/tests/integration/**/*.js'],
      testEnvironment: 'node'
    }
  ]
};
