# 🔐 Kintone ICカード紛失対応プラグイン

[![Security](https://img.shields.io/badge/Security-IPA%20Compliant-green.svg)](docs/ipa-guidelines/)
[![Version](https://img.shields.io/badge/Version-1.0.0-blue.svg)](package.json)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Phase](https://img.shields.io/badge/Phase-2%20完了-brightgreen.svg)]()

**プロジェクト名**: kintone-ic-loss-plugin  
**開発者**: Kei-Adachi0709  
**作成日**: 2025-06-19  
**Phase 2完了日**: 2025-06-19

## 📋 プロジェクト概要

交通系ICカードや社員証等の紛失時緊急対応を支援するKintone プラグインです。IPAセキュリティガイドライン準拠により、安全で実用的な業務システムを提供します。

## 🎯 主要機能

### Phase 1 完了機能 ✅
- **セキュリティクラス**: IPA準拠の暗号化、バリデーション、設定管理
- **セキュリティテスト**: 包括的なセキュリティ検証テストスイート  
- **基盤構築**: Git管理、CI/CD準備、コード品質管理

### Phase 2 完了機能 ✅
- **管理画面**: プラグイン設定UI、セキュリティパラメータ管理
- **メインUI**: ICカード紛失報告フォーム、状況ダッシュボード
- **アクセシビリティ**: WAI-ARIA準拠、レスポンシブデザイン、高コントラスト対応
- **UIテスト**: 統合テスト、セキュリティ検証、アクセシビリティ検証

### Phase 3 予定機能 🚧
- **Kintone統合**: 完全なプラグイン統合とデプロイ
- **ワークフロー**: 承認フロー、自動通知、レポート機能
- **運用機能**: ログ管理、監査証跡、バックアップ機能

## 🛡️ セキュリティ機能

### IPAガイドライン準拠
- **入力値検証**: SQLインジェクション、XSS攻撃防止
- **暗号化**: PBKDF2による堅牢なハッシュ化
- **アクセス制御**: 権限ベースアクセス制御
- **ログ管理**: セキュリティイベント記録

### データ保護
- **機密データマスキング**: ICカード番号等の部分表示
- **セキュアストレージ**: 設定情報の暗号化保存
- **監査証跡**: 全操作の詳細ログ記録

## 🚀 技術スタック

### フロントエンド
- **JavaScript ES6+**: モダンJavaScript、クラスベース設計
- **CSS3**: レスポンシブデザイン、アクセシビリティ対応
- **Webpack**: モジュールバンドリング、最適化
- **Babel**: ブラウザ互換性確保

### テスト・品質管理
- **Jest**: ユニットテスト、統合テスト
- **JSDOM**: UI統合テスト環境
- **ESLint**: コード品質管理
- **カバレッジ**: 80%以上のテストカバレッジ

### セキュリティライブラリ
- **crypto-js**: 暗号化処理
- **カスタムバリデーター**: IPA準拠検証ロジック

## 📦 プロジェクト構造

```
kintone-ic-loss-plugin/
├── src/
│   ├── js/
│   │   ├── security/          # Phase 1: セキュリティクラス
│   │   │   ├── SecureHashManager.js
│   │   │   ├── InputValidator.js
│   │   │   └── SecurityConfig.js
│   │   ├── ui/                # Phase 2: UIコンポーネント
│   │   │   ├── ICLossReportForm.js
│   │   │   └── ICLossStatusDashboard.js
│   │   ├── config/            # Phase 2: 管理画面
│   │   │   └── config.js
│   │   ├── common.js          # Phase 2: 共通ユーティリティ
│   │   └── desktop.js         # Phase 2: メイン機能
│   ├── css/                   # Phase 2: スタイル
│   │   ├── config.css
│   │   ├── desktop.css
│   │   └── ui-components.css
│   └── html/                  # Phase 2: HTML
│       └── config.html
├── tests/
│   ├── security/              # Phase 1: セキュリティテスト
│   │   ├── security-test.js
│   │   └── security-integration.test.js
│   ├── ui/                    # Phase 2: UI統合テスト
│   │   └── ui-integration.test.js
│   └── setup.js
├── docs/
│   └── ipa-guidelines/        # IPAガイドライン資料
├── manifest.json              # Kintone プラグイン設定
├── package.json
├── webpack.config.js          # Phase 2: ビルド設定
├── jest.config.js             # Phase 2: テスト設定
├── .eslintrc.json             # Phase 2: コード品質
└── .babelrc                   # Phase 2: JS変換設定
```

## 🔧 開発環境セットアップ

### 前提条件
- Node.js 16.0.0以上
- npm 8.0.0以上

### インストール手順

```bash
# プロジェクトクローン
git clone https://github.com/Kei-Adachi0709/kintone-ic-loss-plugin.git
cd kintone-ic-loss-plugin

# 依存関係インストール
npm install

# 開発環境起動
npm run dev

# ビルド実行
npm run build

# テスト実行
npm test
npm run test:security
npm run test:coverage
```

## 🧪 テスト実行

### 全体テスト
```bash
npm test                    # 全テスト実行
npm run test:coverage      # カバレッジ付きテスト
```

### 分類別テスト
```bash
npm run test:security      # セキュリティテストのみ
npm run test:ui           # UI統合テストのみ
```

### コード品質
```bash
npm run lint              # ESLint実行
npm run lint:fix          # ESLint自動修正
```

## 📋 Phase 2 実装完了内容

### ✅ 管理画面 (config.html/css/js)
- セキュリティパラメータ設定UI
- リアルタイムバリデーション
- アクセシビリティ対応フォーム

### ✅ メインUI (desktop.js)
- ICカード紛失報告機能
- 状況確認ダッシュボード
- 緊急報告ダイアログ
- Phase 1セキュリティクラス統合

### ✅ UIコンポーネント
- **ICLossReportForm**: 多段階報告フォーム
- **ICLossStatusDashboard**: フィルター付きダッシュボード

### ✅ 共通機能 (common.js)
- セキュリティユーティリティ
- バリデーションヘルパー
- アクセシビリティサポート
- Kintone API統合

### ✅ スタイル (CSS)
- レスポンシブデザイン
- ダークモード対応
- 高コントラストテーマ
- モバイル最適化

### ✅ ビルド・テスト環境
- Webpack設定 (webpack.config.js)
- Jest設定 (jest.config.js)
- ESLint設定 (.eslintrc.json)
- Babel設定 (.babelrc)

### ✅ UI統合テスト
- コンポーネント統合テスト
- アクセシビリティ検証
- セキュリティ統合検証
- レスポンシブデザイン検証

## 🎯 次のステップ (Phase 3)

1. **Kintone完全統合**
   - プラグインパッケージング
   - デプロイメント自動化
   - 本番環境テスト

2. **ワークフロー実装**
   - 承認フロー機能
   - 自動通知システム
   - レポート生成機能

3. **運用機能強化**
   - ログ管理システム
   - 監査証跡機能
   - バックアップ機能

## 📈 品質指標

### テストカバレッジ目標
- **全体**: 80%以上
- **セキュリティクラス**: 90%以上
- **UIコンポーネント**: 85%以上

### アクセシビリティ基準
- **WCAG 2.1 AA準拠**
- **キーボード操作完全対応**
- **スクリーンリーダー対応**
- **高コントラスト対応**

## 📞 連絡先

- **開発者**: Kei-Adachi0709
- **Email**: kei.adachi0709@example.com
- **GitHub**: https://github.com/Kei-Adachi0709/kintone-ic-loss-plugin

## 📄 ライセンス

MIT License - 詳細は [LICENSE](LICENSE) ファイルを参照してください。

---

**🚀 Phase 2 実装完了！次はKintone完全統合のPhase 3へ進みます。**
