# 🔐 Kintone 交通系ICカード紛失対応プラグイン

[![Security](https://img.shields.io/badge/Security-IPA%20Compliant-green.svg)](docs/ipa-guidelines/)
[![Version](https://img.shields.io/badge/Version-1.0.0-blue.svg)](package.json)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**プロジェクト名**: kintone-ic-loss-plugin  
**開発者**: Kei-Adachi0709  
**作成日**: 2025-06-17

## 概要
交通系ICカードや社員証の紛失時に迅速な対応を支援するKintoneプラグイン

## 開発参考資料
- [安全なウェブサイトの作り方 - IPA](docs/ipa-guidelines/安全なウェブサイトの作り方.pdf)
- [安全なSQLの呼び出し方 - IPA](docs/ipa-guidelines/安全なSQLの呼び出し方.pdf)

### 開発者向け
上記PDFを `docs/ipa-guidelines/` フォルダに配置してから開発を開始してください。

## 開発ステータス
- [x] **Phase 1: プロジェクト初期化とセキュリティ基盤構築** ✅ **完了**
  - [x] プロジェクトフォルダ作成・Git初期化
  - [x] IPAガイドライン準拠セキュアハッシュ化クラス実装
  - [x] PDF章節1-4準拠入力値検証クラス実装  
  - [x] セキュリティ設定クラス実装
  - [x] 包括的セキュリティテストスイート実装
  - [x] GitHubリポジトリ初回プッシュ完了
- [ ] Phase 2: Kintoneプラグイン基本構造とUI実装
- [ ] Phase 3: 交通機関データベースと定型文システム実装
- [ ] Phase 4: 紛失時緊急対応機能とKintone連携実装
- [ ] Phase 5: フォローアップ機能と通知システム実装
- [ ] Phase 6: テスト実装・最適化・デプロイメント準備

## IPAセキュリティガイドライン準拠
本プロジェクトは以下のIPAガイドラインに準拠して開発されます：
- SQLインジェクション対策
- 入力値検証
- 重要情報の保護
- 重要な処理での再認証
- ログ出力対策

## 開発環境
- Node.js v16以上
- VS Code with GitHub Copilot
- Kintone開発環境
EOF