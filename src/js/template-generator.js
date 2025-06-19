/**
 * Kintone ICカード紛失対応プラグイン - 定型文生成クラス
 * 自動化された定型文生成とテンプレート管理（Phase 3統合版）
 * IPA安全なプログラム作成 - XSS対策・ファイル操作・入力検証 準拠
 * 
 * @version 3.0.0
 * @author Kintone ICカード紛失対応チーム
 */

import { InputValidator } from './security/input-validator.js';
import { Logger } from './common/logger.js';
import { DataValidator } from './data-validator.js';

/**
 * 定型文生成クラス
 * ICカード紛失報告書の自動生成とテンプレート管理
 * IPA章節1-1, 1-2: 入力検証・XSS対策・セキュアなテンプレート処理
 */
export class TemplateGenerator {
    /**
     * コンストラクタ
     */
    constructor() {
        this.inputValidator = new InputValidator();
        this.dataValidator = new DataValidator();
        this.logger = new Logger('TemplateGenerator');
        
        // テンプレート定義（XSS対策済み）
        this.templates = {
            // 基本的な紛失報告書
            lossReport: {
                title: 'ICカード紛失届',
                sections: [
                    {
                        name: 'basic_info',
                        title: '基本情報',
                        fields: ['reportDate', 'employeeId', 'employeeName', 'department', 'email', 'phoneNumber']
                    },
                    {
                        name: 'card_info',
                        title: 'ICカード情報',
                        fields: ['icCardNumber', 'cardType', 'issuerName', 'lastUsedDate']
                    },
                    {
                        name: 'loss_details',
                        title: '紛失詳細',
                        fields: ['lossDate', 'lossTime', 'lossLocation', 'circumstances', 'searchEfforts']
                    },
                    {
                        name: 'transportation',
                        title: '交通機関対応',
                        fields: ['transportationProvider', 'contactNumber', 'reportedToProvider', 'providerReferenceNumber']
                    },
                    {
                        name: 'next_steps',
                        title: '今後の対応',
                        fields: ['replacementRequired', 'temporaryMeasures', 'preventiveMeasures']
                    }
                ],
                format: 'formal'
            },
            
            // 簡易報告書
            quickReport: {
                title: 'ICカード紛失簡易報告',
                sections: [
                    {
                        name: 'essential_info',
                        title: '必須情報',
                        fields: ['reportDate', 'employeeName', 'icCardNumber', 'lossDate', 'lossLocation']
                    }
                ],
                format: 'simple'
            },
            
            // 交通機関向け報告書
            transportationReport: {
                title: '交通機関向けICカード紛失通知',
                sections: [
                    {
                        name: 'card_details',
                        title: 'カード詳細',
                        fields: ['icCardNumber', 'cardType', 'holderName', 'lossDate', 'lossLocation']
                    },
                    {
                        name: 'contact_info',
                        title: '連絡先',
                        fields: ['employeeName', 'phoneNumber', 'email', 'companyName']
                    }
                ],
                format: 'external'
            },
            
            // 上司向け報告書
            supervisorReport: {
                title: '上司向けICカード紛失報告',
                sections: [
                    {
                        name: 'summary',
                        title: '概要',
                        fields: ['employeeName', 'department', 'lossDate', 'icCardNumber', 'impactAssessment']
                    },
                    {
                        name: 'actions_taken',
                        title: '実施済み対応',
                        fields: ['immediateActions', 'providerNotification', 'securityMeasures']
                    },
                    {
                        name: 'next_actions',
                        title: '今後の対応予定',
                        fields: ['replacementProcess', 'preventiveMeasures', 'followUpSchedule']
                    }
                ],
                format: 'internal'
            }
        };
        
        // フィールドラベル定義（日本語）
        this.fieldLabels = {
            // 基本情報
            reportDate: '報告日',
            employeeId: '従業員ID',
            employeeName: '氏名',
            department: '所属部署',
            email: 'メールアドレス',
            phoneNumber: '電話番号',
            companyName: '会社名',
            
            // ICカード情報
            icCardNumber: 'ICカード番号',
            cardType: 'カード種別',
            issuerName: '発行会社',
            lastUsedDate: '最終利用日',
            holderName: 'カード名義',
            
            // 紛失詳細
            lossDate: '紛失日',
            lossTime: '紛失時刻',
            lossLocation: '紛失場所',
            circumstances: '紛失状況',
            searchEfforts: '捜索状況',
            
            // 交通機関関連
            transportationProvider: '交通機関名',
            contactNumber: '連絡先電話番号',
            reportedToProvider: '交通機関への報告済み',
            providerReferenceNumber: '交通機関管理番号',
            
            // 対応関連
            replacementRequired: '再発行要否',
            temporaryMeasures: '暫定対応',
            preventiveMeasures: '再発防止策',
            impactAssessment: '影響評価',
            immediateActions: '即時対応',
            providerNotification: '事業者通知',
            securityMeasures: 'セキュリティ対策',
            replacementProcess: '再発行手続き',
            followUpSchedule: 'フォローアップ予定'
        };
        
        // デフォルト値
        this.defaultValues = {
            reportDate: () => new Date().toISOString().split('T')[0],
            reportedToProvider: 'いいえ',
            replacementRequired: 'はい',
            companyName: '株式会社サンプル' // 実際の会社名に置き換え
        };
        
        // 生成統計
        this.stats = {
            templatesGenerated: 0,
            lastGeneration: null,
            templateTypes: {},
            errors: 0
        };
        
        this.logger.info('TemplateGenerator initialized with security-compliant templates');
    }
    
    /**
     * 定型文の生成
     * @param {string} templateType - テンプレートタイプ
     * @param {Object} data - データオブジェクト
     * @param {Object} options - 生成オプション
     * @returns {Object} 生成結果
     */
    generateTemplate(templateType, data, options = {}) {
        try {
            this.stats.templatesGenerated++;
            this.stats.lastGeneration = new Date();
            
            // テンプレート存在確認
            const template = this.templates[templateType];
            if (!template) {
                this.stats.errors++;
                return {
                    success: false,
                    error: 'TEMPLATE_NOT_FOUND',
                    message: `テンプレート '${templateType}' が見つかりません`
                };
            }
            
            // データ検証
            const validationResult = this.validateTemplateData(data, template);
            if (!validationResult.valid) {
                this.stats.errors++;
                return {
                    success: false,
                    error: 'DATA_VALIDATION_FAILED',
                    message: 'データ検証に失敗しました',
                    validationErrors: validationResult.errors
                };
            }
            
            // XSS対策：データのサニタイズ
            const sanitizedData = this.sanitizeTemplateData(validationResult.sanitizedData);
            
            // テンプレート生成
            const generatedTemplate = this.buildTemplate(template, sanitizedData, options);
            
            // 統計更新
            if (!this.stats.templateTypes[templateType]) {
                this.stats.templateTypes[templateType] = 0;
            }
            this.stats.templateTypes[templateType]++;
            
            this.logger.info('Template generated successfully', {
                type: templateType,
                sections: template.sections.length,
                dataFields: Object.keys(sanitizedData).length
            });
            
            return {
                success: true,
                templateType,
                title: template.title,
                content: generatedTemplate,
                metadata: {
                    generatedAt: new Date().toISOString(),
                    templateVersion: '3.0.0',
                    dataFields: Object.keys(sanitizedData).length,
                    securityLevel: 'HIGH'
                }
            };
            
        } catch (error) {
            this.stats.errors++;
            this.logger.error('Template generation error', { templateType, error });
            
            return {
                success: false,
                error: 'GENERATION_ERROR',
                message: 'テンプレート生成中にエラーが発生しました'
            };
        }
    }
    
    /**
     * テンプレートデータの検証
     * @param {Object} data - 検証対象データ
     * @param {Object} template - テンプレート定義
     * @returns {Object} 検証結果
     */
    validateTemplateData(data, template) {
        try {
            // 必要なフィールドを収集
            const requiredFields = [];
            for (const section of template.sections) {
                requiredFields.push(...section.fields);
            }
            
            // データ検証
            return this.dataValidator.validateObject(data, requiredFields);
            
        } catch (error) {
            this.logger.error('Template data validation error', error);
            return {
                valid: false,
                errors: [{
                    error: 'VALIDATION_ERROR',
                    message: 'データ検証中にエラーが発生しました'
                }]
            };
        }
    }
    
    /**
     * テンプレートデータのサニタイズ（XSS対策）
     * @param {Object} data - サニタイズ対象データ
     * @returns {Object} サニタイズされたデータ
     */
    sanitizeTemplateData(data) {
        const sanitized = {};
        
        for (const [key, value] of Object.entries(data)) {
            if (typeof value === 'string') {
                // HTMLエスケープ
                sanitized[key] = this.inputValidator.sanitizeString(value)
                    .replace(/&/g, '&amp;')
                    .replace(/</g, '&lt;')
                    .replace(/>/g, '&gt;')
                    .replace(/"/g, '&quot;')
                    .replace(/'/g, '&#x27;')
                    .replace(/\//g, '&#x2F;');
            } else {
                sanitized[key] = value;
            }
        }
        
        return sanitized;
    }
    
    /**
     * テンプレートの構築
     * @param {Object} template - テンプレート定義
     * @param {Object} data - データ
     * @param {Object} options - オプション
     * @returns {string} 構築されたテンプレート
     */
    buildTemplate(template, data, options) {
        try {
            let content = '';
            
            // ヘッダー
            content += this.buildHeader(template, options);
            
            // セクション構築
            for (const section of template.sections) {
                content += this.buildSection(section, data, template.format);
            }
            
            // フッター
            content += this.buildFooter(template, options);
            
            return content;
            
        } catch (error) {
            this.logger.error('Template building error', error);
            return 'テンプレート構築中にエラーが発生しました。';
        }
    }
    
    /**
     * テンプレートヘッダーの構築
     * @param {Object} template - テンプレート定義
     * @param {Object} options - オプション
     * @returns {string} ヘッダー
     */
    buildHeader(template, options) {
        const currentDate = new Date().toLocaleDateString('ja-JP');
        
        let header = '';
        header += `${template.title}\n`;
        header += `${'='.repeat(template.title.length)}\n\n`;
        header += `作成日: ${currentDate}\n`;
        
        if (options.documentNumber) {
            header += `文書番号: ${this.inputValidator.sanitizeString(options.documentNumber)}\n`;
        }
        
        header += '\n';
        
        return header;
    }
    
    /**
     * セクションの構築
     * @param {Object} section - セクション定義
     * @param {Object} data - データ
     * @param {string} format - フォーマット
     * @returns {string} セクション
     */
    buildSection(section, data, format) {
        let sectionContent = '';
        
        // セクションタイトル
        sectionContent += `## ${section.title}\n\n`;
        
        // フィールド処理
        for (const fieldName of section.fields) {
            const label = this.fieldLabels[fieldName] || fieldName;
            let value = data[fieldName];
            
            // デフォルト値の適用
            if ((value === undefined || value === null || value === '') && this.defaultValues[fieldName]) {
                if (typeof this.defaultValues[fieldName] === 'function') {
                    value = this.defaultValues[fieldName]();
                } else {
                    value = this.defaultValues[fieldName];
                }
            }
            
            // 値のフォーマット
            const formattedValue = this.formatFieldValue(fieldName, value, format);
            
            if (format === 'formal') {
                sectionContent += `**${label}**: ${formattedValue}\n\n`;
            } else if (format === 'simple') {
                sectionContent += `${label}: ${formattedValue}\n`;
            } else {
                sectionContent += `- ${label}: ${formattedValue}\n`;
            }
        }
        
        sectionContent += '\n';
        
        return sectionContent;
    }
    
    /**
     * フィールド値のフォーマット
     * @param {string} fieldName - フィールド名
     * @param {any} value - 値
     * @param {string} format - フォーマット
     * @returns {string} フォーマットされた値
     */
    formatFieldValue(fieldName, value, format) {
        if (value === undefined || value === null) {
            return '（未入力）';
        }
        
        const stringValue = String(value);
        
        // 特殊フィールドの処理
        switch (fieldName) {
            case 'icCardNumber':
                // ICカード番号のマスキング
                return this.maskCardNumber(stringValue);
                
            case 'lossDate':
                // 日付フォーマット
                try {
                    const date = new Date(stringValue);
                    return date.toLocaleDateString('ja-JP');
                } catch {
                    return stringValue;
                }
                
            case 'reportedToProvider':
            case 'replacementRequired':
                // Yes/No値の日本語化
                return stringValue.toLowerCase() === 'yes' || stringValue === 'はい' ? 'はい' : 'いいえ';
                
            default:
                return stringValue || '（未入力）';
        }
    }
    
    /**
     * ICカード番号のマスキング
     * @param {string} cardNumber - カード番号
     * @returns {string} マスキングされた番号
     */
    maskCardNumber(cardNumber) {
        if (!cardNumber || cardNumber.length < 4) {
            return '****';
        }
        
        const firstFour = cardNumber.substring(0, 4);
        const lastFour = cardNumber.substring(cardNumber.length - 4);
        const middle = '*'.repeat(Math.max(0, cardNumber.length - 8));
        
        return `${firstFour}${middle}${lastFour}`;
    }
    
    /**
     * テンプレートフッターの構築
     * @param {Object} template - テンプレート定義
     * @param {Object} options - オプション
     * @returns {string} フッター
     */
    buildFooter(template, options) {
        let footer = '\n---\n\n';
        footer += '本書は自動生成されたドキュメントです。\n';
        footer += '内容に不備がある場合は、システム管理者にご連絡ください。\n\n';
        
        if (options.includeSecurityNotice) {
            footer += '【セキュリティ注意事項】\n';
            footer += '- 本文書には個人情報が含まれています\n';
            footer += '- 取り扱いには十分注意してください\n';
            footer += '- 不要になった際は適切に廃棄してください\n\n';
        }
        
        footer += `生成システム: Kintone ICカード紛失対応プラグイン v3.0.0\n`;
        footer += `生成日時: ${new Date().toLocaleString('ja-JP')}\n`;
        
        return footer;
    }
    
    /**
     * 利用可能なテンプレート一覧の取得
     * @returns {Array} テンプレート一覧
     */
    getAvailableTemplates() {
        return Object.keys(this.templates).map(key => ({
            key,
            title: this.templates[key].title,
            format: this.templates[key].format,
            sections: this.templates[key].sections.length
        }));
    }
    
    /**
     * テンプレートのプレビュー生成
     * @param {string} templateType - テンプレートタイプ
     * @returns {Object} プレビュー結果
     */
    generatePreview(templateType) {
        try {
            const template = this.templates[templateType];
            if (!template) {
                return {
                    success: false,
                    error: 'テンプレートが見つかりません'
                };
            }
            
            // サンプルデータの生成
            const sampleData = this.generateSampleData(template);
            
            // プレビュー生成
            const preview = this.generateTemplate(templateType, sampleData, {
                documentNumber: 'SAMPLE-001',
                includeSecurityNotice: true
            });
            
            return {
                success: true,
                preview: preview.content,
                sampleData
            };
            
        } catch (error) {
            this.logger.error('Preview generation error', error);
            return {
                success: false,
                error: 'プレビュー生成中にエラーが発生しました'
            };
        }
    }
    
    /**
     * サンプルデータの生成
     * @param {Object} template - テンプレート定義
     * @returns {Object} サンプルデータ
     */
    generateSampleData(template) {
        const sampleData = {
            reportDate: '2024-01-15',
            employeeId: 'EMP001',
            employeeName: '山田太郎',
            department: '総務部',
            email: 'yamada@example.com',
            phoneNumber: '03-1234-5678',
            icCardNumber: '1234567890123456',
            cardType: 'MANACA',
            issuerName: '名古屋市交通局',
            lossDate: '2024-01-14',
            lossTime: '09:30',
            lossLocation: '名古屋駅',
            circumstances: '通勤時に紛失',
            transportationProvider: '名古屋市営地下鉄',
            contactNumber: '052-123-4567'
        };
        
        return sampleData;
    }
    
    /**
     * 生成統計の取得
     * @returns {Object} 統計情報
     */
    getGenerationStats() {
        return {
            ...this.stats,
            successRate: this.stats.templatesGenerated > 0 ? 
                ((this.stats.templatesGenerated - this.stats.errors) / this.stats.templatesGenerated * 100).toFixed(2) + '%' : '0%'
        };
    }
    
    /**
     * 統計のリセット
     */
    resetStats() {
        this.stats = {
            templatesGenerated: 0,
            lastGeneration: null,
            templateTypes: {},
            errors: 0
        };
        
        this.logger.info('Template generation statistics reset');
    }
}

// デフォルトエクスポート
export default TemplateGenerator;
