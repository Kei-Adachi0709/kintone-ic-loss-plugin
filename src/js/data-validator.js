/**
 * Kintone ICカード紛失対応プラグイン - 汎用データ検証クラス
 * 全体的なデータ検証とセキュリティチェック（Phase 3統合版）
 * IPA安全なプログラム作成 - 入力データ検証・SQLインジェクション対策 準拠
 * 
 * @version 3.0.0
 * @author Kintone ICカード紛失対応チーム
 */

import { InputValidator } from './security/input-validator.js';
import { SecureHashManager } from './security/hash-manager.js';
import { Logger } from './common/logger.js';

/**
 * 汎用データ検証クラス
 * アプリケーション全体のデータ検証とセキュリティチェックを統合管理
 * IPA章節1-1, 1-3, 1-4: 入力検証・SQLインジェクション・OSコマンドインジェクション対策
 */
export class DataValidator {
    /**
     * コンストラクタ
     */
    constructor() {
        this.inputValidator = new InputValidator();
        this.hashManager = new SecureHashManager();
        this.logger = new Logger('DataValidator');
        
        // 検証ルール定義
        this.validationRules = {
            // 個人情報関連
            employeeId: {
                pattern: /^[A-Za-z0-9]{6,12}$/,
                maxLength: 12,
                required: true,
                sanitize: true,
                description: '従業員ID（英数字6-12桁）'
            },
            
            employeeName: {
                pattern: /^[ぁ-んァ-ヶー一-龠a-zA-Z\s]{1,50}$/,
                maxLength: 50,
                required: true,
                sanitize: true,
                description: '従業員名（日本語・英字、50文字以内）'
            },
            
            department: {
                pattern: /^[ぁ-んァ-ヶー一-龠a-zA-Z0-9\s\-]{1,30}$/,
                maxLength: 30,
                required: true,
                sanitize: true,
                description: '部署名（30文字以内）'
            },
            
            email: {
                pattern: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
                maxLength: 100,
                required: false,
                sanitize: true,
                description: 'メールアドレス'
            },
            
            phoneNumber: {
                pattern: /^[0-9\-\(\)\s]{10,15}$/,
                maxLength: 15,
                required: false,
                sanitize: true,
                description: '電話番号'
            },
            
            // ICカード関連
            icCardNumber: {
                pattern: /^[0-9]{4,20}$/,
                maxLength: 20,
                required: true,
                sanitize: true,
                description: 'ICカード番号（数字4-20桁）'
            },
            
            cardType: {
                pattern: /^(SUICA|PASMO|ICOCA|MANACA|TOICA|SUGOCA|KITACA|HAYAKAKEN|NIMOCA|CORPORATE|STUDENT)$/,
                maxLength: 20,
                required: true,
                sanitize: true,
                description: 'ICカードタイプ'
            },
            
            // 日時関連
            lossDate: {
                pattern: /^\d{4}-\d{2}-\d{2}$/,
                maxLength: 10,
                required: true,
                sanitize: true,
                description: '紛失日（YYYY-MM-DD形式）'
            },
            
            lossTime: {
                pattern: /^([01]?[0-9]|2[0-3]):[0-5][0-9]$/,
                maxLength: 5,
                required: false,
                sanitize: true,
                description: '紛失時刻（HH:MM形式）'
            },
            
            // 位置・場所関連
            lossLocation: {
                pattern: /^[ぁ-んァ-ヶー一-龠a-zA-Z0-9\s\-\(\)]{1,100}$/,
                maxLength: 100,
                required: true,
                sanitize: true,
                description: '紛失場所（100文字以内）'
            },
            
            transportationProvider: {
                pattern: /^[ぁ-んァ-ヶー一-龠a-zA-Z0-9\s\-]{1,50}$/,
                maxLength: 50,
                required: false,
                sanitize: true,
                description: '交通機関名（50文字以内）'
            },
            
            // 状態・プロセス関連
            reportStatus: {
                pattern: /^(DRAFT|SUBMITTED|PROCESSING|COMPLETED|CANCELLED)$/,
                maxLength: 20,
                required: true,
                sanitize: true,
                description: '報告ステータス'
            },
            
            priority: {
                pattern: /^(LOW|MEDIUM|HIGH|URGENT)$/,
                maxLength: 10,
                required: false,
                sanitize: true,
                description: '優先度'
            },
            
            // 自由入力フィールド
            description: {
                pattern: null, // 自由入力
                maxLength: 500,
                required: false,
                sanitize: true,
                description: '詳細説明（500文字以内）'
            },
            
            notes: {
                pattern: null, // 自由入力
                maxLength: 1000,
                required: false,
                sanitize: true,
                description: '備考（1000文字以内）'
            }
        };
        
        // SQLインジェクション危険パターン（IPA 1-3）
        this.sqlInjectionPatterns = [
            /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)/i,
            /(\-\-|\#|\/\*|\*\/)/,
            /(\b(OR|AND)\b.*=.*(\b(OR|AND)\b|$))/i,
            /(\'|\").*(\bOR\b|\bAND\b).*(\1)/i,
            /(\b(SCRIPT|JAVASCRIPT|VBSCRIPT)\b)/i
        ];
        
        // OSコマンドインジェクション危険パターン（IPA 1-4）
        this.osCommandPatterns = [
            /(\||;|&|`|\$\(|\$\{)/,
            /(\b(rm|del|format|mkdir|rmdir|copy|move|exec|eval|system|shell_exec)\b)/i,
            /(\.\.\/|\.\.\\)/,
            /(\b(sudo|su|chmod|chown)\b)/i
        ];
        
        // XSS危険パターン
        this.xssPatterns = [
            /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
            /<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi,
            /javascript:/gi,
            /on\w+\s*=/gi,
            /<\s*(object|embed|applet|meta)\b/gi
        ];
        
        // 検証統計
        this.stats = {
            totalValidations: 0,
            successfulValidations: 0,
            failedValidations: 0,
            securityViolations: 0,
            lastValidation: null,
            violationTypes: {
                sqlInjection: 0,
                osCommand: 0,
                xss: 0,
                invalidFormat: 0,
                excessiveLength: 0
            }
        };
        
        this.logger.info('DataValidator initialized with comprehensive security rules');
    }
    
    /**
     * フィールドデータの包括的検証
     * @param {string} fieldName - フィールド名
     * @param {any} value - 検証する値
     * @param {Object} options - 追加オプション
     * @returns {Object} 検証結果
     */
    validateField(fieldName, value, options = {}) {
        try {
            this.stats.totalValidations++;
            this.stats.lastValidation = new Date();
            
            const rule = this.validationRules[fieldName];
            if (!rule) {
                this.stats.failedValidations++;
                return {
                    valid: false,
                    error: 'UNKNOWN_FIELD',
                    message: `未知のフィールド: ${fieldName}`
                };
            }
            
            // null/undefined チェック
            if (value === null || value === undefined) {
                if (rule.required && !options.allowEmpty) {
                    this.stats.failedValidations++;
                    return {
                        valid: false,
                        error: 'REQUIRED_FIELD',
                        message: `${rule.description}は必須項目です`
                    };
                }
                
                this.stats.successfulValidations++;
                return { valid: true, sanitizedValue: '' };
            }
            
            // 文字列変換
            const stringValue = String(value);
            
            // 基本セキュリティチェック
            const securityCheck = this.performSecurityCheck(stringValue, fieldName);
            if (!securityCheck.safe) {
                this.stats.securityViolations++;
                this.stats.failedValidations++;
                this.logger.warn('Security violation detected', {
                    field: fieldName,
                    violation: securityCheck.violation,
                    value: this.maskSensitiveData(stringValue)
                });
                
                return {
                    valid: false,
                    error: 'SECURITY_VIOLATION',
                    message: `セキュリティ違反: ${securityCheck.message}`,
                    violationType: securityCheck.violation
                };
            }
            
            // 長さチェック
            if (stringValue.length > rule.maxLength) {
                this.stats.violationTypes.excessiveLength++;
                this.stats.failedValidations++;
                return {
                    valid: false,
                    error: 'EXCESSIVE_LENGTH',
                    message: `${rule.description}は${rule.maxLength}文字以内で入力してください`,
                    actualLength: stringValue.length,
                    maxLength: rule.maxLength
                };
            }
            
            // 必須チェック
            if (rule.required && stringValue.trim().length === 0) {
                this.stats.failedValidations++;
                return {
                    valid: false,
                    error: 'REQUIRED_FIELD',
                    message: `${rule.description}は必須項目です`
                };
            }
            
            // パターンマッチング
            if (rule.pattern && stringValue.trim().length > 0) {
                if (!rule.pattern.test(stringValue)) {
                    this.stats.violationTypes.invalidFormat++;
                    this.stats.failedValidations++;
                    return {
                        valid: false,
                        error: 'INVALID_FORMAT',
                        message: `${rule.description}の形式が正しくありません`,
                        expectedFormat: rule.pattern.toString()
                    };
                }
            }
            
            // サニタイゼーション
            let sanitizedValue = stringValue;
            if (rule.sanitize) {
                sanitizedValue = this.inputValidator.sanitizeString(stringValue);
            }
            
            this.stats.successfulValidations++;
            this.logger.debug('Field validation successful', {
                field: fieldName,
                originalLength: stringValue.length,
                sanitizedLength: sanitizedValue.length
            });
            
            return {
                valid: true,
                sanitizedValue,
                originalValue: stringValue,
                rule: rule.description
            };
            
        } catch (error) {
            this.stats.failedValidations++;
            this.logger.error('Field validation error', { fieldName, error });
            
            return {
                valid: false,
                error: 'VALIDATION_ERROR',
                message: '検証中にエラーが発生しました'
            };
        }
    }
    
    /**
     * オブジェクト全体の検証
     * @param {Object} data - 検証対象データ
     * @param {Array} requiredFields - 必須フィールド一覧
     * @returns {Object} 検証結果
     */
    validateObject(data, requiredFields = []) {
        try {
            const results = {
                valid: true,
                errors: [],
                sanitizedData: {},
                fieldResults: {}
            };
            
            // 必須フィールドチェック
            for (const field of requiredFields) {
                if (!(field in data) || data[field] === null || data[field] === undefined) {
                    results.valid = false;
                    results.errors.push({
                        field,
                        error: 'MISSING_REQUIRED_FIELD',
                        message: `必須フィールド '${field}' が不足しています`
                    });
                }
            }
            
            // 各フィールドの検証
            for (const [fieldName, value] of Object.entries(data)) {
                const fieldResult = this.validateField(fieldName, value);
                results.fieldResults[fieldName] = fieldResult;
                
                if (fieldResult.valid) {
                    results.sanitizedData[fieldName] = fieldResult.sanitizedValue;
                } else {
                    results.valid = false;
                    results.errors.push({
                        field: fieldName,
                        ...fieldResult
                    });
                }
            }
            
            // オブジェクト全体のセキュリティチェック
            const objectHash = this.hashManager.generateHash(JSON.stringify(results.sanitizedData));
            results.dataHash = objectHash;
            
            this.logger.info('Object validation completed', {
                fields: Object.keys(data).length,
                valid: results.valid,
                errors: results.errors.length
            });
            
            return results;
            
        } catch (error) {
            this.logger.error('Object validation error', error);
            return {
                valid: false,
                errors: [{
                    error: 'VALIDATION_ERROR',
                    message: 'オブジェクト検証中にエラーが発生しました'
                }]
            };
        }
    }
    
    /**
     * セキュリティチェック（SQLインジェクション・OSコマンドインジェクション・XSS対策）
     * @param {string} value - チェック対象の値
     * @param {string} fieldName - フィールド名
     * @returns {Object} セキュリティチェック結果
     */
    performSecurityCheck(value, fieldName) {
        try {
            // SQLインジェクションチェック（IPA 1-3）
            for (const pattern of this.sqlInjectionPatterns) {
                if (pattern.test(value)) {
                    this.stats.violationTypes.sqlInjection++;
                    return {
                        safe: false,
                        violation: 'SQL_INJECTION',
                        message: 'SQLインジェクションの可能性があります',
                        pattern: pattern.toString()
                    };
                }
            }
            
            // OSコマンドインジェクションチェック（IPA 1-4）
            for (const pattern of this.osCommandPatterns) {
                if (pattern.test(value)) {
                    this.stats.violationTypes.osCommand++;
                    return {
                        safe: false,
                        violation: 'OS_COMMAND_INJECTION',
                        message: 'OSコマンドインジェクションの可能性があります',
                        pattern: pattern.toString()
                    };
                }
            }
            
            // XSSチェック
            for (const pattern of this.xssPatterns) {
                if (pattern.test(value)) {
                    this.stats.violationTypes.xss++;
                    return {
                        safe: false,
                        violation: 'XSS',
                        message: 'クロスサイトスクリプティングの可能性があります',
                        pattern: pattern.toString()
                    };
                }
            }
            
            return { safe: true };
            
        } catch (error) {
            this.logger.error('Security check error', error);
            return {
                safe: false,
                violation: 'SECURITY_CHECK_ERROR',
                message: 'セキュリティチェック中にエラーが発生しました'
            };
        }
    }
    
    /**
     * センシティブデータのマスキング
     * @param {string} data - マスキング対象データ
     * @returns {string} マスキングされたデータ
     */
    maskSensitiveData(data) {
        if (!data || data.length < 4) {
            return '***';
        }
        
        const firstTwo = data.substring(0, 2);
        const lastTwo = data.substring(data.length - 2);
        const middle = '*'.repeat(Math.max(0, data.length - 4));
        
        return `${firstTwo}${middle}${lastTwo}`;
    }
    
    /**
     * カスタム検証ルールの追加
     * @param {string} fieldName - フィールド名
     * @param {Object} rule - 検証ルール
     * @returns {boolean} 追加成功
     */
    addValidationRule(fieldName, rule) {
        try {
            if (!this.inputValidator.isValidString(fieldName)) {
                return false;
            }
            
            const requiredProps = ['maxLength', 'required', 'sanitize', 'description'];
            for (const prop of requiredProps) {
                if (!(prop in rule)) {
                    this.logger.warn('Missing required property in validation rule', { fieldName, prop });
                    return false;
                }
            }
            
            this.validationRules[fieldName] = rule;
            this.logger.info('Custom validation rule added', { fieldName, rule });
            return true;
            
        } catch (error) {
            this.logger.error('Error adding validation rule', error);
            return false;
        }
    }
    
    /**
     * 検証ルールの取得
     * @param {string} fieldName - フィールド名
     * @returns {Object|null} 検証ルール
     */
    getValidationRule(fieldName) {
        return this.validationRules[fieldName] || null;
    }
    
    /**
     * サポートされているフィールド一覧の取得
     * @returns {Array} フィールド一覧
     */
    getSupportedFields() {
        return Object.keys(this.validationRules).map(fieldName => ({
            name: fieldName,
            description: this.validationRules[fieldName].description,
            required: this.validationRules[fieldName].required,
            maxLength: this.validationRules[fieldName].maxLength
        }));
    }
    
    /**
     * 検証統計の取得
     * @returns {Object} 統計情報
     */
    getValidationStats() {
        return {
            ...this.stats,
            successRate: this.stats.totalValidations > 0 ? 
                (this.stats.successfulValidations / this.stats.totalValidations * 100).toFixed(2) + '%' : '0%',
            securityViolationRate: this.stats.totalValidations > 0 ? 
                (this.stats.securityViolations / this.stats.totalValidations * 100).toFixed(2) + '%' : '0%'
        };
    }
    
    /**
     * 統計のリセット
     */
    resetStats() {
        this.stats = {
            totalValidations: 0,
            successfulValidations: 0,
            failedValidations: 0,
            securityViolations: 0,
            lastValidation: null,
            violationTypes: {
                sqlInjection: 0,
                osCommand: 0,
                xss: 0,
                invalidFormat: 0,
                excessiveLength: 0
            }
        };
        
        this.logger.info('Validation statistics reset');
    }
}

// デフォルトエクスポート
export default DataValidator;
