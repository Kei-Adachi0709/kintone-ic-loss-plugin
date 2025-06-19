/**
 * Kintone ICカード紛失対応プラグイン - ICカード番号検証クラス
 * ICカード番号の形式検証とタイプ判定（Phase 3統合版）
 * IPA安全なプログラム作成 - 入力データ検証 準拠
 * 
 * @version 3.0.0
 * @author Kintone ICカード紛失対応チーム
 */

import { InputValidator } from './security/input-validator.js';
import { Logger } from './common/logger.js';

/**
 * ICカード番号検証クラス
 * リアルなICカード番号形式の検証とタイプ判定を行う
 * IPA章節1-1, 1-3: 入力データの検証とサニタイゼーション
 */
export class ICCardValidator {
    /**
     * コンストラクタ
     */
    constructor() {
        this.inputValidator = new InputValidator();
        this.logger = new Logger('ICCardValidator');
        
        // ICカード番号パターン定義（実際の形式に基づく）
        this.cardPatterns = {
            // Suica/PASMO - JR東日本系（16桁）
            'SUICA': {
                pattern: /^[0-9]{16}$/,
                length: 16,
                checksum: true,
                description: 'Suica/PASMO系ICカード',
                issuer: 'JR東日本・関東私鉄',
                regions: ['関東', '東海', '仙台', '新潟']
            },
            
            // ICOCA - JR西日本系（16桁）
            'ICOCA': {
                pattern: /^[0-9]{16}$/,
                length: 16,
                checksum: true,
                description: 'ICOCA系ICカード',
                issuer: 'JR西日本・関西私鉄',
                regions: ['関西', '中国', '四国']
            },
            
            // manaca - 名古屋市交通局系（16桁）
            'MANACA': {
                pattern: /^[0-9]{16}$/,
                length: 16,
                checksum: true,
                description: 'manaca系ICカード',
                issuer: '名古屋市交通局・名古屋鉄道',
                regions: ['名古屋', '東海']
            },
            
            // TOICA - JR東海系（16桁）
            'TOICA': {
                pattern: /^[0-9]{16}$/,
                length: 16,
                checksum: true,
                description: 'TOICA系ICカード',
                issuer: 'JR東海',
                regions: ['東海', '静岡']
            },
            
            // SUGOCA - JR九州系（16桁）
            'SUGOCA': {
                pattern: /^[0-9]{16}$/,
                length: 16,
                checksum: true,
                description: 'SUGOCA系ICカード',
                issuer: 'JR九州・福岡市交通局',
                regions: ['九州', '福岡']
            },
            
            // Kitaca - JR北海道系（16桁）
            'KITACA': {
                pattern: /^[0-9]{16}$/,
                length: 16,
                checksum: true,
                description: 'Kitaca系ICカード',
                issuer: 'JR北海道・札幌市交通局',
                regions: ['北海道', '札幌']
            },
            
            // はやかけん - 福岡市交通局系（16桁）
            'HAYAKAKEN': {
                pattern: /^[0-9]{16}$/,
                length: 16,
                checksum: true,
                description: 'はやかけん系ICカード',
                issuer: '福岡市交通局',
                regions: ['福岡']
            },
            
            // nimoca - 西日本鉄道系（16桁）
            'NIMOCA': {
                pattern: /^[0-9]{16}$/,
                length: 16,
                checksum: true,
                description: 'nimoca系ICカード',
                issuer: '西日本鉄道',
                regions: ['九州', '福岡', '熊本']
            },
            
            // 企業系ICカード（社員証等、10-12桁）
            'CORPORATE': {
                pattern: /^[0-9]{10,12}$/,
                length: [10, 11, 12],
                checksum: false,
                description: '企業系ICカード',
                issuer: '各企業・団体',
                regions: ['全国']
            },
            
            // 学生証系ICカード（8-14桁）
            'STUDENT': {
                pattern: /^[0-9]{8,14}$/,
                length: [8, 9, 10, 11, 12, 13, 14],
                checksum: false,
                description: '学生証系ICカード',
                issuer: '各教育機関',
                regions: ['全国']
            }
        };
        
        // セキュリティ統計
        this.stats = {
            validationCount: 0,
            validCards: 0,
            invalidCards: 0,
            suspiciousAttempts: 0,
            lastValidation: null
        };
        
        this.logger.info('ICCardValidator initialized with real card patterns');
    }
    
    /**
     * ICカード番号の基本検証
     * @param {string} cardNumber - ICカード番号
     * @returns {Object} 検証結果
     */
    validateCardNumber(cardNumber) {
        try {
            this.stats.validationCount++;
            this.stats.lastValidation = new Date();
            
            // 入力データのサニタイズと基本検証（IPA 1-1）
            const sanitizedNumber = this.inputValidator.sanitizeString(cardNumber);
            
            if (!this.inputValidator.isValidString(sanitizedNumber)) {
                this.stats.suspiciousAttempts++;
                this.logger.warn('Invalid card number input detected', { 
                    length: cardNumber?.length,
                    hasSpecialChars: /[^0-9]/.test(cardNumber || '')
                });
                
                return {
                    valid: false,
                    error: 'INVALID_INPUT',
                    message: '無効な入力データです',
                    security: 'SUSPICIOUS_INPUT'
                };
            }
            
            // 長さチェック（4-20桁の範囲）
            if (sanitizedNumber.length < 4 || sanitizedNumber.length > 20) {
                this.stats.invalidCards++;
                return {
                    valid: false,
                    error: 'INVALID_LENGTH',
                    message: 'ICカード番号の桁数が正しくありません（4-20桁）',
                    actualLength: sanitizedNumber.length
                };
            }
            
            // 数字のみチェック
            if (!/^\d+$/.test(sanitizedNumber)) {
                this.stats.invalidCards++;
                return {
                    valid: false,
                    error: 'INVALID_FORMAT',
                    message: 'ICカード番号は数字のみで入力してください'
                };
            }
            
            // カードタイプの判定
            const cardType = this.detectCardType(sanitizedNumber);
            
            if (!cardType) {
                this.stats.invalidCards++;
                return {
                    valid: false,
                    error: 'UNKNOWN_CARD_TYPE',
                    message: '認識できないICカード形式です',
                    number: this.maskCardNumber(sanitizedNumber)
                };
            }
            
            // チェックサム検証（対応カードのみ）
            let checksumValid = true;
            if (cardType.checksum) {
                checksumValid = this.validateChecksum(sanitizedNumber, cardType.type);
            }
            
            if (!checksumValid) {
                this.stats.invalidCards++;
                return {
                    valid: false,
                    error: 'INVALID_CHECKSUM',
                    message: 'ICカード番号のチェックサムが正しくありません',
                    cardType: cardType.type
                };
            }
            
            this.stats.validCards++;
            this.logger.info('Valid IC card detected', {
                type: cardType.type,
                issuer: cardType.issuer,
                masked: this.maskCardNumber(sanitizedNumber)
            });
            
            return {
                valid: true,
                cardType: cardType.type,
                issuer: cardType.issuer,
                description: cardType.description,
                regions: cardType.regions,
                number: this.maskCardNumber(sanitizedNumber),
                rawNumber: sanitizedNumber, // セキュアなハッシュ用
                checksum: checksumValid
            };
            
        } catch (error) {
            this.stats.suspiciousAttempts++;
            this.logger.error('Card validation error', error);
            
            return {
                valid: false,
                error: 'VALIDATION_ERROR',
                message: '検証中にエラーが発生しました',
                security: 'SYSTEM_ERROR'
            };
        }
    }
    
    /**
     * ICカードタイプの自動判定
     * @param {string} cardNumber - ICカード番号
     * @returns {Object|null} カードタイプ情報
     */
    detectCardType(cardNumber) {
        try {
            for (const [type, config] of Object.entries(this.cardPatterns)) {
                if (config.pattern.test(cardNumber)) {
                    return {
                        type,
                        ...config
                    };
                }
            }
            
            return null;
            
        } catch (error) {
            this.logger.error('Card type detection error', error);
            return null;
        }
    }
    
    /**
     * チェックサム検証（Luhnアルゴリズム準拠）
     * @param {string} cardNumber - ICカード番号
     * @param {string} cardType - カードタイプ
     * @returns {boolean} チェックサム有効性
     */
    validateChecksum(cardNumber, cardType) {
        try {
            // Luhnアルゴリズムによるチェックサム検証
            const digits = cardNumber.split('').map(Number);
            let sum = 0;
            let alternate = false;
            
            // 右から左へ処理
            for (let i = digits.length - 1; i >= 0; i--) {
                let digit = digits[i];
                
                if (alternate) {
                    digit *= 2;
                    if (digit > 9) {
                        digit -= 9;
                    }
                }
                
                sum += digit;
                alternate = !alternate;
            }
            
            return sum % 10 === 0;
            
        } catch (error) {
            this.logger.error('Checksum validation error', error);
            return false;
        }
    }
    
    /**
     * ICカード番号のマスキング（セキュリティ対策）
     * @param {string} cardNumber - ICカード番号
     * @returns {string} マスキングされた番号
     */
    maskCardNumber(cardNumber) {
        if (!cardNumber || cardNumber.length < 4) {
            return '****';
        }
        
        const firstFour = cardNumber.substring(0, 4);
        const lastFour = cardNumber.substring(cardNumber.length - 4);
        const middle = '*'.repeat(cardNumber.length - 8);
        
        return `${firstFour}${middle}${lastFour}`;
    }
    
    /**
     * 対応地域の確認
     * @param {string} cardType - カードタイプ
     * @param {string} region - 地域名
     * @returns {boolean} 対応地域かどうか
     */
    isRegionSupported(cardType, region) {
        try {
            const cardConfig = this.cardPatterns[cardType];
            if (!cardConfig) {
                return false;
            }
            
            return cardConfig.regions.includes(region) || 
                   cardConfig.regions.includes('全国');
                   
        } catch (error) {
            this.logger.error('Region support check error', error);
            return false;
        }
    }
    
    /**
     * サポートされているカードタイプ一覧の取得
     * @returns {Array} カードタイプ一覧
     */
    getSupportedCardTypes() {
        return Object.keys(this.cardPatterns).map(type => ({
            type,
            description: this.cardPatterns[type].description,
            issuer: this.cardPatterns[type].issuer,
            regions: this.cardPatterns[type].regions
        }));
    }
    
    /**
     * 検証統計の取得
     * @returns {Object} 統計情報
     */
    getValidationStats() {
        return {
            ...this.stats,
            successRate: this.stats.validationCount > 0 ? 
                (this.stats.validCards / this.stats.validationCount * 100).toFixed(2) + '%' : '0%',
            suspiciousRate: this.stats.validationCount > 0 ? 
                (this.stats.suspiciousAttempts / this.stats.validationCount * 100).toFixed(2) + '%' : '0%'
        };
    }
    
    /**
     * バリデーションルールの動的更新
     * @param {string} cardType - カードタイプ
     * @param {Object} config - 新しい設定
     * @returns {boolean} 更新成功
     */
    updateValidationRule(cardType, config) {
        try {
            if (!this.inputValidator.isValidString(cardType)) {
                return false;
            }
            
            // 既存パターンの検証
            if (config.pattern && !(config.pattern instanceof RegExp)) {
                this.logger.warn('Invalid pattern provided for card type update');
                return false;
            }
            
            this.cardPatterns[cardType] = {
                ...this.cardPatterns[cardType],
                ...config
            };
            
            this.logger.info('Card validation rule updated', { cardType, config });
            return true;
            
        } catch (error) {
            this.logger.error('Validation rule update error', error);
            return false;
        }
    }
    
    /**
     * セキュリティ統計のリセット
     */
    resetStats() {
        this.stats = {
            validationCount: 0,
            validCards: 0,
            invalidCards: 0,
            suspiciousAttempts: 0,
            lastValidation: null
        };
        
        this.logger.info('Validation statistics reset');
    }
}

// デフォルトエクスポート
export default ICCardValidator;
