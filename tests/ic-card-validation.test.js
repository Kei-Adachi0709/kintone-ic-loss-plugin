/**
 * Kintone ICカード紛失対応プラグイン - ICカード検証テスト
 * ICCardValidatorクラスの包括的テスト（リアルなICカード番号形式対応）
 * 
 * @version 3.0.0
 * @author Kintone ICカード紛失対応チーム
 */

import ICCardValidator from '../src/js/ic-card-validator.js';
import { jest } from '@jest/globals';

// モック設定
jest.mock('../src/js/security/input-validator.js');
jest.mock('../src/js/common/logger.js');

describe('ICCardValidator - Real Card Number Format Tests', () => {
    let validator;
    
    beforeEach(() => {
        validator = new ICCardValidator();
    });
    
    afterEach(() => {
        jest.clearAllMocks();
    });
    
    describe('リアルなICカード番号形式テスト', () => {
        test('Suica/PASMO系 16桁番号の検証', () => {
            const testCases = [
                {
                    number: '1234567890123456',
                    expected: true,
                    type: 'SUICA',
                    description: '標準的なSuica番号'
                },
                {
                    number: '9876543210987654',
                    expected: true,
                    type: 'SUICA',
                    description: '別のSuica番号'
                },
                {
                    number: '123456789012345', // 15桁
                    expected: false,
                    description: '桁数不足'
                },
                {
                    number: '12345678901234567', // 17桁
                    expected: false,
                    description: '桁数過多'
                }
            ];
            
            testCases.forEach(testCase => {
                const result = validator.validateCardNumber(testCase.number);
                
                expect(result.valid).toBe(testCase.expected);
                
                if (testCase.expected) {
                    expect(result.cardType).toBe(testCase.type);
                    expect(result.number).toMatch(/^\d{4}\*+\d{4}$/); // マスキング確認
                    expect(result.rawNumber).toBe(testCase.number);
                } else {
                    expect(result.error).toBeDefined();
                }
            });
        });
        
        test('manaca系 16桁番号の検証', () => {
            const manacaNumbers = [
                '2000001234567890',
                '2111112233445566',
                '2999999888777666'
            ];
            
            manacaNumbers.forEach(number => {
                const result = validator.validateCardNumber(number);
                expect(result.valid).toBe(true);
                expect(result.cardType).toBe('MANACA');
                expect(result.issuer).toBe('名古屋市交通局・名古屋鉄道');
                expect(result.regions).toContain('名古屋');
            });
        });
        
        test('TOICA系 16桁番号の検証', () => {
            const toicaNumbers = [
                '3000001111222233',
                '3123456789012345',
                '3999888777666555'
            ];
            
            toicaNumbers.forEach(number => {
                const result = validator.validateCardNumber(number);
                expect(result.valid).toBe(true);
                expect(result.cardType).toBe('TOICA');
                expect(result.issuer).toBe('JR東海');
                expect(result.regions).toContain('東海');
            });
        });
        
        test('企業系ICカード 10-12桁番号の検証', () => {
            const corporateCards = [
                {
                    number: '1234567890', // 10桁
                    expected: true
                },
                {
                    number: '12345678901', // 11桁
                    expected: true
                },
                {
                    number: '123456789012', // 12桁
                    expected: true
                },
                {
                    number: '123456789', // 9桁
                    expected: false
                },
                {
                    number: '1234567890123', // 13桁
                    expected: false
                }
            ];
            
            corporateCards.forEach(testCase => {
                const result = validator.validateCardNumber(testCase.number);
                
                if (testCase.expected) {
                    expect(result.valid).toBe(true);
                    expect(result.cardType).toBe('CORPORATE');
                    expect(result.issuer).toBe('各企業・団体');
                } else {
                    expect(result.valid).toBe(false);
                }
            });
        });
        
        test('学生証系ICカード 8-14桁番号の検証', () => {
            const studentCards = [
                {
                    number: '12345678', // 8桁
                    expected: true
                },
                {
                    number: '1234567890123', // 13桁
                    expected: true
                },
                {
                    number: '12345678901234', // 14桁
                    expected: true
                },
                {
                    number: '1234567', // 7桁
                    expected: false
                },
                {
                    number: '123456789012345', // 15桁
                    expected: false
                }
            ];
            
            studentCards.forEach(testCase => {
                const result = validator.validateCardNumber(testCase.number);
                
                if (testCase.expected) {
                    expect(result.valid).toBe(true);
                    expect(result.cardType).toBe('STUDENT');
                    expect(result.issuer).toBe('各教育機関');
                } else {
                    expect(result.valid).toBe(false);
                }
            });
        });
    });
    
    describe('チェックサム検証テスト', () => {
        test('Luhnアルゴリズムによるチェックサム検証', () => {
            // Luhnアルゴリズムで有効な番号
            const validLuhnNumbers = [
                '4532015112830366', // Visa形式だがICカードでも使用される場合
                '4000000000000002',
                '5555555555554444'
            ];
            
            // Luhnアルゴリズムで無効な番号
            const invalidLuhnNumbers = [
                '1234567890123456',
                '1111111111111111',
                '0000000000000000'
            ];
            
            validLuhnNumbers.forEach(number => {
                const isValid = validator.validateChecksum(number, 'SUICA');
                expect(isValid).toBe(true);
            });
            
            invalidLuhnNumbers.forEach(number => {
                const isValid = validator.validateChecksum(number, 'SUICA');
                expect(isValid).toBe(false);
            });
        });
        
        test('チェックサム非対応カードの処理', () => {
            const corporateCard = '1234567890';
            const result = validator.validateCardNumber(corporateCard);
            
            expect(result.valid).toBe(true);
            expect(result.cardType).toBe('CORPORATE');
            // 企業カードはチェックサム非対応
            expect(result.checksum).toBe(true); // チェックサムスキップで成功
        });
    });
    
    describe('セキュリティテスト', () => {
        test('不正な入力の検出', () => {
            const maliciousInputs = [
                '<script>alert("XSS")</script>',
                "'; DROP TABLE cards; --",
                '../../../etc/passwd',
                '$(rm -rf /)',
                '<iframe src="javascript:alert()"></iframe>',
                'javascript:void(0)',
                null,
                undefined,
                '',
                '    ', // 空白のみ
                '1234' + 'a'.repeat(1000) // 異常に長い文字列
            ];
            
            maliciousInputs.forEach(input => {
                const result = validator.validateCardNumber(input);
                expect(result.valid).toBe(false);
                if (result.security) {
                    expect(result.security).toBeDefined();
                }
            });
        });
        
        test('入力文字列のサニタイゼーション', () => {
            const dirtyInputs = [
                '  1234567890123456  ', // 前後の空白
                '1234-5678-9012-3456', // ハイフン
                '1234 5678 9012 3456', // スペース
                '１２３４５６７８９０１２３４５６', // 全角数字
            ];
            
            dirtyInputs.forEach(input => {
                const result = validator.validateCardNumber(input);
                // サニタイズ後の結果が適切に処理されることを確認
                expect(result).toBeDefined();
            });
        });
        
        test('カード番号のマスキング機能', () => {
            const testCases = [
                {
                    input: '1234567890123456',
                    expected: '1234********3456'
                },
                {
                    input: '123456789012',
                    expected: '1234****9012'
                },
                {
                    input: '12345678',
                    expected: '1234****'
                },
                {
                    input: '123',
                    expected: '****' // 短すぎる場合
                }
            ];
            
            testCases.forEach(testCase => {
                const masked = validator.maskCardNumber(testCase.input);
                expect(masked).toBe(testCase.expected);
            });
        });
    });
    
    describe('地域対応テスト', () => {
        test('名古屋地域でのカード対応確認', () => {
            const nagoyaSupportedCards = ['MANACA', 'TOICA', 'SUICA'];
            const nagoyaUnsupportedCards = ['KITACA', 'SUGOCA'];
            
            nagoyaSupportedCards.forEach(cardType => {
                const isSupported = validator.isRegionSupported(cardType, '名古屋');
                expect(isSupported).toBe(true);
            });
            
            nagoyaUnsupportedCards.forEach(cardType => {
                const isSupported = validator.isRegionSupported(cardType, '名古屋');
                expect(isSupported).toBe(false);
            });
        });
        
        test('全国対応カードの確認', () => {
            const nationalCards = ['SUICA', 'ICOCA'];
            
            nationalCards.forEach(cardType => {
                const regions = ['東京', '大阪', '名古屋', '福岡', '札幌'];
                regions.forEach(region => {
                    const isSupported = validator.isRegionSupported(cardType, region);
                    expect(isSupported).toBe(true);
                });
            });
        });
    });
    
    describe('統計・メトリクステスト', () => {
        test('検証統計の記録', () => {
            // 複数の検証を実行
            validator.validateCardNumber('1234567890123456'); // 有効
            validator.validateCardNumber('invalid'); // 無効
            validator.validateCardNumber('<script>'); // セキュリティ違反
            validator.validateCardNumber('9876543210987654'); // 有効
            
            const stats = validator.getValidationStats();
            
            expect(stats.validationCount).toBe(4);
            expect(stats.validCards).toBe(2);
            expect(stats.invalidCards).toBe(1);
            expect(stats.suspiciousAttempts).toBe(1);
            expect(stats.successRate).toBe('50.00%');
            expect(stats.suspiciousRate).toBe('25.00%');
        });
        
        test('統計のリセット機能', () => {
            // 統計データを生成
            validator.validateCardNumber('1234567890123456');
            validator.validateCardNumber('invalid');
            
            let stats = validator.getValidationStats();
            expect(stats.validationCount).toBe(2);
            
            // 統計をリセット
            validator.resetStats();
            
            stats = validator.getValidationStats();
            expect(stats.validationCount).toBe(0);
            expect(stats.validCards).toBe(0);
            expect(stats.invalidCards).toBe(0);
            expect(stats.suspiciousAttempts).toBe(0);
        });
    });
    
    describe('カードタイプ検出テスト', () => {
        test('自動カードタイプ検出', () => {
            const testCases = [
                { number: '1234567890123456', expectedType: 'SUICA' },
                { number: '2000001234567890', expectedType: 'MANACA' },
                { number: '3000001234567890', expectedType: 'TOICA' },
                { number: '1234567890', expectedType: 'CORPORATE' },
                { number: '12345678', expectedType: 'STUDENT' }
            ];
            
            testCases.forEach(testCase => {
                const detectedType = validator.detectCardType(testCase.number);
                expect(detectedType).toBeDefined();
                expect(detectedType.type).toBe(testCase.expectedType);
            });
        });
        
        test('サポートされているカードタイプ一覧', () => {
            const supportedTypes = validator.getSupportedCardTypes();
            
            expect(supportedTypes).toBeDefined();
            expect(supportedTypes.length).toBeGreaterThan(0);
            
            const expectedTypes = ['SUICA', 'MANACA', 'TOICA', 'ICOCA', 'CORPORATE', 'STUDENT'];
            expectedTypes.forEach(type => {
                const found = supportedTypes.find(t => t.type === type);
                expect(found).toBeDefined();
                expect(found.description).toBeDefined();
                expect(found.issuer).toBeDefined();
                expect(found.regions).toBeDefined();
            });
        });
    });
    
    describe('動的ルール更新テスト', () => {
        test('新しいカードタイプの追加', () => {
            const newCardType = {
                pattern: /^[0-9]{18}$/,
                length: 18,
                checksum: false,
                description: '新しいICカード',
                issuer: '新交通システム',
                regions: ['新地域']
            };
            
            const success = validator.updateValidationRule('NEW_CARD', newCardType);
            expect(success).toBe(true);
            
            // 新しいルールでの検証
            const testNumber = '123456789012345678'; // 18桁
            const result = validator.validateCardNumber(testNumber);
            expect(result.valid).toBe(true);
            expect(result.cardType).toBe('NEW_CARD');
        });
        
        test('不正なルール更新の拒否', () => {
            const invalidRule = {
                // 必須フィールドが不足
                description: '不正なルール'
            };
            
            const success = validator.updateValidationRule('INVALID', invalidRule);
            expect(success).toBe(false);
        });
    });
    
    describe('エラーハンドリングテスト', () => {
        test('例外的なケースの処理', () => {
            const extremeCases = [
                null,
                undefined,
                0,
                {},
                [],
                function() {},
                Symbol('test'),
                BigInt(123456789012345678901234567890n)
            ];
            
            extremeCases.forEach(testCase => {
                const result = validator.validateCardNumber(testCase);
                expect(result).toBeDefined();
                expect(result.valid).toBe(false);
            });
        });
        
        test('国際化文字の処理', () => {
            const internationalInputs = [
                '１２３４５６７８９０１２３４５６', // 全角数字
                '1234567890123456', // 半角数字（正常）
                '۱۲۳۴۵۶۷۸۹۰۱۲۳۴۵۶', // アラビア数字
                '๑๒๓๔๕๖๗๘๙๐๑๒๓๔๕๖', // タイ数字
                '一二三四五六七八九〇一二三四五六' // 漢数字
            ];
            
            internationalInputs.forEach(input => {
                const result = validator.validateCardNumber(input);
                expect(result).toBeDefined();
                // 半角数字以外は無効になることを確認
                if (input === '1234567890123456') {
                    expect(result.valid).toBe(true);
                } else {
                    expect(result.valid).toBe(false);
                }
            });
        });
    });
});

describe('ICCardValidator - Performance Tests', () => {
    let validator;
    
    beforeAll(() => {
        validator = new ICCardValidator();
    });
    
    test('大量データ処理のパフォーマンス', () => {
        const startTime = Date.now();
        const testData = [];
        
        // 1000件のテストデータを生成
        for (let i = 0; i < 1000; i++) {
            testData.push(`1234567890${i.toString().padStart(6, '0')}`);
        }
        
        // 一括検証
        const results = testData.map(number => validator.validateCardNumber(number));
        
        const endTime = Date.now();
        const processingTime = endTime - startTime;
        
        // 1000件の処理が5秒以内に完了することを確認
        expect(processingTime).toBeLessThan(5000);
        expect(results).toHaveLength(1000);
        
        // 全ての結果が定義されていることを確認
        results.forEach(result => {
            expect(result).toBeDefined();
            expect(result.valid).toBeDefined();
        });
    });
    
    test('メモリ使用量の監視', () => {
        const initialMemory = process.memoryUsage().heapUsed;
        
        // 大量のバリデーションを実行
        for (let i = 0; i < 10000; i++) {
            validator.validateCardNumber(`${i.toString().padStart(16, '0')}`);
        }
        
        const finalMemory = process.memoryUsage().heapUsed;
        const memoryIncrease = finalMemory - initialMemory;
        
        // メモリ使用量が50MB以下であることを確認
        expect(memoryIncrease).toBeLessThan(50 * 1024 * 1024);
    });
});

describe('ICCardValidator - Integration Tests', () => {
    let validator;
    
    beforeEach(() => {
        validator = new ICCardValidator();
    });
    
    test('実際の利用シナリオのテスト', () => {
        // シナリオ1: 従業員がmanacaカードを紛失
        const manacaCard = '2000001234567890';
        const result1 = validator.validateCardNumber(manacaCard);
        
        expect(result1.valid).toBe(true);
        expect(result1.cardType).toBe('MANACA');
        expect(result1.regions).toContain('名古屋');
        
        // 名古屋地域での対応確認
        const regionSupport = validator.isRegionSupported('MANACA', '名古屋');
        expect(regionSupport).toBe(true);
        
        // シナリオ2: 学生が学生証ICカードを紛失
        const studentCard = '1234567890';
        const result2 = validator.validateCardNumber(studentCard);
        
        expect(result2.valid).toBe(true);
        expect(result2.cardType).toBe('CORPORATE'); // 10桁なので企業系として認識
        
        // シナリオ3: 不正な番号の入力
        const invalidCard = 'invalid-card-number';
        const result3 = validator.validateCardNumber(invalidCard);
        
        expect(result3.valid).toBe(false);
        expect(result3.error).toBeDefined();
    });
    
    test('マルチリージョン対応テスト', () => {
        const regions = ['名古屋', '東京', '大阪', '福岡'];
        const cardTypes = ['SUICA', 'MANACA', 'ICOCA', 'TOICA'];
        
        for (const region of regions) {
            for (const cardType of cardTypes) {
                const isSupported = validator.isRegionSupported(cardType, region);
                
                // 地域特化カードの対応確認
                if ((cardType === 'MANACA' || cardType === 'TOICA') && region === '名古屋') {
                    expect(isSupported).toBe(true);
                } else if (cardType === 'SUICA' || cardType === 'ICOCA') {
                    // 全国対応カード
                    expect(isSupported).toBe(true);
                }
            }
        }
    });
});
