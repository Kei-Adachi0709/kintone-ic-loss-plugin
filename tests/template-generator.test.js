/**
 * Kintone ICカード紛失対応プラグイン - テンプレート生成テスト
 * TemplateGeneratorクラスの包括的セキュリティテスト（XSS対策・定型文生成）
 * 
 * @version 3.0.0
 * @author Kintone ICカード紛失対応チーム
 */

import TemplateGenerator from '../src/js/template-generator.js';
import { jest } from '@jest/globals';

// モック設定
jest.mock('../src/js/security/input-validator.js');
jest.mock('../src/js/data-validator.js');
jest.mock('../src/js/common/logger.js');

describe('TemplateGenerator - Security Tests', () => {
    let generator;
    
    beforeEach(() => {
        generator = new TemplateGenerator();
    });
    
    afterEach(() => {
        jest.clearAllMocks();
    });
    
    describe('XSS対策テスト', () => {
        test('HTMLタグのエスケープ処理', () => {
            const xssAttempts = [
                '<script>alert("XSS")</script>',
                '<img src=x onerror=alert("XSS")>',
                '<iframe src="javascript:alert(\'XSS\')"></iframe>',
                '<svg onload=alert("XSS")>',
                '<div onclick="alert(\'XSS\')">test</div>',
                '<a href="javascript:alert(\'XSS\')">link</a>',
                '<form><input type="text" onFocus="alert(\'XSS\')" /></form>'
            ];
            
            xssAttempts.forEach(xss => {
                const sanitized = generator.sanitizeTemplateData({ maliciousField: xss });
                
                expect(sanitized.maliciousField).not.toContain('<script');
                expect(sanitized.maliciousField).not.toContain('javascript:');
                expect(sanitized.maliciousField).not.toContain('onerror=');
                expect(sanitized.maliciousField).not.toContain('onload=');
                expect(sanitized.maliciousField).not.toContain('onclick=');
                
                // HTMLエスケープされていることを確認
                expect(sanitized.maliciousField).toContain('&lt;');
                expect(sanitized.maliciousField).toContain('&gt;');
            });
        });
        
        test('特殊文字のエスケープ処理', () => {
            const specialChars = {
                ampersand: 'A & B Company',
                quotes: 'He said "Hello" to her',
                singleQuotes: "It's a test",
                lessThan: '2 < 5',
                greaterThan: '10 > 5',
                forwardSlash: 'http://example.com/path'
            };
            
            const sanitized = generator.sanitizeTemplateData(specialChars);
            
            expect(sanitized.ampersand).toBe('A &amp; B Company');
            expect(sanitized.quotes).toBe('He said &quot;Hello&quot; to her');
            expect(sanitized.singleQuotes).toBe('It&#x27;s a test');
            expect(sanitized.lessThan).toBe('2 &lt; 5');
            expect(sanitized.greaterThan).toBe('10 &gt; 5');
            expect(sanitized.forwardSlash).toBe('http:&#x2F;&#x2F;example.com&#x2F;path');
        });
        
        test('JavaScriptプロトコルの無効化', () => {
            const jsProtocols = [
                'javascript:alert("XSS")',
                'javascript:void(0)',
                'javascript:eval("malicious")',
                'JAVASCRIPT:alert(1)',
                'java\nscript:alert(1)',
                'java\tscript:alert(1)'
            ];
            
            jsProtocols.forEach(js => {
                const sanitized = generator.sanitizeTemplateData({ jsField: js });
                
                expect(sanitized.jsField).not.toContain('javascript:');
                expect(sanitized.jsField).not.toContain('JAVASCRIPT:');
            });
        });
    });
    
    describe('テンプレート生成セキュリティテスト', () => {
        test('悪意のあるデータを含むテンプレート生成', () => {
            const maliciousData = {
                employeeName: '<script>steal_cookies()</script>山田太郎',
                description: 'Normal text <img src=x onerror=alert(1)> with XSS',
                lossLocation: 'Station<svg onload=alert(document.domain)>',
                email: 'user<iframe src="javascript:alert()"></iframe>@evil.com',
                phoneNumber: '090-1234<script>hack()</script>-5678'
            };
            
            const result = generator.generateTemplate('lossReport', maliciousData);
            
            if (result.success) {
                // 生成されたテンプレートにXSSが含まれていないことを確認
                expect(result.content).not.toContain('<script');
                expect(result.content).not.toContain('javascript:');
                expect(result.content).not.toContain('onerror=');
                expect(result.content).not.toContain('onload=');
                
                // エスケープされた文字が含まれていることを確認
                expect(result.content).toContain('&lt;');
                expect(result.content).toContain('&gt;');
            }
        });
        
        test('SQLインジェクション試行の無害化', () => {
            const sqlInjectionData = {
                employeeId: "'; DROP TABLE users; --",
                employeeName: "admin'--",
                description: "' OR '1'='1",
                lossLocation: "'; INSERT INTO logs VALUES('hacked'); --"
            };
            
            const result = generator.generateTemplate('quickReport', sqlInjectionData);
            
            if (result.success) {
                // SQLインジェクション文字列が適切にエスケープされていることを確認
                expect(result.content).not.toContain("DROP TABLE");
                expect(result.content).not.toContain("INSERT INTO");
                expect(result.content).not.toContain("'--");
                
                // エスケープされた形で含まれていることを確認
                expect(result.content).toContain('&#x27;');
            }
        });
    });
    
    describe('テンプレートタイプ別テスト', () => {
        test('基本紛失報告書の生成', () => {
            const validData = {
                reportDate: '2024-01-15',
                employeeId: 'EMP001',
                employeeName: '山田太郎',
                department: '総務部',
                email: 'yamada@company.com',
                phoneNumber: '03-1234-5678',
                icCardNumber: '1234567890123456',
                cardType: 'MANACA',
                lossDate: '2024-01-14',
                lossTime: '09:30',
                lossLocation: '名古屋駅',
                circumstances: '通勤時に紛失',
                transportationProvider: '名古屋市営地下鉄'
            };
            
            const result = generator.generateTemplate('lossReport', validData);
            
            expect(result.success).toBe(true);
            expect(result.title).toBe('ICカード紛失届');
            expect(result.content).toContain('基本情報');
            expect(result.content).toContain('ICカード情報');
            expect(result.content).toContain('紛失詳細');
            expect(result.content).toContain('交通機関対応');
            expect(result.content).toContain('今後の対応');
            
            // ICカード番号がマスキングされていることを確認
            expect(result.content).toContain('1234********3456');
            expect(result.content).not.toContain('1234567890123456');
        });
        
        test('簡易報告書の生成', () => {
            const minimalData = {
                reportDate: '2024-01-15',
                employeeName: '田中花子',
                icCardNumber: '2000001234567890',
                lossDate: '2024-01-14',
                lossLocation: '栄駅'
            };
            
            const result = generator.generateTemplate('quickReport', minimalData);
            
            expect(result.success).toBe(true);
            expect(result.title).toBe('ICカード紛失簡易報告');
            expect(result.content).toContain('必須情報');
            expect(result.content).toContain('田中花子');
            expect(result.content).toContain('栄駅');
            
            // ICカード番号のマスキング確認
            expect(result.content).toContain('2000********7890');
        });
        
        test('交通機関向け報告書の生成', () => {
            const transportData = {
                icCardNumber: '3000001234567890',
                cardType: 'TOICA',
                holderName: '佐藤一郎',
                lossDate: '2024-01-14',
                lossLocation: '金山駅',
                employeeName: '佐藤一郎',
                phoneNumber: '052-123-4567',
                email: 'sato@company.com',
                companyName: '株式会社サンプル'
            };
            
            const result = generator.generateTemplate('transportationReport', transportData);
            
            expect(result.success).toBe(true);
            expect(result.title).toBe('交通機関向けICカード紛失通知');
            expect(result.content).toContain('カード詳細');
            expect(result.content).toContain('連絡先');
            expect(result.content).toContain('TOICA');
            expect(result.content).toContain('金山駅');
            
            // カード番号のマスキング確認
            expect(result.content).toContain('3000********7890');
        });
        
        test('上司向け報告書の生成', () => {
            const supervisorData = {
                employeeName: '鈴木次郎',
                department: '営業部',
                lossDate: '2024-01-14',
                icCardNumber: '1111222233334444',
                impactAssessment: '業務への影響は軽微',
                immediateActions: '交通機関への連絡完了',
                providerNotification: '名古屋市営地下鉄に通知済み',
                securityMeasures: 'カード利用停止処理完了',
                replacementProcess: '再発行手続き中',
                preventiveMeasures: 'カード管理研修の実施予定',
                followUpSchedule: '1週間後に状況確認'
            };
            
            const result = generator.generateTemplate('supervisorReport', supervisorData);
            
            expect(result.success).toBe(true);
            expect(result.title).toBe('上司向けICカード紛失報告');
            expect(result.content).toContain('概要');
            expect(result.content).toContain('実施済み対応');
            expect(result.content).toContain('今後の対応予定');
            expect(result.content).toContain('営業部');
            expect(result.content).toContain('業務への影響は軽微');
        });
    });
    
    describe('データ検証テスト', () => {
        test('無効なテンプレートタイプの処理', () => {
            const data = { employeeName: '山田太郎' };
            const result = generator.generateTemplate('nonExistentTemplate', data);
            
            expect(result.success).toBe(false);
            expect(result.error).toBe('TEMPLATE_NOT_FOUND');
            expect(result.message).toContain('nonExistentTemplate');
        });
        
        test('データ検証失敗時の処理', () => {
            const invalidData = {
                employeeName: '<script>alert("XSS")</script>',
                icCardNumber: 'invalid-card-number',
                lossDate: 'invalid-date'
            };
            
            // DataValidatorがエラーを返すようにモック
            const mockValidateObject = jest.fn().mockReturnValue({
                valid: false,
                errors: [
                    { field: 'employeeName', error: 'SECURITY_VIOLATION' },
                    { field: 'icCardNumber', error: 'INVALID_FORMAT' }
                ]
            });
            
            generator.dataValidator = { validateObject: mockValidateObject };
            
            const result = generator.generateTemplate('lossReport', invalidData);
            
            expect(result.success).toBe(false);
            expect(result.error).toBe('DATA_VALIDATION_FAILED');
            expect(result.validationErrors).toBeDefined();
        });
    });
    
    describe('フィールド値フォーマットテスト', () => {
        test('ICカード番号のマスキング', () => {
            const testCases = [
                { input: '1234567890123456', expected: '1234********3456' },
                { input: '123456789012', expected: '1234****9012' },
                { input: '12345678', expected: '1234****' },
                { input: '123', expected: '****' },
                { input: '', expected: '****' },
                { input: null, expected: '****' },
                { input: undefined, expected: '****' }
            ];
            
            testCases.forEach(testCase => {
                const formatted = generator.formatFieldValue('icCardNumber', testCase.input, 'formal');
                expect(formatted).toBe(testCase.expected);
            });
        });
        
        test('日付フォーマット', () => {
            const testCases = [
                { input: '2024-01-15', expected: '2024/1/15' },
                { input: '2023-12-31', expected: '2023/12/31' },
                { input: 'invalid-date', expected: 'invalid-date' },
                { input: null, expected: '（未入力）' },
                { input: undefined, expected: '（未入力）' }
            ];
            
            testCases.forEach(testCase => {
                const formatted = generator.formatFieldValue('lossDate', testCase.input, 'formal');
                expect(formatted).toBe(testCase.expected);
            });
        });
        
        test('Yes/No値の日本語化', () => {
            const testCases = [
                { input: 'yes', expected: 'はい' },
                { input: 'Yes', expected: 'はい' },
                { input: 'YES', expected: 'はい' },
                { input: 'はい', expected: 'はい' },
                { input: 'no', expected: 'いいえ' },
                { input: 'No', expected: 'いいえ' },
                { input: 'いいえ', expected: 'いいえ' },
                { input: 'invalid', expected: 'いいえ' },
                { input: null, expected: 'いいえ' }
            ];
            
            testCases.forEach(testCase => {
                const formatted = generator.formatFieldValue('reportedToProvider', testCase.input, 'formal');
                expect(formatted).toBe(testCase.expected);
            });
        });
    });
    
    describe('テンプレート構造テスト', () => {
        test('ヘッダーの生成', () => {
            const template = { title: 'テストテンプレート' };
            const options = { documentNumber: 'DOC-001' };
            
            const header = generator.buildHeader(template, options);
            
            expect(header).toContain('テストテンプレート');
            expect(header).toContain('='.repeat('テストテンプレート'.length));
            expect(header).toContain('作成日:');
            expect(header).toContain('文書番号: DOC-001');
        });
        
        test('フッターの生成', () => {
            const template = { title: 'テスト' };
            const options = { includeSecurityNotice: true };
            
            const footer = generator.buildFooter(template, options);
            
            expect(footer).toContain('自動生成されたドキュメント');
            expect(footer).toContain('【セキュリティ注意事項】');
            expect(footer).toContain('個人情報が含まれています');
            expect(footer).toContain('Kintone ICカード紛失対応プラグイン v3.0.0');
            expect(footer).toContain('生成日時:');
        });
        
        test('セクション構築（フォーマル）', () => {
            const section = {
                title: 'テストセクション',
                fields: ['employeeName', 'department']
            };
            const data = {
                employeeName: '山田太郎',
                department: '総務部'
            };
            
            const sectionContent = generator.buildSection(section, data, 'formal');
            
            expect(sectionContent).toContain('## テストセクション');
            expect(sectionContent).toContain('**氏名**: 山田太郎');
            expect(sectionContent).toContain('**所属部署**: 総務部');
        });
        
        test('セクション構築（シンプル）', () => {
            const section = {
                title: 'シンプルセクション',
                fields: ['employeeName', 'lossDate']
            };
            const data = {
                employeeName: '田中花子',
                lossDate: '2024-01-15'
            };
            
            const sectionContent = generator.buildSection(section, data, 'simple');
            
            expect(sectionContent).toContain('## シンプルセクション');
            expect(sectionContent).toContain('氏名: 田中花子');
            expect(sectionContent).toContain('紛失日: 2024/1/15');
            expect(sectionContent).not.toContain('**'); // フォーマルな書式ではない
        });
    });
    
    describe('プレビュー機能テスト', () => {
        test('有効なテンプレートのプレビュー生成', () => {
            const result = generator.generatePreview('lossReport');
            
            expect(result.success).toBe(true);
            expect(result.preview).toBeDefined();
            expect(result.sampleData).toBeDefined();
            expect(result.preview).toContain('ICカード紛失届');
            expect(result.preview).toContain('SAMPLE-001');
            expect(result.sampleData.employeeName).toBe('山田太郎');
        });
        
        test('無効なテンプレートのプレビュー', () => {
            const result = generator.generatePreview('invalidTemplate');
            
            expect(result.success).toBe(false);
            expect(result.error).toContain('テンプレートが見つかりません');
        });
    });
    
    describe('利用可能テンプレート取得テスト', () => {
        test('全テンプレートの情報取得', () => {
            const templates = generator.getAvailableTemplates();
            
            expect(templates).toBeDefined();
            expect(templates.length).toBeGreaterThan(0);
            
            const expectedTemplates = ['lossReport', 'quickReport', 'transportationReport', 'supervisorReport'];
            expectedTemplates.forEach(templateKey => {
                const found = templates.find(t => t.key === templateKey);
                expect(found).toBeDefined();
                expect(found.title).toBeDefined();
                expect(found.format).toBeDefined();
                expect(found.sections).toBeGreaterThan(0);
            });
        });
    });
    
    describe('統計・メトリクステスト', () => {
        test('生成統計の記録', () => {
            const testData = {
                employeeName: '山田太郎',
                icCardNumber: '1234567890123456',
                lossDate: '2024-01-15'
            };
            
            // 複数のテンプレートを生成
            generator.generateTemplate('lossReport', testData);
            generator.generateTemplate('quickReport', testData);
            generator.generateTemplate('lossReport', testData);
            
            const stats = generator.getGenerationStats();
            
            expect(stats.templatesGenerated).toBe(3);
            expect(stats.templateTypes.lossReport).toBe(2);
            expect(stats.templateTypes.quickReport).toBe(1);
            expect(stats.lastGeneration).toBeDefined();
        });
        
        test('エラー統計の記録', () => {
            // 無効なテンプレートで複数回エラーを発生
            generator.generateTemplate('invalidTemplate', {});
            generator.generateTemplate('anotherInvalid', {});
            
            const stats = generator.getGenerationStats();
            
            expect(stats.errors).toBe(2);
            expect(stats.templatesGenerated).toBe(2);
            expect(stats.successRate).toBe('0.00%');
        });
        
        test('統計のリセット機能', () => {
            // 統計データを生成
            generator.generateTemplate('lossReport', { employeeName: 'テスト' });
            
            let stats = generator.getGenerationStats();
            expect(stats.templatesGenerated).toBe(1);
            
            // 統計をリセット
            generator.resetStats();
            
            stats = generator.getGenerationStats();
            expect(stats.templatesGenerated).toBe(0);
            expect(stats.templateTypes).toEqual({});
            expect(stats.errors).toBe(0);
        });
    });
    
    describe('エラーハンドリングテスト', () => {
        test('例外的なケースの処理', () => {
            const extremeCases = [
                { template: null, data: {} },
                { template: 'lossReport', data: null },
                { template: 'lossReport', data: undefined },
                { template: '', data: {} },
                { template: 'lossReport', data: 'invalid-data-type' }
            ];
            
            extremeCases.forEach(testCase => {
                const result = generator.generateTemplate(testCase.template, testCase.data);
                expect(result).toBeDefined();
                expect(result.success).toBeDefined();
                // エラーの場合は適切なエラーメッセージが含まれることを確認
                if (!result.success) {
                    expect(result.error).toBeDefined();
                    expect(result.message).toBeDefined();
                }
            });
        });
    });
});

describe('TemplateGenerator - Performance Tests', () => {
    let generator;
    
    beforeAll(() => {
        generator = new TemplateGenerator();
    });
    
    test('大量テンプレート生成のパフォーマンス', () => {
        const startTime = Date.now();
        const testData = {
            employeeName: '山田太郎',
            icCardNumber: '1234567890123456',
            lossDate: '2024-01-15',
            lossLocation: '名古屋駅'
        };
        
        // 100回のテンプレート生成
        for (let i = 0; i < 100; i++) {
            generator.generateTemplate('quickReport', {
                ...testData,
                employeeName: `テストユーザー${i}`
            });
        }
        
        const endTime = Date.now();
        const processingTime = endTime - startTime;
        
        // 100回の生成が5秒以内に完了することを確認
        expect(processingTime).toBeLessThan(5000);
        
        const stats = generator.getGenerationStats();
        expect(stats.templatesGenerated).toBe(100);
    });
    
    test('メモリ使用量の監視', () => {
        const initialMemory = process.memoryUsage().heapUsed;
        
        const largeData = {
            employeeName: '山田太郎',
            description: 'テストデータ'.repeat(1000), // 大きなテキスト
            notes: '備考'.repeat(500)
        };
        
        // 大容量データで複数回生成
        for (let i = 0; i < 50; i++) {
            generator.generateTemplate('lossReport', largeData);
        }
        
        const finalMemory = process.memoryUsage().heapUsed;
        const memoryIncrease = finalMemory - initialMemory;
        
        // メモリ使用量が50MB以下であることを確認
        expect(memoryIncrease).toBeLessThan(50 * 1024 * 1024);
    });
});

describe('TemplateGenerator - Integration Tests', () => {
    let generator;
    
    beforeEach(() => {
        generator = new TemplateGenerator();
    });
    
    test('完全なICカード紛失報告ワークフロー', () => {
        // ステップ1: 簡易報告書の生成
        const quickData = {
            reportDate: '2024-01-15',
            employeeName: '山田太郎',
            icCardNumber: '1234567890123456',
            lossDate: '2024-01-14',
            lossLocation: '名古屋駅'
        };
        
        const quickResult = generator.generateTemplate('quickReport', quickData);
        expect(quickResult.success).toBe(true);
        
        // ステップ2: 詳細報告書の生成
        const detailedData = {
            ...quickData,
            department: '総務部',
            email: 'yamada@company.com',
            phoneNumber: '03-1234-5678',
            cardType: 'MANACA',
            lossTime: '09:30',
            circumstances: '通勤時に紛失',
            transportationProvider: '名古屋市営地下鉄'
        };
        
        const detailedResult = generator.generateTemplate('lossReport', detailedData);
        expect(detailedResult.success).toBe(true);
        
        // ステップ3: 交通機関向け報告書の生成
        const transportResult = generator.generateTemplate('transportationReport', {
            ...detailedData,
            holderName: '山田太郎',
            companyName: '株式会社サンプル'
        });
        expect(transportResult.success).toBe(true);
        
        // ステップ4: 上司向け報告書の生成
        const supervisorResult = generator.generateTemplate('supervisorReport', {
            ...detailedData,
            impactAssessment: '業務への影響は軽微',
            immediateActions: '交通機関への連絡完了'
        });
        expect(supervisorResult.success).toBe(true);
        
        // 全てのテンプレートが生成され、適切にマスキングされていることを確認
        [quickResult, detailedResult, transportResult, supervisorResult].forEach(result => {
            expect(result.content).toContain('1234********3456');
            expect(result.content).not.toContain('1234567890123456');
        });
    });
    
    test('セキュリティが重要な環境での安全なテンプレート生成', () => {
        const sensitiveData = {
            employeeName: '重要人物',
            department: '機密部門',
            icCardNumber: '9999888877776666',
            lossLocation: '機密施設',
            email: 'confidential@secret.com',
            description: '機密情報を含む可能性のある紛失',
            notes: '特別な取り扱いが必要'
        };
        
        const result = generator.generateTemplate('lossReport', sensitiveData, {
            documentNumber: 'CONF-001',
            includeSecurityNotice: true
        });
        
        expect(result.success).toBe(true);
        
        // セキュリティ通知が含まれていることを確認
        expect(result.content).toContain('【セキュリティ注意事項】');
        expect(result.content).toContain('個人情報が含まれています');
        expect(result.content).toContain('適切に廃棄してください');
        
        // ICカード番号がマスキングされていることを確認
        expect(result.content).toContain('9999********6666');
        expect(result.content).not.toContain('9999888877776666');
        
        // 文書番号が含まれていることを確認
        expect(result.content).toContain('CONF-001');
    });
});
