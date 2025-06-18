/**
 * ICLossStatusDashboard.js
 * ICカード紛失状況ダッシュボードコンポーネント
 * IPAガイドライン準拠・セキュリティ対応
 * 
 * @author Kei-Adachi0709
 * @version 1.0.0
 * @date 2025-06-19
 * @compliance IPA安全なウェブサイトの作り方準拠
 */

// 依存関係インポート
const { CommonUtils, KintoneAPIHelper } = require('../common');
const InputValidator = require('../security/InputValidator');

/**
 * ICカード紛失状況ダッシュボードクラス
 */
class ICLossStatusDashboard {
  constructor(container, options = {}) {
    this.container = typeof container === 'string' ? document.getElementById(container) : container;
    this.options = {
      refreshInterval: 30000, // 30秒
      maxRecords: 100,
      enableRealTimeUpdate: true,
      showPersonalOnly: false,
      ...options
    };
    
    this.validator = new InputValidator();
    this.data = [];
    this.filteredData = [];
    this.currentUser = null;
    this.refreshTimer = null;
    this.isLoading = false;
    
    this.initialize();
  }

  /**
   * ダッシュボード初期化
   */
  async initialize() {
    try {
      // 現在のユーザー情報取得
      this.currentUser = kintone.getLoginUser();
      
      // プラグイン設定確認
      await this.loadPluginConfig();
      
      // 初期データ読み込み
      await this.loadData();
      
      // UI描画
      this.render();
      
      // イベントリスナー設定
      this.setupEventListeners();
      
      // リアルタイム更新開始
      if (this.options.enableRealTimeUpdate) {
        this.startRealTimeUpdate();
      }
      
      console.log('ICカード紛失状況ダッシュボードが初期化されました');
    } catch (error) {
      console.error('ダッシュボード初期化エラー:', error);
      this.showError('ダッシュボードの初期化に失敗しました');
    }
  }

  /**
   * プラグイン設定読み込み
   */
  async loadPluginConfig() {
    const config = kintone.plugin.app.getConfig();
    if (!config || config.plugin_enabled !== 'true') {
      throw new Error('プラグインが無効です');
    }
    
    this.config = config;
  }

  /**
   * データ読み込み
   */
  async loadData() {
    if (this.isLoading) return;
    
    this.isLoading = true;
    
    try {
      CommonUtils.showLoading(true, 'データ読み込み中...');
      
      // クエリ構築
      let query = 'report_type = "ICカード紛失" order by submitted_at desc';
      
      if (this.options.showPersonalOnly && this.currentUser) {
        // 個人の報告のみ表示（ハッシュ化された社員番号での比較は困難なため、報告者名で比較）
        query = `report_type = "ICカード紛失" and reporter_name = "${this.currentUser.name}" order by submitted_at desc`;
      }
      
      const result = await KintoneAPIHelper.getRecordsSecurely({
        query: query,
        fields: [
          'レコード番号',
          'reporter_name',
          'reporter_department', 
          'card_type',
          'loss_date',
          'loss_location',
          'status',
          'priority',
          'submitted_at',
          'submission_id',
          'updated_at',
          'assignee'
        ]
      });
      
      if (result.success) {
        this.data = result.records;
        this.applyFilters();
        this.updateUI();
      } else {
        throw new Error(result.error);
      }
      
    } catch (error) {
      console.error('データ読み込みエラー:', error);
      this.showError('データの読み込みに失敗しました');
    } finally {
      this.isLoading = false;
      CommonUtils.showLoading(false);
    }
  }

  /**
   * ダッシュボードHTML生成
   */
  render() {
    if (!this.container) {
      throw new Error('ダッシュボードコンテナが見つかりません');
    }

    this.container.innerHTML = `
      <div class="ic-loss-dashboard" role="main" aria-labelledby="dashboard-title">
        <header class="dashboard-header">
          <h2 id="dashboard-title" class="dashboard-title">
            <span class="icon" aria-hidden="true">📊</span>
            ICカード紛失状況ダッシュボード
          </h2>
          
          <div class="dashboard-controls">
            <div class="view-toggles" role="group" aria-label="表示切り替え">
              <button type="button" 
                      class="btn btn-outline ${!this.options.showPersonalOnly ? 'active' : ''}"
                      id="view-all-btn"
                      aria-pressed="${!this.options.showPersonalOnly}">
                全体表示
              </button>
              <button type="button" 
                      class="btn btn-outline ${this.options.showPersonalOnly ? 'active' : ''}"
                      id="view-personal-btn"
                      aria-pressed="${this.options.showPersonalOnly}">
                個人の報告
              </button>
            </div>
            
            <button type="button" 
                    class="btn btn-secondary"
                    id="refresh-btn"
                    aria-label="データを更新">
              <span class="icon" aria-hidden="true">🔄</span>
              更新
            </button>
            
            <button type="button" 
                    class="btn btn-primary"
                    id="new-report-btn"
                    aria-label="新しい報告を作成">
              <span class="icon" aria-hidden="true">➕</span>
              新規報告
            </button>
          </div>
        </header>

        <!-- 統計サマリー -->
        <section class="dashboard-summary" aria-labelledby="summary-title">
          <h3 id="summary-title" class="sr-only">統計サマリー</h3>
          <div class="summary-cards" id="summary-cards">
            <!-- 統計カードはJavaScriptで動的生成 -->
          </div>
        </section>

        <!-- フィルターとソート -->
        <section class="dashboard-filters" aria-labelledby="filters-title">
          <h3 id="filters-title" class="sr-only">フィルターとソート</h3>
          <div class="filter-controls">
            <div class="filter-group">
              <label for="status-filter" class="filter-label">ステータス</label>
              <select id="status-filter" class="form-control filter-select">
                <option value="">すべて</option>
                <option value="報告受付">報告受付</option>
                <option value="調査中">調査中</option>
                <option value="対応中">対応中</option>
                <option value="完了">完了</option>
                <option value="キャンセル">キャンセル</option>
              </select>
            </div>
            
            <div class="filter-group">
              <label for="priority-filter" class="filter-label">優先度</label>
              <select id="priority-filter" class="form-control filter-select">
                <option value="">すべて</option>
                <option value="緊急">緊急</option>
                <option value="高">高</option>
                <option value="中">中</option>
                <option value="低">低</option>
              </select>
            </div>
            
            <div class="filter-group">
              <label for="card-type-filter" class="filter-label">カード種類</label>
              <select id="card-type-filter" class="form-control filter-select">
                <option value="">すべて</option>
                <option value="Suica">Suica</option>
                <option value="PASMO">PASMO</option>
                <option value="ICOCA">ICOCA</option>
                <option value="社員証">社員証</option>
                <option value="その他">その他</option>
              </select>
            </div>
            
            <div class="filter-group">
              <label for="date-filter" class="filter-label">期間</label>
              <select id="date-filter" class="form-control filter-select">
                <option value="">すべて</option>
                <option value="today">今日</option>
                <option value="week">過去7日</option>
                <option value="month">過去30日</option>
                <option value="quarter">過去3ヶ月</option>
              </select>
            </div>

            <div class="filter-group">
              <label for="search-input" class="filter-label">検索</label>
              <input type="text" 
                     id="search-input" 
                     class="form-control search-input"
                     placeholder="報告者名、場所で検索..."
                     aria-describedby="search-help">
              <div id="search-help" class="sr-only">
                報告者名や紛失場所でレコードを検索できます
              </div>
            </div>
            
            <button type="button" 
                    class="btn btn-outline filter-clear-btn"
                    id="clear-filters-btn">
              フィルタークリア
            </button>
          </div>
        </section>

        <!-- データテーブル -->
        <section class="dashboard-table-section" aria-labelledby="table-title">
          <div class="table-header">
            <h3 id="table-title">報告一覧</h3>
            <div class="table-info">
              <span id="record-count" class="record-count">0件</span>
              <span class="last-updated" id="last-updated"></span>
            </div>
          </div>
          
          <div class="table-container">
            <table class="dashboard-table" 
                   id="reports-table"
                   role="table"
                   aria-labelledby="table-title"
                   aria-describedby="table-description">
              <caption id="table-description" class="sr-only">
                ICカード紛失報告の一覧。各行をクリックして詳細を表示できます。
              </caption>
              <thead>
                <tr>
                  <th scope="col" class="sortable" data-sort="submitted_at" aria-sort="descending">
                    <button type="button" class="sort-button">
                      報告日時
                      <span class="sort-indicator" aria-hidden="true">↓</span>
                    </button>
                  </th>
                  <th scope="col" class="sortable" data-sort="reporter_name">
                    <button type="button" class="sort-button">
                      報告者
                      <span class="sort-indicator" aria-hidden="true"></span>
                    </button>
                  </th>
                  <th scope="col" class="sortable" data-sort="reporter_department">
                    <button type="button" class="sort-button">
                      部署
                      <span class="sort-indicator" aria-hidden="true"></span>
                    </button>
                  </th>
                  <th scope="col" class="sortable" data-sort="card_type">
                    <button type="button" class="sort-button">
                      カード種類
                      <span class="sort-indicator" aria-hidden="true"></span>
                    </button>
                  </th>
                  <th scope="col" class="sortable" data-sort="loss_date">
                    <button type="button" class="sort-button">
                      紛失日時
                      <span class="sort-indicator" aria-hidden="true"></span>
                    </button>
                  </th>
                  <th scope="col">紛失場所</th>
                  <th scope="col" class="sortable" data-sort="status">
                    <button type="button" class="sort-button">
                      ステータス
                      <span class="sort-indicator" aria-hidden="true"></span>
                    </button>
                  </th>
                  <th scope="col" class="sortable" data-sort="priority">
                    <button type="button" class="sort-button">
                      優先度
                      <span class="sort-indicator" aria-hidden="true"></span>
                    </button>
                  </th>
                  <th scope="col">操作</th>
                </tr>
              </thead>
              <tbody id="reports-table-body">
                <!-- データはJavaScriptで動的生成 -->
              </tbody>
            </table>
            
            <div id="no-data-message" class="no-data-message hidden" role="status">
              <div class="no-data-icon" aria-hidden="true">📭</div>
              <h4>表示するデータがありません</h4>
              <p>フィルター条件を変更するか、新しい報告を作成してください。</p>
            </div>
          </div>
        </section>

        <!-- ページネーション -->
        <nav class="dashboard-pagination" aria-label="ページネーション" id="pagination-nav">
          <!-- ページネーションはJavaScriptで動的生成 -->
        </nav>

        <!-- 詳細モーダル -->
        <div id="detail-modal" class="modal" role="dialog" aria-labelledby="modal-title" aria-hidden="true">
          <div class="modal-overlay" aria-hidden="true"></div>
          <div class="modal-content">
            <header class="modal-header">
              <h3 id="modal-title" class="modal-title">報告詳細</h3>
              <button type="button" 
                      class="modal-close" 
                      aria-label="モーダルを閉じる"
                      id="close-modal-btn">
                <span aria-hidden="true">×</span>
              </button>
            </header>
            <div class="modal-body" id="modal-body">
              <!-- 詳細内容はJavaScriptで動的生成 -->
            </div>
            <footer class="modal-footer">
              <button type="button" class="btn btn-secondary" id="modal-close-btn">
                閉じる
              </button>
            </footer>
          </div>
        </div>
      </div>
    `;
  }

  /**
   * イベントリスナー設定
   */
  setupEventListeners() {
    // 表示切り替えボタン
    const viewAllBtn = this.container.querySelector('#view-all-btn');
    const viewPersonalBtn = this.container.querySelector('#view-personal-btn');
    
    if (viewAllBtn) {
      viewAllBtn.addEventListener('click', () => this.switchView(false));
    }
    
    if (viewPersonalBtn) {
      viewPersonalBtn.addEventListener('click', () => this.switchView(true));
    }

    // 更新ボタン
    const refreshBtn = this.container.querySelector('#refresh-btn');
    if (refreshBtn) {
      refreshBtn.addEventListener('click', () => this.loadData());
    }

    // 新規報告ボタン
    const newReportBtn = this.container.querySelector('#new-report-btn');
    if (newReportBtn) {
      newReportBtn.addEventListener('click', () => this.showNewReportForm());
    }

    // フィルター
    const filterElements = this.container.querySelectorAll('.filter-select, .search-input');
    filterElements.forEach(element => {
      element.addEventListener('change', () => this.applyFilters());
      if (element.type === 'text') {
        element.addEventListener('input', CommonUtils.debounce(() => this.applyFilters(), 500));
      }
    });

    // フィルタークリア
    const clearFiltersBtn = this.container.querySelector('#clear-filters-btn');
    if (clearFiltersBtn) {
      clearFiltersBtn.addEventListener('click', () => this.clearFilters());
    }

    // ソート
    const sortButtons = this.container.querySelectorAll('.sort-button');
    sortButtons.forEach(button => {
      button.addEventListener('click', (e) => {
        const th = e.target.closest('th');
        const sortKey = th.dataset.sort;
        if (sortKey) {
          this.toggleSort(sortKey, th);
        }
      });
    });

    // モーダル制御
    const closeModalBtn = this.container.querySelector('#close-modal-btn');
    const modalCloseBtn = this.container.querySelector('#modal-close-btn');
    const modalOverlay = this.container.querySelector('.modal-overlay');
    
    [closeModalBtn, modalCloseBtn, modalOverlay].forEach(element => {
      if (element) {
        element.addEventListener('click', () => this.closeModal());
      }
    });

    // ESCキーでモーダルを閉じる
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        this.closeModal();
      }
    });

    // テーブル行クリック
    this.container.addEventListener('click', (e) => {
      const row = e.target.closest('tr[data-record-id]');
      if (row) {
        const recordId = row.dataset.recordId;
        this.showDetailModal(recordId);
      }
    });
  }

  /**
   * 表示切り替え
   * @param {boolean} showPersonalOnly - 個人のみ表示
   */
  async switchView(showPersonalOnly) {
    this.options.showPersonalOnly = showPersonalOnly;
    
    // ボタンの状態更新
    const viewAllBtn = this.container.querySelector('#view-all-btn');
    const viewPersonalBtn = this.container.querySelector('#view-personal-btn');
    
    if (viewAllBtn && viewPersonalBtn) {
      viewAllBtn.classList.toggle('active', !showPersonalOnly);
      viewAllBtn.setAttribute('aria-pressed', !showPersonalOnly);
      
      viewPersonalBtn.classList.toggle('active', showPersonalOnly);
      viewPersonalBtn.setAttribute('aria-pressed', showPersonalOnly);
    }

    // データ再読み込み
    await this.loadData();
  }

  /**
   * フィルター適用
   */
  applyFilters() {
    const statusFilter = this.container.querySelector('#status-filter')?.value || '';
    const priorityFilter = this.container.querySelector('#priority-filter')?.value || '';
    const cardTypeFilter = this.container.querySelector('#card-type-filter')?.value || '';
    const dateFilter = this.container.querySelector('#date-filter')?.value || '';
    const searchInput = this.container.querySelector('#search-input')?.value.trim().toLowerCase() || '';

    this.filteredData = this.data.filter(record => {
      // ステータスフィルター
      if (statusFilter && record.status?.value !== statusFilter) {
        return false;
      }

      // 優先度フィルター
      if (priorityFilter && record.priority?.value !== priorityFilter) {
        return false;
      }

      // カード種類フィルター
      if (cardTypeFilter && record.card_type?.value !== cardTypeFilter) {
        return false;
      }

      // 日付フィルター
      if (dateFilter && !this.matchesDateFilter(record.submitted_at?.value, dateFilter)) {
        return false;
      }

      // 検索フィルター
      if (searchInput) {
        const reporterName = (record.reporter_name?.value || '').toLowerCase();
        const lossLocation = (record.loss_location?.value || '').toLowerCase();
        
        if (!reporterName.includes(searchInput) && !lossLocation.includes(searchInput)) {
          return false;
        }
      }

      return true;
    });

    this.updateUI();
  }

  /**
   * 日付フィルター判定
   * @param {string} dateString - 対象日付文字列
   * @param {string} filterType - フィルタータイプ
   * @returns {boolean} マッチ結果
   */
  matchesDateFilter(dateString, filterType) {
    if (!dateString) return false;

    const targetDate = new Date(dateString);
    const now = new Date();
    const diffTime = now - targetDate;
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

    switch (filterType) {
      case 'today':
        return diffDays <= 1;
      case 'week':
        return diffDays <= 7;
      case 'month':
        return diffDays <= 30;
      case 'quarter':
        return diffDays <= 90;
      default:
        return true;
    }
  }

  /**
   * フィルタークリア
   */
  clearFilters() {
    const filterElements = this.container.querySelectorAll('.filter-select, .search-input');
    filterElements.forEach(element => {
      element.value = '';
    });

    this.applyFilters();
    CommonUtils.showNotification('フィルターがクリアされました', 'info');
  }

  /**
   * ソート切り替え
   * @param {string} sortKey - ソートキー
   * @param {HTMLElement} th - ヘッダー要素
   */
  toggleSort(sortKey, th) {
    const currentSort = th.getAttribute('aria-sort');
    let newSort = 'ascending';
    
    if (currentSort === 'ascending') {
      newSort = 'descending';
    }

    // 他のソート状態をクリア
    this.container.querySelectorAll('th[aria-sort]').forEach(header => {
      header.removeAttribute('aria-sort');
      const indicator = header.querySelector('.sort-indicator');
      if (indicator) {
        indicator.textContent = '';
      }
    });

    // 新しいソート状態を設定
    th.setAttribute('aria-sort', newSort);
    const indicator = th.querySelector('.sort-indicator');
    if (indicator) {
      indicator.textContent = newSort === 'ascending' ? '↑' : '↓';
    }

    // データソート
    this.sortData(sortKey, newSort === 'ascending');
  }

  /**
   * データソート
   * @param {string} key - ソートキー
   * @param {boolean} ascending - 昇順かどうか
   */
  sortData(key, ascending) {
    this.filteredData.sort((a, b) => {
      let valueA = a[key]?.value || '';
      let valueB = b[key]?.value || '';

      // 日付の場合は Date オブジェクトに変換
      if (key.includes('date') || key === 'submitted_at') {
        valueA = new Date(valueA);
        valueB = new Date(valueB);
      }

      if (valueA < valueB) {
        return ascending ? -1 : 1;
      }
      if (valueA > valueB) {
        return ascending ? 1 : -1;
      }
      return 0;
    });

    this.updateTableBody();
  }

  /**
   * UI更新
   */
  updateUI() {
    this.updateSummaryCards();
    this.updateTableBody();
    this.updateRecordCount();
    this.updateLastUpdated();
  }

  /**
   * サマリーカード更新
   */
  updateSummaryCards() {
    const summaryContainer = this.container.querySelector('#summary-cards');
    if (!summaryContainer) return;

    const stats = this.calculateStatistics();
    
    summaryContainer.innerHTML = `
      <div class="summary-card total" role="region" aria-labelledby="total-title">
        <div class="card-header">
          <h4 id="total-title" class="card-title">総報告数</h4>
          <span class="card-icon" aria-hidden="true">📊</span>
        </div>
        <div class="card-value" aria-label="総報告数">${stats.total}</div>
        <div class="card-description">件</div>
      </div>

      <div class="summary-card urgent" role="region" aria-labelledby="urgent-title">
        <div class="card-header">
          <h4 id="urgent-title" class="card-title">緊急対応</h4>
          <span class="card-icon" aria-hidden="true">🚨</span>
        </div>
        <div class="card-value urgent-count" aria-label="緊急対応数">${stats.urgent}</div>
        <div class="card-description">件</div>
      </div>

      <div class="summary-card in-progress" role="region" aria-labelledby="progress-title">
        <div class="card-header">
          <h4 id="progress-title" class="card-title">対応中</h4>
          <span class="card-icon" aria-hidden="true">⏳</span>
        </div>
        <div class="card-value" aria-label="対応中数">${stats.inProgress}</div>
        <div class="card-description">件</div>
      </div>

      <div class="summary-card completed" role="region" aria-labelledby="completed-title">
        <div class="card-header">
          <h4 id="completed-title" class="card-title">完了</h4>
          <span class="card-icon" aria-hidden="true">✅</span>
        </div>
        <div class="card-value" aria-label="完了数">${stats.completed}</div>
        <div class="card-description">件</div>
      </div>

      <div class="summary-card today" role="region" aria-labelledby="today-title">
        <div class="card-header">
          <h4 id="today-title" class="card-title">本日の報告</h4>
          <span class="card-icon" aria-hidden="true">📅</span>
        </div>
        <div class="card-value" aria-label="本日の報告数">${stats.today}</div>
        <div class="card-description">件</div>
      </div>
    `;
  }

  /**
   * 統計計算
   * @returns {Object} 統計データ
   */
  calculateStatistics() {
    const stats = {
      total: this.filteredData.length,
      urgent: 0,
      inProgress: 0,
      completed: 0,
      today: 0
    };

    const today = new Date();
    today.setHours(0, 0, 0, 0);

    this.filteredData.forEach(record => {
      // 優先度
      if (record.priority?.value === '緊急') {
        stats.urgent++;
      }

      // ステータス
      const status = record.status?.value;
      if (status === '調査中' || status === '対応中') {
        stats.inProgress++;
      } else if (status === '完了') {
        stats.completed++;
      }

      // 本日の報告
      const submittedDate = new Date(record.submitted_at?.value);
      if (submittedDate >= today) {
        stats.today++;
      }
    });

    return stats;
  }

  /**
   * テーブル本体更新
   */
  updateTableBody() {
    const tbody = this.container.querySelector('#reports-table-body');
    const noDataMessage = this.container.querySelector('#no-data-message');
    
    if (!tbody) return;

    if (this.filteredData.length === 0) {
      tbody.innerHTML = '';
      if (noDataMessage) {
        noDataMessage.classList.remove('hidden');
      }
      return;
    }

    if (noDataMessage) {
      noDataMessage.classList.add('hidden');
    }

    tbody.innerHTML = this.filteredData.map(record => this.generateTableRow(record)).join('');
  }

  /**
   * テーブル行生成
   * @param {Object} record - レコードデータ
   * @returns {string} テーブル行HTML
   */
  generateTableRow(record) {
    const recordId = record['レコード番号']?.value || '';
    const reporterName = CommonUtils.escapeHtml(record.reporter_name?.value || '');
    const department = CommonUtils.escapeHtml(record.reporter_department?.value || '');
    const cardType = CommonUtils.escapeHtml(record.card_type?.value || '');
    const lossDate = this.formatDate(record.loss_date?.value);
    const lossLocation = CommonUtils.escapeHtml(this.truncateText(record.loss_location?.value || '', 30));
    const status = record.status?.value || '';
    const priority = record.priority?.value || '';
    const submittedAt = this.formatDate(record.submitted_at?.value);

    const statusClass = this.getStatusClass(status);
    const priorityClass = this.getPriorityClass(priority);

    return `
      <tr data-record-id="${recordId}" 
          class="table-row" 
          tabindex="0" 
          role="button"
          aria-label="報告詳細を表示: ${reporterName}さんの${cardType}紛失報告">
        <td>
          <time datetime="${record.submitted_at?.value}">
            ${submittedAt}
          </time>
        </td>
        <td>
          <span class="reporter-name">${reporterName}</span>
        </td>
        <td>
          <span class="department">${department}</span>
        </td>
        <td>
          <span class="card-type">${cardType}</span>
        </td>
        <td>
          <time datetime="${record.loss_date?.value}">
            ${lossDate}
          </time>
        </td>
        <td>
          <span class="loss-location" title="${CommonUtils.escapeHtml(record.loss_location?.value || '')}">
            ${lossLocation}
          </span>
        </td>
        <td>
          <span class="status-badge ${statusClass}" 
                role="status" 
                aria-label="ステータス: ${status}">
            ${CommonUtils.escapeHtml(status)}
          </span>
        </td>
        <td>
          <span class="priority-badge ${priorityClass}" 
                role="status" 
                aria-label="優先度: ${priority}">
            ${CommonUtils.escapeHtml(priority)}
          </span>
        </td>
        <td>
          <div class="action-buttons">
            <button type="button" 
                    class="btn btn-sm btn-outline"
                    onclick="event.stopPropagation(); window.icLossDashboard.showDetailModal('${recordId}')"
                    aria-label="詳細を表示">
              詳細
            </button>
          </div>
        </td>
      </tr>
    `;
  }

  /**
   * ステータスCSSクラス取得
   * @param {string} status - ステータス
   * @returns {string} CSSクラス
   */
  getStatusClass(status) {
    const statusClasses = {
      '報告受付': 'status-received',
      '調査中': 'status-investigating',
      '対応中': 'status-responding',
      '完了': 'status-completed',
      'キャンセル': 'status-cancelled'
    };
    return statusClasses[status] || 'status-unknown';
  }

  /**
   * 優先度CSSクラス取得
   * @param {string} priority - 優先度
   * @returns {string} CSSクラス
   */
  getPriorityClass(priority) {
    const priorityClasses = {
      '緊急': 'priority-urgent',
      '高': 'priority-high',
      '中': 'priority-medium',
      '低': 'priority-low'
    };
    return priorityClasses[priority] || 'priority-unknown';
  }

  /**
   * テキスト切り詰め
   * @param {string} text - 対象テキスト
   * @param {number} maxLength - 最大長
   * @returns {string} 切り詰めテキスト
   */
  truncateText(text, maxLength) {
    if (!text || text.length <= maxLength) return text;
    return text.substring(0, maxLength) + '...';
  }

  /**
   * 日付フォーマット
   * @param {string} dateString - 日付文字列
   * @returns {string} フォーマット済み日付
   */
  formatDate(dateString) {
    if (!dateString) return '';
    
    try {
      const date = new Date(dateString);
      return CommonUtils.formatDate(date, 'MM/DD HH:mm');
    } catch (error) {
      console.error('日付フォーマットエラー:', error);
      return dateString;
    }
  }

  /**
   * レコード数更新
   */
  updateRecordCount() {
    const recordCountElement = this.container.querySelector('#record-count');
    if (recordCountElement) {
      recordCountElement.textContent = `${this.filteredData.length}件`;
    }
  }

  /**
   * 最終更新時刻更新
   */
  updateLastUpdated() {
    const lastUpdatedElement = this.container.querySelector('#last-updated');
    if (lastUpdatedElement) {
      const now = new Date();
      lastUpdatedElement.textContent = `最終更新: ${CommonUtils.formatDate(now, 'HH:mm:ss')}`;
    }
  }

  /**
   * 詳細モーダル表示
   * @param {string} recordId - レコードID
   */
  async showDetailModal(recordId) {
    const record = this.data.find(r => r['レコード番号']?.value === recordId);
    if (!record) {
      CommonUtils.showNotification('レコードが見つかりません', 'error');
      return;
    }

    const modal = this.container.querySelector('#detail-modal');
    const modalBody = this.container.querySelector('#modal-body');
    
    if (!modal || !modalBody) return;

    // モーダル内容生成
    modalBody.innerHTML = this.generateDetailContent(record);
    
    // モーダル表示
    modal.classList.add('active');
    modal.setAttribute('aria-hidden', 'false');
    
    // フォーカス管理
    const closeButton = modal.querySelector('#close-modal-btn');
    if (closeButton) {
      CommonUtils.setAccessibleFocus(closeButton);
    }

    // 背景スクロール無効化
    document.body.style.overflow = 'hidden';
  }

  /**
   * 詳細内容生成
   * @param {Object} record - レコードデータ
   * @returns {string} 詳細HTML
   */
  generateDetailContent(record) {
    return `
      <div class="detail-content">
        <div class="detail-header">
          <div class="detail-status">
            <span class="status-badge ${this.getStatusClass(record.status?.value)}">
              ${CommonUtils.escapeHtml(record.status?.value || '')}
            </span>
            <span class="priority-badge ${this.getPriorityClass(record.priority?.value)}">
              ${CommonUtils.escapeHtml(record.priority?.value || '')}
            </span>
          </div>
          <div class="detail-meta">
            <p><strong>受付番号:</strong> ${CommonUtils.escapeHtml(record.submission_id?.value || '')}</p>
            <p><strong>報告日時:</strong> ${this.formatDetailDate(record.submitted_at?.value)}</p>
          </div>
        </div>

        <div class="detail-sections">
          <section class="detail-section">
            <h4>報告者情報</h4>
            <dl class="detail-list">
              <dt>氏名</dt>
              <dd>${CommonUtils.escapeHtml(record.reporter_name?.value || '')}</dd>
              <dt>所属部署</dt>
              <dd>${CommonUtils.escapeHtml(record.reporter_department?.value || '')}</dd>
            </dl>
          </section>

          <section class="detail-section">
            <h4>カード情報</h4>
            <dl class="detail-list">
              <dt>カード種類</dt>
              <dd>${CommonUtils.escapeHtml(record.card_type?.value || '')}</dd>
              <dt>残高（概算）</dt>
              <dd>${record.card_balance?.value ? record.card_balance.value + '円' : '不明'}</dd>
              <dt>付帯機能</dt>
              <dd>${CommonUtils.escapeHtml(record.card_features?.value || '未選択')}</dd>
            </dl>
          </section>

          <section class="detail-section">
            <h4>紛失詳細</h4>
            <dl class="detail-list">
              <dt>紛失日時</dt>
              <dd>${this.formatDetailDate(record.loss_date?.value)}</dd>
              <dt>紛失場所</dt>
              <dd>${CommonUtils.escapeHtml(record.loss_location?.value || '')}</dd>
              <dt>紛失状況</dt>
              <dd class="long-text">${CommonUtils.escapeHtml(record.loss_circumstances?.value || '')}</dd>
              <dt>発見の経緯</dt>
              <dd>${CommonUtils.escapeHtml(record.discovery_timing?.value || '')}</dd>
              <dt>実施した対応</dt>
              <dd>${CommonUtils.escapeHtml(record.actions_taken?.value || '未実施')}</dd>
            </dl>
          </section>

          ${record.assignee?.value ? `
          <section class="detail-section">
            <h4>対応状況</h4>
            <dl class="detail-list">
              <dt>担当者</dt>
              <dd>${CommonUtils.escapeHtml(record.assignee.value)}</dd>
              <dt>最終更新</dt>
              <dd>${this.formatDetailDate(record.updated_at?.value)}</dd>
            </dl>
          </section>
          ` : ''}
        </div>
      </div>
    `;
  }

  /**
   * 詳細日付フォーマット
   * @param {string} dateString - 日付文字列
   * @returns {string} フォーマット済み日付
   */
  formatDetailDate(dateString) {
    if (!dateString) return '不明';
    
    try {
      const date = new Date(dateString);
      return CommonUtils.formatDate(date, 'YYYY年MM月DD日 HH:mm');
    } catch (error) {
      console.error('詳細日付フォーマットエラー:', error);
      return dateString;
    }
  }

  /**
   * モーダル閉じる
   */
  closeModal() {
    const modal = this.container.querySelector('#detail-modal');
    if (modal) {
      modal.classList.remove('active');
      modal.setAttribute('aria-hidden', 'true');
    }

    // 背景スクロール復元
    document.body.style.overflow = '';
  }

  /**
   * 新規報告フォーム表示
   */
  showNewReportForm() {
    // 新規報告フォームへの遷移またはモーダル表示
    // 実装は要件に応じて調整
    if (typeof window.showNewReportForm === 'function') {
      window.showNewReportForm();
    } else {
      CommonUtils.showNotification('新規報告フォームが見つかりません', 'warning');
    }
  }

  /**
   * リアルタイム更新開始
   */
  startRealTimeUpdate() {
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
    }

    this.refreshTimer = setInterval(() => {
      if (!this.isLoading) {
        this.loadData();
      }
    }, this.options.refreshInterval);
  }

  /**
   * リアルタイム更新停止
   */
  stopRealTimeUpdate() {
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = null;
    }
  }

  /**
   * エラー表示
   * @param {string} message - エラーメッセージ
   */
  showError(message) {
    CommonUtils.showNotification(message, 'error');
  }

  /**
   * コンポーネント破棄
   */
  destroy() {
    // リアルタイム更新停止
    this.stopRealTimeUpdate();

    // イベントリスナーの削除
    if (this.container) {
      this.container.innerHTML = '';
    }
  }
}

// エクスポート
if (typeof module !== 'undefined' && module.exports) {
  module.exports = ICLossStatusDashboard;
}

// ブラウザ環境でのグローバル変数設定
if (typeof window !== 'undefined') {
  window.ICLossStatusDashboard = ICLossStatusDashboard;
}
