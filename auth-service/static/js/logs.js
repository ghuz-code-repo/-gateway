// WebSocket Logs Client for Golden House Analytics Gateway
// Manages real-time log streaming with filtering, search, and export capabilities

class LogsViewer {
    constructor() {
        this.ws = null;
        this.currentService = 'all';
        this.isPaused = false;
        this.autoScroll = true;
        this.logs = [];
        this.filteredLogs = [];
        this.levelFilter = 'all';
        this.searchQuery = '';

        this.initializeUI();
        this.attachEventListeners();
        this.connect();
    }

    initializeUI() {
        this.logsContent = document.getElementById('logs-content');
        this.statusText = document.getElementById('status-text');
        this.statusDot = document.querySelector('.status-dot');
        this.logsCount = document.getElementById('logs-count');
        this.filteredCount = document.getElementById('filtered-count');
        this.currentServiceName = document.getElementById('current-service');
    }

    attachEventListeners() {
        // Service selection
        document.querySelectorAll('.service-item').forEach(item => {
            item.addEventListener('click', (e) => {
                this.selectService(e.currentTarget.dataset.service);
            });
        });

        // Level filter
        document.getElementById('level-filter').addEventListener('change', (e) => {
            this.levelFilter = e.target.value;
            this.applyFilters();
        });

        // Search input
        const searchInput = document.getElementById('search-input');
        searchInput.addEventListener('input', (e) => {
            this.searchQuery = e.target.value.toLowerCase();
            this.applyFilters();
        });

        // Control buttons
        document.getElementById('pause-btn').addEventListener('click', () => this.togglePause());
        document.getElementById('clear-btn').addEventListener('click', () => this.clearLogs());
        document.getElementById('export-btn').addEventListener('click', () => this.exportLogs());
        document.getElementById('autoscroll-btn').addEventListener('click', () => this.toggleAutoScroll());
    }

    connect() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/logs/ws?service=${this.currentService}&tail=100&follow=true`;

        this.updateStatus('Подключение...', 'connecting');

        try {
            this.ws = new WebSocket(wsUrl);

            this.ws.onopen = () => {
                this.updateStatus('Подключено', 'connected');
                this.clearEmptyState();
            };

            this.ws.onmessage = (event) => {
                try {
                    const logMessage = JSON.parse(event.data);
                    if (logMessage.error) {
                        console.error('Log error:', logMessage.error);
                        this.updateStatus('Ошибка: ' + logMessage.error, 'disconnected');
                    } else {
                        this.addLogLine(logMessage);
                    }
                } catch (error) {
                    console.error('Failed to parse log message:', error);
                }
            };

            this.ws.onerror = (error) => {
                console.error('WebSocket error:', error);
                this.updateStatus('Ошибка соединения', 'disconnected');
            };

            this.ws.onclose = () => {
                this.updateStatus('Отключено', 'disconnected');
                setTimeout(() => this.reconnect(), 3000);
            };
        } catch (error) {
            console.error('Failed to create WebSocket:', error);
            this.updateStatus('Ошибка подключения', 'disconnected');
        }
    }

    reconnect() {
        if (this.ws.readyState === WebSocket.CLOSED) {
            console.log('Reconnecting...');
            this.connect();
        }
    }

    selectService(service) {
        // Update active state
        document.querySelectorAll('.service-item').forEach(item => {
            item.classList.remove('active');
        });
        document.querySelector(`[data-service="${service}"]`).classList.add('active');

        // Update current service
        this.currentService = service;
        this.currentServiceName.textContent = service === 'all' ? 'Все сервисы' : service;

        // Clear logs and reconnect
        this.logs = [];
        this.clearLogs();
        
        if (this.ws) {
            this.ws.close();
        }
        this.connect();
    }

    addLogLine(logMessage) {
        if (this.isPaused) return;

        // Add to logs array
        this.logs.push(logMessage);

        // Apply filters
        if (this.shouldShowLog(logMessage)) {
            this.filteredLogs.push(logMessage);
            this.renderLogLine(logMessage);
        }

        // Update counter
        this.updateLogCount();

        // Auto-scroll
        if (this.autoScroll) {
            this.scrollToBottom();
        }
    }

    shouldShowLog(logMessage) {
        // Level filter
        if (this.levelFilter !== 'all' && logMessage.level !== this.levelFilter) {
            return false;
        }

        // Search filter
        if (this.searchQuery && !logMessage.message.toLowerCase().includes(this.searchQuery)) {
            return false;
        }

        return true;
    }

    renderLogLine(logMessage) {
        const logLine = document.createElement('div');
        logLine.className = `log-line ${logMessage.level}`;

        const timestamp = this.formatTimestamp(logMessage.timestamp);
        const message = this.highlightSearch(this.escapeHtml(logMessage.message));

        logLine.innerHTML = `
            <span class="log-timestamp">${timestamp}</span>
            <span class="log-service">${this.escapeHtml(logMessage.service)}</span>
            <span class="log-level">${logMessage.level}</span>
            <span class="log-message">${message}</span>
        `;

        this.logsContent.appendChild(logLine);

        // Limit to 1000 lines to prevent memory issues
        if (this.logsContent.childElementCount > 1000) {
            this.logsContent.removeChild(this.logsContent.firstChild);
        }
    }

    applyFilters() {
        // Clear displayed logs
        this.logsContent.innerHTML = '';

        // Re-render filtered logs
        this.filteredLogs = [];
        this.logs.forEach(log => {
            if (this.shouldShowLog(log)) {
                this.filteredLogs.push(log);
                this.renderLogLine(log);
            }
        });

        this.updateLogCount();
    }

    clearLogs() {
        this.logs = [];
        this.filteredLogs = [];
        this.logsContent.innerHTML = '';
        this.updateLogCount();
    }

    clearEmptyState() {
        const emptyState = this.logsContent.querySelector('.logs-empty');
        if (emptyState) {
            emptyState.remove();
        }
    }

    togglePause() {
        this.isPaused = !this.isPaused;
        const btn = document.getElementById('pause-btn');
        const icon = btn.querySelector('i');
        
        if (this.isPaused) {
            icon.className = 'fas fa-play';
            btn.classList.add('active');
            this.updateStatus('Пауза', 'connected');
        } else {
            icon.className = 'fas fa-pause';
            btn.classList.remove('active');
            this.updateStatus('Подключено', 'connected');
        }
    }

    toggleAutoScroll() {
        this.autoScroll = !this.autoScroll;
        const btn = document.getElementById('autoscroll-btn');
        
        if (this.autoScroll) {
            btn.classList.add('active');
            this.scrollToBottom();
        } else {
            btn.classList.remove('active');
        }
    }

    exportLogs() {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const filename = `logs-${this.currentService}-${timestamp}.txt`;

        let content = `# Логи сервиса: ${this.currentService}\n`;
        content += `# Экспортировано: ${new Date().toLocaleString('ru-RU')}\n`;
        content += `# Всего строк: ${this.filteredLogs.length}\n\n`;

        this.filteredLogs.forEach(log => {
            content += `[${log.timestamp}] [${log.service}] [${log.level}] ${log.message}\n`;
        });

        const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    updateStatus(text, status) {
        this.statusText.textContent = text;
        this.statusDot.className = `fas fa-circle status-dot ${status}`;
    }

    updateLogCount() {
        this.logsCount.textContent = `Строк: ${this.logs.length}`;
        
        if (this.filteredLogs.length < this.logs.length) {
            this.filteredCount.textContent = `Отфильтровано: ${this.filteredLogs.length}`;
        } else {
            this.filteredCount.textContent = '';
        }
    }

    scrollToBottom() {
        this.logsContent.scrollTop = this.logsContent.scrollHeight;
    }

    formatTimestamp(timestamp) {
        try {
            const date = new Date(timestamp);
            return date.toLocaleString('ru-RU', {
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                day: '2-digit',
                month: '2-digit'
            });
        } catch (error) {
            return timestamp;
        }
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    highlightSearch(text) {
        if (!this.searchQuery) return text;

        const regex = new RegExp(`(${this.escapeRegex(this.searchQuery)})`, 'gi');
        return text.replace(regex, '<mark>$1</mark>');
    }

    escapeRegex(text) {
        return text.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&');
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    new LogsViewer();
});
