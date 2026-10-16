/**
 * WireGuard Status Dashboard Client
 * Clean enterprise-grade DOM reconciliation, search/filters, mobile card view,
 * device comment names & custom aliases, and telemetry polling.
 */

let currentFilter = 'online';
let currentSearch = '';
let isUpdating = false;

const ICON_COPY = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>`;
const ICON_CHECK = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>`;
const ICON_CHART = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="20" x2="18" y2="10"></line><line x1="12" y1="20" x2="12" y2="4"></line><line x1="6" y1="20" x2="6" y2="14"></line></svg>`;
const ICON_HISTORY = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>`;
const ICON_EDIT = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"></path><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"></path></svg>`;

// Theme Management (Defaults to Stealth Dark, toggles light-mode)
function initDarkMode() {
    const saved = localStorage.getItem('wgstatus_theme');
    const isLight = saved === 'light';
    if (isLight) {
        document.body.classList.add('light-mode');
    } else {
        document.body.classList.remove('light-mode');
    }
    updateThemeControls(!isLight);
}

function toggleDarkMode() {
    const isLight = document.body.classList.toggle('light-mode');
    const isDark = !isLight;
    localStorage.setItem('wgstatus_theme', isLight ? 'light' : 'dark');
    updateThemeControls(isDark);
    if (typeof updateChartTheme === 'function') {
        updateChartTheme();
    }
    if (typeof updateAnalyticsChartsTheme === 'function') {
        updateAnalyticsChartsTheme();
    }
}

function updateThemeControls(isDark) {
    const moon = document.getElementById('theme-icon-moon');
    const sun = document.getElementById('theme-icon-sun');
    const label = document.getElementById('theme-label');
    if (moon && sun) {
        moon.style.display = isDark ? 'none' : 'inline-block';
        sun.style.display = isDark ? 'inline-block' : 'none';
    }
    if (label) {
        label.textContent = isDark ? 'Light' : 'Dark';
    }
}

// Filter and Search Handlers
function setFilter(filterType, element) {
    currentFilter = filterType;
    document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
    if (element) element.classList.add('active');
    applyClientFilters();
}

function onSearchInput(val) {
    currentSearch = (val || '').toLowerCase().trim();
    applyClientFilters();
}

function applyClientFilters() {
    const rows = document.querySelectorAll('#status-table-body tr[data-ip]');
    let visibleCount = 0;

    rows.forEach(row => {
        const ip = (row.dataset.ip || '').toLowerCase();
        const name = (row.dataset.name || '').toLowerCase();
        const endpoint = (row.dataset.endpoint || '').toLowerCase();
        const isp = (row.dataset.isp || '').toLowerCase();
        const isOnline = row.dataset.online === 'true';
        const sinceRestart = row.dataset.sinceRestart === 'true';

        let matchesFilter = true;
        if (currentFilter === 'online' && !isOnline) matchesFilter = false;
        if (currentFilter === 'offline' && isOnline) matchesFilter = false;
        if (currentFilter === 'since_restart' && !sinceRestart) matchesFilter = false;

        let matchesSearch = true;
        if (currentSearch) {
            matchesSearch = name.includes(currentSearch) || ip.includes(currentSearch) || endpoint.includes(currentSearch) || isp.includes(currentSearch);
        }

        if (matchesFilter && matchesSearch) {
            row.style.display = '';
            visibleCount++;
        } else {
            row.style.display = 'none';
        }
    });

    const emptyRow = document.getElementById('empty-filter-row');
    if (emptyRow) {
        emptyRow.style.display = (visibleCount === 0 && rows.length > 0) ? '' : 'none';
    }
}

// Live Polling & Reconciliation
async function fetchStatus() {
    if (isUpdating) return;
    isUpdating = true;

    try {
        // High-efficiency single-request fetch for both peers & summary
        const res = await fetch('/api/live');
        if (res.ok) {
            const data = await res.json();
            if (data.peers) updatePeersTable(data.peers);
            if (data.summary) updateSummaryPanels(data.summary);
        } else {
            // Graceful fallback to separate endpoints
            const [statusRes, summaryRes] = await Promise.all([
                fetch('/status'),
                fetch('/summary')
            ]);
            if (statusRes.ok) updatePeersTable(await statusRes.json());
            if (summaryRes.ok) updateSummaryPanels(await summaryRes.json());
        }
    } catch (err) {
        console.error('Failed to update telemetry:', err);
    } finally {
        isUpdating = false;
    }
}

function updateSummaryPanels(summary) {
    if (!summary) return;

    const elOnline = document.getElementById('metric-online-peers');
    const elSinceRestart = document.getElementById('metric-since-restart');
    const elDown = document.getElementById('metric-down-rate');
    const elUp = document.getElementById('metric-up-rate');
    const elTotal = document.getElementById('metric-total-usage');
    const elMonthTag = document.getElementById('metric-month-tag');
    const demoBanner = document.getElementById('demo-mode-banner');

    if (elOnline) elOnline.textContent = `${summary.online_peers} / ${summary.total_peers}`;
    if (elSinceRestart) elSinceRestart.textContent = summary.connected_since_restart !== undefined ? summary.connected_since_restart : '--';
    if (elDown) elDown.textContent = summary.total_rx_rate_human || '0 bps';
    if (elUp) elUp.textContent = summary.total_tx_rate_human || '0 bps';
    if (elTotal) elTotal.textContent = summary.total_usage_human || '0 B';
    if (elMonthTag) elMonthTag.textContent = summary.current_month || '--';
    if (demoBanner) demoBanner.style.display = summary.mock_mode ? 'flex' : 'none';

    if (typeof updateServerChartFromSummary === 'function') {
        updateServerChartFromSummary(summary);
    }
}

function renderDeviceCell(ip, name, confName, isCustom) {
    if (name) {
        return `
            <div class="peer-name-wrap">
                <span class="peer-name-text">${escapeHtml(name)}</span>
                <button class="btn-rename" data-action="open-alias" data-ip="${escapeHtml(ip)}" data-name="${escapeHtml(name)}" data-conf="${escapeHtml(confName)}" title="Edit device nickname">
                    ${ICON_EDIT}
                </button>
            </div>
            <div style="display: flex; align-items: center; gap: 4px;">
                <span class="col-mono">${escapeHtml(ip)}</span>
                <button class="btn-copy" data-action="copy-ip" data-ip="${escapeHtml(ip)}" title="Copy IP address">${ICON_COPY}</button>
            </div>
        `;
    } else {
        return `
            <div class="peer-name-wrap">
                <span class="col-mono" style="font-weight: 600; color: var(--text-main);">${escapeHtml(ip)}</span>
                <button class="btn-copy" data-action="copy-ip" data-ip="${escapeHtml(ip)}" title="Copy IP address">${ICON_COPY}</button>
                <button class="btn-rename" data-action="open-alias" data-ip="${escapeHtml(ip)}" data-name="" data-conf="${escapeHtml(confName)}" title="Add device nickname" style="margin-left: 2px;">
                    ${ICON_EDIT}
                </button>
            </div>
        `;
    }
}

function renderPingBadge(pingMs, isOnline, samples) {
    if (!isOnline || pingMs === null || pingMs === undefined) {
        return `<span class="ping-badge ping-idle">-</span>`;
    }
    const val = parseFloat(pingMs);
    if (isNaN(val)) return `<span class="ping-badge ping-idle">-</span>`;
    let cls = 'ping-good';
    if (val >= 150) cls = 'ping-high';
    else if (val >= 60) cls = 'ping-med';

    let title = "Latency measured once upon fresh handshake (2 back-to-back pings to wake device)";
    if (Array.isArray(samples) && samples.length > 1) {
        const samplesStr = samples.map(s => `${Number(s).toFixed(1)}ms`).join(' \u2192 ');
        title = `Latency: ${val.toFixed(1)} ms (2 pings: ${samplesStr} \u2014 1st wakes device)`;
    }

    return `<span class="ping-badge ${cls}" title="${escapeHtml(title)}">${val.toFixed(1)} ms</span>`;
}

function updatePeersTable(peers) {
    const tbody = document.getElementById('status-table-body');
    if (!tbody) return;

    if (peers && peers.error) {
        tbody.innerHTML = `<tr><td colspan="9" style="text-align:center; padding: 24px; color: var(--danger-color, #ef4444);">
            Error loading WireGuard telemetry: ${escapeHtml(peers.error)}
        </td></tr>`;
        return;
    }

    if (!Array.isArray(peers) || peers.length === 0) {
        tbody.innerHTML = `<tr><td colspan="9" style="text-align:center; padding: 24px; color: var(--text-dim);">
            No WireGuard peers configured on this server.
        </td></tr>`;
        return;
    }

    const loadingRow = document.getElementById('loading-row');
    if (loadingRow) loadingRow.remove();

    const existingRows = new Map();
    tbody.querySelectorAll('tr[data-ip]').forEach(r => {
        existingRows.set(r.dataset.ip, r);
    });

    const activeIps = new Set();

    peers.forEach(peer => {
        const ip = peer.ip;
        const name = peer.name || '';
        const confName = peer.conf_name || '';
        const isCustom = !!peer.is_custom_alias;
        activeIps.add(ip);
        let row = existingRows.get(ip);

        const isOnline = !!peer.online_status;
        const sinceRestart = !!peer.connected_since_restart;
        const statusClass = isOnline ? 'online' : 'offline';
        const statusText = isOnline ? 'Online' : 'Offline';
        const lastSeen = peer.latest_handshake_human || (isOnline ? 'Active' : 'Never');
        const rxRate = peer.rx_rate_human || '0 bps';
        const txRate = peer.tx_rate_human || '0 bps';
        const sessionUsage = peer.data_usage || '0 B';
        const monthlyUsage = peer.monthly_usage || '0 B';
        const endpoint = peer.endpoint_ip || '-';
        const isp = peer.isp || '-';
        const pingMs = peer.ping_ms;
        const pingSamples = peer.ping_samples || [];

        if (!row) {
            row = document.createElement('tr');
            row.dataset.ip = ip;
            row.dataset.name = name;
            row.dataset.custom = String(isCustom);
            row.innerHTML = `
                <td data-label="Device" class="device-cell">
                    ${renderDeviceCell(ip, name, confName, isCustom)}
                </td>
                <td data-label="Endpoint" class="col-endpoint">${escapeHtml(endpoint)}</td>
                <td data-label="ISP / Network"><span class="isp-badge" title="${escapeHtml(isp)}">${escapeHtml(isp)}</span></td>
                <td data-label="Ping" class="col-ping">${renderPingBadge(pingMs, isOnline, pingSamples)}</td>
                <td data-label="Session" class="col-mono tnum session-usage-cell">${escapeHtml(sessionUsage)}</td>
                <td data-label="Monthly" class="col-mono tnum monthly-usage-cell" style="font-weight:600;">${escapeHtml(monthlyUsage)}</td>
                <td data-label="Throughput">
                    <div class="rates-stack tnum">
                        <span class="rate-rx">&darr; ${escapeHtml(rxRate)}</span>
                        <span class="rate-tx">&uarr; ${escapeHtml(txRate)}</span>
                    </div>
                </td>
                <td data-label="Status">
                    <span class="status-pill ${statusClass}">
                        <span class="status-bullet"></span>
                        <span class="status-text">${statusText}</span>
                    </span>
                    <div class="time-sub">${escapeHtml(lastSeen)}</div>
                </td>
                <td data-label="Actions" style="text-align: right; white-space: nowrap;">
                    <button class="btn btn-sm" data-action="open-history" data-ip="${escapeHtml(ip)}" title="Device connection history" style="margin-right: 4px;">
                        ${ICON_HISTORY}
                        <span>Log</span>
                    </button>
                    <button class="btn btn-sm" data-action="show-graph" data-ip="${escapeHtml(ip)}" title="Live bandwidth graph">
                        ${ICON_CHART}
                        <span>Graph</span>
                    </button>
                </td>
            `;
            tbody.appendChild(row);
        } else {
            if (row.dataset.name !== name || row.dataset.custom !== String(isCustom)) {
                row.dataset.name = name;
                row.dataset.custom = String(isCustom);
                const devCell = row.querySelector('.device-cell');
                if (devCell) devCell.innerHTML = renderDeviceCell(ip, name, confName, isCustom);
            }

            const endpointEl = row.querySelector('.col-endpoint');
            if (endpointEl && endpointEl.textContent !== endpoint) endpointEl.textContent = endpoint;

            const ispEl = row.querySelector('.isp-badge');
            if (ispEl && ispEl.textContent !== isp) {
                ispEl.textContent = isp;
                ispEl.title = isp;
            }

            const pingEl = row.querySelector('.col-ping');
            const expectedPingHtml = renderPingBadge(pingMs, isOnline, pingSamples);
            if (pingEl && pingEl.innerHTML !== expectedPingHtml) {
                pingEl.innerHTML = expectedPingHtml;
            }

            const sessionUsageEl = row.querySelector('.session-usage-cell');
            if (sessionUsageEl && sessionUsageEl.textContent !== sessionUsage) sessionUsageEl.textContent = sessionUsage;

            const monthlyUsageEl = row.querySelector('.monthly-usage-cell');
            if (monthlyUsageEl && monthlyUsageEl.textContent !== monthlyUsage) monthlyUsageEl.textContent = monthlyUsage;

            const rateRxEl = row.querySelector('.rate-rx');
            if (rateRxEl) rateRxEl.textContent = `↓ ${rxRate}`;

            const rateTxEl = row.querySelector('.rate-tx');
            if (rateTxEl) rateTxEl.textContent = `↑ ${txRate}`;

            const statusPill = row.querySelector('.status-pill');
            if (statusPill) {
                statusPill.className = `status-pill ${statusClass}`;
                const txt = statusPill.querySelector('.status-text');
                if (txt) txt.textContent = statusText;
            }

            const timeSub = row.querySelector('.time-sub');
            if (timeSub && timeSub.textContent !== lastSeen) timeSub.textContent = lastSeen;
        }

        row.dataset.endpoint = endpoint;
        row.dataset.isp = isp;
        row.dataset.online = String(isOnline);
        row.dataset.sinceRestart = String(sinceRestart);
    });

    existingRows.forEach((row, ip) => {
        if (!activeIps.has(ip)) row.remove();
    });

    applyClientFilters();
}

// Device Nickname / Alias Modal Handlers
let currentAliasModalIp = null;

function openAliasModal(ip, currentName, confName) {
    currentAliasModalIp = ip;
    const modal = document.getElementById('alias-modal');
    const ipEl = document.getElementById('alias-modal-ip');
    const confRow = document.getElementById('alias-modal-conf-row');
    const confEl = document.getElementById('alias-modal-conf-name');
    const input = document.getElementById('alias-input');

    if (ipEl) ipEl.textContent = ip;
    if (confEl) confEl.textContent = confName || 'None';
    if (confRow) confRow.style.display = confName ? 'block' : 'none';
    if (input) {
        input.value = currentName || '';
        setTimeout(() => input.focus(), 60);
    }
    if (modal) modal.classList.add('active');
}

function closeAliasModal() {
    currentAliasModalIp = null;
    const modal = document.getElementById('alias-modal');
    if (modal) modal.classList.remove('active');
}

function onAliasModalBackdropClick(event) {
    if (event.target.id === 'alias-modal') {
        closeAliasModal();
    }
}

async function saveAlias() {
    if (!currentAliasModalIp) return;
    const input = document.getElementById('alias-input');
    const alias = input ? input.value.trim() : '';

    try {
        const res = await fetch('/api/alias', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: currentAliasModalIp, alias: alias })
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            if (err.auth_required) {
                openExportAuthModal(() => saveAlias());
                return;
            }
            alert('Failed to save nickname: ' + (err.error || 'Server error'));
            return;
        }
        closeAliasModal();
        fetchStatus();
    } catch (e) {
        console.error('Error saving alias:', e);
        alert('Network error while saving device nickname.');
    }
}

async function resetAliasToDefault() {
    if (!currentAliasModalIp) return;
    const input = document.getElementById('alias-input');
    if (input) input.value = '';
    await saveAlias();
}

// History Modal Handlers
let currentModalPeerIp = null;

async function openHistoryModal(ip) {
    currentModalPeerIp = ip;
    const modal = document.getElementById('history-modal');
    const titleEl = document.getElementById('modal-peer-ip');
    const tbody = document.getElementById('history-sessions-body');

    if (titleEl) titleEl.textContent = ip;
    if (tbody) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding: 20px; color: var(--text-dim);">Loading history for ${escapeHtml(ip)}...</td></tr>`;
    }
    if (modal) modal.classList.add('active');

    try {
        const res = await fetch(`/api/history?ip=${encodeURIComponent(ip)}`);
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();

        // Update stats
        const elMonthly = document.getElementById('hist-stat-monthly');
        const elRx = document.getElementById('hist-stat-rx');
        const elTx = document.getElementById('hist-stat-tx');
        const elPing = document.getElementById('hist-stat-ping');
        const elBoot = document.getElementById('hist-stat-boot');

        if (elMonthly) elMonthly.textContent = data.monthly_total_human || '0 B';
        if (elRx) elRx.textContent = data.monthly_rx_human || '0 B';
        if (elTx) elTx.textContent = data.monthly_tx_human || '0 B';
        if (elPing) {
            if (data.last_ping_ms !== undefined && data.last_ping_ms !== null) {
                const pVal = Number(data.last_ping_ms);
                elPing.textContent = `${pVal.toFixed(1)} ms`;
                elPing.style.color = pVal < 60 ? 'var(--chart-rx)' : (pVal < 150 ? '#fbbf24' : '#ef4444');
                const lastSamples = data.last_ping_samples || [];
                if (lastSamples.length > 1) {
                    elPing.title = `2 pings: ${lastSamples.map(s => Number(s).toFixed(1) + 'ms').join(' \u2192 ')} (1st wakes device)`;
                } else {
                    elPing.title = 'Latest latency measurement';
                }
            } else {
                elPing.textContent = '--';
                elPing.style.color = 'var(--text-dim)';
                elPing.title = '';
            }
        }
        if (elBoot) {
            elBoot.textContent = data.connected_since_restart ? 'Yes' : 'No';
            elBoot.style.color = data.connected_since_restart ? 'var(--success-text)' : 'var(--text-dim)';
        }

        if (tbody) {
            const sessions = data.sessions || [];
            if (sessions.length === 0) {
                tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding: 20px; color: var(--text-dim);">No connection sessions logged for this device yet this month.</td></tr>`;
                return;
            }

            tbody.innerHTML = '';
            sessions.forEach(sess => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td class="col-mono">${escapeHtml(sess.started_at_human)}</td>
                    <td class="col-endpoint">${escapeHtml(sess.endpoint_ip || '-')}</td>
                    <td><span class="isp-badge" title="${escapeHtml(sess.isp)}">${escapeHtml(sess.isp)}</span></td>
                    <td data-label="Ping">${renderPingBadge(sess.ping_ms, true, sess.ping_samples)}</td>
                    <td class="col-mono tnum">
                        <span class="rate-rx">&darr; ${escapeHtml(sess.rx_human)}</span> / 
                        <span class="rate-tx">&uarr; ${escapeHtml(sess.tx_human)}</span>
                    </td>
                    <td class="time-sub">${escapeHtml(sess.duration_human)}</td>
                `;
                tbody.appendChild(tr);
            });
        }
    } catch (err) {
        console.error('History fetch failed:', err);
        if (tbody) {
            tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding: 20px; color: var(--danger-color, #ef4444);">Failed to load history: ${escapeHtml(err.message)}</td></tr>`;
        }
    }
}

function closeHistoryModal() {
    currentModalPeerIp = null;
    const modal = document.getElementById('history-modal');
    if (modal) modal.classList.remove('active');
}

function onModalBackdropClick(event) {
    if (event.target.id === 'history-modal') {
        closeHistoryModal();
    }
}

// ==========================================================================
// Export Authentication & Security Handlers
// ==========================================================================
let pendingExportAction = null;

function isExportAuthenticated() {
    return !!sessionStorage.getItem('wgstatus_export_token');
}

function openExportAuthModal(callback) {
    pendingExportAction = callback || null;
    const modal = document.getElementById('export-auth-modal');
    const input = document.getElementById('export-password-input');
    const errEl = document.getElementById('export-auth-error');
    if (errEl) {
        errEl.textContent = '';
        errEl.style.display = 'none';
    }
    if (input) {
        input.value = '';
        setTimeout(() => input.focus(), 80);
    }
    if (modal) modal.classList.add('active');
}

function closeExportAuthModal() {
    pendingExportAction = null;
    const modal = document.getElementById('export-auth-modal');
    if (modal) modal.classList.remove('active');
}

function onExportAuthBackdropClick(event) {
    if (event.target.id === 'export-auth-modal') {
        closeExportAuthModal();
    }
}

async function submitExportPassword() {
    const input = document.getElementById('export-password-input');
    const errEl = document.getElementById('export-auth-error');
    const pw = input ? input.value.trim() : '';
    if (!pw) {
        if (errEl) {
            errEl.textContent = 'Please enter the server password.';
            errEl.style.display = 'block';
        }
        return;
    }

    try {
        const res = await fetch('/api/export/verify-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password: pw })
        });
        const data = await res.json();
        if (res.ok && data.status === 'ok') {
            sessionStorage.setItem('wgstatus_export_token', data.token || 'authenticated');
            const actionToRun = pendingExportAction;
            closeExportAuthModal();
            if (typeof actionToRun === 'function') {
                actionToRun();
            }
        } else {
            if (errEl) {
                errEl.textContent = data.error || 'Incorrect server password.';
                errEl.style.display = 'block';
            }
            if (input) input.select();
        }
    } catch (e) {
        console.error('Error verifying export password:', e);
        if (errEl) {
            errEl.textContent = 'Network error while verifying password.';
            errEl.style.display = 'block';
        }
    }
}

function toggleExportMenu(event) {
    if (event) {
        event.stopPropagation();
        event.preventDefault();
    }

    if (!isExportAuthenticated()) {
        openExportAuthModal(() => {
            const menu = document.getElementById('export-dropdown');
            if (menu) menu.style.display = 'block';
        });
        return;
    }

    const menu = document.getElementById('export-dropdown');
    if (!menu) return;
    const isHidden = menu.style.display === 'none' || !menu.style.display;
    menu.style.display = isHidden ? 'block' : 'none';
}

async function checkInitialAuth() {
    try {
        const res = await fetch('/api/auth/status');
        if (res.ok) {
            const data = await res.json();
            if (data.authenticated) {
                sessionStorage.setItem('wgstatus_export_token', 'authenticated');
            } else {
                sessionStorage.removeItem('wgstatus_export_token');
            }
        }
    } catch (e) {}
}

function downloadExport(url) {
    const menu = document.getElementById('export-dropdown');
    if (menu) menu.style.display = 'none';

    if (!isExportAuthenticated()) {
        openExportAuthModal(() => {
            window.location.href = url;
        });
        return;
    }

    window.location.href = url;
}

function exportCurrentPeerSessions(format) {
    if (!currentModalPeerIp) return;
    const baseUrl = `/api/export/sessions?format=${encodeURIComponent(format)}&ip=${encodeURIComponent(currentModalPeerIp)}`;
    downloadExport(baseUrl);
}

document.addEventListener('click', (e) => {
    // 1. Export dropdown outside click dismissal
    const menu = document.getElementById('export-dropdown');
    const btn = document.getElementById('export-menu-btn');
    if (menu && menu.style.display === 'block') {
        if (!btn || !btn.contains(e.target)) {
            if (!menu.contains(e.target)) {
                menu.style.display = 'none';
            }
        }
    }

    // 2. Data Action delegation
    const actionEl = e.target.closest('[data-action]');
    if (!actionEl) return;

    const action = actionEl.dataset.action;
    switch (action) {
        case 'toggle-export-menu':
            toggleExportMenu(e);
            break;
        case 'download':
            if (actionEl.dataset.url) downloadExport(actionEl.dataset.url);
            break;
        case 'toggle-theme':
            toggleDarkMode();
            break;
        case 'server-chart-open':
            if (typeof toggleServerChartVisibility === 'function') toggleServerChartVisibility(false);
            break;
        case 'server-chart-toggle':
            if (typeof toggleServerChartVisibility === 'function') toggleServerChartVisibility();
            break;
        case 'filter':
            setFilter(actionEl.dataset.filter, actionEl);
            break;
        case 'close-chart':
            if (typeof closeBandwidthChart === 'function') closeBandwidthChart();
            break;
        case 'open-analytics':
            if (typeof openAnalyticsModal === 'function') openAnalyticsModal();
            break;
        case 'close-analytics':
            if (typeof closeAnalyticsModal === 'function') closeAnalyticsModal();
            break;
        case 'backdrop-analytics':
            if (e.target.id === 'analytics-modal' && typeof closeAnalyticsModal === 'function') {
                closeAnalyticsModal();
            }
            break;
        case 'analytics-range':
            if (typeof setAnalyticsRange === 'function') setAnalyticsRange(actionEl.dataset.range);
            break;
        case 'analytics-sort':
            if (typeof setAnalyticsSort === 'function') setAnalyticsSort(actionEl.dataset.sort);
            break;
        case 'analytics-export':
            if (typeof exportAnalyticsData === 'function') exportAnalyticsData(actionEl.dataset.format);
            break;
        case 'open-history':
            openHistoryModal(actionEl.dataset.ip);
            break;
        case 'close-history':
            closeHistoryModal();
            break;
        case 'backdrop-history':
            if (e.target.id === 'history-modal') closeHistoryModal();
            break;
        case 'export-peer-sessions':
            exportCurrentPeerSessions(actionEl.dataset.format);
            break;
        case 'open-alias':
            openAliasModal(actionEl.dataset.ip, actionEl.dataset.name, actionEl.dataset.conf);
            break;
        case 'close-alias':
            closeAliasModal();
            break;
        case 'backdrop-alias':
            if (e.target.id === 'alias-modal') closeAliasModal();
            break;
        case 'reset-alias':
            resetAliasToDefault();
            break;
        case 'save-alias':
            saveAlias();
            break;
        case 'show-graph':
            if (typeof showBandwidthChart === 'function') showBandwidthChart(actionEl.dataset.ip);
            break;
        case 'copy-ip':
            copyIp(actionEl, actionEl.dataset.ip);
            break;
        case 'close-auth':
            closeExportAuthModal();
            break;
        case 'submit-auth':
            submitExportPassword();
            break;
        case 'backdrop-auth':
            if (e.target.id === 'export-auth-modal') closeExportAuthModal();
            break;
    }
});

document.addEventListener('input', (e) => {
    if (e.target.matches('[data-input="search"]')) {
        onSearchInput(e.target.value);
    }
});

document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        closeHistoryModal();
        closeAliasModal();
        closeExportAuthModal();
        if (typeof closeAnalyticsModal === 'function') closeAnalyticsModal();
        const exportMenu = document.getElementById('export-dropdown');
        if (exportMenu) exportMenu.style.display = 'none';
        if (typeof closeBandwidthChart === 'function') closeBandwidthChart();
    } else if (e.key === 'Enter') {
        const enterAction = e.target.dataset.enter;
        if (enterAction === 'save-alias') {
            saveAlias();
        } else if (enterAction === 'submit-auth') {
            submitExportPassword();
        }
    }
});

function copyIp(button, text) {
    const origHtml = button.innerHTML;
    const performCopy = () => {
        button.innerHTML = ICON_CHECK;
        setTimeout(() => { button.innerHTML = origHtml; }, 1500);
    };

    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(performCopy);
    } else {
        const ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        ta.remove();
        performCopy();
    }
}

function escapeHtml(str) {
    return String(str || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function escapeJs(str) {
    return String(str || '')
        .replace(/\\/g, '\\\\')
        .replace(/'/g, "\\'")
        .replace(/"/g, '&quot;');
}

// ==========================================================================
// Real-time Push & Telemetry Manager (WebSocket -> SSE -> Polling)
// ==========================================================================
let realtimeWs = null;
let realtimeSse = null;
let isRealtimeActive = false;
let wsReconnectTimer = null;
let pollIntervalTimer = null;
let currentPollRate = 1000;
let isPollingActive = false;

function updateRealtimeBadge(status, text, tooltip) {
    const badge = document.getElementById('realtime-badge');
    const label = document.getElementById('realtime-status-text');
    if (!badge || !label) return;

    badge.className = `connection-pill status-pill ${status}`;
    label.textContent = text;
    badge.title = tooltip || text;
}

function handleTelemetryPayload(payload) {
    if (!payload) return;
    if (payload.peers) updatePeersTable(payload.peers);
    if (payload.summary) updateSummaryPanels(payload.summary);
}

function initRealtimeConnection() {
    if (!('WebSocket' in window)) {
        console.warn('WebSockets not supported in this browser. Falling back to SSE.');
        initSseConnection();
        return;
    }

    if (realtimeWs && (realtimeWs.readyState === WebSocket.OPEN || realtimeWs.readyState === WebSocket.CONNECTING)) {
        return;
    }

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;

    try {
        realtimeWs = new WebSocket(wsUrl);

        realtimeWs.onopen = () => {
            isRealtimeActive = true;
            stopPolling();
            if (realtimeSse) {
                realtimeSse.close();
                realtimeSse = null;
            }
            updateRealtimeBadge('online', 'Live WS', 'Real-time WebSocket push active (Zero Polling / Minimal CPU)');
        };

        realtimeWs.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                handleTelemetryPayload(data);
            } catch (e) {
                console.error('Error parsing WebSocket message:', e);
            }
        };

        realtimeWs.onerror = (err) => {
            console.warn('WebSocket encountered error:', err);
        };

        realtimeWs.onclose = () => {
            isRealtimeActive = false;
            realtimeWs = null;
            updateRealtimeBadge('offline', 'Reconnecting', 'WebSocket disconnected. Falling back to stream/polling...');
            // Seamlessly fall back to SSE or polling
            initSseConnection();
            scheduleWsReconnect();
        };
    } catch (e) {
        console.error('Failed to instantiate WebSocket:', e);
        initSseConnection();
        scheduleWsReconnect();
    }
}

function scheduleWsReconnect() {
    if (wsReconnectTimer) clearTimeout(wsReconnectTimer);
    wsReconnectTimer = setTimeout(() => {
        if (!isRealtimeActive) {
            initRealtimeConnection();
        }
    }, 4000);
}

function initSseConnection() {
    if (isRealtimeActive) return;
    if (!('EventSource' in window)) {
        startPolling();
        return;
    }

    if (realtimeSse && realtimeSse.readyState !== EventSource.CLOSED) {
        return;
    }

    try {
        realtimeSse = new EventSource('/api/stream');

        realtimeSse.onopen = () => {
            if (!isRealtimeActive) {
                stopPolling();
                updateRealtimeBadge('online', 'Live SSE', 'Real-time Server-Sent Events stream active');
            }
        };

        realtimeSse.onmessage = (event) => {
            if (isRealtimeActive) return; // WS takes precedence
            try {
                const data = JSON.parse(event.data);
                handleTelemetryPayload(data);
            } catch (e) {
                console.error('Error parsing SSE telemetry payload:', e);
            }
        };

        realtimeSse.onerror = () => {
            if (realtimeSse) {
                realtimeSse.close();
                realtimeSse = null;
            }
            if (!isRealtimeActive) {
                updateRealtimeBadge('offline', 'Polling', 'HTTP polling fallback active');
                startPolling();
            }
        };
    } catch (e) {
        console.warn('SSE initialization failed, resorting to polling:', e);
        startPolling();
    }
}

function startPolling() {
    if (isPollingActive) return;
    isPollingActive = true;
    updateRealtimeBadge('offline', 'Polling (1s)', 'HTTP polling fallback active');
    setPollInterval(1000);
}

function stopPolling() {
    isPollingActive = false;
    if (pollIntervalTimer) {
        clearInterval(pollIntervalTimer);
        pollIntervalTimer = null;
    }
}

function setPollInterval(ms) {
    currentPollRate = ms;
    if (pollIntervalTimer) clearInterval(pollIntervalTimer);
    pollIntervalTimer = setInterval(fetchStatus, ms);
}

document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
        if (isPollingActive) {
            setPollInterval(5000);
        }
    } else {
        if (!isRealtimeActive) {
            fetchStatus();
            initRealtimeConnection();
        }
    }
});

document.addEventListener('DOMContentLoaded', () => {
    initDarkMode();
    if (typeof initServerBandwidthChart === 'function') {
        initServerBandwidthChart();
    }
    // Instant initial render
    fetchStatus();
    // Connect zero-polling real-time push
    initRealtimeConnection();
});