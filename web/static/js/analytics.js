/**
 * WireGuard Status - Network Analytics Client
 * Visualises hourly volume, hour-of-day profile, and ISP / network rankings.
 */

let analyticsData = null;
let currentAnalyticsRange = '7d';
let currentAnalyticsSort = 'total';
let analyticsSeriesChart = null;
let analyticsHodChart = null;
let isAnalyticsLoading = false;

function isDarkMode() {
    return !document.body.classList.contains('light-mode');
}

function getAnalyticsThemeColors() {
    const dark = isDarkMode();
    return {
        text: dark ? '#94a3b8' : '#64748b',
        title: dark ? '#f8fafc' : '#0f172a',
        grid: dark ? 'rgba(255, 255, 255, 0.05)' : 'rgba(0, 0, 0, 0.06)',
        rx: '#34d399',
        rxBg: 'rgba(52, 211, 153, 0.7)',
        tx: '#fbbf24',
        txBg: 'rgba(251, 191, 36, 0.7)',
        palette: [
            '#38bdf8', '#a78bfa', '#f472b6', '#34d399', '#fbbf24',
            '#f87171', '#4ade80', '#fb923c', '#818cf8', '#94a3b8'
        ]
    };
}

function formatBps(bps) {
    if (!bps || bps <= 0) return '0 bps';
    if (bps < 1000) return `${Math.round(bps)} bps`;
    if (bps < 1_000_000) return `${(bps / 1000).toFixed(1)} Kbps`;
    if (bps < 1_000_000_000) return `${(bps / 1_000_000).toFixed(2)} Mbps`;
    return `${(bps / 1_000_000_000).toFixed(2)} Gbps`;
}

function formatBytes(bytes) {
    if (!bytes || bytes <= 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let n = Number(bytes);
    let u = 0;
    while (n >= 1024 && u < units.length - 1) {
        n /= 1024;
        u++;
    }
    return `${n.toFixed(u === 0 ? 0 : 2)} ${units[u]}`;
}

function formatHourRange(h) {
    if (h === null || h === undefined || h < 0) return '-';
    const next = (h + 1) % 24;
    const pad = (v) => String(v).padStart(2, '0');
    return `${pad(h)}:00 - ${pad(next)}:00`;
}

async function openAnalyticsModal() {
    const modal = document.getElementById('analytics-modal');
    if (!modal) return;
    modal.classList.add('active');
    await loadAnalytics(currentAnalyticsRange);
}

function closeAnalyticsModal() {
    const modal = document.getElementById('analytics-modal');
    if (modal) modal.classList.remove('active');
}

async function setAnalyticsRange(range) {
    if (isAnalyticsLoading || range === currentAnalyticsRange) return;
    currentAnalyticsRange = range;
    document.querySelectorAll('#analytics-range-pills [data-range]').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.range === range);
    });
    await loadAnalytics(range);
}

function setAnalyticsSort(sortKey) {
    currentAnalyticsSort = sortKey;
    document.querySelectorAll('#analytics-sort-pills [data-sort]').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.sort === sortKey);
    });
    renderIspTable();
}

async function loadAnalytics(range = '7d') {
    isAnalyticsLoading = true;
    const tbody = document.getElementById('analytics-isp-body');
    if (tbody && !analyticsData) {
        tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; padding: 24px; color: var(--text-dim);">Loading analytics...</td></tr>`;
    }

    try {
        const res = await fetch(`/api/analytics?range=${encodeURIComponent(range)}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        analyticsData = data;
        renderAnalyticsView(data);
    } catch (err) {
        console.error('Failed to load analytics:', err);
        if (tbody) {
            tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; padding: 20px; color: var(--danger-color, #ef4444);">Failed to load analytics: ${escapeHtml(err.message)}</td></tr>`;
        }
    } finally {
        isAnalyticsLoading = false;
    }
}

function renderAnalyticsView(data) {
    if (!data) return;

    // Demo badge
    const demoTag = document.getElementById('analytics-demo-tag');
    if (demoTag) demoTag.style.display = data.demo ? 'inline-block' : 'none';

    // KPIs
    const totals = data.totals || {};
    const elTotal = document.getElementById('an-total');
    const elTotalSub = document.getElementById('an-total-sub');
    if (elTotal) elTotal.textContent = totals.total_human || '0 B';
    if (elTotalSub) elTotalSub.textContent = `↓ ${totals.rx_human || '0 B'} · ↑ ${totals.tx_human || '0 B'}`;

    const elPeakHour = document.getElementById('an-peak-hour');
    const elPeakHourSub = document.getElementById('an-peak-hour-sub');
    if (elPeakHour) {
        elPeakHour.textContent = data.peak_hour ? data.peak_hour.label : '--';
    }
    if (elPeakHourSub) {
        elPeakHourSub.textContent = data.peak_hour ? `Avg ${data.peak_hour.avg_human}/day` : 'No activity';
    }

    const topIsps = data.top_isps || [];
    const elTopIsp = document.getElementById('an-top-isp');
    const elTopIspSub = document.getElementById('an-top-isp-sub');
    if (elTopIsp) {
        elTopIsp.textContent = topIsps.length > 0 ? topIsps[0].isp : '--';
        elTopIsp.title = topIsps.length > 0 ? topIsps[0].isp : '';
    }
    if (elTopIspSub) {
        elTopIspSub.textContent = topIsps.length > 0 ? `${topIsps[0].share_pct}% · ${topIsps[0].total_human}` : '&nbsp;';
    }

    const elNetworks = document.getElementById('an-networks');
    const elNetworksSub = document.getElementById('an-networks-sub');
    if (elNetworks) elNetworks.textContent = totals.networks !== undefined ? totals.networks : '--';
    if (elNetworksSub) elNetworksSub.textContent = `${data.days_with_data || 1} day(s) recorded`;

    const elPeakRate = document.getElementById('an-peak-rate');
    const elPeakRateSub = document.getElementById('an-peak-rate-sub');
    const maxBps = Math.max(totals.peak_rx_bps || 0, totals.peak_tx_bps || 0);
    if (elPeakRate) elPeakRate.textContent = formatBps(maxBps);
    if (elPeakRateSub) elPeakRateSub.textContent = `Peak burst across peers`;

    // Series title
    const seriesTitle = document.getElementById('an-series-title');
    if (seriesTitle) {
        seriesTitle.textContent = data.granularity === 'day' ? 'Daily Traffic Volume' : 'Hourly Traffic Volume';
    }

    // Footnote
    const noteEl = document.getElementById('an-note');
    if (noteEl) {
        const since = data.data_since ? new Date(data.data_since * 1000).toLocaleDateString() : '--';
        noteEl.innerHTML = `Persistent RAM metrics with SSD wear protection &bull; Historical retention: 32 days &bull; Tracking since ${since}`;
    }

    renderSeriesChart(data);
    renderHodChart(data);
    renderIspTable();
}

function renderSeriesChart(data) {
    const canvas = document.getElementById('analytics-series-chart');
    if (!canvas || !window.Chart) return;

    const series = data.series || [];
    const labels = series.map(pt => {
        if (data.granularity === 'day') return pt.key.slice(5); // MM-DD
        return pt.key.slice(11) + ':00'; // HH:00
    });
    const rxMB = series.map(pt => (pt.rx / 1_000_000).toFixed(2));
    const txMB = series.map(pt => (pt.tx / 1_000_000).toFixed(2));

    const colors = getAnalyticsThemeColors();

    if (analyticsSeriesChart) {
        analyticsSeriesChart.destroy();
        analyticsSeriesChart = null;
    }

    const ctx = canvas.getContext('2d');
    analyticsSeriesChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Download (MB)',
                    data: rxMB,
                    backgroundColor: colors.rxBg,
                    borderColor: colors.rx,
                    borderWidth: 1,
                    borderRadius: 2,
                    stack: 'traffic',
                },
                {
                    label: 'Upload (MB)',
                    data: txMB,
                    backgroundColor: colors.txBg,
                    borderColor: colors.tx,
                    borderWidth: 1,
                    borderRadius: 2,
                    stack: 'traffic',
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            interaction: { mode: 'index', intersect: false },
            plugins: {
                legend: {
                    position: 'top',
                    align: 'end',
                    labels: { color: colors.text, boxWidth: 10, font: { size: 10 } }
                },
                tooltip: {
                    callbacks: {
                        label: (ctx) => `${ctx.dataset.label}: ${ctx.raw} MB`
                    }
                }
            },
            scales: {
                x: {
                    grid: { display: false },
                    ticks: {
                        color: colors.text,
                        font: { size: 9 },
                        maxRotation: 0,
                        autoSkip: true,
                        maxTicksLimit: 12,
                    }
                },
                y: {
                    stacked: true,
                    grid: { color: colors.grid },
                    ticks: {
                        color: colors.text,
                        font: { size: 9 },
                        callback: (v) => `${v} MB`
                    }
                }
            }
        }
    });
}

function renderHodChart(data) {
    const canvas = document.getElementById('analytics-hod-chart');
    if (!canvas || !window.Chart) return;

    const colors = getAnalyticsThemeColors();
    const hodIsps = data.hour_of_day_by_isp || [];
    const labels = Array.from({ length: 24 }, (_, i) => `${String(i).padStart(2, '0')}:00`);

    const datasets = hodIsps.map((item, idx) => {
        const color = colors.palette[idx % colors.palette.length];
        return {
            label: item.isp,
            data: item.bytes.map(b => (b / 1_000_000).toFixed(2)),
            backgroundColor: color,
            borderRadius: 2,
            stack: 'hod',
        };
    });

    if (analyticsHodChart) {
        analyticsHodChart.destroy();
        analyticsHodChart = null;
    }

    const ctx = canvas.getContext('2d');
    analyticsHodChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: datasets
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            interaction: { mode: 'index', intersect: false },
            plugins: {
                legend: {
                    position: 'top',
                    align: 'end',
                    labels: { color: colors.text, boxWidth: 10, font: { size: 10 } }
                },
                tooltip: {
                    callbacks: {
                        label: (ctx) => `${ctx.dataset.label}: ${ctx.raw} MB/day`
                    }
                }
            },
            scales: {
                x: {
                    grid: { display: false },
                    ticks: {
                        color: colors.text,
                        font: { size: 9 },
                        maxTicksLimit: 12
                    }
                },
                y: {
                    stacked: true,
                    grid: { color: colors.grid },
                    ticks: {
                        color: colors.text,
                        font: { size: 9 },
                        callback: (v) => `${v} MB`
                    }
                }
            }
        }
    });
}

function renderIspTable() {
    const tbody = document.getElementById('analytics-isp-body');
    if (!tbody || !analyticsData) return;

    const isps = [...(analyticsData.top_isps || [])];
    if (isps.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; padding: 20px; color: var(--text-dim);">No ISP traffic recorded yet for this period.</td></tr>`;
        return;
    }

    // Sort
    isps.sort((a, b) => {
        if (currentAnalyticsSort === 'sessions') return (b.sessions || 0) - (a.sessions || 0);
        if (currentAnalyticsSort === 'active_seconds') return (b.active_seconds || 0) - (a.active_seconds || 0);
        if (currentAnalyticsSort === 'devices') return (b.devices || 0) - (a.devices || 0);
        return (b.total || 0) - (a.total || 0);
    });

    tbody.innerHTML = '';
    isps.forEach((r, idx) => {
        const tr = document.createElement('tr');
        const share = Math.min(100, Math.max(0, r.share_pct || 0));
        tr.innerHTML = `
            <td style="color: var(--text-dim); font-size: 11px;">${idx + 1}</td>
            <td>
                <span class="isp-badge" title="${escapeHtml(r.isp)}" style="font-weight: 600;">${escapeHtml(r.isp)}</span>
            </td>
            <td>
                <div style="display: flex; align-items: center; gap: 8px;">
                    <div class="an-progress-wrap" title="${share}%">
                        <div class="an-progress-fill" style="width: ${share}%;"></div>
                    </div>
                    <span class="col-mono tnum" style="font-weight: 600; font-size: 12px;">${escapeHtml(r.total_human)}</span>
                    <span class="time-sub" style="font-size: 10px;">${share}%</span>
                </div>
            </td>
            <td class="col-mono tnum" style="font-size: 11px;">
                <span class="rate-rx">&darr; ${escapeHtml(r.rx_human)}</span> /
                <span class="rate-tx">&uarr; ${escapeHtml(r.tx_human)}</span>
            </td>
            <td class="tnum" style="font-size: 12px; font-weight: 500;">${r.sessions || 0}</td>
            <td class="tnum" style="font-size: 12px; font-weight: 500;">${r.devices || 0}</td>
            <td class="time-sub" style="font-size: 12px;">${escapeHtml(r.active_human || '-')}</td>
            <td class="col-mono" style="font-size: 11px; color: var(--text-muted);">${formatHourRange(r.peak_hour)}</td>
        `;
        tbody.appendChild(tr);
    });
}

function updateAnalyticsChartsTheme() {
    if (analyticsSeriesChart && analyticsData) {
        renderSeriesChart(analyticsData);
    }
    if (analyticsHodChart && analyticsData) {
        renderHodChart(analyticsData);
    }
}

function exportAnalyticsData(format) {
    const url = `/api/export/analytics?range=${encodeURIComponent(currentAnalyticsRange)}&format=${encodeURIComponent(format)}`;
    if (typeof downloadExport === 'function') {
        downloadExport(url);
    } else {
        window.location.href = url;
    }
}
