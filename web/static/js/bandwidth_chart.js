/**
 * Real-time Bandwidth Telemetry Chart
 * Enterprise styling with instant history preload, theme sync,
 * total server traffic monitoring, and individual peer telemetry.
 */

let serverChart = null;
let activeChart = null;
let activeChartIp = null;
let chartPollTimer = null;
let lastBandwidthSample = null;

function isDarkModeActive() {
    return !document.body.classList.contains('light-mode');
}

function getChartColors() {
    const isDark = isDarkModeActive();
    return {
        textColor: isDark ? '#94a3b8' : '#64748b',
        gridColor: isDark ? 'rgba(255, 255, 255, 0.05)' : 'rgba(0, 0, 0, 0.05)',
        rxBorder: '#34d399',
        rxBg: 'rgba(52, 211, 153, 0.12)',
        txBorder: '#fbbf24',
        txBg: 'rgba(251, 191, 36, 0.12)',
    };
}

function ensureChartJs(callback) {
    if (window.Chart) {
        callback();
        return;
    }
    const script = document.createElement('script');
    script.src = '/static/vendor/chart.umd.js';
    script.onload = () => callback();
    document.head.appendChild(script);
}

// ==========================================================================
// Total Server Bandwidth Chart
// ==========================================================================

async function initServerBandwidthChart() {
    ensureChartJs(async () => {
        const canvas = document.getElementById('server-bandwidth-chart');
        if (!canvas) return;

        // Restore collapse state if user previously collapsed it
        const isCollapsed = localStorage.getItem('wgstatus_server_chart_collapsed') === 'true';
        if (isCollapsed) {
            applyServerChartCollapse(true);
        }

        let labels = [];
        let rxData = [];
        let txData = [];

        try {
            const res = await fetch('/bandwidth/total');
            if (res.ok) {
                const history = await res.json();
                if (history.labels && history.labels.length > 0) {
                    labels = history.labels;
                    rxData = history.rx;
                    txData = history.tx;
                }
            }
        } catch (e) {
            console.debug('Could not preload total bandwidth history:', e);
        }

        if (labels.length === 0) {
            labels.push(new Date().toLocaleTimeString());
            rxData.push(0);
            txData.push(0);
        }

        if (serverChart) {
            serverChart.destroy();
            serverChart = null;
        }

        const colors = getChartColors();
        const ctx = canvas.getContext('2d');

        serverChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [
                    {
                        label: 'Download (RX) Mbps',
                        data: rxData,
                        borderColor: colors.rxBorder,
                        backgroundColor: colors.rxBg,
                        fill: true,
                        tension: 0.25,
                        borderWidth: 1.8,
                        pointRadius: 0,
                        pointHoverRadius: 4,
                    },
                    {
                        label: 'Upload (TX) Mbps',
                        data: txData,
                        borderColor: colors.txBorder,
                        backgroundColor: colors.txBg,
                        fill: true,
                        tension: 0.25,
                        borderWidth: 1.8,
                        pointRadius: 0,
                        pointHoverRadius: 4,
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                interaction: {
                    mode: 'index',
                    intersect: false,
                },
                plugins: {
                    legend: {
                        position: 'top',
                        align: 'end',
                        labels: {
                            color: colors.textColor,
                            boxWidth: 12,
                            boxHeight: 12,
                            font: { size: 11, family: 'system-ui' }
                        }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(15, 23, 42, 0.9)',
                        titleFont: { size: 11 },
                        bodyFont: { size: 12, family: 'ui-monospace, monospace' },
                        padding: 8,
                        cornerRadius: 4,
                        callbacks: {
                            label: (c) => ` ${c.dataset.label}: ${c.parsed.y.toFixed(2)} Mbps`
                        }
                    }
                },
                scales: {
                    x: {
                        grid: { color: colors.gridColor },
                        ticks: {
                            color: colors.textColor,
                            maxTicksLimit: 8,
                            font: { size: 10, family: 'ui-monospace, monospace' }
                        }
                    },
                    y: {
                        beginAtZero: true,
                        grid: { color: colors.gridColor },
                        ticks: {
                            color: colors.textColor,
                            font: { size: 10, family: 'ui-monospace, monospace' },
                            callback: (v) => `${v.toFixed(1)} Mbps`
                        }
                    }
                }
            }
        });
    });
}

function updateServerChartFromSummary(summary) {
    if (!summary) return;

    const rxHumanEl = document.getElementById('server-chart-rx');
    const txHumanEl = document.getElementById('server-chart-tx');
    if (rxHumanEl) rxHumanEl.textContent = `↓ ${summary.total_rx_rate_human || '0 bps'}`;
    if (txHumanEl) txHumanEl.textContent = `↑ ${summary.total_tx_rate_human || '0 bps'}`;

    if (!serverChart) return;

    const rxBps = summary.total_rx_rate_bps || 0;
    const txBps = summary.total_tx_rate_bps || 0;
    const rxMbps = Math.max(0, rxBps / 1_000_000);
    const txMbps = Math.max(0, txBps / 1_000_000);
    const timeLabel = summary.updated_at || new Date().toLocaleTimeString();

    serverChart.data.labels.push(timeLabel);
    serverChart.data.datasets[0].data.push(round2(rxMbps));
    serverChart.data.datasets[1].data.push(round2(txMbps));

    if (serverChart.data.labels.length > 60) {
        serverChart.data.labels.shift();
        serverChart.data.datasets[0].data.shift();
        serverChart.data.datasets[1].data.shift();
    }

    serverChart.update('none');
}

function toggleServerChartVisibility(focusIfHidden = false) {
    const wrapper = document.getElementById('server-chart-wrapper');
    if (!wrapper) return;
    const currentlyCollapsed = wrapper.style.display === 'none';
    const nextCollapsed = focusIfHidden ? false : !currentlyCollapsed;
    applyServerChartCollapse(nextCollapsed);
    localStorage.setItem('wgstatus_server_chart_collapsed', String(nextCollapsed));
    if (!nextCollapsed && serverChart) {
        setTimeout(() => serverChart.resize(), 50);
    }
}

function applyServerChartCollapse(isCollapsed) {
    const wrapper = document.getElementById('server-chart-wrapper');
    const btnText = document.getElementById('server-chart-toggle-text');
    const btnIcon = document.getElementById('server-chart-toggle-icon');
    if (wrapper) wrapper.style.display = isCollapsed ? 'none' : 'block';
    if (btnText) btnText.textContent = isCollapsed ? 'Expand' : 'Collapse';
    if (btnIcon) {
        btnIcon.innerHTML = isCollapsed
            ? '<polyline points="6 9 12 15 18 9"></polyline>'
            : '<polyline points="18 15 12 9 6 15"></polyline>';
    }
}

// ==========================================================================
// Individual Peer Bandwidth Chart
// ==========================================================================

function closeBandwidthChart() {
    if (chartPollTimer) {
        clearInterval(chartPollTimer);
        chartPollTimer = null;
    }
    if (activeChart) {
        activeChart.destroy();
        activeChart = null;
    }
    activeChartIp = null;
    lastBandwidthSample = null;
    const card = document.getElementById('bandwidth-chart-card');
    if (card) card.style.display = 'none';
}

function showBandwidthChart(ip) {
    ensureChartJs(() => {
        initBandwidthChart(ip);
    });
}

async function initBandwidthChart(ip) {
    activeChartIp = ip;
    const card = document.getElementById('bandwidth-chart-card');
    const title = document.getElementById('chart-peer-title');
    if (card) card.style.display = 'block';
    if (title) title.textContent = `Peer ${ip}`;

    card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

    let labels = [];
    let rxData = [];
    let txData = [];

    try {
        const res = await fetch(`/bandwidth/history?ip=${encodeURIComponent(ip)}`);
        if (res.ok) {
            const history = await res.json();
            if (history.labels && history.labels.length > 0) {
                labels = history.labels;
                rxData = history.rx;
                txData = history.tx;
            }
        }
    } catch (e) {
        console.debug('Could not preload peer history:', e);
    }

    if (labels.length === 0) {
        labels.push(new Date().toLocaleTimeString());
        rxData.push(0);
        txData.push(0);
    }

    if (activeChart) {
        activeChart.destroy();
        activeChart = null;
    }

    const canvas = document.getElementById('bandwidth-chart');
    if (!canvas) return;

    const colors = getChartColors();
    const ctx = canvas.getContext('2d');

    activeChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'RX (Download) Mbps',
                    data: rxData,
                    borderColor: colors.rxBorder,
                    backgroundColor: colors.rxBg,
                    fill: true,
                    tension: 0.2,
                    borderWidth: 1.75,
                    pointRadius: 0,
                    pointHoverRadius: 4,
                },
                {
                    label: 'TX (Upload) Mbps',
                    data: txData,
                    borderColor: colors.txBorder,
                    backgroundColor: colors.txBg,
                    fill: true,
                    tension: 0.2,
                    borderWidth: 1.75,
                    pointRadius: 0,
                    pointHoverRadius: 4,
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            interaction: {
                mode: 'index',
                intersect: false,
            },
            plugins: {
                legend: {
                    position: 'top',
                    align: 'end',
                    labels: {
                        color: colors.textColor,
                        boxWidth: 12,
                        boxHeight: 12,
                        font: { size: 11, family: 'system-ui' }
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(15, 23, 42, 0.9)',
                    titleFont: { size: 11 },
                    bodyFont: { size: 12, family: 'ui-monospace, monospace' },
                    padding: 8,
                    cornerRadius: 4,
                    callbacks: {
                        label: (c) => ` ${c.dataset.label}: ${c.parsed.y.toFixed(2)} Mbps`
                    }
                }
            },
            scales: {
                x: {
                    grid: { color: colors.gridColor },
                    ticks: {
                        color: colors.textColor,
                        maxTicksLimit: 8,
                        font: { size: 10, family: 'ui-monospace, monospace' }
                    }
                },
                y: {
                    beginAtZero: true,
                    grid: { color: colors.gridColor },
                    ticks: {
                        color: colors.textColor,
                        font: { size: 10, family: 'ui-monospace, monospace' },
                        callback: (v) => `${v.toFixed(1)} Mbps`
                    }
                }
            }
        }
    });

    if (chartPollTimer) clearInterval(chartPollTimer);
    chartPollTimer = setInterval(pollChartStep, 1000);
}

async function pollChartStep() {
    if (!activeChart || !activeChartIp) return;
    try {
        const res = await fetch('/bandwidth');
        if (!res.ok) return;
        const data = await res.json();
        const peer = data[activeChartIp];
        if (!peer) return;

        const now = Date.now();
        let rxMbps = 0;
        let txMbps = 0;

        if (peer.rx_rate !== undefined && peer.tx_rate !== undefined) {
            rxMbps = Math.max(0, peer.rx_rate / 1_000_000);
            txMbps = Math.max(0, peer.tx_rate / 1_000_000);
        } else if (lastBandwidthSample && lastBandwidthSample.ip === activeChartIp) {
            const dt = (now - lastBandwidthSample.time) / 1000;
            if (dt > 0.1) {
                const dRx = Math.max(0, peer.received - lastBandwidthSample.rx);
                const dTx = Math.max(0, peer.sent - lastBandwidthSample.tx);
                rxMbps = (dRx * 8) / (dt * 1_000_000);
                txMbps = (dTx * 8) / (dt * 1_000_000);
            }
        }

        lastBandwidthSample = {
            ip: activeChartIp,
            rx: peer.received,
            tx: peer.sent,
            time: now,
        };

        const timeLabel = new Date().toLocaleTimeString();
        activeChart.data.labels.push(timeLabel);
        activeChart.data.datasets[0].data.push(round2(rxMbps));
        activeChart.data.datasets[1].data.push(round2(txMbps));

        if (activeChart.data.labels.length > 60) {
            activeChart.data.labels.shift();
            activeChart.data.datasets[0].data.shift();
            activeChart.data.datasets[1].data.shift();
        }

        activeChart.update('none');
    } catch (err) {
        console.debug('Chart poll error:', err);
    }
}

function updateChartTheme() {
    const colors = getChartColors();
    [serverChart, activeChart].forEach(chart => {
        if (!chart) return;
        chart.options.scales.x.grid.color = colors.gridColor;
        chart.options.scales.x.ticks.color = colors.textColor;
        chart.options.scales.y.grid.color = colors.gridColor;
        chart.options.scales.y.ticks.color = colors.textColor;
        chart.options.plugins.legend.labels.color = colors.textColor;
        chart.data.datasets[0].borderColor = colors.rxBorder;
        chart.data.datasets[0].backgroundColor = colors.rxBg;
        chart.data.datasets[1].borderColor = colors.txBorder;
        chart.data.datasets[1].backgroundColor = colors.txBg;
        chart.update();
    });
}

function round2(num) {
    return Math.round(num * 100) / 100;
}
