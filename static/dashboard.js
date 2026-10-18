(() => {
  'use strict';
  const byId = (id) => document.getElementById(id);
  const num = new Intl.NumberFormat('en-IN');
  const severityColors = {
    Critical: '#ff6178', High: '#ffb547', Medium: '#ffd36b', Low: '#579cff', Informational: '#94a9c7', Unknown: '#667b96'
  };
  let dashboardData = window.SIEM_INITIAL || null;
  let charts = {};
  let toastTimer;

  function esc(value) {
    return String(value ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }
  function fmt(value) { return num.format(Number(value || 0)); }
  function showToast(message) {
    const toast = byId('toastMessage');
    toast.textContent = message;
    toast.classList.add('visible');
    window.clearTimeout(toastTimer);
    toastTimer = window.setTimeout(() => toast.classList.remove('visible'), 3400);
  }
  function showUploadStatus(message, error = false) {
    const box = byId('uploadStatus');
    box.hidden = false;
    box.classList.toggle('error', error);
    box.textContent = message;
  }
  function animateMetric(el, target) {
    if (!el) return;
    const end = Math.max(0, Number(target) || 0);
    const start = Number(el.dataset.current || 0);
    const duration = 360;
    const beginning = performance.now();
    function tick(now) {
      const progress = Math.min(1, (now - beginning) / duration);
      const eased = 1 - Math.pow(1 - progress, 3);
      el.textContent = fmt(Math.round(start + (end - start) * eased));
      if (progress < 1) requestAnimationFrame(tick);
      else el.dataset.current = String(end);
    }
    requestAnimationFrame(tick);
  }
  function renderMetrics(data) {
    const s = data.summary || {};
    animateMetric(byId('metricTotalRecords'), s.total_records);
    animateMetric(byId('metricValidRecords'), s.valid_records);
    animateMetric(byId('metricRejectedRecords'), s.rejected_records);
    animateMetric(byId('metricUniqueIPs'), s.unique_source_ips);
    animateMetric(byId('metricAlerts'), s.alerts);
    animateMetric(byId('severityTotal'), s.alerts);
    byId('sideAlertCount').textContent = fmt(s.alerts || 0);
    byId('qualityTotal').textContent = fmt(s.total_records || 0);
    byId('qualityValid').textContent = fmt(s.valid_records || 0);
    byId('qualityRejected').textContent = fmt(s.rejected_records || 0);
    const total = Number(s.total_records || 0);
    const valid = Number(s.valid_records || 0);
    byId('qualityValidBar').style.width = `${total ? Math.max(0, Math.min(100, valid * 100 / total)) : 0}%`;
    byId('datasetLabel').textContent = data.data_mode === 'uploaded-csv' ? 'Uploaded CSV analyzed locally' : 'Project CSV files loaded';
  }
  function chartAvailable() {
    if (window.Chart) return true;
    showToast('Chart.js did not load. Check your internet connection to enable charts.');
    return false;
  }
  function chartOptions() {
    return {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 650, easing: 'easeOutQuart' },
      plugins: {
        legend: { display: false },
        tooltip: { backgroundColor: '#14253b', titleColor: '#eef7ff', bodyColor: '#c3d4e8', borderColor: '#34516f', borderWidth: 1, padding: 10, displayColors: true }
      },
      scales: {
        x: { grid: { color: 'rgba(120, 150, 183, .08)' }, ticks: { color: '#7f94ad', maxRotation: 0, autoSkip: true, font: { size: 9 } }, border: { color: 'rgba(120,150,183,.15)' } },
        y: { beginAtZero: true, grid: { color: 'rgba(120, 150, 183, .1)' }, ticks: { color: '#7f94ad', precision: 0, font: { size: 9 } }, border: { display: false } }
      }
    };
  }
  function replaceChart(id, config) {
    if (!chartAvailable()) return;
    const canvas = byId(id);
    if (!canvas) return;
    if (charts[id]) charts[id].destroy();
    charts[id] = new Chart(canvas, config);
  }
  function renderTrend(data) {
    const trend = data.trend || { labels: [], values: [] };
    const empty = !trend.labels?.length;
    byId('eventTrendEmpty').hidden = !empty;
    byId('eventTrendChart').style.visibility = empty ? 'hidden' : 'visible';
    replaceChart('eventTrendChart', {
      type: 'line',
      data: { labels: trend.labels || [], datasets: [{ label: 'Records', data: trend.values || [], borderColor: '#48caff', backgroundColor: 'rgba(72,202,255,.12)', fill: true, borderWidth: 2, tension: .36, pointRadius: 3, pointHoverRadius: 5, pointBackgroundColor: '#d4f5ff', pointBorderColor: '#48caff' }] },
      options: { ...chartOptions(), scales: { ...chartOptions().scales, y: { ...chartOptions().scales.y, suggestedMax: Math.max(3, ...(trend.values || [0])) } } }
    });
  }
  function renderSeverity(data) {
    const sev = data.severity || { labels: [], values: [] };
    const labels = sev.labels || [];
    const values = sev.values || [];
    const colors = labels.map((label) => severityColors[label] || severityColors.Unknown);
    replaceChart('severityChart', {
      type: 'doughnut',
      data: { labels, datasets: [{ data: values, backgroundColor: colors, borderColor: '#0c1727', borderWidth: 3, hoverOffset: 5 }] },
      options: { responsive: true, maintainAspectRatio: false, cutout: '72%', animation: { animateRotate: true, duration: 650 }, plugins: { legend: { display: false }, tooltip: { backgroundColor: '#14253b', titleColor: '#eef7ff', bodyColor: '#c3d4e8', borderColor: '#34516f', borderWidth: 1, padding: 10 } } }
    });
    const total = values.reduce((acc, value) => acc + Number(value || 0), 0);
    byId('severityLegend').innerHTML = labels.map((label, index) => {
      const value = Number(values[index] || 0);
      const percent = total ? Math.round(value * 100 / total) : 0;
      return `<div class="severity-row"><span class="severity-dot" style="background:${colors[index]}"></span><span>${esc(label)}</span><strong>${fmt(value)} <span class="severity-percent">(${percent}%)</span></strong></div>`;
    }).join('') || '<div class="empty-cell">No severity values in supplied alerts.</div>';
  }
  function renderEventTypes(data) {
    const rows = data.event_types || [];
    byId('eventTypesEmpty').hidden = rows.length > 0;
    byId('eventTypesChart').style.visibility = rows.length ? 'visible' : 'hidden';
    replaceChart('eventTypesChart', {
      type: 'bar',
      data: { labels: rows.map((row) => row.label), datasets: [{ label: 'Records', data: rows.map((row) => row.value), backgroundColor: rows.map((_, i) => ['#4acbff', '#539bff', '#a58cff', '#42d4a2', '#ffb547', '#fb7489', '#5fcac7', '#9bb3d0'][i % 8]), borderRadius: 5, maxBarThickness: 32 }] },
      options: { ...chartOptions(), indexAxis: 'y', scales: { x: { ...chartOptions().scales.x, beginAtZero: true, ticks: { color: '#7f94ad', precision: 0, font: { size: 9 } } }, y: { grid: { display: false }, ticks: { color: '#b8c9dd', font: { size: 9 } }, border: { display: false } } } }
    });
  }
  function severityClass(severity) { return `severity-${String(severity || 'Unknown').toLowerCase().replace(/[^a-z]/g, '')}`; }
  function statusClass(status) { return `status-${String(status || 'unassigned').toLowerCase().replace(/[^a-z]/g, '')}`; }
  function renderAlerts(data) {
    const alerts = data.alerts || [];
    const query = (byId('alertSearch')?.value || '').trim().toLowerCase();
    const filter = byId('severityFilter')?.value || 'all';
    const matched = alerts.map((alert, index) => ({ alert, index })).filter(({ alert }) => {
      const text = [alert.alert_id, alert.alert_name, alert.source_ip, alert.username, alert.rule_id, alert.status, alert.reason, alert.destination_ip].join(' ').toLowerCase();
      return (!query || text.includes(query)) && (filter === 'all' || alert.severity === filter);
    });
    byId('alertsTableBody').innerHTML = matched.length ? matched.map(({ alert, index }) => `
      <tr class="clickable-row" tabindex="0" role="button" data-alert-index="${index}" aria-label="View ${esc(alert.alert_name)} details">
        <td>${esc(alert.timestamp_display || alert.timestamp || '—')}</td>
        <td class="alert-name-cell">${esc(alert.alert_name)}<span class="row-subtext">${esc(alert.alert_id)}</span></td>
        <td><span class="severity-badge ${severityClass(alert.severity)}"><i class="fa-solid fa-circle"></i>${esc(alert.severity)}</span></td>
        <td class="ip-cell">${esc(alert.source_ip || '—')}</td>
        <td><span class="rule-chip">${esc(alert.rule_id || 'Not provided')}</span></td>
        <td><span class="status-badge ${statusClass(alert.status)}"><i class="fa-solid fa-circle"></i>${esc(alert.status || 'Unassigned')}</span></td>
        <td class="reason-cell">${esc(alert.reason || 'No evidence provided.')}</td>
      </tr>`).join('') : '<tr><td colspan="7" class="empty-cell">No alert rows match this search/filter.</td></tr>';
    byId('alertsTableCount').textContent = `${fmt(matched.length)} of ${fmt(alerts.length)} alert rows`;
    byId('suspiciousEventCount').textContent = `${fmt(data.summary?.suspicious_events || 0)} processed event row(s) match the configured suspicious-keyword summary.`;
  }
  function renderIncidents(data) {
    const rows = data.incidents || [];
    byId('incidentsTableBody').innerHTML = rows.length ? rows.map((item) => `
      <tr><td class="incident-id">${esc(item.incident_id)}</td><td>${fmt(item.alert_count)}</td><td><span class="severity-badge ${severityClass(item.highest_severity)}"><i class="fa-solid fa-circle"></i>${esc(item.highest_severity)}</span></td><td class="ip-cell">${esc(item.source_ip || '—')}</td></tr>`).join('') : '<tr><td colspan="4" class="empty-cell">No incident IDs were supplied in the current alert rows. Connect the team incident module to populate this table.</td></tr>';
  }
  function renderCorrelation(data) {
    const rows = data.correlated_groups || [];
    byId('correlationTableBody').innerHTML = rows.length ? rows.map((item) => `
      <tr><td><strong class="incident-id">${esc(item.incident_id)}</strong><span class="row-subtext">${esc(item.alerts)}</span></td><td>${fmt(item.alert_count)}</td><td><span class="severity-badge ${severityClass(item.highest_severity)}"><i class="fa-solid fa-circle"></i>${esc(item.highest_severity)}</span></td><td class="reason-cell">${esc(item.correlation_method)}</td></tr>`).join('') : '<tr><td colspan="4" class="empty-cell">No related alert groups were found in the supplied identifiers/source IPs.</td></tr>';
  }
  function renderRejected(data) {
    const rows = data.rejected_records || [];
    byId('rejectedTableBody').innerHTML = rows.length ? rows.map((item) => `
      <tr><td>${esc(item.row_number)}</td><td>${esc(item.timestamp)}</td><td class="ip-cell">${esc(item.source_ip || '(missing)')}</td><td class="reason-cell">${esc(item.reject_reason || 'No reason supplied.')}</td></tr>`).join('') : '<tr><td colspan="4" class="empty-cell">No rejected records in the current dataset.</td></tr>';
  }
  function renderRules(data) {
    const rules = data.rules || [];
    byId('rulesList').innerHTML = rules.map((rule) => `
      <div class="rule-item"><div class="rule-head"><span class="rule-id">${esc(rule.rule_id)}</span><strong>${esc(rule.name)}</strong></div><div class="rule-condition">${esc(rule.condition)}</div><div class="rule-priority">Priority: ${esc(rule.priority)}</div></div>`).join('') || '<div class="empty-cell">No rule catalog supplied.</div>';
  }
  function renderSourceFiles(data) {
    const files = data.source_files || {};
    byId('sourceFileSummary').innerHTML = Object.entries(files).map(([name, count]) => `<div class="source-file-entry"><span>${esc(name)}</span><strong>${fmt(count)} row(s)</strong></div>`).join('') || '<div class="source-file-entry"><span>Source file counts unavailable</span></div>';
  }
  function renderDashboard(data) {
    dashboardData = data;
    renderMetrics(data);
    renderTrend(data);
    renderSeverity(data);
    renderEventTypes(data);
    renderAlerts(data);
    renderIncidents(data);
    renderCorrelation(data);
    renderRejected(data);
    renderRules(data);
    renderSourceFiles(data);
  }
  function openAlertDetail(index) {
    const alert = dashboardData?.alerts?.[index];
    if (!alert) return;
    byId('detailTitle').textContent = alert.alert_name || 'Alert details';
    byId('detailModalBody').innerHTML = `
      <div class="detail-badges"><span class="severity-badge ${severityClass(alert.severity)}"><i class="fa-solid fa-circle"></i>${esc(alert.severity)}</span><span class="status-badge ${statusClass(alert.status)}"><i class="fa-solid fa-circle"></i>${esc(alert.status)}</span><span class="rule-chip">${esc(alert.alert_id)}</span></div>
      <div class="detail-grid">
        <div class="detail-field"><span>Timestamp</span><strong>${esc(alert.timestamp || '—')}</strong></div>
        <div class="detail-field"><span>Rule ID</span><strong>${esc(alert.rule_id || 'Not provided')}</strong></div>
        <div class="detail-field"><span>Source IP</span><strong>${esc(alert.source_ip || '—')}</strong></div>
        <div class="detail-field"><span>Destination IP</span><strong>${esc(alert.destination_ip || '—')}</strong></div>
        <div class="detail-field"><span>Username</span><strong>${esc(alert.username || '—')}</strong></div>
        <div class="detail-field"><span>Incident ID</span><strong>${esc(alert.incident_id || 'Not linked')}</strong></div>
        <div class="detail-field"><span>Event count</span><strong>${fmt(alert.event_count || 1)}</strong></div>
        <div class="detail-field"><span>Source</span><strong>${esc(dashboardData.data_mode === 'uploaded-csv' ? 'Uploaded CSV + example rules' : 'security_alerts.csv')}</strong></div>
      </div>
      <p class="detail-reason"><strong>Evidence / reason:</strong> ${esc(alert.reason || 'No reason was supplied in the source row.')}</p>
      <p class="detail-reason">This alert is an investigation lead. It does not, by itself, prove compromise.</p>`;
    byId('alertDetailModal').hidden = false;
  }
  function closeDetail() { byId('alertDetailModal').hidden = true; }
  function csvEscape(value) { const text = String(value ?? ''); return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text; }
  function downloadCsv(rows, columns, filename) {
    const content = [columns.map((col) => csvEscape(col.label)).join(','), ...rows.map((row) => columns.map((col) => csvEscape(row[col.key])).join(','))].join('\r\n');
    const blob = new Blob(['\ufeff', content], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  }
  const ALERT_EXPORT_COLUMNS = [
    { key: 'alert_id', label: 'alert_id' }, { key: 'timestamp', label: 'timestamp' }, { key: 'alert_name', label: 'alert_name' },
    { key: 'severity', label: 'severity' }, { key: 'source_ip', label: 'source_ip' }, { key: 'destination_ip', label: 'destination_ip' },
    { key: 'username', label: 'username' }, { key: 'rule_id', label: 'rule_id' }, { key: 'status', label: 'status' },
    { key: 'event_count', label: 'event_count' }, { key: 'reason', label: 'reason' }, { key: 'incident_id', label: 'incident_id' }
  ];
  const REJECT_EXPORT_COLUMNS = [
    { key: 'row_number', label: 'row_number' }, { key: 'timestamp', label: 'timestamp' }, { key: 'username', label: 'username' },
    { key: 'source_ip', label: 'source_ip' }, { key: 'event_type', label: 'event_type' }, { key: 'reject_reason', label: 'reject_reason' }
  ];
  async function uploadSelectedFile(file) {
    if (!file) return;
    const form = new FormData();
    form.append('log_file', file);
    const button = byId('uploadButton');
    const oldText = button.innerHTML;
    button.disabled = true;
    button.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i><span>Analyzing…</span>';
    try {
      const response = await fetch('/api/analyze', { method: 'POST', body: form });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'The CSV could not be analyzed.');
      byId('alertSearch').value = '';
      byId('severityFilter').value = 'all';
      renderDashboard(result);
      showUploadStatus(`Analyzed “${file.name}” locally: ${fmt(result.summary.total_records)} total, ${fmt(result.summary.valid_records)} valid, ${fmt(result.summary.rejected_records)} rejected and ${fmt(result.summary.alerts)} rule-based alerts. The original project CSV files were not overwritten.`);
      showToast('CSV analysis completed locally.');
    } catch (error) {
      showUploadStatus(error.message || 'Could not analyze the CSV.', true);
    } finally {
      button.disabled = false;
      button.innerHTML = oldText;
      byId('logFileInput').value = '';
    }
  }
  async function resetProjectData() {
    try {
      const response = await fetch('/api/demo');
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Could not reload the project CSV files.');
      byId('alertSearch').value = '';
      byId('severityFilter').value = 'all';
      renderDashboard(result);
      byId('uploadStatus').hidden = true;
      showToast('Reloaded processed_logs.csv, invalid_logs.csv and security_alerts.csv.');
    } catch (error) {
      showUploadStatus(error.message || 'Could not reload project data.', true);
    }
  }
  function init() {
    byId('uploadButton').addEventListener('click', () => byId('logFileInput').click());
    byId('sidebarUploadButton').addEventListener('click', () => byId('logFileInput').click());
    byId('logFileInput').addEventListener('change', (event) => uploadSelectedFile(event.target.files?.[0]));
    byId('resetDemoButton').addEventListener('click', resetProjectData);
    byId('alertSearch').addEventListener('input', () => renderAlerts(dashboardData || {}));
    byId('severityFilter').addEventListener('change', () => renderAlerts(dashboardData || {}));
    byId('clearFiltersButton').addEventListener('click', () => { byId('alertSearch').value = ''; byId('severityFilter').value = 'all'; renderAlerts(dashboardData || {}); });
    byId('alertsTableBody').addEventListener('click', (event) => { const row = event.target.closest('[data-alert-index]'); if (row) openAlertDetail(Number(row.dataset.alertIndex)); });
    byId('alertsTableBody').addEventListener('keydown', (event) => { if (event.key === 'Enter' || event.key === ' ') { const row = event.target.closest('[data-alert-index]'); if (row) { event.preventDefault(); openAlertDetail(Number(row.dataset.alertIndex)); } } });
    byId('closeDetailModal').addEventListener('click', closeDetail);
    byId('alertDetailModal').addEventListener('click', (event) => { if (event.target === byId('alertDetailModal')) closeDetail(); });
    document.addEventListener('keydown', (event) => { if (event.key === 'Escape') closeDetail(); });
    byId('exportAlertsButton').addEventListener('click', () => downloadCsv(dashboardData?.alerts || [], ALERT_EXPORT_COLUMNS, 'security_alerts_export.csv'));
    byId('exportRejectedButton').addEventListener('click', () => downloadCsv(dashboardData?.rejected_records || [], REJECT_EXPORT_COLUMNS, 'invalid_logs_export.csv'));
    byId('printReportButton').addEventListener('click', () => window.print());
    byId('mobileMenuButton').addEventListener('click', () => byId('sidebar').classList.toggle('open'));
    byId('sidebar').addEventListener('click', (event) => { if (event.target.closest('a')) byId('sidebar').classList.remove('open'); });
    if (dashboardData) renderDashboard(dashboardData);
    else if (window.SIEM_LOAD_ERROR) showUploadStatus(`Initial CSV load failed: ${window.SIEM_LOAD_ERROR}`, true);
  }
  document.addEventListener('DOMContentLoaded', init);
})();
