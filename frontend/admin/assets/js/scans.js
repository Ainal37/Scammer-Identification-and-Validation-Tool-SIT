// ===== SIT Admin – Scans Page =====
requireAuth();

const PER_PAGE = 10;
let allScans = [], currentPage = 1, typingTimer = null, refreshPaused = false, lastTopId = null;

function setStatus(msg) { const el = document.getElementById("liveStatus"); if (el) el.textContent = msg; }

function getFiltered() {
  const q = document.getElementById("searchInput").value.trim().toLowerCase();
  const v = document.getElementById("verdictFilter").value;
  return allScans.filter(s => {
    if (v && s.verdict !== v) return false;
    if (q && !(s.link || "").toLowerCase().includes(q)) return false;
    return true;
  });
}

function render() {
  const f = getFiltered(), tp = Math.max(1, Math.ceil(f.length / PER_PAGE));
  if (currentPage > tp) currentPage = tp;
  const start = (currentPage - 1) * PER_PAGE, page = f.slice(start, start + PER_PAGE);
  const tbody = document.getElementById("scansBody");

  if (page.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" class="text-muted text-center">No scans found</td></tr>';
  } else {
    tbody.innerHTML = page.map(s => {
      var reportCell = "\u2014";
      if (s.linked_report) {
        var lr = s.linked_report;
        reportCell = '#<span>' + lr.id + '</span> (' + lr.status + ') ' +
          '<button class="btn btn-sm" style="font-size:11px;padding:2px 6px;margin-left:4px" onclick="event.stopPropagation();window.location.href=\'reports.html\'">Go to Report</button>';
      }
      return '<tr data-id="' + s.id + '" onclick="openScanModal(' + s.id + ')">' +
        '<td>' + s.id + '</td>' +
        '<td class="link-cell" title="' + (s.link || "").replace(/"/g, "&quot;") + '">' + (s.link || "\u2014") + '</td>' +
        '<td><span class="badge ' + (s.threat_level || s.verdict) + '">' + (s.threat_level || s.verdict) + '</span></td>' +
        '<td>' + s.score + '</td>' +
        '<td>' + (s.reason || "\u2014").substring(0, 60) + '</td>' +
        '<td>' + reportCell + '</td>' +
        '<td>' + (s.created_at || "\u2014") + '</td></tr>';
    }).join("");
    const topId = allScans[0]?.id;
    if (lastTopId !== null && topId && topId !== lastTopId && currentPage === 1) {
      const tr = tbody.querySelector('tr[data-id="' + topId + '"]');
      if (tr) { tr.classList.add("row-new"); setTimeout(() => tr.classList.remove("row-new"), 2500); }
    }
    lastTopId = topId;
  }
  document.getElementById("pageInfo").textContent = f.length + " result" + (f.length !== 1 ? "s" : "") + " \u2014 Page " + currentPage + " / " + tp;
  document.getElementById("prevBtn").disabled = currentPage <= 1;
  document.getElementById("nextBtn").disabled = currentPage >= tp;
}

async function refresh() {
  if (refreshPaused) return;
  try { setStatus("Updating\u2026"); allScans = await listScans() || []; render(); setStatus("Last updated: " + new Date().toLocaleTimeString()); }
  catch (e) { setStatus("Update failed"); }
}

// Events
document.getElementById("searchInput").addEventListener("input", () => {
  refreshPaused = true; clearTimeout(typingTimer);
  typingTimer = setTimeout(() => { refreshPaused = false; }, 2000);
  currentPage = 1; render();
});
document.getElementById("verdictFilter").addEventListener("change", () => { currentPage = 1; render(); });
document.getElementById("prevBtn").addEventListener("click", () => { if (currentPage > 1) { currentPage--; render(); } });
document.getElementById("nextBtn").addEventListener("click", () => { if (currentPage < Math.ceil(getFiltered().length / PER_PAGE)) { currentPage++; render(); } });

// Quick Scan
document.getElementById("scanForm").addEventListener("submit", async e => {
  e.preventDefault();
  const link = document.getElementById("scanLink").value.trim();
  const rd = document.getElementById("scanResult"); rd.style.display = "none";
  try {
    const d = await createScan({ link });
    if (!d) return;
    rd.style.display = "block";
    rd.innerHTML = '<div class="stat-card" style="margin-top:10px;border-left-color:' +
      (d.threat_level === "HIGH" ? "#dc2626" : d.threat_level === "MED" ? "#d97706" : "#059669") + '">' +
      '<div class="label">Result</div><div><span class="badge ' + (d.threat_level || d.verdict) + '">' +
      (d.threat_level || d.verdict) + '</span> Score: <strong>' + d.score + '</strong></div>' +
      '<div class="mt-1 text-muted" style="font-size:12px">' + (d.reason || "") + '</div></div>';
    document.getElementById("scanLink").value = "";
    if (d.auto_report_id) {
      showToast("High risk detected. Report #" + d.auto_report_id + " created automatically.", "success");
    } else {
      showToast("Scan complete", "success");
    }
    refreshPaused = false; await refresh();
  } catch (err) { rd.style.display = "block"; rd.innerHTML = '<p style="color:#dc2626">Error: ' + err.message + '</p>'; }
});

// ── Scan Evidence Modal ──
async function openScanModal(id) {
  const s = allScans.find(x => x.id === id) || await getScan(id);
  if (!s) return;
  let overlay = document.getElementById("scanModal");
  if (!overlay) {
    overlay = document.createElement("div"); overlay.id = "scanModal"; overlay.className = "modal-overlay";
    overlay.addEventListener("click", e => { if (e.target === overlay) overlay.style.display = "none"; });
    document.body.appendChild(overlay);
  }
  const bd = s.breakdown || [];
  const intel = s.intel_summary || {};
  const domain = (() => { try { return new URL(s.link).hostname; } catch { return s.link; } })();
  const scoreClass = s.score >= 55 ? "high" : s.score >= 25 ? "med" : "low";

  // Build intel summary section
  let intelHtml = "";
  if (intel && Object.keys(intel).length > 0) {
    intelHtml = '<h3 style="margin-top:16px;font-size:14px;border-bottom:1px solid var(--border);padding-bottom:6px">Threat Intelligence</h3>' +
      '<table style="width:100%;font-size:12px">';
    if (intel.virustotal) {
      const vt = intel.virustotal;
      const vtStatus = vt.found ? (vt.positives > 0 ? '<span class="badge scam">Flagged ' + vt.positives + '/' + vt.total + '</span>' : '<span class="badge safe">Clean</span>') : '<span class="badge" style="background:#f3f4f6">Not found</span>';
      intelHtml += '<tr><td style="font-weight:600;width:130px;color:var(--text-3)">VirusTotal</td><td>' + vtStatus;
      if (vt.threat_label) intelHtml += ' <span class="reason-chip">' + vt.threat_label + '</span>';
      if (vt.error) intelHtml += ' <span style="color:var(--text-3);font-size:11px">(' + vt.error + ')</span>';
      intelHtml += '</td></tr>';
    }
    if (intel.urlhaus) {
      const uh = intel.urlhaus;
      const uhStatus = uh.found ? '<span class="badge scam">' + (uh.threat || 'Listed') + '</span>' : '<span class="badge safe">Not listed</span>';
      intelHtml += '<tr><td style="font-weight:600;width:130px;color:var(--text-3)">URLhaus</td><td>' + uhStatus;
      if (uh.tags && uh.tags.length) intelHtml += ' ' + uh.tags.map(function(t){ return '<span class="reason-chip">' + t + '</span>'; }).join("");
      if (uh.error) intelHtml += ' <span style="color:var(--text-3);font-size:11px">(' + uh.error + ')</span>';
      intelHtml += '</td></tr>';
    }
    intelHtml += '</table>';
  }

  overlay.innerHTML = '<div class="modal"><div class="modal-header"><h2>Scan Evidence #' + s.id + '</h2>' +
    '<button class="btn-ghost" onclick="document.getElementById(\'scanModal\').style.display=\'none\'">&times;</button></div>' +
    '<div class="modal-body" id="evidenceBody">' +
    '<div class="score-gauge"><div class="score-number">' + s.score + '</div><div style="flex:1"><div style="font-size:12px;margin-bottom:4px"><span class="badge ' +
    (s.threat_level || s.verdict) + '">' + (s.threat_level || s.verdict) + '</span> <span class="badge ' +
    s.verdict + '">' + s.verdict + '</span></div>' +
    '<div class="score-bar"><div class="score-fill ' + scoreClass + '" style="width:' + s.score + '%"></div></div></div></div>' +
    '<table class="evidence-table"><tr><td>URL</td><td><code>' + s.link + '</code></td></tr>' +
    '<tr><td>Domain</td><td>' + domain + '</td></tr>' +
    '<tr><td>Score</td><td>' + s.score + ' / 100</td></tr>' +
    '<tr><td>Threat Level</td><td><span class="badge ' + (s.threat_level || "LOW") + '">' + (s.threat_level || "N/A") + '</span></td></tr>' +
    '<tr><td>Verdict</td><td><span class="badge ' + s.verdict + '">' + s.verdict + '</span></td></tr>' +
    '<tr><td>Date</td><td>' + (s.created_at || "N/A") + '</td></tr>' +
    (s.message ? '<tr><td>Message</td><td style="font-size:12px;color:var(--text-2)">' + s.message.substring(0, 200) + '</td></tr>' : '') +
    '<tr><td>Reasons</td><td>' + (s.reason || "").split(";").map(function(r){ return '<span class="reason-chip">' + r.trim() + '</span>'; }).join("") + '</td></tr></table>' +
    intelHtml +
    (bd.length ? '<h3 style="margin-top:16px;font-size:14px;border-bottom:1px solid var(--border);padding-bottom:6px">Breakdown (' + bd.length + ' rules)</h3>' +
    '<table style="width:100%;font-size:12px"><thead><tr><th>Source</th><th>Rule</th><th>Points</th><th>Detail</th></tr></thead><tbody>' +
    bd.map(function(b){ return '<tr class="breakdown-row"><td><span class="badge" style="background:#f3f4f6;text-transform:none">' + b.source + '</span></td><td>' + b.rule + '</td><td style="font-weight:600">+' + b.points + '</td><td>' + b.detail + '</td></tr>'; }).join("") +
    '</tbody></table>' : '') +
    '</div><div class="modal-footer">' +
    '<button class="btn btn-sm" onclick="copyEvidence()">Copy Evidence</button>' +
    '<button class="btn btn-sm" onclick="exportPDF()">Export PDF</button>' +
    '<button class="btn btn-sm btn-primary" onclick="createReportFromScan(' + s.id + ')">Create Report</button>' +
    '</div></div>';
  overlay.style.display = "flex";
  window._currentScanEvidence = s;
}

function copyEvidence() {
  const s = window._currentScanEvidence; if (!s) return;
  const text = "SIT Scan Evidence #" + s.id + "\nURL: " + s.link + "\nScore: " + s.score + "/100\nThreat: " + (s.threat_level || "N/A") +
    "\nVerdict: " + s.verdict + "\nReasons: " + (s.reason || "N/A") + "\nDate: " + (s.created_at || "N/A") +
    (s.breakdown ? "\n\nBreakdown:\n" + s.breakdown.map(b => "  [" + b.source + "] " + b.rule + " (+" + b.points + ") " + b.detail).join("\n") : "");
  navigator.clipboard.writeText(text).then(() => showToast("Evidence copied", "success"));
}

function exportPDF() {
  const body = document.getElementById("evidenceBody"); if (!body) return;
  const w = window.open("", "_blank");
  w.document.write('<html><head><title>SIT Evidence</title><style>body{font-family:Arial,sans-serif;padding:30px;font-size:13px;color:#111}table{width:100%;border-collapse:collapse}td,th{padding:6px 8px;border-bottom:1px solid #ddd;text-align:left}th{background:#f5f5f5}code{background:#f3f4f6;padding:2px 6px;border-radius:3px}.badge{display:inline-block;padding:2px 10px;border-radius:4px;font-size:11px;font-weight:600}</style></head><body>' +
    '<h1 style="font-size:18px">SIT Scan Evidence</h1>' + body.innerHTML + '</body></html>');
  w.document.close();
  setTimeout(() => { w.print(); }, 500);
}

async function createReportFromScan(id) {
  const s = window._currentScanEvidence || allScans.find(x => x.id === id);
  if (!s) return;
  try {
    const r = await createReport({ link: s.link, report_type: "scam", description: "Auto-created from scan #" + s.id + ": " + (s.reason || "N/A").substring(0, 200) });
    if (r) { showToast("Report #" + r.id + " created", "success"); document.getElementById("scanModal").style.display = "none"; }
  } catch (e) { showToast("Failed to create report", "error"); }
}

refresh();
setInterval(refresh, 5000);
