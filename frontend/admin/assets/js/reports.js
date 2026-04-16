// ===== SIT Admin – Reports Page (Table + Kanban) =====
requireAuth();

const PER_PAGE = 10;
let allReports = [], recentScans = [], currentPage = 1, typingTimer = null, refreshPaused = false, lastTopId = null;
let viewMode = "table"; // "table" or "kanban"

const PRIORITY_SLA = { low: "7 days", medium: "3 days", high: "24 hours", critical: "6 hours" };

function setStatus(msg) { const el = document.getElementById("liveStatus"); if (el) el.textContent = msg; }

function getFilterParams() {
  var st = document.getElementById("statusFilter");
  var pf = document.getElementById("priorityFilter");
  var af = document.getElementById("assigneeFilter");
  var params = { limit: 200 };
  if (st && st.value) params.status = st.value;
  if (pf && pf.value) params.priority = pf.value;
  if (af && af.value) params.assignee = af.value === "__unassigned__" ? "unassigned" : af.value;
  return params;
}

function getFiltered() {
  const q = document.getElementById("searchInput");
  const search = q ? q.value.trim().toLowerCase() : "";
  return allReports.filter(r => {
    if (search) {
      const h = ((r.link || "") + " " + (r.description || "")).toLowerCase();
      if (!h.includes(search)) return false;
    }
    return true;
  });
}

function getSelectedIds() {
  var ids = [];
  document.querySelectorAll('.report-row-cb:checked').forEach(function (cb) {
    var id = parseInt(cb.dataset.id, 10);
    if (!isNaN(id)) ids.push(id);
  });
  return ids;
}

function updateBulkBar() {
  var bar = document.getElementById("bulkActionsBar");
  var countEl = document.getElementById("bulkSelectedCount");
  var ids = getSelectedIds();
  if (bar && countEl) {
    bar.style.display = ids.length > 0 ? "flex" : "none";
    countEl.textContent = ids.length;
  }
}

// ── Table view ──
function renderTable() {
  const f = getFiltered(), tp = Math.max(1, Math.ceil(f.length / PER_PAGE));
  if (currentPage > tp) currentPage = tp;
  const start = (currentPage - 1) * PER_PAGE, page = f.slice(start, start + PER_PAGE);
  const tbody = document.getElementById("reportsBody");

  if (page.length === 0) {
    tbody.innerHTML = '<tr><td colspan="11" class="text-muted text-center">No reports found</td></tr>';
  } else {
    tbody.innerHTML = page.map(r => {
      var dueStr = r.due_at ? new Date(r.due_at).toLocaleDateString() : "\u2014";
      var pri = (r.priority || "medium");
      var scanCell = r.linked_scan_id ? '<span class="badge" style="background:var(--border)">Scan #' + r.linked_scan_id + '</span>' : "\u2014";
      return '<tr data-id="' + r.id + '">' +
        '<td><input type="checkbox" class="report-row-cb" data-id="' + r.id + '" /></td>' +
        '<td>' + r.id + '</td>' +
        '<td>' + scanCell + '</td>' +
        '<td class="link-cell" title="' + (r.link || "").replace(/"/g, "&quot;") + '">' + (r.link || "\u2014").substring(0, 50) + (r.link && r.link.length > 50 ? "..." : "") + '</td>' +
        '<td>' + (r.report_type || "\u2014") + '</td>' +
        '<td><span class="badge badge-priority-' + pri + '">' + pri + '</span></td>' +
        '<td>' + dueStr + '</td>' +
        '<td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + (r.description || "\u2014") + '</td>' +
        '<td><span class="badge ' + r.status + '">' + r.status + '</span></td>' +
        '<td>' + (r.assignee || "\u2014") + '</td>' +
        '<td>' +
        '<select class="status-select" data-id="' + r.id + '" style="font-size:11px;padding:2px 6px;border:1px solid var(--border);border-radius:4px;margin-right:4px">' +
        ['new','investigating','resolved'].map(s => '<option value="' + s + '"' + (r.status === s ? ' selected' : '') + '>' + s + '</option>').join("") +
        '</select>' +
        '<button class="btn btn-sm" style="font-size:11px;padding:2px 6px" onclick="downloadReportCasePdf(' + r.id + ')">Download PDF</button>' +
        '</td></tr>';
    }).join("");
    tbody.querySelectorAll(".status-select").forEach(sel => {
      sel.addEventListener("change", async function (e) {
        const id = e.target.dataset.id;
        await updateReport(id, { status: e.target.value });
        showToast("Status updated", "success"); await refresh();
      });
    });
    tbody.querySelectorAll(".report-row-cb").forEach(function (cb) {
      cb.addEventListener("change", updateBulkBar);
    });
    const topId = allReports[0]?.id;
    if (lastTopId !== null && topId && topId !== lastTopId && currentPage === 1) {
      const tr = tbody.querySelector('tr[data-id="' + topId + '"]');
      if (tr) { tr.classList.add("row-new"); setTimeout(() => tr.classList.remove("row-new"), 2500); }
    }
    lastTopId = topId;
  }
  var pageInfo = document.getElementById("pageInfo");
  if (pageInfo) pageInfo.textContent = f.length + " result" + (f.length !== 1 ? "s" : "") + " \u2014 Page " + currentPage + " / " + tp;
  var prevBtn = document.getElementById("prevBtn"), nextBtn = document.getElementById("nextBtn");
  if (prevBtn) prevBtn.disabled = currentPage <= 1;
  if (nextBtn) nextBtn.disabled = currentPage >= tp;
  updateBulkBar();
}

// ── Kanban view ──
function renderKanban() {
  ["new", "investigating", "resolved"].forEach(status => {
    const col = document.getElementById("kanban-" + status);
    if (!col) return;
    const items = allReports.filter(r => r.status === status);
    const countEl = col.parentElement.querySelector(".count");
    if (countEl) countEl.textContent = items.length;
    if (items.length === 0) {
      col.innerHTML = '<div class="kanban-empty text-muted" style="font-size:12px;padding:8px">No items</div>';
      col.dataset.status = status;
      return;
    }
    col.dataset.status = status;
    col.innerHTML = items.slice(0, 20).map(r => {
      var pri = r.priority || "medium";
      var dueStr = r.due_at ? new Date(r.due_at).toLocaleDateString() : "";
      var scanBadge = r.linked_scan_id ? '<span class="badge" style="background:var(--border);font-size:10px">Scan #' + r.linked_scan_id + '</span>' : '';
      return '<div class="kanban-card" draggable="true" data-id="' + r.id + '">' +
        '<div class="kc-link">' + (r.link || "No link").substring(0, 60) + (r.link && r.link.length > 60 ? "..." : "") + '</div>' +
        '<div style="font-size:11px;color:var(--text-2);margin:4px 0">' + (r.description || "").substring(0, 80) + '</div>' +
        '<div class="kc-meta"><span class="badge badge-priority-' + pri + '">' + pri + '</span>' + scanBadge + '<span>#' + r.id + '</span>' + (dueStr ? '<span>' + dueStr + '</span>' : '') + '</div></div>';
    }).join("");
    col.querySelectorAll(".kanban-card").forEach(function (card) {
      card.addEventListener("dragstart", onKanbanDragStart);
    });
    col.addEventListener("dragover", onKanbanDragOver);
    col.addEventListener("drop", onKanbanDrop);
  });
}

function onKanbanDragStart(e) {
  e.dataTransfer.setData("text/plain", e.currentTarget.dataset.id);
  e.dataTransfer.effectAllowed = "move";
}

function onKanbanDragOver(e) {
  e.preventDefault();
  e.dataTransfer.dropEffect = "move";
}

function onKanbanDrop(e) {
  e.preventDefault();
  var reportId = e.dataTransfer.getData("text/plain");
  var col = e.currentTarget;
  var newStatus = col.dataset.status;
  if (!reportId || !newStatus) return;
  putReport(reportId, { status: newStatus }).then(function () {
    showToast("Status updated", "success");
    refresh();
  }).catch(function (err) {
    showToast(err.message || "Update failed", "error");
  });
}

function render() {
  if (viewMode === "kanban") { renderKanban(); } else { renderTable(); }
  document.getElementById("tableView").style.display = viewMode === "table" ? "block" : "none";
  document.getElementById("kanbanView").style.display = viewMode === "kanban" ? "block" : "none";
}

async function refresh() {
  if (refreshPaused) return;
  try {
    setStatus("Updating\u2026");
    var params = getFilterParams();
    allReports = await listReports(params) || [];
    render();
    setStatus("Last updated: " + new Date().toLocaleTimeString());
    populateAssigneeFilter();
  } catch (e) { setStatus("Update failed"); }
}

function populateAssigneeFilter() {
  var sel = document.getElementById("assigneeFilter");
  var bulkAssign = document.getElementById("bulkAssign");
  if (!sel) return;
  var assignees = [];
  allReports.forEach(function (r) {
    if (r.assignee && r.assignee.trim() && assignees.indexOf(r.assignee) === -1) assignees.push(r.assignee);
  });
  assignees.sort();
  var opts = '<option value="">All assignee</option><option value="__unassigned__">Unassigned</option>';
  assignees.forEach(function (a) { opts += '<option value="' + String(a).replace(/"/g, "&quot;") + '">' + String(a).replace(/</g, "&lt;") + '</option>'; });
  sel.innerHTML = opts;
  if (bulkAssign) {
    bulkAssign.innerHTML = '<option value="">Assign to...</option><option value="__clear__">Unassigned</option>' +
      assignees.map(function (a) { return '<option value="' + String(a).replace(/"/g, "&quot;") + '">' + String(a).replace(/</g, "&lt;") + '</option>'; }).join("");
  }
}

async function loadRecentScans() {
  try {
    recentScans = await getRecentScans(20) || [];
    var sel = document.getElementById("reportScanSelect");
    if (!sel) return;
    sel.innerHTML = '<option value="">— None —</option>' + recentScans.map(s =>
      '<option value="' + s.id + '">Scan #' + s.id + ' – ' + (s.verdict || "?") + ' (' + s.score + ') – ' + (s.link || "").substring(0, 40) + '...</option>'
    ).join("");
  } catch (e) {}
}

function updateDuePreview() {
  var pri = document.getElementById("reportPriority");
  var el = document.getElementById("reportDuePreview");
  if (el && pri) el.textContent = PRIORITY_SLA[pri.value] || "—";
}

window.downloadReportCasePdf = function (id) {
  downloadCasePdf(id).then(function () { showToast("Case PDF downloaded", "success"); }).catch(function (e) { showToast(e.message || "Download failed", "error"); });
};

// Events
document.getElementById("searchInput").addEventListener("input", function () {
  refreshPaused = true; clearTimeout(typingTimer);
  typingTimer = setTimeout(function () { refreshPaused = false; }, 2000);
  currentPage = 1; render();
});
document.getElementById("statusFilter").addEventListener("change", function () { currentPage = 1; refresh(); });
document.getElementById("priorityFilter").addEventListener("change", function () { currentPage = 1; refresh(); });
document.getElementById("assigneeFilter").addEventListener("change", function () { currentPage = 1; refresh(); });
document.getElementById("prevBtn").addEventListener("click", function () { if (currentPage > 1) { currentPage--; render(); } });
document.getElementById("nextBtn").addEventListener("click", function () { if (currentPage < Math.ceil(getFiltered().length / PER_PAGE)) { currentPage++; render(); } });
document.getElementById("viewToggle").addEventListener("click", function () {
  viewMode = viewMode === "table" ? "kanban" : "table";
  document.getElementById("viewToggle").textContent = viewMode === "table" ? "Kanban View" : "Table View";
  render();
});

document.getElementById("reportScanSelect").addEventListener("change", function () {
  var val = this.value;
  if (!val) return;
  var scan = recentScans.find(function (s) { return String(s.id) === val; });
  if (!scan) return;
  document.getElementById("reportLink").value = scan.link || "";
  var desc = "Scan #" + scan.id + ": " + (scan.verdict || "?") + " (score " + scan.score + ") – " + (scan.reason || "N/A").substring(0, 200);
  document.getElementById("reportDescription").value = desc;
});

document.getElementById("reportPriority").addEventListener("change", updateDuePreview);

document.getElementById("selectAll").addEventListener("change", function () {
  var checked = this.checked;
  document.querySelectorAll(".report-row-cb").forEach(function (cb) { cb.checked = checked; });
  updateBulkBar();
});

document.getElementById("bulkApply").addEventListener("click", async function () {
  var ids = getSelectedIds();
  if (ids.length === 0) { showToast("Select reports first", "error"); return; }
  var assignEl = document.getElementById("bulkAssign");
  var statusVal = document.getElementById("bulkStatus").value;
  var payload = {};
  if (assignEl && assignEl.value) {
    payload.assignee = assignEl.value === "__clear__" ? "" : assignEl.value;
  }
  if (statusVal) payload.status = statusVal;
  if (Object.keys(payload).length === 0) { showToast("Choose assignee or status", "error"); return; }
  try {
    await bulkUpdateReports(ids, payload);
    showToast("Updated " + ids.length + " report(s)", "success");
    document.querySelectorAll(".report-row-cb:checked").forEach(function (cb) { cb.checked = false; });
    document.getElementById("selectAll").checked = false;
    updateBulkBar();
    refresh();
  } catch (e) { showToast(e.message || "Bulk update failed", "error"); }
});

document.getElementById("bulkExport").addEventListener("click", function () {
  var ids = getSelectedIds();
  if (ids.length === 0) { showToast("Select reports first", "error"); return; }
  var f = getFiltered().filter(function (r) { return ids.indexOf(r.id) !== -1; });
  var headers = ["id","link","report_type","priority","due_at","description","status","assignee","created_at"];
  var rows = f.map(function (r) {
    return headers.map(function (h) {
      var v = r[h];
      if (typeof v === "string" && v.indexOf(",") >= 0) return '"' + v.replace(/"/g, '""') + '"';
      return v || "";
    }).join(",");
  });
  var csv = headers.join(",") + "\n" + rows.join("\n");
  var a = document.createElement("a");
  a.href = "data:text/csv;charset=utf-8," + encodeURIComponent(csv);
  a.download = "reports-export.csv";
  a.click();
  showToast("Export downloaded", "success");
});

document.getElementById("bulkClear").addEventListener("click", function () {
  document.querySelectorAll(".report-row-cb:checked").forEach(function (cb) { cb.checked = false; });
  document.getElementById("selectAll").checked = false;
  updateBulkBar();
});

// Submit Report
document.getElementById("reportForm").addEventListener("submit", async function (e) {
  e.preventDefault();
  var rd = document.getElementById("reportResult"); rd.style.display = "none";
  var scanSel = document.getElementById("reportScanSelect");
  var payload = {
    link: document.getElementById("reportLink").value.trim() || null,
    report_type: document.getElementById("reportType").value,
    description: document.getElementById("reportDescription").value.trim(),
    priority: document.getElementById("reportPriority").value || "medium",
    linked_scan_id: scanSel && scanSel.value ? parseInt(scanSel.value, 10) : null,
  };
  try {
    var d = await createReport(payload);
    if (!d) return;
    rd.style.display = "block";
    rd.innerHTML = '<div class="stat-card" style="margin-top:10px"><div class="label">Report Submitted</div><div>ID: <strong>' +
      d.id + '</strong> <span class="badge ' + d.status + '">' + d.status + '</span></div></div>';
    document.getElementById("reportForm").reset();
    document.getElementById("reportScanSelect").innerHTML = '<option value="">— None —</option>';
    loadRecentScans();
    updateDuePreview();
    showToast("Report submitted", "success");
    refreshPaused = false; await refresh();
  } catch (err) { rd.style.display = "block"; rd.innerHTML = '<p style="color:#dc2626">Error: ' + err.message + '</p>'; }
});

loadRecentScans();
updateDuePreview();
refresh();
setInterval(refresh, 5000);
