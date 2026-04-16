// ===== SIT Admin – API & Shared Utilities (Enterprise v2.0) =====

var BASE_URL = window.API_BASE;

// ── Token ──
function getToken()   { return localStorage.getItem("sit_token"); }
function setToken(t)  { localStorage.setItem("sit_token", t); }
function clearToken() { localStorage.removeItem("sit_token"); }
function requireAuth() { if (!getToken()) window.location.href = "login.html"; }
function logout() { clearToken(); window.location.href = "login.html"; }

// ══════════════════════════════════════════════════════════════
//  Connectivity: /health ping, offline banner, retry backoff
// ══════════════════════════════════════════════════════════════

var _backendOnline = true;
var _lastHealthData = null;
var _retryTimer = null;
var _retryAttempt = 0;
var _lastError = "";
var _RETRY_DELAYS = [1000, 2000, 5000, 10000];

async function pingBackend() {
  var url = BASE_URL + "/health";
  try {
    var res = await fetch(url, { method: "GET", cache: "no-store" });
    if (!res.ok) { _lastError = "Backend returned HTTP " + res.status; _setOnline(false); return null; }
    var data = await res.json();
    _lastHealthData = data;
    _lastError = "";
    _setOnline(true);
    return data;
  } catch (err) {
    _lastError = err.message || "Network error";
    _setOnline(false);
    return null;
  }
}

function _setOnline(online) {
  var changed = (_backendOnline !== online);
  _backendOnline = online;
  if (online) { _retryAttempt = 0; _clearRetry(); _showOfflineBanner(false); }
  else { _showOfflineBanner(true); if (changed || !_retryTimer) { _scheduleRetry(); } }
}

function _scheduleRetry() {
  _clearRetry();
  var delay = _retryAttempt < _RETRY_DELAYS.length ? _RETRY_DELAYS[_retryAttempt] : _RETRY_DELAYS[_RETRY_DELAYS.length - 1];
  _retryAttempt++;
  _retryTimer = setTimeout(function () { _retryTimer = null; pingBackend(); }, delay);
}
function _clearRetry() { if (_retryTimer) { clearTimeout(_retryTimer); _retryTimer = null; } }

function _showOfflineBanner(show) {
  var b = document.getElementById("offlineBanner");
  if (!b && show) {
    b = document.createElement("div"); b.id = "offlineBanner"; b.className = "offline-banner";
    b.innerHTML = '<div class="offline-inner"><span id="offlineMsg">Backend offline</span>' +
      '<button id="offlineRetry" class="btn-offline">Retry now</button>' +
      '<button id="offlineCopy" class="btn-offline">Copy debug</button></div>';
    document.body.prepend(b);
    document.getElementById("offlineRetry").addEventListener("click", function () {
      _retryAttempt = 0; _clearRetry();
      document.getElementById("offlineMsg").textContent = "Retrying\u2026"; pingBackend();
    });
    document.getElementById("offlineCopy").addEventListener("click", function () {
      var fixHint = _lastError === "Failed to fetch" ? "\nFix: 1) Start XAMPP MySQL  2) Run run_all.ps1" : "";
      var info = "SIT Debug\nTime: " + new Date().toISOString() + "\nBASE_URL: " + BASE_URL +
        "\nError: " + (_lastError || "none") + "\nOnline: " + _backendOnline +
        "\nToken: " + (getToken() ? "present" : "absent") + "\nPage: " + window.location.href + fixHint;
      navigator.clipboard.writeText(info).then(function () { showToast("Debug info copied", "info"); });
    });
  }
  if (b) {
    b.style.display = show ? "block" : "none";
    if (show) {
      var msg = "Backend offline";
      if (_lastError) msg += " \u2013 " + _lastError;
      if (_lastError === "Failed to fetch") msg += ". Fix: Start XAMPP MySQL, then run_all.ps1";
      var nextDelay = _retryAttempt < _RETRY_DELAYS.length ? _RETRY_DELAYS[_retryAttempt] : _RETRY_DELAYS[_RETRY_DELAYS.length - 1];
      msg += " (retry in " + (nextDelay / 1000) + "s)";
      var el = document.getElementById("offlineMsg"); if (el) el.textContent = msg;
    }
  }
}
function showOfflineBanner(show) { _showOfflineBanner(show); }

// ── Toast ──
function showToast(msg, type) {
  if (!type) type = "info";
  var c = document.getElementById("toastContainer");
  if (!c) { c = document.createElement("div"); c.id = "toastContainer"; c.className = "toast-container"; document.body.appendChild(c); }
  var t = document.createElement("div"); t.className = "toast toast-" + type; t.textContent = msg;
  c.appendChild(t);
  requestAnimationFrame(function () { t.classList.add("show"); });
  setTimeout(function () { t.classList.remove("show"); setTimeout(function () { t.remove(); }, 300); }, 3500);
}

// ══════════════════════════════════════════════════════════════
//  Core fetch
// ══════════════════════════════════════════════════════════════
async function authFetch(path, options) {
  if (!options) options = {};
  var token = getToken();
  var headers = Object.assign({ "Content-Type": "application/json" }, options.headers || {});
  if (token) headers["Authorization"] = "Bearer " + token;
  var url = BASE_URL + path;
  try {
    var res = await fetch(url, Object.assign({}, options, { headers: headers }));
    _setOnline(true);
    if (res.status === 401 || res.status === 403) {
      showToast("Session expired \u2013 please log in again", "error");
      clearToken(); window.location.href = "login.html"; return;
    }
    if (res.status === 429) { showToast("Rate limit hit \u2013 slow down", "error"); return; }
    if (res.status === 503) {
      res.json().then(function (b) { showToast(b.detail || "Service unavailable", "error"); }).catch(function () { showToast("Database unavailable. Start XAMPP MySQL.", "error"); });
      return res;
    }
    return res;
  } catch (err) {
    _lastError = err.message || "Network error";
    _setOnline(false);
    throw err;
  }
}

// ── Auth ──
async function login(email, password) {
  var res = await fetch(BASE_URL + "/auth/login", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: email, password: password }),
  });
  var data = await res.json();
  if (!res.ok) throw new Error(data.detail || "Login failed");
  return data;
}

async function verify2FA(tempTokenOrPayload, code) {
  var payload = {};
  if (typeof tempTokenOrPayload === "string") {
    payload.temp_token = tempTokenOrPayload;
    payload.code = code;
  } else if (tempTokenOrPayload && typeof tempTokenOrPayload === "object") {
    payload = {
      temp_token: tempTokenOrPayload.temp_token,
      code: tempTokenOrPayload.code || code,
    };
  }
  var res = await fetch(BASE_URL + "/auth/verify-2fa", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  var data = await res.json();
  if (!res.ok) throw new Error(data.detail || "2FA verification failed");
  return data;
}

async function sendEmailOtp(tempTokenOrPayload) {
  var payload = {};
  if (typeof tempTokenOrPayload === "string") {
    payload.temp_token = tempTokenOrPayload;
  } else if (tempTokenOrPayload && typeof tempTokenOrPayload === "object") {
    payload = {
      temp_token: tempTokenOrPayload.temp_token,
    };
  }
  var res = await fetch(BASE_URL + "/auth/send-email-otp", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  var data = await res.json();
  if (!res.ok) throw new Error(data.detail || "Failed to send email");
  return data;
}

// ── Dashboard ──
async function loadDashboardStats() { var r = await authFetch("/dashboard/stats"); return r ? r.json() : null; }

// ── Scans ──
async function createScan(payload) { var r = await authFetch("/scans", { method: "POST", body: JSON.stringify(payload) }); return r ? r.json() : null; }
async function listScans(limit) { if (!limit) limit = 200; var r = await authFetch("/scans?limit=" + limit); return r ? r.json() : []; }
async function getScan(id) { var r = await authFetch("/scans/" + id); return r ? r.json() : null; }
async function getRecentScans(limit) { limit = limit || 20; var r = await authFetch("/scans/recent?limit=" + limit); return r ? r.json() : []; }
async function analyzeMessage(message) { var r = await authFetch("/scans/analyze-message", { method: "POST", body: JSON.stringify({ message: message }) }); return r ? r.json() : null; }

// ── Reports ──
async function createReport(payload) { var r = await authFetch("/reports", { method: "POST", body: JSON.stringify(payload) }); return r ? r.json() : null; }
async function listReports(params) {
  var q = [];
  if (params && typeof params === "object") {
    if (params.limit != null) q.push("limit=" + params.limit);
    else q.push("limit=200");
    if (params.skip != null) q.push("skip=" + params.skip);
    if (params.status) q.push("status=" + encodeURIComponent(params.status));
    if (params.priority) q.push("priority=" + encodeURIComponent(params.priority));
    if (params.assignee != null) q.push("assignee=" + encodeURIComponent(params.assignee));
    if (params.search) q.push("search=" + encodeURIComponent(params.search));
  } else {
    q.push("limit=200");
  }
  var r = await authFetch("/reports?" + q.join("&"));
  return r ? r.json() : [];
}
async function updateReport(id, payload) { var r = await authFetch("/reports/" + id, { method: "PATCH", body: JSON.stringify(payload) }); return r ? r.json() : null; }
async function putReport(id, payload) { var r = await authFetch("/reports/" + id, { method: "PUT", body: JSON.stringify(payload) }); return r ? r.json() : null; }
async function bulkUpdateReports(reportIds, payload) {
  var r = await authFetch("/reports/bulk-update", { method: "POST", body: JSON.stringify({ report_ids: reportIds, status: payload.status, assignee: payload.assignee, priority: payload.priority }) });
  return r ? r.json() : null;
}
async function downloadCasePdf(reportId) {
  var token = getToken();
  if (!token) return;
  var url = BASE_URL + "/reports/" + reportId + "/case.pdf";
  var res = await fetch(url, { headers: { "Authorization": "Bearer " + token } });
  if (!res.ok) throw new Error("Failed to download case PDF");
  var blob = await res.blob();
  var a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "SIT-Case-" + reportId + ".pdf";
  a.click();
  URL.revokeObjectURL(a.href);
}

// ── Evaluation ──
async function getMetrics() { var r = await authFetch("/evaluation/metrics"); return r ? r.json() : null; }
async function runEvaluation() { var r = await authFetch("/evaluation/run", { method: "POST" }); return r ? r.json() : null; }

// ── Users (enterprise) ──
async function listUsers(q) { var r = await authFetch("/users" + (q || "")); return r ? r.json() : []; }
async function createUser(payload) { var r = await authFetch("/users", { method: "POST", body: JSON.stringify(payload) }); return r ? r.json() : null; }
async function updateUser(id, payload) { var r = await authFetch("/users/" + id, { method: "PATCH", body: JSON.stringify(payload) }); return r ? r.json() : null; }

// ── Notifications (enterprise) ──
async function listNotifications(unreadOnly, limit) {
  var q = "?unread_only=" + (unreadOnly ? "true" : "false") + "&limit=" + (limit || 20);
  var r = await authFetch("/notifications" + q);
  if (!r || !r.ok) throw new Error("Notifications API failed");
  var list = await r.json();
  return Array.isArray(list) ? list : [];
}
async function getUnreadCount() {
  var r = await authFetch("/notifications/unread-count");
  if (!r || !r.ok) return null;
  return r.json();
}
async function createNotification(payload) { var r = await authFetch("/notifications", { method: "POST", body: JSON.stringify(payload) }); return r ? r.json() : null; }
async function markNotificationsRead(ids) {
  var body = ids ? ids : [];
  var r = await authFetch("/notifications/mark-read", { method: "POST", body: JSON.stringify(body) });
  return r ? r.json() : null;
}
async function markNotificationRead(id) {
  var r = await authFetch("/notifications/" + id + "/mark-read", { method: "POST" });
  return r ? r.json() : null;
}
async function markAllNotificationsRead() {
  var r = await authFetch("/notifications/mark-all-read", { method: "POST" });
  return r ? r.json() : null;
}

// ── Settings (enterprise) ──
async function getSettings() { var r = await authFetch("/settings"); return r ? r.json() : null; }
async function updateSettings(payload) { var r = await authFetch("/settings", { method: "PATCH", body: JSON.stringify(payload) }); return r ? r.json() : null; }

// ── Auth / Profile ──
async function getAuthMe() { var r = await authFetch("/auth/me"); return r ? r.json() : null; }
async function listAuditLogsForMe(limit, search) {
  var q = "?limit=" + (limit || 10) + "&actor_email=me";
  if (search) q += "&search=" + encodeURIComponent(search);
  var r = await authFetch("/audit" + q);
  return r ? r.json() : [];
}

// ── Security (enterprise) ──
async function changePasswordAPI(cur, nw, cf, hint) {
  var body = { current_password: cur, new_password: nw };
  if (cf !== undefined) body.confirm_new_password = cf;
  if (hint !== undefined) body.password_hint = hint;
  var r = await authFetch("/auth/change-password", { method: "POST", body: JSON.stringify(body) });
  return r;
}
async function getSecurityStatus() { var r = await authFetch("/auth/security-status"); return r ? r.json() : null; }
async function setup2FA() { var r = await authFetch("/security/2fa/setup", { method: "POST" }); return r ? r.json() : null; }
async function confirm2FA(code) { var r = await authFetch("/security/2fa/confirm", { method: "POST", body: JSON.stringify({ code: code }) }); return r; }
async function get2FAStatus() { var r = await authFetch("/security/2fa/status"); return r ? r.json() : null; }

// ── Backup (enterprise) ──
async function runBackup(opts) {
  var body = typeof opts === "object" ? opts : { scopes: opts || ["system_settings", "admin_users", "reports", "audit_logs"], type: "db_only" };
  if (!body.type) body.type = "db_only";
  var r = await authFetch("/backup/run", { method: "POST", body: JSON.stringify(body) });
  if (!r) return null;
  var data = await r.json();
  if (r.status === 409) return { status: "conflict", detail: data.detail || "backup_already_running" };
  if (!r.ok) return { status: "failed", detail: data.detail || "Backup failed" };
  return data;
}
async function getBackupJobStatus(backupId) {
  var r = await authFetch("/backup/" + backupId + "/status");
  if (!r) return null;
  var data = await r.json();
  if (!r.ok) throw new Error(data.detail || "Failed to get backup status");
  return data;
}
async function listBackups() { var r = await authFetch("/backup"); return r ? r.json() : []; }
async function getBackupHistory(limit) { var r = await authFetch("/backup/history?limit=" + (limit || 20)); return r ? r.json() : []; }
async function getBackupStatus() { var r = await authFetch("/backup/status"); return r ? r.json() : null; }
async function getLatestBackup() { var r = await authFetch("/backup/latest"); return r ? r.json() : null; }
async function getLatestBackupSummary() { var r = await authFetch("/backup/latest-summary"); return r ? r.json() : null; }
async function getBackupSummary(id) { var r = await authFetch("/backup/" + id + "/summary"); return r ? r.json() : null; }
async function downloadBackupSummary(backupId) {
  var token = getToken();
  if (!token) return null;
  var r = await fetch(BASE_URL + "/backup/download/" + backupId + "/summary", { headers: { "Authorization": "Bearer " + token } });
  if (!r.ok) throw new Error(r.status === 404 ? "Summary not found" : "Download failed");
  var blob = await r.blob();
  var url = URL.createObjectURL(blob);
  var a = document.createElement("a"); a.href = url; a.download = "backup-summary.json"; a.click();
  URL.revokeObjectURL(url);
  return true;
}
async function downloadBackup(backupId) {
  var token = getToken();
  if (!token) return null;
  var r = await fetch(BASE_URL + "/backup/download/" + backupId, { headers: { "Authorization": "Bearer " + token } });
  if (!r.ok) throw new Error(r.status === 404 ? "Backup or file not found" : "Download failed");
  var blob = await r.blob();
  var ext = blob.type && blob.type.indexOf("zip") !== -1 ? "zip" : "json";
  var url = URL.createObjectURL(blob);
  var a = document.createElement("a"); a.href = url; a.download = "backup_" + backupId + "." + ext; a.click();
  URL.revokeObjectURL(url);
  return true;
}
async function restoreBackup(backupId, mode) {
  var r = await authFetch("/backup/restore/" + backupId, { method: "POST", body: JSON.stringify({ mode: mode || "safe" }) });
  if (!r) return null;
  var body = await r.json();
  if (!r.ok) return { ok: false, detail: body.detail || "Restore failed" };
  return body;
}

// ── Audit (enterprise) ──
async function listAuditLogs(q) { var r = await authFetch("/audit" + (q || "")); return r ? r.json() : []; }

// ── Analytics (enterprise) ──
async function getAnalyticsStats() { var r = await authFetch("/analytics/stats"); return r ? r.json() : null; }

// ══════════════════════════════════════════════════════════════
//  Modal helpers
// ══════════════════════════════════════════════════════════════
function openModal(id) {
  var el = document.getElementById(id);
  if (el) el.style.display = "flex";
}
function closeModal(id) {
  var el = document.getElementById(id);
  if (el) el.style.display = "none";
}

// ══════════════════════════════════════════════════════════════
//  Notification bell + dropdown
// ══════════════════════════════════════════════════════════════
var _notifDropdownOpen = false;
var _lastUnreadCount = 0;
var _notifFirstPoll = true;

function toggleNotifDropdown() {
  var dd = document.getElementById("notifDropdown");
  if (!dd) return;
  _notifDropdownOpen = !_notifDropdownOpen;
  dd.classList.toggle("show", _notifDropdownOpen);
  if (_notifDropdownOpen) {
    _ensureNotifSendForm(dd);
    loadNotifDropdown();
  }
}

function _ensureNotifSendForm(dd) {
  if (document.getElementById("notifSendForm")) return;
  var header = dd.querySelector(".notif-dropdown-header");
  if (!header) return;
  var btns = header.querySelectorAll("button");
  if (btns.length > 0) {
    var sendBtn = document.createElement("button");
    sendBtn.className = "btn btn-sm";
    sendBtn.textContent = "Send";
    sendBtn.onclick = toggleNotifSendForm;
    header.insertBefore(sendBtn, btns[0]);
  }
  var form = document.createElement("div");
  form.id = "notifSendForm";
  form.className = "notif-send-form";
  form.style.cssText = "display:none;padding:12px 16px;border-bottom:1px solid var(--border);background:var(--bg-2)";
  form.innerHTML = '<div class="form-group" style="margin-bottom:8px"><input type="text" id="nsf_title" placeholder="Title" style="width:100%;padding:6px 10px;border:1px solid var(--border);border-radius:var(--radius);background:var(--bg-1)" /></div>' +
    '<div class="form-group" style="margin-bottom:8px"><select id="nsf_type" style="width:100%;padding:6px 10px;border:1px solid var(--border);border-radius:var(--radius);background:var(--bg-1)"><option value="info">Info</option><option value="warning">Warning</option><option value="alert">Alert</option><option value="success">Success</option></select></div>' +
    '<div class="form-group" style="margin-bottom:8px"><textarea id="nsf_body" placeholder="Body" rows="2" style="width:100%;padding:6px 10px;resize:vertical;border:1px solid var(--border);border-radius:var(--radius);background:var(--bg-1)"></textarea></div>' +
    '<button class="btn btn-primary btn-sm" onclick="submitNotifFromDropdown()">Send</button>';
  var body = dd.querySelector(".notif-dropdown-body");
  if (body) dd.insertBefore(form, body);
}

function toggleNotifSendForm() {
  var f = document.getElementById("notifSendForm");
  if (!f) return;
  f.style.display = f.style.display === "none" ? "block" : "none";
}

async function submitNotifFromDropdown() {
  var title = document.getElementById("nsf_title");
  var body = document.getElementById("nsf_body");
  var type = document.getElementById("nsf_type");
  if (!title || !title.value.trim()) { showToast("Title is required", "error"); return; }
  try {
    var res = await createNotification({ recipient_scope: "all", type: type ? type.value : "info", title: title.value.trim(), body: (body && body.value) ? body.value.trim() : null });
    if (res && res.id) {
      showToast("Notification sent!", "success");
      title.value = ""; if (body) body.value = "";
      toggleNotifSendForm();
      refreshNotifBadge();
      if (_notifDropdownOpen) loadNotifDropdown();
    } else {
      showToast("Failed to send notification", "error");
    }
  } catch (e) { showToast("Error sending notification", "error"); }
}

function _renderNotifItem(n) {
  var iconClass = n.type || "info";
  var unreadClass = n.is_read ? "" : " unread";
  var timeStr = "";
  if (n.created_at) {
    try {
      var d = new Date(n.created_at);
      timeStr = isNaN(d.getTime()) ? n.created_at : d.toLocaleString();
    } catch (_) { timeStr = n.created_at; }
  }
  return '<div class="notif-item' + unreadClass + '" data-id="' + n.id + '" data-read="' + (n.is_read ? "1" : "0") + '">' +
    '<div class="notif-item-icon ' + iconClass + '">' + _notifIcon(n.type) + '</div>' +
    '<div class="notif-item-content">' +
      '<div class="notif-title">' + _esc(n.title) + '</div>' +
      '<div class="notif-body">' + _esc(n.body || "") + '</div>' +
      '<div class="notif-time">' + timeStr + '</div>' +
    '</div></div>';
}

async function loadNotifDropdown() {
  var body = document.getElementById("notifList");
  if (!body) return;
  try {
    var list = await listNotifications(false, 20);
    if (!list || list.length === 0) {
      body.innerHTML = '<div style="padding:20px;text-align:center;color:var(--text-3);font-size:12px">No notifications yet. Click Send above to create one.</div>';
      return;
    }
    body.innerHTML = list.slice(0, 20).map(_renderNotifItem).join("");
    body.querySelectorAll(".notif-item").forEach(function (el) {
      el.addEventListener("click", function () { handleNotifItemClick(el); });
    });
  } catch (e) {
    body.innerHTML = '<div style="padding:20px;text-align:center;color:var(--warn);font-size:12px">Cannot reach backend</div>';
  }
}

async function handleNotifItemClick(el) {
  var id = el.getAttribute("data-id");
  var read = el.getAttribute("data-read");
  if (!id || read === "1") return;
  try {
    var res = await markNotificationRead(parseInt(id, 10));
    if (res && res.ok) {
      el.classList.remove("unread");
      el.setAttribute("data-read", "1");
      refreshNotifBadge();
    }
  } catch (e) {}
}

function setNotifBadgeCount(count) {
  var badge = document.getElementById("notifCount");
  if (!badge) return;
  if (count > 0) {
    badge.textContent = count > 99 ? "99+" : count;
    badge.style.display = "flex";
  } else {
    badge.style.display = "none";
  }
}

async function markAllNotifRead() {
  try {
    var res = await markAllNotificationsRead();
    if (res && res.ok) {
      showToast("All notifications marked read", "success");
      setNotifBadgeCount(0);
      _lastUnreadCount = 0;
      if (_notifDropdownOpen) loadNotifDropdown();
    }
  } catch (e) {}
}

async function refreshNotifBadge() {
  try {
    var data = await getUnreadCount();
    if (!data) return;
    var count = data.unread_count || 0;
    if (_notifFirstPoll) {
      _notifFirstPoll = false;
    } else if (count > _lastUnreadCount) {
      showToast("New notification", "info");
      var dd = document.getElementById("notifDropdown");
      if (dd && !_notifDropdownOpen) {
        _notifDropdownOpen = true;
        dd.classList.add("show");
        _ensureNotifSendForm(dd);
      }
      loadNotifDropdown();
    }
    _lastUnreadCount = count;
    setNotifBadgeCount(count);
  } catch (e) {}
}

function _notifIcon(type) {
  if (type === "warning") return "\u26A0";
  if (type === "alert") return "\u26D4";
  if (type === "success") return "\u2714";
  return "\u2139";
}

function _esc(s) { if (!s) return ""; var d = document.createElement("div"); d.textContent = s; return d.innerHTML; }

// Refresh notification badge on load and poll every 8 seconds
if (getToken()) {
  refreshNotifBadge();
  setInterval(refreshNotifBadge, 8000);
}

// Close dropdown when clicking outside
document.addEventListener("click", function (e) {
  if (_notifDropdownOpen) {
    var dd = document.getElementById("notifDropdown");
    var bell = document.getElementById("notifBell");
    if (dd && !dd.contains(e.target) && bell && !bell.contains(e.target)) {
      _notifDropdownOpen = false;
      dd.classList.remove("show");
    }
  }
});

// ══════════════════════════════════════════════════════════════
//  User pill – populate from token
// ══════════════════════════════════════════════════════════════
(function initUserPill() {
  var token = getToken();
  if (!token) return;
  try {
    var parts = token.split(".");
    if (parts.length !== 3) return;
    var payload = JSON.parse(atob(parts[1]));
    var email = payload.sub || "";
    var nameEl = document.getElementById("userName");
    var emailEl = document.getElementById("userEmail");
    var avatarEl = document.getElementById("userAvatar");
    if (nameEl) nameEl.textContent = email ? email.split("@")[0] : "User";
    if (emailEl) emailEl.textContent = email;
    if (avatarEl) avatarEl.textContent = email ? email.charAt(0).toUpperCase() : "?";
  } catch (e) {}
})();

// ══════════════════════════════════════════════════════════════
//  Command Palette (Ctrl+K)
// ══════════════════════════════════════════════════════════════
(function initCommandPalette() {
  var ACTIONS = [
    { label: "Go to Dashboard",    key: "D", action: function () { window.location.href = "dashboard.html"; } },
    { label: "Go to Scans",        key: "S", action: function () { window.location.href = "scans.html"; } },
    { label: "Go to Admin Profile", key: "U", action: function () { window.location.href = "profile.html"; } },
    { label: "Go to Reports",      key: "R", action: function () { window.location.href = "reports.html"; } },
    { label: "Go to Analytics",    key: "A", action: function () { window.location.href = "analytics.html"; } },
    { label: "Go to 2FA & Security", key: "2", action: function () { window.location.href = "2fa.html"; } },
    { label: "Go to Settings",     key: "G", action: function () { window.location.href = "settings.html"; } },
    { label: "Quick Scan URL",     key: "Q", action: function () { window.location.href = "scans.html"; } },
    { label: "Open Notifications", key: "N", action: function () { toggleNotifDropdown(); } },
    { label: "Refresh Page",       key: "F5", action: function () { window.location.reload(); } },
    { label: "Copy Auth Token",    key: "T", action: function () {
      var t = getToken();
      if (t) { navigator.clipboard.writeText(t).then(function () { showToast("Token copied", "success"); }); }
      else { showToast("No token found", "error"); }
    }},
    { label: "Logout",             key: "L", action: logout },
  ];

  document.addEventListener("keydown", function (e) {
    if ((e.ctrlKey || e.metaKey) && e.key === "k") { e.preventDefault(); togglePalette(); }
    if (e.key === "Escape") closePalette();
  });

  function togglePalette() {
    var el = document.getElementById("cmdPalette");
    if (el) { el.style.display = el.style.display === "none" ? "flex" : "none"; if (el.style.display === "flex") el.querySelector("input").focus(); return; }
    el = document.createElement("div"); el.id = "cmdPalette"; el.className = "cmd-overlay"; el.style.display = "flex";
    el.innerHTML = '<div class="cmd-box"><input class="cmd-input" placeholder="Type a command\u2026" /><div class="cmd-list" id="cmdList"></div></div>';
    document.body.appendChild(el);
    el.addEventListener("click", function (e) { if (e.target === el) closePalette(); });
    var input = el.querySelector("input"); input.focus();
    renderCmds(""); input.addEventListener("input", function () { renderCmds(input.value); });
  }

  function renderCmds(q) {
    var list = document.getElementById("cmdList"); if (!list) return;
    var filtered = ACTIONS.filter(function (a) { return a.label.toLowerCase().indexOf(q.toLowerCase()) !== -1; });
    list.innerHTML = filtered.map(function (a, i) {
      return '<div class="cmd-item' + (i === 0 ? ' active' : '') + '" data-idx="' + i + '">' + a.label +
        '<span class="cmd-key">' + a.key + '</span></div>';
    }).join("");
    list.querySelectorAll(".cmd-item").forEach(function (el, i) {
      el.addEventListener("click", function () { closePalette(); filtered[i].action(); });
    });
  }

  function closePalette() {
    var el = document.getElementById("cmdPalette"); if (el) el.style.display = "none";
  }
})();
