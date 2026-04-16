/* profile.js – Admin Profile page */
(function () {
  if (!getToken()) { window.location.href = "login.html"; return; }

  var auditSearchInput = document.getElementById("auditSearchInput");
  var auditBody = document.getElementById("auditBody");
  var debounceTimer = null;

  function setStatus(msg) {
    var el = document.getElementById("liveStatus");
    if (el) el.textContent = msg;
  }

  function esc(s) {
    if (!s) return "";
    var d = document.createElement("div");
    d.textContent = s;
    return d.innerHTML;
  }

  function shortUserAgent(ua) {
    if (!ua) return "";
    return ua.length > 40 ? ua.substring(0, 40) + "…" : ua;
  }

  async function loadProfile() {
    try {
      var me = await getAuthMe();
      if (!me) {
        setStatus("Failed to load profile");
        return;
      }
      document.getElementById("profileEmail").textContent = me.email || "—";
      document.getElementById("profileRole").textContent = "Admin";
      document.getElementById("profileCreated").textContent = me.created_at || "—";
      document.getElementById("profileLastLogin").textContent = me.last_login_at ? me.last_login_at : "First login (no history yet)";
      setStatus("Profile loaded");
    } catch (e) {
      setStatus("Failed to load profile");
    }
  }

  async function loadAuditLogs() {
    try {
      var search = auditSearchInput ? auditSearchInput.value.trim() : "";
      var list = await listAuditLogsForMe(10, search);

      if (!auditBody) return;
      if (!list || list.length === 0) {
        auditBody.innerHTML = '<tr><td colspan="5" class="text-center text-muted" style="padding:20px">No activity found</td></tr>';
        return;
      }

      auditBody.innerHTML = list.map(function (a) {
        var targetHtml = (a.target && a.target.trim()) ? esc(a.target.substring(0, 60)) + (a.target.length > 60 ? "…" : "") : '<span class="badge badge-system-action">System action</span>';
        var uaDisplay = (a.user_agent && a.user_agent.trim()) ? shortUserAgent(a.user_agent) : "Not recorded";
        return "<tr>" +
          "<td>" + (a.created_at || "—") + "</td>" +
          "<td>" + esc(a.action) + "</td>" +
          "<td class=\"link-cell\" title=\"" + esc(a.target || "") + "\">" + targetHtml + "</td>" +
          "<td>" + (a.ip_address || "—") + "</td>" +
          "<td style=\"font-size:11px;max-width:120px\" title=\"" + esc(a.user_agent || "") + "\">" + esc(uaDisplay) + "</td>" +
          "</tr>";
      }).join("");
    } catch (e) {
      if (auditBody) auditBody.innerHTML = '<tr><td colspan="5" class="text-center text-muted" style="padding:20px">Failed to load activity</td></tr>';
    }
  }

  function renderSessionInfo() {
    var startedEl = document.getElementById("sessionStarted");
    var expiresEl = document.getElementById("sessionExpires");
    if (!startedEl) return;
    try {
      var token = getToken();
      if (!token) { startedEl.textContent = "—"; if (expiresEl) expiresEl.textContent = "—"; return; }
      var parts = token.split(".");
      if (parts.length !== 3) { startedEl.textContent = "—"; if (expiresEl) expiresEl.textContent = "—"; return; }
      var payload = JSON.parse(atob(parts[1]));
      var iat = payload.iat;
      var exp = payload.exp;
      if (iat) {
        var d = new Date(iat * 1000);
        startedEl.textContent = d.toLocaleString();
      } else {
        startedEl.textContent = "—";
      }
      if (expiresEl) {
        if (exp) {
          var expDate = new Date(exp * 1000);
          expiresEl.textContent = expDate.toLocaleString();
        } else {
          expiresEl.textContent = "—";
        }
      }
    } catch (e) {
      startedEl.textContent = "—";
      if (expiresEl) expiresEl.textContent = "—";
    }
  }

  async function init() {
    await loadProfile();
    await loadAuditLogs();
    renderSessionInfo();
  }

  if (auditSearchInput) {
    auditSearchInput.addEventListener("input", function () {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(loadAuditLogs, 400);
    });
  }

  init();
})();
