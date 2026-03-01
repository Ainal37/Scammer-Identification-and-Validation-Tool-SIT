// ===== SIT Admin – Dashboard (Command Center) =====
requireAuth();

var lastTopScanId = null;
var trendChart = null;
var distChart = null;

function setStatus(msg) { var el = document.getElementById("liveStatus"); if (el) el.textContent = msg; }

// Set welcome text with date
(function () {
  var wel = document.getElementById("welcomeText");
  if (wel) {
    var d = new Date();
    var opts = { weekday: "long", year: "numeric", month: "long", day: "numeric" };
    wel.textContent = "Welcome back. Today is " + d.toLocaleDateString("en-MY", opts);
  }
})();

// ── Status chips driven by /health ──
async function updateStatusChips() {
  var chipBe = document.getElementById("chipBackend");
  var chipDb = document.getElementById("chipDB");
  var chipIn = document.getElementById("chipIntel");
  var h = await pingBackend();
  if (h) {
    if (chipBe) { chipBe.className = "chip chip-ok"; chipBe.textContent = "Backend"; }
    if (chipDb) { chipDb.className = h.db ? "chip chip-ok" : "chip chip-err"; chipDb.textContent = h.db ? "MySQL" : "MySQL DOWN"; }
    if (chipIn) { chipIn.className = h.intel ? "chip chip-ok" : "chip chip-warn"; chipIn.textContent = h.intel ? "Intel" : "Intel (no key)"; }
  } else {
    if (chipBe) { chipBe.className = "chip chip-err"; chipBe.textContent = "Backend DOWN"; }
    if (chipDb) { chipDb.className = "chip"; chipDb.textContent = "MySQL ?"; }
    if (chipIn) { chipIn.className = "chip"; chipIn.textContent = "Intel ?"; }
  }
}

function renderDashboard(d) {
  if (!d) return;

  // Stats
  document.getElementById("totalScans").textContent = (d.total_scans != null) ? d.total_scans : "--";
  document.getElementById("totalReports").textContent = (d.total_reports != null) ? d.total_reports : "--";
  var tb = d.threat_breakdown || {};
  document.getElementById("highCount").textContent = tb.HIGH || 0;
  document.getElementById("medCount").textContent = tb.MED || 0;
  document.getElementById("lowCount").textContent = tb.LOW || 0;

  // Charts
  renderTrendChart(d.trend);
  renderDistChart(d.breakdown);

  // Top triggers
  var trig = document.getElementById("triggersSection");
  if (trig && d.top_triggers) {
    if (d.top_triggers.length === 0) { trig.innerHTML = '<p class="text-muted">No data yet</p>'; }
    else {
      trig.innerHTML = '<table><thead><tr><th>Rule</th><th>Count</th></tr></thead><tbody>' +
        d.top_triggers.map(function (t) { return '<tr><td>' + t.rule + '</td><td>' + t.count + '</td></tr>'; }).join("") +
        '</tbody></table>';
    }
  }

  // Activity feed
  var feed = document.getElementById("activityFeed");
  if (feed && d.recent_activity) {
    if (d.recent_activity.length === 0) { feed.innerHTML = '<p class="text-muted">No activity yet</p>'; }
    else {
      feed.innerHTML = d.recent_activity.map(function (a) {
        return '<div class="activity-item"><div class="activity-dot"></div><div><span class="act-action">' +
          a.action + '</span> by ' + (a.actor || "system") +
          '</div><span class="act-time">' + (a.time || "") + '</span></div>';
      }).join("");
    }
  }

  // Metrics
  var met = document.getElementById("metricsSection");
  if (met && d.metrics && !d.metrics.error) {
    met.innerHTML = '<div class="metrics-grid">' +
      mc("Accuracy", d.metrics.accuracy) + mc("Precision", d.metrics.precision) +
      mc("Recall", d.metrics.recall) + mc("F1 Score", d.metrics.f1) +
      mc("Dataset", d.metrics.dataset_size) +
      '</div><p class="text-muted mt-1" style="font-size:11px">Last evaluated: ' + (d.metrics.last_evaluated || "N/A") + '</p>';
  } else if (met) {
    met.innerHTML = '<p class="text-muted">No evaluation run yet. <button class="btn btn-sm" onclick="doEval()">Run Now</button></p>';
  }

  // Latest scans
  var stb = document.getElementById("latestScansBody");
  var scans = d.latest_scans || [];
  if (stb) {
    if (scans.length === 0) { stb.innerHTML = '<tr><td colspan="5" class="text-muted text-center">No scans yet</td></tr>'; }
    else {
      stb.innerHTML = scans.map(function (s) {
        return '<tr data-id="' + s.id + '"><td>' + s.id + '</td><td class="link-cell" title="' + s.link + '">' + s.link +
          '</td><td><span class="badge ' + (s.threat_level || s.verdict) + '">' + (s.threat_level || s.verdict) + '</span></td><td>' +
          s.score + '</td><td>' + (s.created_at || "\u2014") + '</td></tr>';
      }).join("");
      var topId = scans[0] ? scans[0].id : null;
      if (lastTopScanId !== null && topId && topId !== lastTopScanId) {
        var tr = stb.querySelector('tr[data-id="' + topId + '"]');
        if (tr) { tr.classList.add("row-new"); setTimeout(function () { tr.classList.remove("row-new"); }, 2500); }
      }
      lastTopScanId = topId;
    }
  }

  // Latest reports
  var rtb = document.getElementById("latestReportsBody");
  var reps = d.latest_reports || [];
  if (rtb) {
    if (reps.length === 0) { rtb.innerHTML = '<tr><td colspan="5" class="text-muted text-center">No reports yet</td></tr>'; }
    else {
      rtb.innerHTML = reps.map(function (r) {
        return '<tr><td>' + r.id + '</td><td class="link-cell" title="' + (r.link || "") + '">' + (r.link || "\u2014") +
          '</td><td>' + (r.report_type || "\u2014") + '</td><td><span class="badge ' + r.status + '">' + r.status +
          '</span></td><td>' + (r.created_at || "\u2014") + '</td></tr>';
      }).join("");
    }
  }
}

function mc(label, val) {
  var v = typeof val === "number" && val <= 1 ? (val * 100).toFixed(1) + "%" : val;
  return '<div class="metric-card"><div class="metric-val">' + v + '</div><div class="metric-label">' + label + '</div></div>';
}

function renderTrendChart(trend) {
  if (!trend || !document.getElementById("trendChart")) return;
  var ctx = document.getElementById("trendChart").getContext("2d");
  var cfg = {
    type: "line",
    data: {
      labels: trend.labels,
      datasets: [
        { label: "Scam", data: trend.scam, borderColor: "#991b1b", backgroundColor: "rgba(153,27,27,.08)", tension: .3, fill: true },
        { label: "Suspicious", data: trend.suspicious, borderColor: "#92400e", backgroundColor: "rgba(146,64,14,.08)", tension: .3, fill: true },
        { label: "Safe", data: trend.safe, borderColor: "#065f46", backgroundColor: "rgba(6,95,70,.08)", tension: .3, fill: true },
      ],
    },
    options: { responsive: true, plugins: { legend: { position: "bottom", labels: { boxWidth: 12, font: { size: 11 } } } }, scales: { y: { beginAtZero: true, ticks: { font: { size: 11 } } }, x: { ticks: { font: { size: 11 } } } } },
  };
  if (trendChart) { trendChart.data = cfg.data; trendChart.update(); } else { trendChart = new Chart(ctx, cfg); }
}

function renderDistChart(breakdown) {
  if (!breakdown || !document.getElementById("distChart")) return;
  var ctx = document.getElementById("distChart").getContext("2d");
  var cfg = {
    type: "doughnut",
    data: {
      labels: ["Scam", "Suspicious", "Safe"],
      datasets: [{ data: [breakdown.scam || 0, breakdown.suspicious || 0, breakdown.safe || 0], backgroundColor: ["#991b1b", "#d97706", "#059669"], borderWidth: 0 }],
    },
    options: { responsive: true, cutout: "65%", plugins: { legend: { position: "bottom", labels: { boxWidth: 12, font: { size: 11 } } } } },
  };
  if (distChart) { distChart.data = cfg.data; distChart.update(); } else { distChart = new Chart(ctx, cfg); }
}

async function doEval() {
  showToast("Running evaluation\u2026", "info");
  var r = await runEvaluation();
  if (r && !r.error) { showToast("Evaluation complete", "success"); refresh(); }
  else showToast("Evaluation failed", "error");
}

// ── Quick Action Modal Handlers ──

window.submitAddUser = async function () {
  var name = document.getElementById("mu_name").value.trim();
  var email = document.getElementById("mu_email").value.trim();
  var role = document.getElementById("mu_role").value;
  var status = document.getElementById("mu_status").value;
  if (!name || !email) { showToast("Name and email are required", "error"); return; }
  try {
    var res = await authFetch("/users", {
      method: "POST",
      body: JSON.stringify({ full_name: name, email: email, role: role, status: status }),
    });
    if (!res) return;
    if (res.ok) {
      showToast("User created!", "success");
      closeModal("addUserModal");
      document.getElementById("mu_name").value = "";
      document.getElementById("mu_email").value = "";
    } else {
      var d = await res.json();
      showToast(d.detail || "Failed to create user", "error");
    }
  } catch (e) { showToast("Error creating user", "error"); }
};

window.submitGenReport = async function () {
  var type = document.getElementById("gr_type").value;
  var desc = document.getElementById("gr_desc").value.trim();
  if (!desc) { showToast("Description is required", "error"); return; }
  try {
    var res = await authFetch("/reports", {
      method: "POST",
      body: JSON.stringify({ report_type: type, description: desc }),
    });
    if (!res) return;
    if (res.ok) {
      showToast("Report created!", "success");
      closeModal("genReportModal");
      document.getElementById("gr_desc").value = "";
      refresh();
    } else {
      var d = await res.json();
      showToast(d.detail || "Failed to create report", "error");
    }
  } catch (e) { showToast("Error creating report", "error"); }
};

window.submitSendNotif = async function () {
  var scope = document.getElementById("sn_scope").value;
  var type = document.getElementById("sn_type").value;
  var title = document.getElementById("sn_title").value.trim();
  var body = document.getElementById("sn_body").value.trim();
  if (!title) { showToast("Title is required", "error"); return; }
  try {
    var res = await authFetch("/notifications", {
      method: "POST",
      body: JSON.stringify({ recipient_scope: scope, type: type, title: title, body: body }),
    });
    if (!res) return;
    if (res.ok) {
      showToast("Notification sent!", "success");
      closeModal("sendNotifModal");
      document.getElementById("sn_title").value = "";
      document.getElementById("sn_body").value = "";
      if (typeof refreshNotifBadge === "function") refreshNotifBadge();
    } else {
      var d = await res.json();
      showToast(d.detail || "Failed to send notification", "error");
    }
  } catch (e) { showToast("Error sending notification", "error"); }
};

window.submitBackup = async function () {
  var checks = document.querySelectorAll('#backupModal .checkbox-group input[type="checkbox"]:checked');
  var scopes = [];
  checks.forEach(function (c) { scopes.push(c.value); });
  if (scopes.length === 0) { showToast("Select at least one scope", "error"); return; }
  try {
    var res = await authFetch("/backup/run", {
      method: "POST",
      body: JSON.stringify({ scopes: scopes }),
    });
    if (!res) return;
    if (res.ok) {
      showToast("Backup completed!", "success");
      closeModal("backupModal");
    } else {
      showToast("Backup failed", "error");
    }
  } catch (e) { showToast("Error running backup", "error"); }
};

// ── Refresh loop ──
async function refresh() {
  try {
    setStatus("Updating\u2026");
    await updateStatusChips();
    var d = await loadDashboardStats();
    renderDashboard(d);
    setStatus("Last updated: " + new Date().toLocaleTimeString());
  } catch (e) { setStatus("Update failed"); }
}

refresh();
setInterval(refresh, 5000);
