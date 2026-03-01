/* settings.js – Settings page logic */
(function () {
  if (!getToken()) { window.location.href = "login.html"; return; }

  function setStatus(msg) {
    var el = document.getElementById("liveStatus");
    if (el) el.textContent = msg;
  }

  /* ── General Settings ── */
  window.loadSettings = async function () {
    try {
      var res = await authFetch("/settings");
      if (!res) return;
      var d = await res.json();
      document.getElementById("settSystemName").value = d.system_name || "";
      var tz = document.getElementById("settTimezone");
      if (tz) { tz.value = d.timezone || "Asia/Kuala_Lumpur"; }
      var abVal = (d.auto_backup === "true" || d.auto_backup_enabled === true || d.auto_backup === undefined);
      var ab = document.getElementById("toggleAutoBackup");
      if (ab) { ab.checked = abVal; }
      var settAb = document.getElementById("settAutoBackupEnabled");
      if (settAb) { settAb.checked = abVal; }
      var bs = document.getElementById("backupScheduleText");
      if (bs) { bs.textContent = d.backup_schedule || "Daily 3:00 AM"; }
      var bt = document.getElementById("backupTime");
      if (bt) { bt.value = (d.backup_time_of_day || d.backup_time || "03:00").substring(0, 5); }
      var ret = document.getElementById("backupRetention");
      if (ret) { ret.value = String(d.retention_days || d.retention_count || 7); }
      setStatus("Settings loaded");
    } catch (e) { setStatus("Failed to load settings"); }
  };

  window.saveGeneralSettings = async function () {
    try {
      var body = {
        system_name: document.getElementById("settSystemName").value,
        timezone: document.getElementById("settTimezone").value,
      };
      var res = await authFetch("/settings", {
        method: "PATCH",
        body: JSON.stringify(body),
      });
      if (!res) return;
      showToast("General settings saved", "success");
    } catch (e) { showToast("Failed to save settings", "error"); }
  };

  window.load2FAStatus = async function () {
    var sett2fa = document.getElementById("sett2FAEnabled");
    if (sett2fa) { sett2fa.checked = true; sett2fa.disabled = true; }
  };

  /* ── Backup ── */
  function setBackupStatusBadge(el, status) {
    if (!el) return;
    el.className = "badge-pending";
    if (status === "running") el.className = "badge-running";
    else if (status === "success") el.className = "badge-success";
    else if (status === "failed") el.className = "badge-failed";
    el.textContent = (status || "--").toUpperCase();
  }

  function setBackupButtonsEnabled(enabled) {
    ["btnViewSummary", "btnDownloadSummary", "btnDownloadBackup", "btnRestoreBackup"].forEach(function (id) {
      var b = document.getElementById(id);
      if (b) b.disabled = !enabled;
    });
  }

  window.loadLastBackup = async function () {
    try {
      var status = await getBackupStatus();
      if (status) {
        var lastEl = document.getElementById("lastBackupTime");
        var nextEl = document.getElementById("nextBackupInfo");
        var statusEl = document.getElementById("lastBackupStatus");
        var sizeEl = document.getElementById("lastBackupSize");
        var checksumEl = document.getElementById("lastBackupChecksum");
        var tablesEl = document.getElementById("lastBackupKeyTables");
        var stepEl = document.getElementById("backupStepMessage");
        if (stepEl) { stepEl.style.display = "none"; stepEl.textContent = ""; }
        if (lastEl) lastEl.textContent = status.last_backup_at || "Never";
        if (nextEl) nextEl.textContent = status.next_scheduled_backup || (status.automatic_backup_enabled ? "Today at " + (status.backup_time_of_day || "03:00") : "Disabled");
        var latest = status.latest;
        if (latest) {
          setBackupStatusBadge(statusEl, latest.status);
          if (sizeEl) sizeEl.textContent = latest.size_bytes ? (latest.size_bytes < 1024 ? latest.size_bytes + " B" : (latest.size_bytes < 1048576 ? (latest.size_bytes / 1024).toFixed(1) + " KB" : (latest.size_bytes / 1048576).toFixed(1) + " MB")) : "--";
          if (checksumEl) checksumEl.textContent = latest.checksum_sha256 ? (latest.checksum_sha256.substring(0, 16) + "...") : "--";
          var kh = (latest.summary && latest.summary.key_tables_highlight) ? latest.summary.key_tables_highlight : {};
          if (tablesEl) tablesEl.textContent = Object.keys(kh).length ? Object.entries(kh).map(function (e) { return e[0] + ": " + e[1]; }).join(" | ") : "--";
        } else {
          setBackupStatusBadge(statusEl, null);
          if (sizeEl) sizeEl.textContent = "--";
          if (checksumEl) checksumEl.textContent = "--";
          if (tablesEl) tablesEl.textContent = "--";
        }
      }
    } catch (e) {
      var lastEl = document.getElementById("lastBackupTime");
      if (lastEl) lastEl.textContent = "Never";
      setBackupStatusBadge(document.getElementById("lastBackupStatus"), null);
      if (typeof showToast === "function") showToast("Backend offline or backup unavailable", "error");
    } finally {
      loadBackupHistory();
    }
  };

  window.viewBackupSummary = async function () {
    try {
      var summary = await getLatestBackupSummary();
      if (!summary) { showToast("No summary available", "error"); return; }
      var modal = document.getElementById("backupSummaryModal");
      var pre = document.getElementById("backupSummaryContent");
      pre.textContent = JSON.stringify(summary, null, 2);
      modal.style.display = "flex";
    } catch (e) { showToast(e.message || "Failed to load summary", "error"); }
  };

  window.closeSummaryModal = function () {
    var modal = document.getElementById("backupSummaryModal");
    if (modal) modal.style.display = "none";
  };

  window.downloadLatestSummary = async function () {
    try {
      var latest = await getLatestBackup();
      if (!latest || !latest.id) { showToast("No backup to download summary from", "error"); return; }
      if (latest.id >= 100000) { showToast("Summary not available for legacy backups", "error"); return; }
      await downloadBackupSummary(latest.id);
      showToast("Summary download started", "success");
    } catch (e) { showToast(e.message || "Download failed", "error"); }
  };

  window.loadBackupHistory = async function () {
    var el = document.getElementById("backupHistory");
    if (!el) return;
    try {
      var list = await getBackupHistory(10);
      if (!list || list.length === 0) { el.innerHTML = "No backups yet"; return; }
      el.innerHTML = list.map(function (b) {
        var label = "Backup #" + b.id + " – " + (b.finished_at || b.started_at || "?") + " (" + (b.status || "?") + ")";
        if (b.size_bytes) label += " – " + (b.size_bytes < 1024 ? b.size_bytes + " B" : (b.size_bytes < 1048576 ? (b.size_bytes / 1024).toFixed(1) + " KB" : (b.size_bytes / 1048576).toFixed(1) + " MB"));
        return "<div>" + label + "</div>";
      }).join("");
    } catch (e) {
      el.innerHTML = "Failed to load. Check backend is running.";
    }
  };

  window.runManualBackup = async function () {
    var btn = document.getElementById("btnManualBackup");
    var lastEl = document.getElementById("lastBackupTime");
    var statusEl = document.getElementById("lastBackupStatus");
    var stepEl = document.getElementById("backupStepMessage");
    var sizeEl = document.getElementById("lastBackupSize");
    var checksumEl = document.getElementById("lastBackupChecksum");
    var tablesEl = document.getElementById("lastBackupKeyTables");

    function restoreButton() {
      if (btn) { btn.disabled = false; btn.classList.remove("btn-loading"); btn.textContent = "Manual Backup Now"; }
      setBackupButtonsEnabled(true);
    }

    if (btn) { btn.disabled = true; btn.classList.add("btn-loading"); btn.textContent = "Running…"; }
    setBackupButtonsEnabled(false);
    if (lastEl) lastEl.textContent = "Running…";
    setBackupStatusBadge(statusEl, "running");
    if (stepEl) { stepEl.style.display = "block"; stepEl.textContent = "Dumping DB → Zipping → Computing checksum → Writing summary"; }
    await new Promise(function (r) { requestAnimationFrame(function () { requestAnimationFrame(r); }); });

    try {
      var res = await runBackup({ type: "db_only" });
      if (!res) { restoreButton(); loadLastBackup(); return; }
      if (res.status === "conflict") {
        showToast("A backup is already running. Please wait.", "error");
        restoreButton();
        loadLastBackup();
        return;
      }
      if (res.status === "failed") {
        showToast(res.detail || "Backup failed", "error");
        setBackupStatusBadge(statusEl, "failed");
        if (lastEl) lastEl.textContent = "Failed";
        restoreButton();
        loadLastBackup();
        return;
      }
      if (res.status !== "running" || !res.id) {
        restoreButton();
        loadLastBackup();
        return;
      }

      var jobId = res.id;
      var pollInterval = 1500;
      var pollTimer = null;

      function poll() {
        getBackupJobStatus(jobId).then(function (job) {
          if (!job) return;
          if (job.message && stepEl) stepEl.textContent = job.message;
          if (job.status === "running") {
            pollTimer = setTimeout(poll, pollInterval);
            return;
          }
          clearTimeout(pollTimer);
          if (stepEl) { stepEl.style.display = "none"; stepEl.textContent = ""; }
          restoreButton();
          if (job.status === "success") {
            if (lastEl) lastEl.textContent = job.finished_at ? new Date(job.finished_at).toLocaleString() : "Just now";
            setBackupStatusBadge(statusEl, "success");
            if (sizeEl && job.size_bytes) sizeEl.textContent = job.size_bytes < 1024 ? job.size_bytes + " B" : (job.size_bytes < 1048576 ? (job.size_bytes / 1024).toFixed(1) + " KB" : (job.size_bytes / 1048576).toFixed(1) + " MB");
            if (checksumEl && job.checksum_sha256) checksumEl.textContent = job.checksum_sha256.substring(0, 16) + "...";
            if (tablesEl && job.key_tables) tablesEl.textContent = Object.keys(job.key_tables).length ? Object.entries(job.key_tables).map(function (e) { return e[0] + ": " + e[1]; }).join(" | ") : "--";
            loadBackupHistory();
            showToast("Backup completed", "success");
          } else {
            setBackupStatusBadge(statusEl, "failed");
            if (lastEl) lastEl.textContent = "Failed";
            showToast(job.error_message || "Backup failed", "error");
            loadLastBackup();
          }
        }).catch(function (e) {
          clearTimeout(pollTimer);
          if (stepEl) stepEl.style.display = "none";
          restoreButton();
          showToast(e.message || "Backup status check failed", "error");
          loadLastBackup();
        });
      }
      poll();
    } catch (e) {
      if (stepEl) stepEl.style.display = "none";
      restoreButton();
      showToast(e.message || "Backup error", "error");
      setBackupStatusBadge(statusEl, "failed");
      if (lastEl) lastEl.textContent = "Error";
      loadLastBackup();
    }
  };

  window.downloadLatestBackup = async function () {
    var btn = document.getElementById("btnDownloadBackup");
    if (btn) { btn.disabled = true; btn.textContent = "Downloading..."; }
    try {
      var latest = await getLatestBackup();
      if (!latest || !latest.id) { showToast("No backups to download", "error"); return; }
      await downloadBackup(latest.id);
      showToast("Download started", "success");
    } catch (e) { showToast(e.message || "Download failed", "error"); }
    if (btn) { btn.disabled = false; btn.textContent = "Download latest backup"; }
  };

  window.openRestoreModal = function () {
    var sel = document.getElementById("restoreBackupId");
    var modal = document.getElementById("restoreBackupModal");
    if (!sel || !modal) return;
    sel.innerHTML = "<option value=\"\">Loading...</option>";
    modal.style.display = "flex";
    getBackupHistory(20).then(function (list) {
      sel.innerHTML = "";
      if (!list || list.length === 0) { sel.innerHTML = "<option value=\"\">No backups</option>"; return; }
      list.forEach(function (b) {
        if (b.status === "success") {
          var opt = document.createElement("option");
          opt.value = b.id;
          opt.textContent = "Backup #" + b.id + " – " + (b.finished_at || b.started_at || "?");
          sel.appendChild(opt);
        }
      });
      if (sel.options.length === 0) sel.innerHTML = "<option value=\"\">No completed backups</option>";
    });
    document.getElementById("restoreConfirm").value = "";
  };

  window.closeRestoreModal = function () {
    var modal = document.getElementById("restoreBackupModal");
    if (modal) modal.style.display = "none";
  };

  window.submitRestore = async function () {
    var confirmVal = document.getElementById("restoreConfirm").value.trim();
    if (confirmVal !== "RESTORE") { showToast("Type RESTORE to confirm", "error"); return; }
    var backupId = document.getElementById("restoreBackupId").value;
    var mode = document.getElementById("restoreMode").value || "safe";
    if (!backupId) { showToast("Select a backup", "error"); return; }
    var btn = document.getElementById("btnRestoreSubmit");
    if (btn) { btn.disabled = true; btn.textContent = "Restoring..."; }
    try {
      var res = await restoreBackup(parseInt(backupId, 10), mode);
      if (res && res.ok) {
        showToast("Restore completed" + (res.restart_required ? " – restart backend recommended" : ""), "success");
        closeRestoreModal();
        loadSettings();
        loadLastBackup();
      } else {
        showToast(res && res.detail ? res.detail : "Restore failed", "error");
      }
    } catch (e) { showToast(e.message || "Restore failed", "error"); }
    if (btn) { btn.disabled = false; btn.textContent = "Restore"; }
  };

  window.saveAutoBackup = async function (el) {
    try {
      var body = {
        auto_backup: el.checked ? "true" : "false",
        automatic_backup_enabled: el.checked,
        backup_time_of_day: document.getElementById("backupTime") ? document.getElementById("backupTime").value : "03:00",
        retention_days: document.getElementById("backupRetention") ? parseInt(document.getElementById("backupRetention").value, 10) : 7,
      };
      var res = await authFetch("/settings", {
        method: "PATCH",
        body: JSON.stringify(body),
      });
      if (res && res.ok) {
        showToast("Auto-backup " + (el.checked ? "enabled" : "disabled"), "success");
        loadLastBackup();
      }
    } catch (e) {}
  };

  window.saveBackupSettings = async function () {
    try {
      var body = {
        backup_time_of_day: document.getElementById("backupTime") ? document.getElementById("backupTime").value : "03:00",
        retention_days: document.getElementById("backupRetention") ? parseInt(document.getElementById("backupRetention").value, 10) : 7,
      };
      var res = await authFetch("/settings", { method: "PATCH", body: JSON.stringify(body) });
      if (res && res.ok) {
        showToast("Backup settings saved", "success");
        loadLastBackup();
      }
    } catch (e) {}
  };

  var btnManual = document.getElementById("btnManualBackup");
  if (btnManual && typeof window.runManualBackup === "function") {
    btnManual.addEventListener("click", window.runManualBackup);
  }

  loadSettings();
  load2FAStatus();
  loadLastBackup();
})();
