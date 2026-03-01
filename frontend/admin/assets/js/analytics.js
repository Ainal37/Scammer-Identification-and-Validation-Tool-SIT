/* analytics.js – Analytics page */
(function () {
  if (!getToken()) { window.location.href = "login.html"; return; }

  var verdictChartInst = null;
  var threatChartInst = null;
  var reportChartInst = null;

  function setStatus(msg) {
    var el = document.getElementById("liveStatus");
    if (el) el.textContent = msg;
  }

  async function loadAnalytics() {
    try {
      var res = await authFetch("/analytics/stats");
      if (!res) return;
      var d = await res.json();
      renderAnalytics(d);
      setStatus("Last updated: " + new Date().toLocaleTimeString());
    } catch (e) { setStatus("Failed to load analytics"); }
  }

  function renderAnalytics(d) {
    setText("anTotalScans", d.total_scans);
    setText("anWeekScans", d.scans_this_week);
    setText("anTotalUsers", d.total_users);
    setText("anAvgScore", d.avg_score);

    // Verdict chart
    var vb = d.verdict_breakdown || {};
    if (verdictChartInst) verdictChartInst.destroy();
    var ctx1 = document.getElementById("anVerdictChart");
    if (ctx1) {
      verdictChartInst = new Chart(ctx1, {
        type: "doughnut",
        data: {
          labels: ["Safe", "Suspicious", "Scam"],
          datasets: [{ data: [vb.safe || 0, vb.suspicious || 0, vb.scam || 0], backgroundColor: ["#059669", "#d97706", "#dc2626"] }]
        },
        options: { responsive: true, plugins: { legend: { position: "bottom" } } }
      });
    }

    // Threat chart
    var tb = d.threat_breakdown || {};
    if (threatChartInst) threatChartInst.destroy();
    var ctx2 = document.getElementById("anThreatChart");
    if (ctx2) {
      threatChartInst = new Chart(ctx2, {
        type: "bar",
        data: {
          labels: ["LOW", "MED", "HIGH"],
          datasets: [{ label: "Count", data: [tb.LOW || 0, tb.MED || 0, tb.HIGH || 0], backgroundColor: ["#059669", "#d97706", "#dc2626"] }]
        },
        options: { responsive: true, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, ticks: { stepSize: 1 } } } }
      });
    }

    // Report status chart
    var rs = d.report_status || {};
    if (reportChartInst) reportChartInst.destroy();
    var ctx3 = document.getElementById("anReportChart");
    if (ctx3) {
      reportChartInst = new Chart(ctx3, {
        type: "bar",
        data: {
          labels: ["New", "Investigating", "Resolved"],
          datasets: [{ label: "Reports", data: [rs["new"] || 0, rs.investigating || 0, rs.resolved || 0], backgroundColor: ["#2563eb", "#d97706", "#059669"] }]
        },
        options: { responsive: true, indexAxis: "y", plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true, ticks: { stepSize: 1 } } } }
      });
    }
  }

  function setText(id, val) {
    var el = document.getElementById(id);
    if (el) el.textContent = val !== undefined && val !== null ? val : "--";
  }

  loadAnalytics();
  setInterval(loadAnalytics, 30000);
})();
