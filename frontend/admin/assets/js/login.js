// ===== SIT Admin – Login (with 2FA support) =====
if (getToken()) window.location.href = "dashboard.html";

var _tempToken = null;
var _emailOtpAvailable = false;

// Check backend on load – show status so user knows if server is reachable
(function checkBackend() {
  var el = document.getElementById("backendStatus");
  if (!el) return;
  el.style.display = "block";
  el.textContent = "Checking backend…";
  el.style.background = "rgba(107,114,128,0.2)";
  el.style.color = "var(--text-2)";
  pingBackend().then(function (data) {
    if (data) {
      el.textContent = "Backend online (v" + (data.version || "?") + ")";
      el.style.background = "rgba(34,197,94,0.15)";
      el.style.color = "var(--success)";
    } else {
      el.textContent = "Backend offline – run .\\run_all.ps1 first";
      el.style.background = "rgba(239,68,68,0.15)";
      el.style.color = "var(--error)";
    }
  });
})();

// Password hint: debounced fetch on email input
var _hintDebounceTimer = null;

function fetchPasswordHint() {
  var emailEl = document.getElementById("email");
  var hintEl = document.getElementById("passwordHint");
  if (!emailEl || !hintEl) return;
  var email = emailEl.value.trim();
  if (!email) {
    hintEl.textContent = "—";
    return;
  }
  var url = BASE_URL + "/auth/password-hint";
  fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: email }),
  })
    .then(function (res) { return res.json().then(function (d) { return { ok: res.ok, status: res.status, data: d }; }); })
    .then(function (r) {
      var masked = (r.data && r.data.hint_masked) ? r.data.hint_masked : "—";
      hintEl.textContent = masked;
    })
    .catch(function (err) {
      if (typeof console !== "undefined" && console.log) {
        console.log("[SIT] Password hint request failed:", err.message || err);
      }
      hintEl.textContent = "—";
    });
}

var emailEl = document.getElementById("email");
if (emailEl) {
  function scheduleHintFetch() {
    clearTimeout(_hintDebounceTimer);
    _hintDebounceTimer = setTimeout(fetchPasswordHint, 500);
  }
  emailEl.addEventListener("input", scheduleHintFetch);
  emailEl.addEventListener("change", scheduleHintFetch);
  // Fetch on load if email already has value (e.g. autofill)
  if (emailEl.value.trim()) {
    setTimeout(fetchPasswordHint, 600);
  }
}

document.getElementById("loginForm").addEventListener("submit", async function (e) {
  e.preventDefault();
  var err = document.getElementById("errorMsg");
  err.style.display = "none";
  try {
    var data = await login(
      document.getElementById("email").value.trim(),
      document.getElementById("password").value
    );

    if (data.requires_2fa && data.temp_token) {
      sessionStorage.setItem("sit_2fa_temp_token", data.temp_token);
      sessionStorage.setItem("sit_2fa_email_otp_available", data.email_otp_available ? "1" : "0");
      window.location.href = "login-2fa.html";
      return;
    } else if (data.access_token) {
      setToken(data.access_token);
      window.location.href = "dashboard.html";
    }
  } catch (ex) {
    var msg = ex.message || "Login failed";
    if (msg === "Failed to fetch" || msg.indexOf("fetch") !== -1 || msg.indexOf("NetworkError") !== -1) {
      msg = "Cannot connect to backend. Is the server running? Run .\\run_all.ps1 first, then open http://127.0.0.1:5500/login.html";
    } else if (msg === "Invalid email or password") {
      msg = "Invalid email or password. Try: nalcsbaru@gmail.com / admin123 (needs 2FA) or bot@example.com / bot123 (no 2FA).";
    }
    err.textContent = msg;
    err.style.display = "block";
  }
});

// 2FA form handler
var twofaForm = document.getElementById("twofaForm");
if (twofaForm) {
  twofaForm.addEventListener("submit", async function (e) {
    e.preventDefault();
    var err = document.getElementById("errorMsg");
    err.style.display = "none";
    var code = document.getElementById("twofaCode").value.trim();
    if (code.length !== 6) {
      err.textContent = "Enter a 6-digit code";
      err.style.display = "block";
      return;
    }
    try {
      var data = await verify2FA(_tempToken, code);
      if (data.access_token) {
        setToken(data.access_token);
        window.location.href = "dashboard.html";
      }
    } catch (ex) {
      err.textContent = ex.message || "Invalid 2FA code";
      err.style.display = "block";
    }
  });
}

// Send code via email button
var sendEmailOtpBtn = document.getElementById("sendEmailOtpBtn");
if (sendEmailOtpBtn) {
  sendEmailOtpBtn.addEventListener("click", async function () {
    if (!_tempToken) return;
    sendEmailOtpBtn.disabled = true;
    sendEmailOtpBtn.textContent = "Sending…";
    var err = document.getElementById("errorMsg");
    err.style.display = "none";
    try {
      var data = await sendEmailOtp(_tempToken);
      if (typeof showToast === "function") showToast(data.message || "Code sent to your email", "success");
      else err.textContent = data.message || "Code sent. Check your email.";
      err.style.display = "block";
      err.style.background = "rgba(34,197,94,0.15)";
      err.style.color = "var(--success)";
    } catch (ex) {
      err.textContent = ex.message || "Failed to send email";
      err.style.display = "block";
      err.style.background = "";
      err.style.color = "";
    }
    sendEmailOtpBtn.disabled = false;
    sendEmailOtpBtn.textContent = "Send code via email";
  });
}

// Back to login link
window.show2FABack = function () {
  _tempToken = null;
  var loginStep = document.getElementById("loginStep");
  var twofaSection = document.getElementById("twofaSection");
  if (twofaSection) twofaSection.style.display = "none";
  if (loginStep) loginStep.style.display = "block";
  var sub = document.querySelector(".login-box .subtitle");
  if (sub) sub.textContent = "Sign in to your account";
  document.title = "SIT Admin – Login";
  document.getElementById("errorMsg").style.display = "none";
  var codeEl = document.getElementById("twofaCode");
  if (codeEl) codeEl.value = "";
};
