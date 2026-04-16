// ===== SIT Admin – Login (with 2FA support) =====
if (getToken()) window.location.href = "dashboard.html";

(function showRedirectedMfaError() {
  var msg = sessionStorage.getItem("mfa_redirect_error");
  if (!msg) return;
  sessionStorage.removeItem("mfa_redirect_error");
  var err = document.getElementById("errorMsg");
  if (!err) return;
  err.textContent = msg;
  err.style.display = "block";
})();

var _tempToken = null;
var _emailOtpAvailable = false;

function _setMfaStorageValue(keys, value) {
  for (var i = 0; i < keys.length; i++) {
    if (value === null || value === undefined || value === "") sessionStorage.removeItem(keys[i]);
    else sessionStorage.setItem(keys[i], String(value));
  }
}

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

// Password hint: debounced fetch on email input (login.html only)
var _hintDebounceTimer = null;
var _hintEmailEl = document.getElementById("email");
var _hintTextEl = document.getElementById("passwordHintText");
var _hintRowEl = document.getElementById("passwordHintRow");

function _isValidEmail(v) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
}

function _hideHintRow() {
  if (_hintRowEl) _hintRowEl.style.display = "none";
  if (_hintTextEl) _hintTextEl.textContent = "";
}

function _showHintRow(text) {
  if (_hintTextEl) _hintTextEl.textContent = text;
  if (_hintRowEl) _hintRowEl.style.display = "block";
}

function fetchPasswordHint() {
  if (!_hintEmailEl || !_hintTextEl || !_hintRowEl) return;
  var email = _hintEmailEl.value.trim();
  if (!email || !_isValidEmail(email)) { _hideHintRow(); return; }
  var url = BASE_URL + "/public/password-hint?email=" + encodeURIComponent(email);
  fetch(url, { method: "GET", cache: "no-store" })
    .then(function (res) { return res.ok ? res.json() : null; })
    .then(function (d) {
      var hint = d && d.hint ? d.hint : null;
      if (hint) { _showHintRow(hint); }
      else { _hideHintRow(); }
    })
    .catch(function () { _hideHintRow(); });
}

if (_hintEmailEl && _hintRowEl) {
  _hintEmailEl.addEventListener("input", function () {
    clearTimeout(_hintDebounceTimer);
    _hintDebounceTimer = setTimeout(fetchPasswordHint, 350);
  });
  _hintEmailEl.addEventListener("change", function () {
    clearTimeout(_hintDebounceTimer);
    _hintDebounceTimer = setTimeout(fetchPasswordHint, 350);
  });
  if (_hintEmailEl.value.trim()) setTimeout(fetchPasswordHint, 400);
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

    var needs2FA = !!data.requires_2fa;
    if (needs2FA && data.temp_token) {
      _tempToken = data.temp_token;
      _emailOtpAvailable = !!data.email_otp_available;
      var preferredMethod = _emailOtpAvailable ? "email" : "totp";

      _setMfaStorageValue(["mfa_temp_token", "sit_2fa_temp_token"], data.temp_token);
      _setMfaStorageValue(["mfa_masked_email", "sit_2fa_masked_email"], data.masked_email || null);
      _setMfaStorageValue(["mfa_method", "sit_2fa_method"], preferredMethod);
      _setMfaStorageValue(
        ["email_otp_available", "sit_2fa_email_otp_available"],
        data.email_otp_available ? "1" : "0"
      );
      _setMfaStorageValue(["otp_sent_once", "sit_2fa_otp_sent_once"], null);
      _setMfaStorageValue(["email_otp_requested", "sit_2fa_email_otp_sent"], null);
      _setMfaStorageValue(["otp_cooldown_until", "sit_2fa_email_otp_cooldown_until"], null);
      window.location.href = "2fa.html";
      return;
    } else if (data.access_token) {
      _setMfaStorageValue(["mfa_temp_token", "sit_2fa_temp_token"], null);
      _setMfaStorageValue(["mfa_masked_email", "sit_2fa_masked_email"], null);
      _setMfaStorageValue(["mfa_method", "sit_2fa_method"], null);
      _setMfaStorageValue(["email_otp_available", "sit_2fa_email_otp_available"], null);
      _setMfaStorageValue(["otp_sent_once", "sit_2fa_otp_sent_once"], null);
      _setMfaStorageValue(["email_otp_requested", "sit_2fa_email_otp_sent"], null);
      _setMfaStorageValue(["otp_cooldown_until", "sit_2fa_email_otp_cooldown_until"], null);
      setToken(data.access_token);
      window.location.href = "dashboard.html";
    }
  } catch (ex) {
    var msg = ex.message || "Login failed";
    if (msg === "Failed to fetch" || msg.indexOf("fetch") !== -1 || msg.indexOf("NetworkError") !== -1) {
      msg = "Cannot connect to backend. Is the server running? Run .\\run_all.ps1 first, then open http://127.0.0.1:5500/login.html";
      err.textContent = msg;
      err.style.display = "block";
    } else if (msg === "Invalid email or password") {
      err.innerHTML =
        "<strong>Sign-in failed</strong><br/>Incorrect email or password. Please try again.";
      err.style.display = "block";
    } else {
      err.textContent = msg;
      err.style.display = "block";
    }
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
