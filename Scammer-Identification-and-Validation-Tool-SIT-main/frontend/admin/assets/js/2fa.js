/* 2fa.js – supports login verification flow + security page */
(function () {
  function getSessionValue(primaryKey, fallbackKey) {
    var v = sessionStorage.getItem(primaryKey);
    if (v !== null && v !== "") return v;
    if (fallbackKey) return sessionStorage.getItem(fallbackKey);
    return null;
  }

  function setSessionValue(primaryKey, fallbackKey, value) {
    var keys = [primaryKey];
    if (fallbackKey) keys.push(fallbackKey);
    for (var i = 0; i < keys.length; i++) {
      if (value === null || value === undefined || value === "") {
        sessionStorage.removeItem(keys[i]);
      } else {
        sessionStorage.setItem(keys[i], String(value));
      }
    }
  }

  function clearMfaSessionState() {
    setSessionValue("mfa_temp_token", "sit_2fa_temp_token", null);
    setSessionValue("mfa_masked_email", "sit_2fa_masked_email", null);
    setSessionValue("mfa_method", "sit_2fa_method", null);
    setSessionValue("email_otp_available", "sit_2fa_email_otp_available", null);
    setSessionValue("otp_sent_once", "sit_2fa_otp_sent_once", null);
    setSessionValue("email_otp_requested", "sit_2fa_email_otp_sent", null);
    setSessionValue("otp_cooldown_until", "sit_2fa_email_otp_cooldown_until", null);
  }

  function parseBool(v, fallback) {
    if (v === null || v === undefined || v === "") return !!fallback;
    return v === "1" || v === "true" || v === true;
  }

  function getCooldownUntil() {
    var raw = getSessionValue("otp_cooldown_until", "sit_2fa_email_otp_cooldown_until");
    var t = raw ? parseInt(raw, 10) : 0;
    return Number.isFinite(t) ? t : 0;
  }

  function setCooldown(seconds) {
    var until = Date.now() + (seconds * 1000);
    setSessionValue("otp_cooldown_until", "sit_2fa_email_otp_cooldown_until", until);
  }

  async function sendOtpWithTempToken(tempToken) {
    var res = await fetch(BASE_URL + "/auth/send-email-otp", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + tempToken, // optional; backend uses JSON temp_token
      },
      body: JSON.stringify({ temp_token: tempToken }),
    });
    var data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Failed to send email OTP");
    return data;
  }

  function initMfaVerifyMode(tempToken, maskedEmail, emailOtpAvailable) {
    document.body.classList.add("mfa-verify-active");

    var main = document.querySelector(".main");
    if (!main) {
      alert("2FA page is missing required layout elements.");
      window.location.href = "login.html";
      return;
    }

    main.innerHTML =
      '<div class="auth-page">' +
      '<div class="auth-card">' +
      '  <div class="auth-header">' +
      '    <div><div class="auth-brand">SIT Admin</div><h1>Verify 2FA</h1></div>' +
      '    <button class="theme-toggle-btn" id="themeToggleBtn" aria-label="Toggle theme" type="button" onclick="window.toggleTheme&&window.toggleTheme()">&#9728;</button>' +
      '  </div>' +
      '  <p id="mfaHint" class="auth-subtitle"></p>' +
      '  <div id="mfaError" class="error-msg" style="display:none"></div>' +
      '  <div class="form-group">' +
      '    <label for="mfaCodeInput">6-digit code</label>' +
      '    <input type="text" id="mfaCodeInput" placeholder="000000" maxlength="6" autocomplete="one-time-code" style="text-align:center;font-size:24px;letter-spacing:8px" />' +
      '  </div>' +
      '  <div class="auth-actions">' +
      '    <button id="mfaVerifyBtn" class="btn btn-primary">Verify</button>' +
      '    <button id="mfaResendBtn" class="btn">Resend code</button>' +
      '  </div>' +
      '  <div id="mfaCooldownHint" style="margin-top:12px;font-size:12px;color:var(--text-3)"></div>' +
      '  <div class="auth-footer"><a href="login.html" id="mfaBackBtn">Back to login</a></div>' +
      '</div>' +
      '</div>';

    if (typeof window.toggleTheme === "function") {
      var tBtn = document.getElementById("themeToggleBtn");
      if (tBtn) {
        var curTheme = document.documentElement.getAttribute("data-theme") || "light";
        tBtn.innerHTML = (curTheme === "dark" ? "&#9790;" : "&#9728;");
      }
    }

    var hintEl = document.getElementById("mfaHint");
    var errEl = document.getElementById("mfaError");
    var codeEl = document.getElementById("mfaCodeInput");
    var verifyBtn = document.getElementById("mfaVerifyBtn");
    var resendBtn = document.getElementById("mfaResendBtn");
    var backBtn = document.getElementById("mfaBackBtn");
    var cooldownEl = document.getElementById("mfaCooldownHint");

    var requestedBefore = parseBool(getSessionValue("email_otp_requested", "sit_2fa_email_otp_sent"), false);
    var otpSentOnce = parseBool(getSessionValue("otp_sent_once", "sit_2fa_otp_sent_once"), false);
    var cooldownTimer = null;
    var COOLDOWN_SECONDS = 30;
    var currentMasked = maskedEmail || "your email";

    hintEl.textContent = "Code will be sent to " + currentMasked + ".";

    function setError(text, isSuccess) {
      if (!text) {
        errEl.style.display = "none";
        errEl.textContent = "";
        errEl.style.background = "";
        errEl.style.color = "";
        return;
      }
      errEl.style.display = "block";
      errEl.textContent = text;
      if (isSuccess) {
        errEl.style.background = "rgba(34,197,94,0.15)";
        errEl.style.color = "var(--success)";
      } else {
        errEl.style.background = "";
        errEl.style.color = "";
      }
    }

    function updateResendState() {
      var until = getCooldownUntil();
      var now = Date.now();
      var inCooldown = until > now;
      var left = inCooldown ? Math.max(1, Math.ceil((until - now) / 1000)) : 0;

      resendBtn.disabled = !emailOtpAvailable || inCooldown;
      resendBtn.textContent = requestedBefore ? "Resend code" : "Send code";
      if (inCooldown) resendBtn.textContent += " (" + left + "s)";

      if (!emailOtpAvailable) {
        cooldownEl.textContent = "Email OTP is unavailable for this account. Use authenticator app code.";
      } else if (inCooldown) {
        cooldownEl.textContent = "You can request another code in " + left + "s.";
      } else {
        cooldownEl.textContent = "";
      }
    }

    async function requestEmailOtp(autoMode) {
      if (!emailOtpAvailable) {
        setError("Email OTP is unavailable for this account.", false);
        return;
      }
      if (!autoMode && resendBtn.disabled) return;

      resendBtn.disabled = true;
      resendBtn.textContent = "Sending...";
      setError("", false);

      try {
        var data = await sendOtpWithTempToken(tempToken);
        requestedBefore = true;
        otpSentOnce = true;
        setSessionValue("otp_sent_once", "sit_2fa_otp_sent_once", "1");
        setSessionValue("email_otp_requested", "sit_2fa_email_otp_sent", "1");
        setCooldown(COOLDOWN_SECONDS);
        if (data && data.masked_email) {
          currentMasked = data.masked_email;
          hintEl.textContent = "Code sent to " + currentMasked + ".";
          setSessionValue("mfa_masked_email", "sit_2fa_masked_email", currentMasked);
        } else {
          hintEl.textContent = "Code sent to " + currentMasked + ".";
        }
        setError((data && data.message) ? data.message : "Verification code sent.", true);
      } catch (e) {
        var msg = e.message || "Failed to send email OTP";
        if (msg === "Failed to fetch" || msg.indexOf("fetch") !== -1 || msg.indexOf("NetworkError") !== -1) {
          msg = "Backend unreachable. Please try again.";
        } else if (msg.indexOf("not configured") !== -1 || msg.indexOf("Unable to send email OTP") !== -1) {
          msg = "Email service unavailable right now. Please try again later.";
        }
        setError(msg, false);
      } finally {
        updateResendState();
      }
    }

    async function verifyCode() {
      var code = (codeEl.value || "").trim();
      if (code.length !== 6) {
        setError("Enter a valid 6-digit code.", false);
        return;
      }

      verifyBtn.disabled = true;
      verifyBtn.textContent = "Verifying...";
      setError("", false);

      try {
        var data = await verify2FA({ temp_token: tempToken, code: code });
        if (data && data.access_token) {
          clearMfaSessionState();
          setToken(data.access_token);
          window.location.href = "dashboard.html";
          return;
        }
        setError("Verification failed. Try again.", false);
      } catch (e) {
        var msg = e.message || "Invalid or expired 2FA code";
        if (msg === "Failed to fetch" || msg.indexOf("fetch") !== -1 || msg.indexOf("NetworkError") !== -1) {
          msg = "Backend unreachable. Please try again.";
        } else if (msg.indexOf("expired") !== -1 || msg.indexOf("Invalid") !== -1) {
          msg = "Invalid or expired OTP. Please try again.";
        }
        setError(msg, false);
      } finally {
        verifyBtn.disabled = false;
        verifyBtn.textContent = "Verify";
      }
    }

    verifyBtn.addEventListener("click", verifyCode);
    codeEl.addEventListener("keydown", function (e) {
      if (e.key === "Enter") {
        e.preventDefault();
        verifyCode();
      }
    });
    resendBtn.addEventListener("click", function () { requestEmailOtp(false); });
    backBtn.addEventListener("click", function (e) {
      e.preventDefault();
      clearMfaSessionState();
      window.location.href = "login.html";
    });

    updateResendState();
    cooldownTimer = setInterval(updateResendState, 1000);
    window.addEventListener("beforeunload", function () {
      if (cooldownTimer) clearInterval(cooldownTimer);
    });

    if (emailOtpAvailable && !otpSentOnce) {
      requestEmailOtp(true);
    } else if (emailOtpAvailable && requestedBefore) {
      hintEl.textContent = "Code sent to " + currentMasked + ".";
    } else {
      setError("Email OTP is unavailable for this account. Use authenticator app code.", false);
    }
    codeEl.focus();
  }

  function initSecurityPageMode() {
    var statusEl = document.getElementById("liveStatus");
    function setStatus(msg) { if (statusEl) statusEl.textContent = msg; }

    setStatus("Loading...");

    window.load2FAStatus = async function () {
      try {
        var status = await get2FAStatus();
        var toggle = document.getElementById("toggle2FA");
        if (toggle) {
          toggle.checked = !!(status && status.totp_enabled);
          toggle.disabled = false;
        }
        var hintDisplay = document.getElementById("savedHintDisplay");
        var hintMasked = document.getElementById("savedHintMasked");
        if (hintDisplay && hintMasked) {
          var hint = (status && status.password_hint) ? status.password_hint : "";
          if (hint) {
            hintMasked.textContent = hint;
            hintDisplay.style.display = "block";
          } else {
            hintDisplay.style.display = "none";
          }
        }
        setStatus("Ready");
      } catch (e) {
        setStatus("Failed to load 2FA status");
      }
    };

    window.changePassword = async function () {
      var cur = document.getElementById("settCurrentPw").value;
      var nw = document.getElementById("settNewPw").value;
      var cf = document.getElementById("settConfirmPw").value;
      var hintEl = document.getElementById("settPasswordHint");
      var hint = hintEl ? hintEl.value.trim() || undefined : undefined;
      if (!cur || !nw) { showToast("Fill in both password fields", "error"); return; }
      if (nw !== cf) { showToast("Passwords do not match", "error"); return; }
      if (nw.length < 8) { showToast("Password must be at least 8 characters", "error"); return; }
      try {
        var res = await authFetch("/auth/change-password", {
          method: "POST",
          body: JSON.stringify({
            current_password: cur,
            new_password: nw,
            confirm_new_password: cf,
            password_hint: hint,
          }),
        });
        if (!res) return;
        if (res.ok) {
          var d = await res.json();
          showToast("Password changed", "success");
          document.getElementById("settCurrentPw").value = "";
          document.getElementById("settNewPw").value = "";
          document.getElementById("settConfirmPw").value = "";
          if (hintEl) hintEl.value = "";
          var hintDisplay = document.getElementById("savedHintDisplay");
          var hintMasked = document.getElementById("savedHintMasked");
          if (hintDisplay && hintMasked) {
            var savedHint = d.hint || d.hint_masked || "";
            if (savedHint) {
              hintMasked.textContent = savedHint;
              hintDisplay.style.display = "block";
            } else {
              hintDisplay.style.display = "none";
            }
          }
        } else {
          var d2 = await res.json();
          showToast(d2.detail || "Failed to change password", "error");
        }
      } catch (e2) { showToast("Error changing password", "error"); }
    };

    window.saveHintOnly = async function () {
      var hintEl = document.getElementById("settPasswordHint");
      var hintValue = hintEl ? hintEl.value.trim() : "";
      try {
        var res = await authFetch("/auth/password-hint", {
          method: "PATCH",
          body: JSON.stringify({ hint: hintValue || null }),
        });
        if (!res) return;
        if (res.ok) {
          var d = await res.json();
          var hintDisplay = document.getElementById("savedHintDisplay");
          var hintMasked = document.getElementById("savedHintMasked");
          if (hintDisplay && hintMasked) {
            var saved = d.hint || "";
            if (saved) {
              hintMasked.textContent = saved;
              hintDisplay.style.display = "block";
            } else {
              hintDisplay.style.display = "none";
            }
          }
          showToast("Password hint saved", "success");
        } else {
          var d2 = await res.json();
          showToast(d2.detail || "Failed to save hint", "error");
        }
      } catch (e) { showToast("Error saving hint", "error"); }
    };

    window.handle2FAToggle = async function (el) {
      if (el.checked) {
        try {
          var res = await authFetch("/security/2fa/setup", { method: "POST" });
          if (!res) { el.checked = false; return; }
          if (res.ok) {
            var d = await res.json();
            document.getElementById("twofaSecret").textContent = d.secret;
            document.getElementById("twofaSetupPanel").style.display = "block";
            showToast("Add the secret to your authenticator app", "info");
          } else {
            var err = await res.json();
            showToast(err.detail || "2FA setup failed", "error");
            el.checked = false;
          }
        } catch (e) { el.checked = false; showToast("Failed to setup 2FA", "error"); }
      } else {
        try {
          var res2 = await authFetch("/security/2fa/disable", { method: "POST" });
          if (!res2) { el.checked = true; return; }
          if (res2.ok) {
            document.getElementById("twofaSetupPanel").style.display = "none";
            showToast("2FA disabled", "success");
            load2FAStatus();
          } else {
            var err2 = await res2.json();
            showToast(err2.detail || "Failed to disable 2FA", "error");
            el.checked = true;
          }
        } catch (e3) { el.checked = true; showToast(e3.message || "Failed to disable 2FA", "error"); }
      }
    };

    window.confirm2FA = async function () {
      var code = document.getElementById("twofaConfirmCode").value.trim();
      if (code.length !== 6) { showToast("Enter a 6-digit code", "error"); return; }
      try {
        var res = await authFetch("/security/2fa/confirm", {
          method: "POST",
          body: JSON.stringify({ code: code }),
        });
        if (!res) return;
        if (res.ok) {
          document.getElementById("twofaSetupPanel").style.display = "none";
          document.getElementById("twofaConfirmCode").value = "";
          showToast("2FA enabled successfully!", "success");
          load2FAStatus();
        } else {
          var d = await res.json();
          showToast(d.detail || "Invalid code", "error");
        }
      } catch (e) { showToast("Error confirming 2FA", "error"); }
    };

    load2FAStatus();
  }

  var accessToken = getToken();
  var pendingTempToken = getSessionValue("mfa_temp_token", "sit_2fa_temp_token");
  var maskedEmail = getSessionValue("mfa_masked_email", "sit_2fa_masked_email");
  var emailOtpAvailable = parseBool(getSessionValue("email_otp_available", "sit_2fa_email_otp_available"), true);

  if (!accessToken && pendingTempToken) {
    initMfaVerifyMode(pendingTempToken, maskedEmail, emailOtpAvailable);
    return;
  }

  if (!accessToken) {
    sessionStorage.setItem("mfa_redirect_error", "2FA session is missing or expired. Please sign in again.");
    window.location.href = "login.html";
    return;
  }

  initSecurityPageMode();
})();
