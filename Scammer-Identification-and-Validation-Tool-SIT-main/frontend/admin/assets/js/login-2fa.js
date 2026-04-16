/* login-2fa.js – Dedicated 2FA verification page */
(function () {
  var COOLDOWN_SECONDS = 30;
  var cooldownTimer = null;

  function getStoredValue(keys) {
    for (var i = 0; i < keys.length; i++) {
      var value = sessionStorage.getItem(keys[i]);
      if (value !== null && value !== "") return value;
    }
    return null;
  }

  function setStoredValue(keys, value) {
    for (var i = 0; i < keys.length; i++) {
      if (value === null || value === undefined || value === "") {
        sessionStorage.removeItem(keys[i]);
      } else {
        sessionStorage.setItem(keys[i], String(value));
      }
    }
  }

  function parseStoredBool(keys, fallback) {
    var value = getStoredValue(keys);
    if (value === null) return !!fallback;
    return value === "1" || value === "true";
  }

  function init() {
    var tempToken = getStoredValue(["mfa_temp_token", "sit_2fa_temp_token"]);
    var maskedEmail = getStoredValue(["mfa_masked_email", "sit_2fa_masked_email"]);
    var emailOtpAvailable = parseStoredBool(["email_otp_available", "sit_2fa_email_otp_available"], false);
    var hasRequestedEmailOtp = parseStoredBool(["email_otp_requested", "sit_2fa_email_otp_sent"], false);

    var formEl = document.getElementById("twofaForm");
    var codeEl = document.getElementById("twofaCode");
    var sendEmailOtpBtn = document.getElementById("sendEmailOtpBtn");
    var messageEl = document.getElementById("errorMsg");
    var maskedEmailHintEl = document.getElementById("maskedEmailHint");
    var maskedEmailTextEl = document.getElementById("maskedEmailText");
    var cooldownHintEl = document.getElementById("otpCooldownHint");

    if (!formEl || !codeEl || !sendEmailOtpBtn) return;
    if (!tempToken) {
      window.location.href = "login.html";
      return;
    }

    function setMessage(text, type) {
      if (!messageEl) return;
      messageEl.textContent = text || "";
      if (!text) {
        messageEl.style.display = "none";
        messageEl.style.background = "";
        messageEl.style.color = "";
        return;
      }

      messageEl.style.display = "block";
      if (type === "success") {
        messageEl.style.background = "rgba(34,197,94,0.15)";
        messageEl.style.color = "var(--success)";
      } else if (type === "info") {
        messageEl.style.background = "rgba(59,130,246,0.12)";
        messageEl.style.color = "var(--text-1)";
      } else {
        messageEl.style.background = "";
        messageEl.style.color = "";
      }
    }

    function updateMaskedEmailHint() {
      if (!maskedEmailHintEl || !maskedEmailTextEl) return;
      if (maskedEmail) {
        maskedEmailTextEl.textContent = maskedEmail;
        maskedEmailHintEl.style.display = "block";
      } else {
        maskedEmailHintEl.style.display = "none";
      }
    }

    function getCooldownUntil() {
      var raw = getStoredValue(["otp_cooldown_until", "sit_2fa_email_otp_cooldown_until"]);
      var timestamp = raw ? parseInt(raw, 10) : 0;
      return Number.isFinite(timestamp) ? timestamp : 0;
    }

    function setCooldown(seconds) {
      var until = Date.now() + (seconds * 1000);
      setStoredValue(["otp_cooldown_until", "sit_2fa_email_otp_cooldown_until"], until);
    }

    function clearCooldown() {
      setStoredValue(["otp_cooldown_until", "sit_2fa_email_otp_cooldown_until"], null);
    }

    function clearMfaSessionState() {
      setStoredValue(["mfa_temp_token", "sit_2fa_temp_token"], null);
      setStoredValue(["mfa_masked_email", "sit_2fa_masked_email"], null);
      setStoredValue(["email_otp_available", "sit_2fa_email_otp_available"], null);
      setStoredValue(["email_otp_requested", "sit_2fa_email_otp_sent"], null);
      setStoredValue(["otp_cooldown_until", "sit_2fa_email_otp_cooldown_until"], null);
    }

    function updateEmailButtonState() {
      var cooldownUntil = getCooldownUntil();
      var isInCooldown = cooldownUntil > Date.now();
      var secondsLeft = isInCooldown ? Math.max(1, Math.ceil((cooldownUntil - Date.now()) / 1000)) : 0;
      var label = hasRequestedEmailOtp ? "Resend OTP" : "Send Email OTP";

      if (!isInCooldown && cooldownUntil) clearCooldown();

      sendEmailOtpBtn.textContent = isInCooldown ? (label + " (" + secondsLeft + "s)") : label;
      sendEmailOtpBtn.disabled = !emailOtpAvailable || isInCooldown;

      if (cooldownHintEl) {
        if (!emailOtpAvailable) {
          cooldownHintEl.textContent = "Email OTP is unavailable for this account. Use your authenticator app code to continue.";
        } else if (isInCooldown) {
          cooldownHintEl.textContent = "You can request another code in " + secondsLeft + "s.";
        } else {
          cooldownHintEl.textContent = "";
        }
      }
    }

    function startCooldownTicker() {
      if (cooldownTimer) clearInterval(cooldownTimer);
      cooldownTimer = setInterval(updateEmailButtonState, 1000);
    }

    sendEmailOtpBtn.addEventListener("click", async function () {
      if (sendEmailOtpBtn.disabled) return;

      setMessage("", "error");
      sendEmailOtpBtn.disabled = true;
      sendEmailOtpBtn.textContent = "Sending...";

      try {
        var response = await sendEmailOtp({ temp_token: tempToken });
        if (response && response.masked_email) {
          maskedEmail = response.masked_email;
          setStoredValue(["mfa_masked_email", "sit_2fa_masked_email"], maskedEmail);
        }

        hasRequestedEmailOtp = true;
        emailOtpAvailable = true;
        setStoredValue(["email_otp_requested", "sit_2fa_email_otp_sent"], "1");
        setStoredValue(["email_otp_available", "sit_2fa_email_otp_available"], "1");

        setCooldown(COOLDOWN_SECONDS);
        updateMaskedEmailHint();
        updateEmailButtonState();
        setMessage((response && response.message) || "Verification code sent. Check your email.", "success");
      } catch (err) {
        updateEmailButtonState();
        setMessage((err && err.message) || "Failed to send email OTP", "error");
      }
    });

    formEl.addEventListener("submit", async function (e) {
      e.preventDefault();
      setMessage("", "error");

      var code = codeEl.value.trim();
      if (code.length !== 6) {
        setMessage("Enter a 6-digit code.", "error");
        return;
      }

      try {
        var data = await verify2FA({ temp_token: tempToken, code: code });
        if (data && data.access_token) {
          clearMfaSessionState();
          setToken(data.access_token);
          window.location.href = "dashboard.html";
        } else {
          setMessage("Verification failed. Please try again.", "error");
        }
      } catch (err) {
        setMessage((err && err.message) || "Invalid or expired 2FA code", "error");
      }
    });

    updateMaskedEmailHint();
    updateEmailButtonState();
    if (!emailOtpAvailable) {
      setMessage("Email OTP is unavailable for this account. Use your authenticator app code to continue.", "info");
    }
    startCooldownTicker();
    codeEl.focus();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
