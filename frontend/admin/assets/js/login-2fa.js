/* login-2fa.js – Dedicated 2FA verification page */
(function () {
  var tempToken = sessionStorage.getItem("sit_2fa_temp_token");
  if (!tempToken) {
    window.location.href = "login.html";
    return;
  }

  var emailOtpAvailable = sessionStorage.getItem("sit_2fa_email_otp_available") === "1";
  var sendEmailOtpBtn = document.getElementById("sendEmailOtpBtn");
  if (sendEmailOtpBtn && emailOtpAvailable) {
    sendEmailOtpBtn.style.display = "block";
    sendEmailOtpBtn.addEventListener("click", async function () {
      sendEmailOtpBtn.disabled = true;
      sendEmailOtpBtn.textContent = "Sending…";
      var err = document.getElementById("errorMsg");
      err.style.display = "none";
      try {
        var data = await sendEmailOtp(tempToken);
        err.textContent = data.message || "Code sent. Check your email.";
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

  document.getElementById("twofaForm").addEventListener("submit", async function (e) {
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
      var data = await verify2FA(tempToken, code);
      if (data.access_token) {
        sessionStorage.removeItem("sit_2fa_temp_token");
        setToken(data.access_token);
        window.location.href = "dashboard.html";
      }
    } catch (ex) {
      err.textContent = ex.message || "Invalid 2FA code";
      err.style.display = "block";
    }
  });

  document.getElementById("twofaCode").focus();
})();
