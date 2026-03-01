/* 2fa.js – 2FA & Security page */
(function () {
  if (!getToken()) { window.location.href = "login.html"; return; }

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
      if (status && status.password_hint_masked && hintDisplay && hintMasked) {
        hintMasked.textContent = status.password_hint_masked;
        hintDisplay.style.display = "block";
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
        if (d.hint_masked && hintDisplay && hintMasked) {
          hintMasked.textContent = d.hint_masked;
          hintDisplay.style.display = "block";
        }
      } else {
        var d = await res.json();
        showToast(d.detail || "Failed to change password", "error");
      }
    } catch (e) { showToast("Error changing password", "error"); }
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
        var res = await authFetch("/security/2fa/disable", { method: "POST" });
        if (!res) { el.checked = true; return; }
        if (res.ok) {
          document.getElementById("twofaSetupPanel").style.display = "none";
          showToast("2FA disabled", "success");
          load2FAStatus();
        } else {
          var err = await res.json();
          showToast(err.detail || "Failed to disable 2FA", "error");
          el.checked = true;
        }
      } catch (e) { el.checked = true; showToast(e.message || "Failed to disable 2FA", "error"); }
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

  // #region agent log
  fetch('http://127.0.0.1:7814/ingest/d20e7645-655f-4650-9f54-84f6bd738367',{method:'POST',headers:{'Content-Type':'application/json','X-Debug-Session-Id':'5c1df0'},body:JSON.stringify({sessionId:'5c1df0',location:'2fa.js:127',message:'about to call load2FAStatus',data:{load2FAStatusDefined:typeof window.load2FAStatus==='function'},timestamp:Date.now(),hypothesisId:'C'})}).catch(function(){});
  // #endregion
  load2FAStatus();
})();
