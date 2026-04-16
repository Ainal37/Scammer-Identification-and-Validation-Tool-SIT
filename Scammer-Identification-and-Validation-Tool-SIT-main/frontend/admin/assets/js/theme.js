/* theme.js – Dark/Light mode toggle. Load AFTER config.js, BEFORE page scripts. */
(function () {
  var STORAGE_KEY = "sit_theme";

  function getTheme() {
    var stored = null;
    try { stored = localStorage.getItem(STORAGE_KEY); } catch (e) {}
    if (stored === "dark" || stored === "light") return stored;
    try {
      return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
    } catch (e) { return "light"; }
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    try { localStorage.setItem(STORAGE_KEY, theme); } catch (e) {}
    var icon = theme === "dark" ? "&#9790;" : "&#9728;";
    var label = theme === "dark" ? "Dark" : "Light";
    var btn = document.getElementById("themeToggleBtn");
    if (btn) {
      btn.setAttribute("aria-label", theme === "dark" ? "Switch to light mode" : "Switch to dark mode");
      btn.innerHTML = icon + " " + '<span class="theme-toggle-label">' + label + "</span>";
    }
    var loginBtn = document.getElementById("loginThemeBtn");
    if (loginBtn) loginBtn.innerHTML = icon + " " + label;
  }

  function toggle() {
    var current = getTheme();
    applyTheme(current === "dark" ? "light" : "dark");
  }

  // Apply immediately (may have already been done by inline head script, but idempotent)
  applyTheme(getTheme());

  // Wire up button once DOM is ready
  function wireBtn() {
    var btn = document.getElementById("themeToggleBtn");
    if (btn && !btn._themeWired) {
      btn._themeWired = true;
      btn.addEventListener("click", toggle);
    }
    var loginBtn = document.getElementById("loginThemeBtn");
    if (loginBtn && !loginBtn._themeWired) {
      loginBtn._themeWired = true;
      loginBtn.addEventListener("click", toggle);
    }
    applyTheme(getTheme()); // re-apply to update labels
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", wireBtn);
  } else {
    wireBtn();
  }

  // Expose for inline onclick usage
  window.toggleTheme = toggle;
})();
