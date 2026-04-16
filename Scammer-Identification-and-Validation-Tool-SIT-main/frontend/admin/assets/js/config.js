// Global frontend config. Define API_BASE once here.
(function () {
  if (!window.API_BASE || typeof window.API_BASE !== "string") {
    window.API_BASE = "http://127.0.0.1:8001";
  }
})();
