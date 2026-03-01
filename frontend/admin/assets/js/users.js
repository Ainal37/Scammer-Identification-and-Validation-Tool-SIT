/* users.js – Users management page */
(function () {
  if (!getToken()) { window.location.href = "login.html"; return; }

  var searchInput = document.getElementById("searchInput");
  var roleFilter = document.getElementById("roleFilter");
  var statusFilter = document.getElementById("statusFilter");
  var usersBody = document.getElementById("usersBody");
  var debounceTimer = null;

  function setStatus(msg) {
    var el = document.getElementById("liveStatus");
    if (el) el.textContent = msg;
  }

  async function loadUsers() {
    try {
      var q = "?limit=100";
      var s = searchInput ? searchInput.value.trim() : "";
      var r = roleFilter ? roleFilter.value : "";
      var st = statusFilter ? statusFilter.value : "";
      if (s) q += "&search=" + encodeURIComponent(s);
      if (r) q += "&role=" + encodeURIComponent(r);
      if (st) q += "&status=" + encodeURIComponent(st);

      var res = await authFetch("/users" + q);
      if (!res) return;
      var list = await res.json();
      renderUsers(list);
      setStatus("Loaded " + list.length + " user(s)");
    } catch (e) { setStatus("Failed to load users"); }
  }

  function renderUsers(list) {
    if (!list || list.length === 0) {
      usersBody.innerHTML = '<tr><td colspan="7" class="text-center text-muted" style="padding:20px">No users found</td></tr>';
      return;
    }
    usersBody.innerHTML = list.map(function (u) {
      return '<tr>' +
        '<td>' + u.id + '</td>' +
        '<td style="font-weight:500">' + esc(u.full_name) + '</td>' +
        '<td>' + esc(u.email) + '</td>' +
        '<td><span class="badge ' + u.role + '">' + u.role + '</span></td>' +
        '<td><span class="badge ' + u.status + '">' + u.status + '</span></td>' +
        '<td class="text-muted" style="font-size:11px">' + (u.last_login_at || 'Never') + '</td>' +
        '<td>' +
          '<select onchange="updateUserStatus(' + u.id + ', this.value)" style="padding:4px 8px;font-size:11px;border:1px solid var(--border);border-radius:4px">' +
            '<option value="">Change...</option>' +
            '<option value="active"' + (u.status === "active" ? " selected" : "") + '>Active</option>' +
            '<option value="inactive"' + (u.status === "inactive" ? " selected" : "") + '>Inactive</option>' +
            '<option value="suspended"' + (u.status === "suspended" ? " selected" : "") + '>Suspended</option>' +
          '</select>' +
        '</td></tr>';
    }).join("");
  }

  function esc(s) { if (!s) return ""; var d = document.createElement("div"); d.textContent = s; return d.innerHTML; }

  window.updateUserStatus = async function (id, newStatus) {
    if (!newStatus) return;
    try {
      var res = await authFetch("/users/" + id, {
        method: "PATCH",
        body: JSON.stringify({ status: newStatus }),
      });
      if (res && res.ok) {
        showToast("User status updated", "success");
        loadUsers();
      } else {
        var d = await res.json();
        showToast(d.detail || "Update failed", "error");
      }
    } catch (e) { showToast("Error updating user", "error"); }
  };

  window.submitAddUserPage = async function () {
    var name = document.getElementById("aup_name").value.trim();
    var email = document.getElementById("aup_email").value.trim();
    var role = document.getElementById("aup_role").value;
    var status = document.getElementById("aup_status").value;
    if (!name || !email) { showToast("Name and email required", "error"); return; }
    try {
      var res = await authFetch("/users", {
        method: "POST",
        body: JSON.stringify({ full_name: name, email: email, role: role, status: status }),
      });
      if (!res) return;
      if (res.ok) {
        showToast("User created!", "success");
        closeModal("addUserModalPage");
        document.getElementById("aup_name").value = "";
        document.getElementById("aup_email").value = "";
        loadUsers();
      } else {
        var d = await res.json();
        showToast(d.detail || "Failed to create user", "error");
      }
    } catch (e) { showToast("Error creating user", "error"); }
  };

  // Event listeners
  if (searchInput) {
    searchInput.addEventListener("input", function () {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(loadUsers, 500);
    });
  }
  if (roleFilter) roleFilter.addEventListener("change", loadUsers);
  if (statusFilter) statusFilter.addEventListener("change", loadUsers);

  loadUsers();
})();
