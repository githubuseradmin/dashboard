/* Small progressive-enhancement helpers. The app is fully usable without JS;
   this only adds the theme toggle, the user menu and an HTMX CSRF header. */
(function () {
  "use strict";

  var STORAGE_KEY = "dashboard-theme";

  /* ---- Theme (light/dark) ---- */
  function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
  }

  // Restore the saved theme as early as possible.
  try {
    var saved = localStorage.getItem(STORAGE_KEY);
    if (saved) applyTheme(saved);
  } catch (e) {
    /* localStorage may be unavailable (private mode); ignore. */
  }

  window.toggleTheme = function () {
    var current = document.documentElement.getAttribute("data-theme") || "light";
    var next = current === "light" ? "dark" : "light";
    applyTheme(next);
    try {
      localStorage.setItem(STORAGE_KEY, next);
    } catch (e) {
      /* ignore persistence failures */
    }
  };

  /* ---- User menu dropdown ---- */
  window.toggleMenu = function (event) {
    event.stopPropagation();
    var menu = document.getElementById("usermenu");
    if (menu) menu.classList.toggle("is-open");
  };

  // Close the menu when clicking elsewhere.
  document.addEventListener("click", function () {
    var menu = document.getElementById("usermenu");
    if (menu) menu.classList.remove("is-open");
  });

  /* ---- HTMX: attach the CSRF token to every request ---- */
  document.body.addEventListener("htmx:configRequest", function (evt) {
    var meta = document.querySelector('input[name="csrf_token"]');
    if (meta) {
      evt.detail.headers["X-CSRFToken"] = meta.value;
    }
  });

  /* ---- Close the mobile sidebar after navigating ---- */
  document.body.addEventListener("htmx:afterSwap", function () {
    document.body.classList.remove("sidebar-open");
  });
})();
