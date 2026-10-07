(function () {
  "use strict";

  // Light/dark theme only; follows the system setting until the user picks one. Nothing is stored.
  const root = document.documentElement;
  const media = typeof window.matchMedia === "function" ? window.matchMedia("(prefers-color-scheme: dark)") : null;
  let chosen = false;

  function current() {
    return root.getAttribute("data-theme") === "dark" ? "dark" : "light";
  }

  function sync() {
    const button = document.getElementById("theme-toggle");
    if (!button) return;
    const next = current() === "dark" ? "light" : "dark";
    button.setAttribute("aria-label", "Switch to " + next + " theme");
    button.title = "Switch to " + next + " theme";
  }

  function apply(theme) {
    root.setAttribute("data-theme", theme);
    sync();
  }

  apply(media && media.matches ? "dark" : "light");

  if (media) {
    const follow = function (event) { if (!chosen) apply(event.matches ? "dark" : "light"); };
    if (typeof media.addEventListener === "function") media.addEventListener("change", follow);
    else if (typeof media.addListener === "function") media.addListener(follow);
  }

  document.addEventListener("DOMContentLoaded", function () {
    const button = document.getElementById("theme-toggle");
    if (!button) return;
    sync();
    button.addEventListener("click", function () {
      chosen = true;
      apply(current() === "dark" ? "light" : "dark");
    });
  });
})();
