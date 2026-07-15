(function () {
  "use strict";

  // Mobile menu
  var toggle = document.querySelector(".nav-toggle");
  var links = document.querySelector(".nav-links");
  if (toggle && links) {
    toggle.addEventListener("click", function () {
      var open = links.style.display === "flex";
      links.style.display = open ? "" : "flex";
      links.style.flexDirection = "column";
      links.style.position = "absolute";
      links.style.top = "64px";
      links.style.left = "0";
      links.style.right = "0";
      links.style.background = "var(--paper)";
      links.style.padding = "16px 24px";
      links.style.borderBottom = "1px solid var(--line)";
      toggle.setAttribute("aria-expanded", String(!open));
    });
  }

  // Fade sections into view on scroll
  var revealTargets = document.querySelectorAll(".reveal");
  if ("IntersectionObserver" in window && revealTargets.length) {
    var observer = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            entry.target.classList.add("is-visible");
            observer.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.15 }
    );
    revealTargets.forEach(function (el) {
      observer.observe(el);
    });
  } else {
    revealTargets.forEach(function (el) {
      el.classList.add("is-visible");
    });
  }

  // A small "live" status console detail in the hero (purely cosmetic,
  // doesn't call out anywhere).
  var deployEl = document.querySelector("[data-deploy-ago]");
  if (deployEl) {
    var startMinutes = parseInt(deployEl.getAttribute("data-deploy-ago"), 10) || 3;
    var minutes = startMinutes;
    setInterval(function () {
      minutes += 1;
      deployEl.textContent = minutes + "m ago";
    }, 60000);
  }

  var yearEl = document.querySelector("[data-current-year]");
  if (yearEl) {
    yearEl.textContent = String(new Date().getFullYear());
  }
})();
