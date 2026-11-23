(() => {
  document.addEventListener("click", async (event) => {
    const copyBtn = event.target.closest("[data-copy-url]");
    if (copyBtn) {
      const target = copyBtn.getAttribute("data-copy-url");
      const fullUrl = target.startsWith("http") ? target : new URL(target, window.location.origin).toString();
      try {
        await navigator.clipboard.writeText(fullUrl);
        if (!copyBtn.dataset.origLabel) copyBtn.dataset.origLabel = copyBtn.textContent;
        copyBtn.textContent = "Copied";
        clearTimeout(copyBtn._copyTimer);
        copyBtn._copyTimer = setTimeout(() => { copyBtn.textContent = copyBtn.dataset.origLabel; }, 1500);
      } catch {
        window.prompt("Copy link:", fullUrl);
      }
      return;
    }

    const fsBtn = event.target.closest("[data-fullscreen-target]");
    if (fsBtn) {
      const el = document.getElementById(fsBtn.getAttribute("data-fullscreen-target"));
      if (el && el.requestFullscreen) {
        try { await el.requestFullscreen(); } catch {}
      }
    }
  });
})();
