// Pilihan manual disimpan di browser; tanpa pilihan, ikuti tema sistem.
(function() {
    const storageKey = "bkn_kredensial_theme";
    const button = document.getElementById("themeToggle");
    const label = document.getElementById("themeLabel");
    const systemTheme = window.matchMedia("(prefers-color-scheme: dark)");

    function savedTheme() {
        try {
            const value = localStorage.getItem(storageKey);
            return value === "dark" || value === "light" ? value : null;
        } catch (_) {
            return null;
        }
    }

    function applyTheme(theme) {
        const isDark = theme === "dark";
        document.documentElement.dataset.theme = isDark ? "dark" : "light";
        button.setAttribute("aria-pressed", String(isDark));
        label.textContent = isDark ? "Tema: Gelap" : "Tema: Terang";
        button.title = isDark ? "Ganti ke tema terang" : "Ganti ke tema gelap";
    }

    let manualTheme = savedTheme();
    applyTheme(manualTheme || (systemTheme.matches ? "dark" : "light"));

    button.addEventListener("click", function() {
        const nextTheme = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
        manualTheme = nextTheme;
        try {
            localStorage.setItem(storageKey, nextTheme);
        } catch (_) {
            /* Pilihan tetap berlaku pada tab ini. */
        }
        applyTheme(nextTheme);
    });

    systemTheme.addEventListener("change", function(event) {
        if (!manualTheme) applyTheme(event.matches ? "dark" : "light");
    });

    window.addEventListener("storage", function(event) {
        if (event.key === storageKey) {
            manualTheme = savedTheme();
            applyTheme(manualTheme || (systemTheme.matches ? "dark" : "light"));
        }
    });
})();
