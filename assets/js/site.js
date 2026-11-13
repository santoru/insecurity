// (in)security — site behaviour. Loaded with `defer` on every page.
(function () {
    var root = document.documentElement;
    var nav = document.getElementById('mainNav');
    var header = document.querySelector('.intro-header');
    var btn = document.getElementById('scrollTop');
    // Content marked [data-overlaps-header] (home "Latest post" card, about stats) ends the dark area early.
    var overlap = document.querySelector('[data-overlaps-header]');
    // Below 992px the hero text runs under the navbar, so it goes solid as soon as the page scrolls.
    var compact = window.matchMedia('(max-width: 991.98px)');
    var toggler = document.querySelector('.navbar-toggler');
    var menu = toggler && document.getElementById(toggler.getAttribute('aria-controls'));
    var menuOpen = false;

    // Solid navbar once it leaves the dark header, or while the mobile menu is open
    function update() {
        if (!nav || !header) return;
        var darkEnd = header.offsetTop + header.offsetHeight;
        if (overlap) darkEnd = Math.min(darkEnd, overlap.getBoundingClientRect().top + window.scrollY);
        var pastDark = window.scrollY > darkEnd - nav.offsetHeight;
        nav.classList.toggle('nav-scrolled', menuOpen || (compact.matches ? window.scrollY > 0 : pastDark));
        if (btn) btn.classList.toggle('visible', pastDark);
    }

    // Mobile menu: animated open/close (CSS), hamburger <-> X, Esc closes
    function setMenu(open) {
        menuOpen = open;
        menu.classList.toggle('show', open);
        toggler.setAttribute('aria-expanded', open ? 'true' : 'false');
        toggler.setAttribute('aria-label', open ? 'Close menu' : 'Open menu');
        update();
    }
    if (menu) {
        toggler.addEventListener('click', function () { setMenu(!menuOpen); });
        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape' && menuOpen) { setMenu(false); toggler.focus(); }
        });
        if (compact.addEventListener) compact.addEventListener('change', function () { if (!compact.matches && menuOpen) setMenu(false); });
    }

    // Light/dark toggle. No saved choice = follow the system; the <head> script applies a saved one before paint.
    var prefersDark = window.matchMedia('(prefers-color-scheme: dark)');
    function theme() { return root.getAttribute('data-theme') || (prefersDark.matches ? 'dark' : 'light'); }
    document.querySelectorAll('.theme-toggle').forEach(function (b) {
        function label() { b.setAttribute('aria-label', theme() === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'); }
        b.addEventListener('click', function () {
            var next = theme() === 'dark' ? 'light' : 'dark';
            root.setAttribute('data-theme', next);
            try { localStorage.setItem('theme', next); } catch (e) {}
            label();
        });
        if (prefersDark.addEventListener) prefersDark.addEventListener('change', label);
        label();
    });

    if (!nav || !header) return;
    var raf;
    window.addEventListener('scroll', function () {
        if (!raf) raf = requestAnimationFrame(function () { update(); raf = null; });
    }, { passive: true });
    window.addEventListener('resize', update);
    update();

    if (btn) {
        btn.addEventListener('click', function (e) {
            e.preventDefault();
            window.scrollTo({ top: 0 }); // smoothness comes from CSS scroll-behavior (respects reduced motion)
        });
    }
})();
