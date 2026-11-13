// (in)security — site behaviour. Loaded with `defer` on every page.
(function () {
    // Mobile navbar toggle
    var toggler = document.querySelector('.navbar-toggler');
    var menu = toggler && document.getElementById(toggler.getAttribute('aria-controls'));
    if (menu) {
        toggler.addEventListener('click', function () {
            toggler.setAttribute('aria-expanded', menu.classList.toggle('show') ? 'true' : 'false');
        });
    }

    // Light/dark toggle. No saved choice = follow the system; the <head> script applies a saved one before paint.
    var root = document.documentElement;
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

    // Solid navbar + scroll-to-top button once the navbar leaves the dark header.
    // Content marked [data-overlaps-header] (home "Latest post" card, about stats) ends the dark area early.
    var nav = document.getElementById('mainNav');
    var header = document.querySelector('.intro-header');
    var btn = document.getElementById('scrollTop');
    if (!nav || !header) return;
    var overlap = document.querySelector('[data-overlaps-header]');
    var raf;

    // Below 992px the hero text runs under the navbar, so go solid as soon as the page scrolls.
    var compact = window.matchMedia('(max-width: 991.98px)');

    function update() {
        var darkEnd = header.offsetTop + header.offsetHeight;
        if (overlap) darkEnd = Math.min(darkEnd, overlap.getBoundingClientRect().top + window.scrollY);
        var pastDark = window.scrollY > darkEnd - nav.offsetHeight;
        nav.classList.toggle('nav-scrolled', compact.matches ? window.scrollY > 0 : pastDark);
        if (btn) btn.classList.toggle('visible', pastDark);
    }

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
