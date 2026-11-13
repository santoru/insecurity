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

    // Solid navbar + scroll-to-top button once the navbar leaves the dark header.
    // Content marked [data-overlaps-header] (home "Latest post" card, about stats) ends the dark area early.
    var nav = document.getElementById('mainNav');
    var header = document.querySelector('.intro-header');
    var btn = document.getElementById('scrollTop');
    if (!nav || !header) return;
    var overlap = document.querySelector('[data-overlaps-header]');
    var raf;

    function update() {
        var darkEnd = header.offsetTop + header.offsetHeight;
        if (overlap) darkEnd = Math.min(darkEnd, overlap.getBoundingClientRect().top + window.scrollY);
        var scrolled = window.scrollY > darkEnd - nav.offsetHeight;
        nav.classList.toggle('nav-scrolled', scrolled);
        if (btn) btn.classList.toggle('visible', scrolled);
    }

    window.addEventListener('scroll', function () {
        if (!raf) raf = requestAnimationFrame(function () { update(); raf = null; });
    }, { passive: true });
    update();

    if (btn) {
        btn.addEventListener('click', function (e) {
            e.preventDefault();
            window.scrollTo({ top: 0 }); // smoothness comes from CSS scroll-behavior (respects reduced motion)
        });
    }
})();
