(function() {
    var toc = document.getElementById('markdown-toc');
    if (!toc || window.innerWidth < 992) return;

    var sidebar = document.getElementById('toc-sidebar');
    var nav = document.getElementById('toc-sidebar-nav');
    var closeBtn = document.getElementById('toc-sidebar-close');
    var active = false;

    // Clone TOC into sidebar
    var clone = toc.cloneNode(true);
    clone.id = 'sidebar-toc';
    nav.appendChild(clone);

    // Add pin button inside inline TOC
    var openBtn = document.createElement('button');
    openBtn.className = 'toc-inline-toggle';
    openBtn.title = 'Pin TOC to sidebar';
    openBtn.setAttribute('aria-label', 'Pin TOC to sidebar');
    openBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-panel-left-icon lucide-panel-left"><rect width="18" height="18" x="3" y="3" rx="2"/><path d="M9 3v18"/></svg>';
    toc.insertBefore(openBtn, toc.firstChild);

    // Collect heading targets from sidebar TOC links
    var links = clone.querySelectorAll('a');
    var sections = [];
    links.forEach(function(a) {
        var id = a.getAttribute('href');
        if (id && id.startsWith('#')) {
            var el = document.getElementById(id.slice(1));
            if (el) sections.push({ link: a, target: el });
        }
    });

    function openSidebar() {
        active = true;
        sidebar.classList.add('open');
        document.body.classList.add('toc-sidebar-open');
        toc.style.display = 'none';
        positionSidebar();
        highlightCurrent();
    }

    function closeSidebar() {
        active = false;
        sidebar.classList.remove('open');
        document.body.classList.remove('toc-sidebar-open');
        toc.style.display = '';
    }

    openBtn.addEventListener('click', openSidebar);
    closeBtn.addEventListener('click', closeSidebar);

    function positionSidebar() {
        var navbar = document.getElementById('mainNav');
        var header = document.querySelector('.intro-header');
        if (!navbar || !header) return;
        var navH = navbar.offsetHeight;
        var headerBottom = header.offsetTop + header.offsetHeight;
        var top = Math.max(navH, headerBottom - window.scrollY);
        sidebar.style.top = top + 'px';
        sidebar.style.height = 'calc(100vh - ' + top + 'px)';
    }

    function highlightCurrent() {
        if (!active) return;
        var scrollPos = window.scrollY + 120;
        var current = null;
        for (var i = 0; i < sections.length; i++) {
            if (sections[i].target.offsetTop <= scrollPos) current = sections[i];
        }
        links.forEach(function(a) { a.classList.remove('toc-active'); });
        if (current) current.link.classList.add('toc-active');
    }

    var raf;
    window.addEventListener('scroll', function() {
        if (raf) return;
        raf = requestAnimationFrame(function() {
            if (active) { positionSidebar(); highlightCurrent(); }
            raf = null;
        });
    });
})();
