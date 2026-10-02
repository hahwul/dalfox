document.addEventListener('DOMContentLoaded', function() {
    const toc = document.querySelector('.docs-toc');
    if (!toc) return;

    const links = toc.querySelectorAll('a');
    if (links.length === 0) return;

    // Retrieve all headers inside the article that have an ID
    const headings = Array.from(document.querySelectorAll('.docs-article h2, .docs-article h3'))
        .filter(h => h.id);

    if (headings.length === 0) return;

    let activeLink = null;
    const headerHeight = 100; // Offset to account for fixed header + padding

    function getActiveHeading() {
        const scrollPosition = window.scrollY + headerHeight;

        // 1. If we are close to the top of the page, active first heading
        if (window.scrollY < 80) {
            return headings[0];
        }

        // 2. If we are close to the bottom of the page, active last heading
        if ((window.innerHeight + window.scrollY) >= document.documentElement.scrollHeight - 50) {
            return headings[headings.length - 1];
        }

        // 3. Find the heading that is closest to the top of the viewport but above the threshold
        for (let i = headings.length - 1; i >= 0; i--) {
            if (headings[i].offsetTop <= scrollPosition) {
                return headings[i];
            }
        }
        
        return headings[0];
    }

    function updateActiveState() {
        const currentHeading = getActiveHeading();
        if (!currentHeading) return;

        const id = currentHeading.id;
        links.forEach(link => {
            const href = link.getAttribute('href');
            // Support both direct matching and url-decoded matching
            if (href === '#' + id || href === decodeURIComponent('#' + id)) {
                if (activeLink !== link) {
                    if (activeLink) {
                        activeLink.classList.remove('active');
                        activeLink.parentElement.classList.remove('active');
                    }
                    link.classList.add('active');
                    link.parentElement.classList.add('active');
                    activeLink = link;

                    // Automatically scroll the TOC container if the active item is not fully visible
                    const tocContent = toc.querySelector('.toc-content');
                    if (tocContent) {
                        const linkRect = link.getBoundingClientRect();
                        const containerRect = tocContent.getBoundingClientRect();
                        
                        if (linkRect.top < containerRect.top) {
                            tocContent.scrollTop -= (containerRect.top - linkRect.top) + 10;
                        } else if (linkRect.bottom > containerRect.bottom) {
                            tocContent.scrollTop += (linkRect.bottom - containerRect.bottom) + 10;
                        }
                    }
                }
            }
        });
    }

    // Scroll listener with passive flag for better performance
    window.addEventListener('scroll', updateActiveState, { passive: true });
    
    // Run initially
    updateActiveState();

    // Re-run on layout change/images loaded
    window.addEventListener('load', updateActiveState);
});
