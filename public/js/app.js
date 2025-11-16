// app.js
// client-side javascript for ZTS

// generate a simple device fingerprint
function getFingerprint() {
    var parts = [];
    parts.push(navigator.userAgent);
    parts.push(screen.width + 'x' + screen.height);
    parts.push(screen.colorDepth);
    parts.push(new Date().getTimezoneOffset());
    parts.push(navigator.language);
    parts.push(navigator.platform);

    var hash = 0;
    var str = parts.join('|');
    for (var i = 0; i < str.length; i++) {
        var char = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash;
    }
    return 'fp-' + Math.abs(hash).toString(16);
}

// format a UTC date to readable form
function formatDate(dateStr) {
    if (!dateStr) return '-';
    var d = new Date(dateStr);
    var day = String(d.getDate()).padStart(2, '0');
    var months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    var month = months[d.getMonth()];
    var year = d.getFullYear();
    var hours = String(d.getHours()).padStart(2, '0');
    var mins = String(d.getMinutes()).padStart(2, '0');
    return day + ' ' + month + ' ' + year + ', ' + hours + ':' + mins;
}

// send POST request
async function postJSON(url, data) {
    var response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    });
    return response.json();
}

// mobile sidebar toggle
function setupMobileMenu() {
    var navbar = document.querySelector('.navbar');
    var sidebar = document.querySelector('.sidebar');
    if (!navbar || !sidebar) return;

    // add hamburger button if not already there
    if (!document.querySelector('.menu-toggle')) {
        var btn = document.createElement('button');
        btn.className = 'menu-toggle';
        btn.textContent = 'Menu';
        btn.setAttribute('aria-label', 'Toggle menu');
        navbar.insertBefore(btn, navbar.firstChild.nextSibling || navbar.firstChild);
    }

    // add overlay
    var overlay = document.createElement('div');
    overlay.className = 'sidebar-overlay';
    document.body.appendChild(overlay);

    var toggle = document.querySelector('.menu-toggle');

    toggle.addEventListener('click', function () {
        sidebar.classList.toggle('open');
        overlay.classList.toggle('show');
    });

    overlay.addEventListener('click', function () {
        sidebar.classList.remove('open');
        overlay.classList.remove('show');
    });

    // close sidebar when a link is clicked (mobile)
    sidebar.addEventListener('click', function (e) {
        if (e.target.tagName === 'A') {
            sidebar.classList.remove('open');
            overlay.classList.remove('show');
        }
    });
}

// run when DOM ready
document.addEventListener('DOMContentLoaded', setupMobileMenu);
