// app.js
// client-side javascript for ZTS

// show a toast notification (success, error, or info)
// replaces the old browser alert() dialogs
function showToast(message, type) {
    type = type || 'info';

    // remove any existing toast
    var old = document.querySelector('.toast');
    if (old) old.remove();

    var toast = document.createElement('div');
    toast.className = 'toast toast-' + type;
    toast.textContent = message;
    document.body.appendChild(toast);

    // trigger animation
    setTimeout(function () { toast.classList.add('show'); }, 10);

    // auto-hide after 3.5 seconds
    setTimeout(function () {
        toast.classList.remove('show');
        setTimeout(function () { toast.remove(); }, 300);
    }, 3500);
}

// generate a  device fingerprint
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

// build horizontal navbar
function buildNavbar(role, activePage, username) {
    var nav = document.getElementById('mainNav');
    if (!nav) return;

    var html = '';

    // Dashboard - direct link
    html += '<div class="nav-item' + (activePage === 'dashboard' ? ' active' : '') + '">';
    html += '<a href="/dashboard" class="nav-link' + (activePage === 'dashboard' ? ' active' : '') + '">Dashboard</a>';
    html += '</div>';

    // Network dropdown
    var networkActive = (activePage === 'network') ? ' active' : '';
    html += '<div class="nav-item' + networkActive + '">';
    html += '<button class="nav-link' + networkActive + '" onclick="toggleDropdown(this)">Network <span class="arrow">▾</span></button>';
    html += '<div class="dropdown-menu">';
    html += '<a href="/network"' + (activePage === 'network' ? ' class="active"' : '') + '>IP Rule</a>';
    html += '</div>';
    html += '</div>';

    // Mapping dropdown (SuperAdmin only)
    if (role === 'SuperAdmin') {
        var mappingActive = (activePage === 'mapping' || activePage === 'register-device' || activePage === 'live-monitoring') ? ' active' : '';
        html += '<div class="nav-item' + mappingActive + '">';
        html += '<button class="nav-link' + mappingActive + '" onclick="toggleDropdown(this)">Mapping <span class="arrow">▾</span></button>';
        html += '<div class="dropdown-menu">';
        html += '<a href="/mapping"' + (activePage === 'mapping' ? ' class="active"' : '') + '>User Management</a>';
        html += '<a href="/register-device"' + (activePage === 'register-device' ? ' class="active"' : '') + '>Register Device</a>';
        html += '</div>';
        html += '</div>';

        // Live Monitoring - separate nav item for SuperAdmin
        var monActive = (activePage === 'live-monitoring') ? ' active' : '';
        html += '<div class="nav-item' + monActive + '">';
        html += '<a href="/admin/live-monitoring" class="nav-link' + monActive + '" style="display:flex;align-items:center;gap:5px;">';
        html += '<span style="display:inline-block;width:7px;height:7px;border-radius:50%;background:#22c55e;animation:pulse-nav 1.5s infinite;"></span>';
        html += 'Live Monitor</a>';
        html += '</div>';
    }

    // Security dropdown
    var securityActive = (activePage === 'risk') ? ' active' : '';
    html += '<div class="nav-item' + securityActive + '">';
    html += '<button class="nav-link' + securityActive + '" onclick="toggleDropdown(this)">Security <span class="arrow">▾</span></button>';
    html += '<div class="dropdown-menu">';
    html += '<a href="/risk"' + (activePage === 'risk' ? ' class="active"' : '') + '>Risk Score</a>';
    html += '</div>';
    html += '</div>';

    nav.innerHTML = html;

    // build user menu
    var userMenu = document.getElementById('userMenu');
    if (userMenu) {
        var initial = username ? username.charAt(0).toUpperCase() : '?';
        var userHtml = '';
        userHtml += '<button class="user-menu-btn" onclick="toggleUserMenu(this)">';
        userHtml += '<div class="user-avatar">' + initial + '</div>';
        userHtml += '<span>' + username + '</span>';
        userHtml += '<span class="arrow">▾</span>';
        userHtml += '</button>';
        userHtml += '<div class="dropdown-menu">';
        userHtml += '<a href="/profile"' + (activePage === 'profile' ? ' class="active"' : '') + '>Profile</a>';
        userHtml += '<div class="dropdown-divider"></div>';
        userHtml += '<a href="/logout" style="color:#e74c3c;">Logout</a>';
        userHtml += '</div>';
        userMenu.innerHTML = userHtml;
    }
}

// toggle dropdown open/close
function toggleDropdown(btn) {
    var item = btn.closest('.nav-item');
    var wasOpen = item.classList.contains('open');

    // close all dropdowns
    document.querySelectorAll('.nav-item.open').forEach(function (el) {
        el.classList.remove('open');
    });
    document.querySelectorAll('.user-menu.open').forEach(function (el) {
        el.classList.remove('open');
    });

    if (!wasOpen) {
        item.classList.add('open');
    }
}

// toggle user menu
function toggleUserMenu(btn) {
    var menu = btn.closest('.user-menu');
    var wasOpen = menu.classList.contains('open');

    // close all
    document.querySelectorAll('.nav-item.open').forEach(function (el) {
        el.classList.remove('open');
    });
    document.querySelectorAll('.user-menu.open').forEach(function (el) {
        el.classList.remove('open');
    });

    if (!wasOpen) {
        menu.classList.add('open');
    }
}

// close dropdowns when clicking outside
document.addEventListener('click', function (e) {
    if (!e.target.closest('.nav-item') && !e.target.closest('.user-menu')) {
        document.querySelectorAll('.nav-item.open').forEach(function (el) {
            el.classList.remove('open');
        });
        document.querySelectorAll('.user-menu.open').forEach(function (el) {
            el.classList.remove('open');
        });
    }
});

// mobile menu toggle
document.addEventListener('DOMContentLoaded', function () {
    var toggle = document.querySelector('.menu-toggle');
    var navMenu = document.querySelector('.nav-menu');
    if (toggle && navMenu) {
        toggle.addEventListener('click', function () {
            navMenu.classList.toggle('open');
        });
    }
});
