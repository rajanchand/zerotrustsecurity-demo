// shared helpers for all ZTS pages

// Show a small notification message
function showToast(message, type) {
    if (!type) type = 'info';
    var existing = document.querySelector('.toast');
    if (existing) existing.remove();

    var toast = document.createElement('div');
    toast.className = 'toast toast-' + type;
    toast.textContent = message;
    document.body.appendChild(toast);

    setTimeout(function() { toast.classList.add('show'); }, 10);
    setTimeout(function() {
        toast.classList.remove('show');
        setTimeout(function() { toast.remove(); }, 300);
    }, 3500);
}

// Get a simple device fingerprint
function getFingerprint() {
    var parts = [
        navigator.userAgent,
        screen.width + 'x' + screen.height,
        screen.colorDepth,
        new Date().getTimezoneOffset(),
        navigator.language,
        navigator.platform
    ];
    var str = parts.join('|');
    var hash = 0;
    for (var i = 0; i < str.length; i++) {
        hash = ((hash << 5) - hash) + str.charCodeAt(i);
        hash |= 0;
    }
    return 'fp-' + Math.abs(hash).toString(16);
}

// Format a date nicely
function formatDate(dateStr) {
    if (!dateStr) return '-';
    var d = new Date(dateStr);
    var day = String(d.getDate()).padStart(2, '0');
    var months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    var time = String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0');
    return day + ' ' + months[d.getMonth()] + ' ' + d.getFullYear() + ', ' + time;
}

// Show a JSON value as readable text
function renderJSON(val) {
    if (val === null || val === undefined) return '-';
    if (typeof val !== 'object') return val;
    try {
        if (Object.keys(val).length === 0) return '{}';
        if (val.reason) return val.reason;
        if (val.message) return val.message;
        if (val.action) return val.action;
        var parts = [];
        for (var key in val) {
            parts.push(key + ': ' + (typeof val[key] === 'object' ? '(...)' : val[key]));
            if (parts.length > 2) break;
        }
        return parts.join(', ');
    } catch (e) {
        return '[Object]';
    }
}

var csrfToken = '';

// Get CSRF token from server
function fetchCSRFToken() {
    fetch('/api/csrf-token').then(function(res) {
        return res.json();
    }).then(function(data) {
        if (data.csrfToken) csrfToken = data.csrfToken;
    }).catch(function() {});
}
fetchCSRFToken();

// Send POST request with JSON data
async function postJSON(url, data) {
    var headers = { 'Content-Type': 'application/json' };
    if (csrfToken) headers['X-CSRF-Token'] = csrfToken;

    try {
        var response = await fetch(url, {
            method: 'POST',
            headers: headers,
            body: JSON.stringify(data)
        });

        if (response.status === 401 && url !== '/api/verify-reauth') {
            return { requireReAuth: true, success: false, message: 'Please confirm your password' };
        }

        if (response.status === 403) {
            var err = {};
            try { err = await response.json(); } catch(e) { err = { message: 'Access denied' }; }
            return { requireReAuth: !!err.requireReAuth, success: false, message: err.message || 'Access denied' };
        }

        var contentType = response.headers.get('content-type');
        if (contentType && contentType.indexOf('application/json') >= 0) {
            return await response.json();
        }

        return { success: response.ok, message: response.ok ? 'OK' : 'Server error (' + response.status + ')' };
    } catch (e) {
        return { success: false, message: 'Could not connect to the server' };
    }
}

// Build the navigation bar
function buildNavbar(role, activePage, username) {
    var nav = document.getElementById('mainNav');
    if (!nav) return;

    var html = '';

    // Dashboard - everyone
    html += '<div class="nav-item ' + (activePage === 'dashboard' ? 'active' : '') + '">';
    html += '<a href="/dashboard" class="nav-link">Dashboard</a></div>';

    // Roles - everyone
    html += '<div class="nav-item ' + (activePage === 'portal' ? 'active' : '') + '">';
    html += '<a href="/portal" class="nav-link">Roles</a></div>';

    // Network - SuperAdmin, IT only
    if (role === 'SuperAdmin' || role === 'IT') {
        html += '<div class="nav-item ' + (activePage === 'network' ? 'active' : '') + '">';
        html += '<a href="/network" class="nav-link">Network</a></div>';
    }

    // Mapping - SuperAdmin, IT, HR
    if (role === 'SuperAdmin' || role === 'IT' || role === 'HR') {
        var mappingActive = (activePage === 'mapping' || activePage === 'register-device' || activePage === 'user-access');
        html += '<div class="nav-item ' + (mappingActive ? 'active' : '') + '">';
        html += '<button class="nav-link" onclick="toggleDropdown(this)">Mapping <span class="arrow">&#9662;</span></button>';
        html += '<div class="dropdown-menu">';
        html += '<a href="/mapping" ' + (activePage === 'mapping' ? 'class="active"' : '') + '>Users</a>';
        if (role === 'SuperAdmin') {
            html += '<a href="/admin/user-access" ' + (activePage === 'user-access' ? 'class="active"' : '') + '>Permissions</a>';
        }
        if (role !== 'HR') {
            html += '<a href="/register-device" ' + (activePage === 'register-device' ? 'class="active"' : '') + '>Devices</a>';
        }
        html += '</div></div>';
    }

    // Live Monitor - SuperAdmin, IT
    if (role === 'SuperAdmin' || role === 'IT') {
        html += '<div class="nav-item ' + (activePage === 'live-monitoring' ? 'active' : '') + '">';
        html += '<a href="/admin/live-monitoring" class="nav-link">Live Monitor</a></div>';
    }

    // Analytics - SuperAdmin, IT
    if (role === 'SuperAdmin' || role === 'IT') {
        html += '<div class="nav-item ' + (activePage === 'remote-analytics' ? 'active' : '') + '">';
        html += '<a href="/admin/remote-analytics" class="nav-link">Analytics</a></div>';
    }

    // Security - everyone
    var secActive = (activePage === 'risk' || activePage === 'user-log');
    html += '<div class="nav-item ' + (secActive ? 'active' : '') + '">';
    html += '<button class="nav-link" onclick="toggleDropdown(this)">Security <span class="arrow">&#9662;</span></button>';
    html += '<div class="dropdown-menu">';
    html += '<a href="/risk" ' + (activePage === 'risk' ? 'class="active"' : '') + '>Risk Score</a>';
    if (role === 'SuperAdmin') {
        html += '<a href="/admin/user-log" ' + (activePage === 'user-log' ? 'class="active"' : '') + '>Activity Logs</a>';
    }
    html += '</div></div>';

    nav.innerHTML = html;

    // User menu
    var userMenu = document.getElementById('userMenu');
    if (userMenu) {
        var initial = username ? username.charAt(0).toUpperCase() : '?';
        userMenu.innerHTML = '<button class="user-menu-btn" onclick="toggleUserMenu(this)">' +
            '<div class="user-avatar">' + initial + '</div>' +
            '<span>' + username + '</span>' +
            '<span class="arrow">&#9662;</span></button>' +
            '<div class="dropdown-menu">' +
            '<a href="/profile" ' + (activePage === 'profile' ? 'class="active"' : '') + '>My Profile</a>' +
            '<div class="dropdown-divider"></div>' +
            '<a href="/logout" style="color:#ef4444;">Sign Out</a></div>';
    }
}

function toggleDropdown(btn) {
    var item = btn.closest('.nav-item');
    var wasOpen = item.classList.contains('open');
    document.querySelectorAll('.nav-item.open, .user-menu.open').forEach(function(el) { el.classList.remove('open'); });
    if (!wasOpen) item.classList.add('open');
}

function toggleUserMenu(btn) {
    var menu = btn.closest('.user-menu');
    var wasOpen = menu.classList.contains('open');
    document.querySelectorAll('.nav-item.open, .user-menu.open').forEach(function(el) { el.classList.remove('open'); });
    if (!wasOpen) menu.classList.add('open');
}

document.addEventListener('click', function(e) {
    if (!e.target.closest('.nav-item') && !e.target.closest('.user-menu')) {
        document.querySelectorAll('.nav-item.open, .user-menu.open').forEach(function(el) { el.classList.remove('open'); });
    }
});

document.addEventListener('DOMContentLoaded', function() {
    var toggle = document.querySelector('.menu-toggle');
    var navMenu = document.querySelector('.nav-menu');
    if (toggle && navMenu) {
        toggle.addEventListener('click', function() { navMenu.classList.toggle('open'); });
    }
});
