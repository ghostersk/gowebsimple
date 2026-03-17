// GoApp — base JavaScript (no third-party libraries)
// Page-specific scripts go in {{block "scripts"}} sections in templates.

// ── Sidebar mobile toggle ────────────────────────────────────────────────────
function openSidebar() {
    document.getElementById('sidebar').classList.remove('-translate-x-full');
    document.getElementById('sidebar-overlay').classList.remove('hidden');
    document.body.style.overflow = 'hidden';
}

function closeSidebar() {
    document.getElementById('sidebar').classList.add('-translate-x-full');
    document.getElementById('sidebar-overlay').classList.add('hidden');
    document.body.style.overflow = '';
}

// Close sidebar on ESC
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') closeSidebar();
});

// ── Auto-dismiss flash messages ──────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', function() {
    ['flash-msg', 'flash-err'].forEach(function(id) {
        var el = document.getElementById(id);
        if (el) {
            setTimeout(function() {
                el.style.transition = 'opacity 400ms ease';
                el.style.opacity = '0';
                setTimeout(function() { el.remove(); }, 400);
            }, 5000);
        }
    });
});

// ── Close modals on backdrop click ───────────────────────────────────────────
document.addEventListener('click', function(e) {
    if (e.target.id === 'create-modal' || e.target.id === 'reset-modal') {
        e.target.classList.add('hidden');
    }
});

// ── Confirm for destructive form actions (extra safety) ──────────────────────
document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('[data-confirm]').forEach(function(el) {
        el.addEventListener('submit', function(e) {
            if (!confirm(el.dataset.confirm)) {
                e.preventDefault();
            }
        });
    });
});
