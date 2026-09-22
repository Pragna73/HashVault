/**
 * HashVault Dashboard & Client-Side Interactivity
 */

document.addEventListener('DOMContentLoaded', () => {
    initClipboard();
    initBaselineModal();
    initScanTrigger();
    initFilters();
});

/**
 * Toast Notification System
 */
function showToast(message, type = 'info') {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        container.className = 'toast-container';
        document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    
    let icon = 'ℹ️';
    if (type === 'success') icon = '✓';
    if (type === 'error') icon = '⚠';
    if (type === 'warning') icon = '⚡';

    toast.innerHTML = `<span>${icon}</span> <span>${message}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100%)';
        toast.style.transition = 'all 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

/**
 * Clipboard Copy Handler for Hashes
 */
function initClipboard() {
    document.addEventListener('click', (e) => {
        const copyBtn = e.target.closest('.copy-btn') || e.target.closest('.hash-snippet');
        if (copyBtn) {
            const hashValue = copyBtn.getAttribute('data-hash') || copyBtn.textContent.trim();
            if (hashValue && hashValue !== 'NONE (Deleted)' && hashValue !== 'NONE (Unmonitored)') {
                navigator.clipboard.writeText(hashValue).then(() => {
                    showToast('SHA-256 hash copied to clipboard', 'success');
                }).catch(() => {
                    showToast('Could not copy to clipboard', 'error');
                });
            }
        }
    });
}

/**
 * Baseline Creation & Confirmation Modal
 */
function initBaselineModal() {
    const createBtn = document.getElementById('btn-create-baseline');
    const modal = document.getElementById('baseline-confirm-modal');
    const confirmBtn = document.getElementById('btn-confirm-overwrite');
    const cancelBtn = document.getElementById('btn-cancel-modal');

    if (!createBtn) return;

    createBtn.addEventListener('click', () => {
        triggerBaselineCreation(false);
    });

    if (confirmBtn) {
        confirmBtn.addEventListener('click', () => {
            if (modal) modal.classList.remove('active');
            triggerBaselineCreation(true);
        });
    }

    if (cancelBtn && modal) {
        cancelBtn.addEventListener('click', () => {
            modal.classList.remove('active');
        });
    }
}

async function triggerBaselineCreation(force = false) {
    const btn = document.getElementById('btn-create-baseline');
    const modal = document.getElementById('baseline-confirm-modal');
    
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner">⏳</span> Creating Baseline...';
    }

    try {
        const response = await fetch('/api/baseline', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ force: force })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            showToast(data.message, 'success');
            setTimeout(() => {
                window.location.reload();
            }, 1000);
        } else if (data.data && data.data.requires_confirmation) {
            if (modal) {
                modal.classList.add('active');
            } else if (confirm(data.message)) {
                triggerBaselineCreation(true);
            }
        } else {
            showToast(data.message || 'Error creating baseline', 'error');
        }
    } catch (err) {
        showToast('Network error while creating baseline: ' + err.message, 'error');
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '⚡ CREATE BASELINE';
        }
    }
}

/**
 * Integrity Scan Trigger
 */
function initScanTrigger() {
    const scanBtn = document.getElementById('btn-run-scan');
    if (!scanBtn) return;

    scanBtn.addEventListener('click', async () => {
        scanBtn.disabled = true;
        scanBtn.innerHTML = '<span class="spinner">⏳</span> Scanning Filesystem...';

        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });

            const data = await response.json();

            if (response.ok && data.success) {
                showToast(data.message, data.data.modified_files > 0 || data.data.new_files > 0 || data.data.deleted_files > 0 ? 'warning' : 'success');
                setTimeout(() => {
                    window.location.reload();
                }, 1000);
            } else {
                showToast(data.message || 'Error executing integrity scan', 'error');
            }
        } catch (err) {
            showToast('Scan error: ' + err.message, 'error');
        } finally {
            scanBtn.disabled = false;
            scanBtn.innerHTML = '🔍 RUN INTEGRITY SCAN';
        }
    });
}

/**
 * Client-Side Table Filtering & Search
 */
function initFilters() {
    const searchInput = document.getElementById('table-search');
    const statusSelect = document.getElementById('status-filter');
    const table = document.querySelector('.data-table');

    if (!table) return;

    function applyFilters() {
        const query = (searchInput ? searchInput.value.toLowerCase().trim() : '');
        const selectedStatus = (statusSelect ? statusSelect.value.toUpperCase() : 'ALL');

        const rows = table.querySelectorAll('tbody tr');
        rows.forEach(row => {
            const text = row.innerText.toLowerCase();
            const statusBadge = row.querySelector('.badge');
            const rowStatus = statusBadge ? statusBadge.innerText.trim().toUpperCase() : '';

            const matchesQuery = query === '' || text.includes(query);
            const matchesStatus = selectedStatus === 'ALL' || rowStatus === selectedStatus;

            if (matchesQuery && matchesStatus) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        });
    }

    if (searchInput) searchInput.addEventListener('input', applyFilters);
    if (statusSelect) statusSelect.addEventListener('change', applyFilters);
}
