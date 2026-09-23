/**
 * HashVault Modern Chart.js Visualizations
 * Palette: Electric Indigo, Emerald Neon, Amber Gold, Cyber Cyan, Rose Crimson
 */

document.addEventListener('DOMContentLoaded', () => {
    loadAndRenderCharts();
});

async function loadAndRenderCharts() {
    const distCanvas = document.getElementById('chart-status-distribution');
    const trendCanvas = document.getElementById('chart-score-trend');
    const activityCanvas = document.getElementById('chart-scan-activity');

    if (!distCanvas && !trendCanvas && !activityCanvas) return;

    try {
        const response = await fetch('/api/stats');
        if (!response.ok) return;
        const data = await response.json();

        if (distCanvas) {
            renderStatusDistribution(distCanvas, data.distribution);
        }

        if (trendCanvas) {
            renderScoreTrend(trendCanvas, data.scans);
        }

        if (activityCanvas) {
            renderScanActivity(activityCanvas, data.scans);
        }
    } catch (err) {
        console.error('Error rendering HashVault charts:', err);
    }
}

/**
 * 1. File Status Distribution Chart (Doughnut)
 */
function renderStatusDistribution(canvas, dist) {
    const total = dist.safe + dist.modified + dist.new + dist.deleted;

    if (total === 0) {
        const parent = canvas.parentElement;
        parent.innerHTML = '<div class="chart-empty"><p>No monitored files in baseline yet.<br>Create a baseline to view distribution.</p></div>';
        return;
    }

    new Chart(canvas, {
        type: 'doughnut',
        data: {
            labels: ['Safe', 'Modified', 'New', 'Deleted'],
            datasets: [{
                data: [dist.safe, dist.modified, dist.new, dist.deleted],
                backgroundColor: [
                    '#10b981', // Safe (Emerald)
                    '#f59e0b', // Modified (Amber)
                    '#06b6d4', // New (Cyan)
                    '#f43f5e'  // Deleted (Rose)
                ],
                borderColor: '#101726',
                borderWidth: 4,
                hoverOffset: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#94a3b8',
                        font: { family: 'Inter', size: 12, weight: 500 },
                        padding: 16,
                        usePointStyle: true,
                        pointStyle: 'circle'
                    }
                },
                tooltip: {
                    backgroundColor: '#0f172a',
                    titleColor: '#fff',
                    bodyColor: '#cbd5e1',
                    borderColor: 'rgba(99, 102, 241, 0.3)',
                    borderWidth: 1,
                    padding: 12,
                    cornerRadius: 8
                }
            },
            cutout: '72%'
        }
    });
}

/**
 * 2. Integrity Score Over Time (Line Chart)
 */
function renderScoreTrend(canvas, scans) {
    if (!scans || scans.length === 0) {
        const parent = canvas.parentElement;
        parent.innerHTML = '<div class="chart-empty"><p>No scan history recorded.<br>Run integrity scans to generate score trends.</p></div>';
        return;
    }

    const chronologicalScans = [...scans].reverse();
    const labels = chronologicalScans.map(s => `Scan #${s.id}`);
    const scores = chronologicalScans.map(s => s.integrity_score);

    const ctx = canvas.getContext('2d');
    const gradient = ctx.createLinearGradient(0, 0, 0, 260);
    gradient.addColorStop(0, 'rgba(99, 102, 241, 0.35)');
    gradient.addColorStop(1, 'rgba(99, 102, 241, 0.0)');

    new Chart(canvas, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Integrity Score (%)',
                data: scores,
                borderColor: '#6366f1',
                backgroundColor: gradient,
                borderWidth: 3,
                fill: true,
                tension: 0.35,
                pointBackgroundColor: '#8b5cf6',
                pointBorderColor: '#ffffff',
                pointBorderWidth: 2,
                pointRadius: 5,
                pointHoverRadius: 7
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    min: 0,
                    max: 100,
                    grid: { color: 'rgba(255, 255, 255, 0.04)' },
                    ticks: { color: '#64748b', font: { family: 'Inter', size: 11 } }
                },
                x: {
                    grid: { display: false },
                    ticks: { color: '#64748b', font: { family: 'Inter', size: 11 } }
                }
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: '#0f172a',
                    titleColor: '#fff',
                    bodyColor: '#cbd5e1',
                    borderColor: 'rgba(99, 102, 241, 0.3)',
                    borderWidth: 1,
                    padding: 12,
                    cornerRadius: 8,
                    callbacks: {
                        label: function(ctx) {
                            return ` Score: ${ctx.parsed.y}%`;
                        }
                    }
                }
            }
        }
    });
}

/**
 * 3. Scan Activity & File Changes History (Stacked Bar)
 */
function renderScanActivity(canvas, scans) {
    if (!scans || scans.length === 0) {
        const parent = canvas.parentElement;
        parent.innerHTML = '<div class="chart-empty"><p>No scan activity recorded yet.</p></div>';
        return;
    }

    const chronological = [...scans].reverse();
    const labels = chronological.map(s => `Scan #${s.id}`);
    const safeData = chronological.map(s => s.safe_files);
    const modifiedData = chronological.map(s => s.modified_files);
    const newData = chronological.map(s => s.new_files);
    const deletedData = chronological.map(s => s.deleted_files);

    new Chart(canvas, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Safe',
                    data: safeData,
                    backgroundColor: '#10b981',
                    borderRadius: 6
                },
                {
                    label: 'Modified',
                    data: modifiedData,
                    backgroundColor: '#f59e0b',
                    borderRadius: 6
                },
                {
                    label: 'New',
                    data: newData,
                    backgroundColor: '#06b6d4',
                    borderRadius: 6
                },
                {
                    label: 'Deleted',
                    data: deletedData,
                    backgroundColor: '#f43f5e',
                    borderRadius: 6
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    stacked: true,
                    grid: { display: false },
                    ticks: { color: '#64748b', font: { family: 'Inter', size: 11 } }
                },
                y: {
                    stacked: true,
                    beginAtZero: true,
                    grid: { color: 'rgba(255, 255, 255, 0.04)' },
                    ticks: { color: '#64748b', font: { family: 'Inter', size: 11 }, precision: 0 }
                }
            },
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#94a3b8',
                        font: { family: 'Inter', size: 12, weight: 500 },
                        padding: 14,
                        usePointStyle: true
                    }
                },
                tooltip: {
                    backgroundColor: '#0f172a',
                    titleColor: '#fff',
                    bodyColor: '#cbd5e1',
                    borderColor: 'rgba(99, 102, 241, 0.3)',
                    borderWidth: 1,
                    padding: 12,
                    cornerRadius: 8
                }
            }
        }
    });
}
