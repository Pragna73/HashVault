/**
 * HashVault Chart.js Visualizations
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
        parent.innerHTML = '<div class="chart-empty"><p>No monitored files in baseline yet.<br>Create a baseline to view status distribution.</p></div>';
        return;
    }

    new Chart(canvas, {
        type: 'doughnut',
        data: {
            labels: ['Safe', 'Modified', 'New', 'Deleted'],
            datasets: [{
                data: [dist.safe, dist.modified, dist.new, dist.deleted],
                backgroundColor: [
                    '#10b981', // Safe (Green)
                    '#f59e0b', // Modified (Amber)
                    '#06b6d4', // New (Cyan)
                    '#ef4444'  // Deleted (Red)
                ],
                borderColor: '#151d30',
                borderWidth: 3,
                hoverOffset: 4
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
                        font: { family: 'Inter', size: 12 },
                        padding: 15,
                        usePointStyle: true,
                        pointStyle: 'circle'
                    }
                },
                tooltip: {
                    backgroundColor: '#111726',
                    titleColor: '#fff',
                    bodyColor: '#cbd5e1',
                    borderColor: '#232f48',
                    borderWidth: 1,
                    padding: 10,
                    cornerRadius: 6
                }
            },
            cutout: '70%'
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

    // Scans come newest first, reverse for chronological chart
    const chronologicalScans = [...scans].reverse();
    const labels = chronologicalScans.map((s, idx) => `Scan #${s.id}`);
    const scores = chronologicalScans.map(s => s.integrity_score);

    new Chart(canvas, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Integrity Score (%)',
                data: scores,
                borderColor: '#f59e0b',
                backgroundColor: 'rgba(245, 158, 11, 0.1)',
                fill: true,
                tension: 0.35,
                pointBackgroundColor: '#f59e0b',
                pointBorderColor: '#fff',
                pointBorderWidth: 2,
                pointRadius: 4,
                pointHoverRadius: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    min: 0,
                    max: 100,
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
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
                    backgroundColor: '#111726',
                    titleColor: '#fff',
                    bodyColor: '#cbd5e1',
                    borderColor: '#232f48',
                    borderWidth: 1,
                    padding: 10,
                    cornerRadius: 6,
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
                    borderRadius: 4
                },
                {
                    label: 'Modified',
                    data: modifiedData,
                    backgroundColor: '#f59e0b',
                    borderRadius: 4
                },
                {
                    label: 'New',
                    data: newData,
                    backgroundColor: '#06b6d4',
                    borderRadius: 4
                },
                {
                    label: 'Deleted',
                    data: deletedData,
                    backgroundColor: '#ef4444',
                    borderRadius: 4
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
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: { color: '#64748b', font: { family: 'Inter', size: 11 }, precision: 0 }
                }
            },
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#94a3b8',
                        font: { family: 'Inter', size: 12 },
                        padding: 12,
                        usePointStyle: true
                    }
                },
                tooltip: {
                    backgroundColor: '#111726',
                    titleColor: '#fff',
                    bodyColor: '#cbd5e1',
                    borderColor: '#232f48',
                    borderWidth: 1,
                    padding: 10,
                    cornerRadius: 6
                }
            }
        }
    });
}
