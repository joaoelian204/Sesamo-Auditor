/**
 * Sésamo Auditor — Dashboard JavaScript
 * Gráficos interactivos con Chart.js
 */

const SEVERITY_COLORS = {
    'Crítica': '#DC2626',
    'Alta': '#EA580C',
    'Media': '#CA8A04',
    'Baja': '#2563EB',
    'Informativo': '#6B7280',
};

const OWASP_COLORS = [
    '#7C3AED', '#6D28D9', '#5B21B6', '#4C1D95',
    '#10B981', '#059669', '#047857', '#065F46',
    '#3B82F6', '#2563EB',
];

function renderSeverityChart(canvasId, data) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;

    const entries = Object.entries(data).filter(([_, v]) => v > 0);
    const labels = entries.map(([k, _]) => k);
    const values = entries.map(([_, v]) => v);
    const colors = labels.map(label => SEVERITY_COLORS[label] || '#6B7280');

    new Chart(canvas, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: colors,
                borderWidth: 2,
                borderColor: '#0B0F19'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#94A3B8',
                        font: { family: 'Inter', size: 12 }
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return ` ${context.label}: ${context.raw} hallazgo(s)`;
                        }
                    }
                }
            },
            cutout: '60%'
        }
    });
}

function renderOwaspChart(canvasId, data) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;

    const entries = Object.entries(data).sort((a, b) => b[1] - a[1]);
    const labels = entries.map(([k, _]) => k);
    const values = entries.map(([_, v]) => v);
    const colors = labels.map((_, i) => OWASP_COLORS[i % OWASP_COLORS.length]);

    new Chart(canvas, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Hallazgos',
                data: values,
                backgroundColor: colors,
                borderRadius: 6,
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return ` ${context.raw} hallazgo(s)`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    grid: { display: false },
                    ticks: {
                        color: '#64748B',
                        font: { family: 'Inter', size: 10 }
                    }
                },
                y: {
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: {
                        color: '#64748B',
                        font: { family: 'Inter', size: 10 },
                        precision: 0
                    }
                }
            }
        }
    });
}
