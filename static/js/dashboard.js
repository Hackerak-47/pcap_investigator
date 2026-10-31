// dashboard.js - Chart.js visualizations and live event handling

let eventsCache = [];

document.addEventListener('DOMContentLoaded', () => {
    initCharts();
    loadEventsData();

    // Auto-poll if status is processing
    if (typeof IS_PROCESSING !== 'undefined' && IS_PROCESSING) {
        pollAnalysisStatus();
    }
});

function pollAnalysisStatus() {
    const interval = setInterval(async () => {
        try {
            const res = await fetch(`/api/analysis/${ANALYSIS_ID}/status`);
            if (!res.ok) return;
            const data = await res.json();
            
            const livePacketEl = document.getElementById('livePacketCount');
            if (livePacketEl && data.packet_count) {
                livePacketEl.textContent = data.packet_count;
            }

            if (data.status === 'complete' || data.status === 'error') {
                clearInterval(interval);
                window.location.reload();
            }
        } catch (err) {
            console.error('Status polling error:', err);
        }
    }, 2500);
}

function initCharts() {
    // 1. Protocol Chart (Doughnut)
    const protoCtx = document.getElementById('protocolChart');
    if (protoCtx && typeof PROTOCOL_STATS !== 'undefined') {
        const labels = Object.keys(PROTOCOL_STATS);
        const data = Object.values(PROTOCOL_STATS);

        new Chart(protoCtx, {
            type: 'doughnut',
            data: {
                labels: labels.length ? labels : ['No Data'],
                datasets: [{
                    data: data.length ? data : [1],
                    backgroundColor: [
                        '#00b4d8', '#10b981', '#f59e0b', '#ef4444', 
                        '#8b5cf6', '#ec4899', '#6366f1', '#64748b'
                    ],
                    borderWidth: 1,
                    borderColor: '#111724'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: { color: '#94a3b8', font: { family: 'Fira Code', size: 11 } }
                    }
                }
            }
        });
    }

    // 2. Severity Chart (Bar)
    const sevCtx = document.getElementById('severityChart');
    if (sevCtx && typeof SEVERITY_COUNTS !== 'undefined') {
        new Chart(sevCtx, {
            type: 'bar',
            data: {
                labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                datasets: [{
                    label: 'Threat Count',
                    data: [
                        SEVERITY_COUNTS.CRITICAL || 0,
                        SEVERITY_COUNTS.HIGH || 0,
                        SEVERITY_COUNTS.MEDIUM || 0,
                        SEVERITY_COUNTS.LOW || 0
                    ],
                    backgroundColor: ['#ef4444', '#f97316', '#f59e0b', '#10b981'],
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: { ticks: { color: '#94a3b8' }, grid: { display: false } },
                    y: { 
                        beginAtZero: true, 
                        ticks: { stepSize: 1, color: '#94a3b8' }, 
                        grid: { color: 'rgba(255, 255, 255, 0.05)' } 
                    }
                },
                plugins: {
                    legend: { display: false }
                }
            }
        });
    }

    // 3. Top Ports Chart (Horizontal Bar)
    const portCtx = document.getElementById('portsChart');
    if (portCtx && typeof PORT_STATS !== 'undefined') {
        const labels = Object.keys(PORT_STATS).slice(0, 6);
        const data = Object.values(PORT_STATS).slice(0, 6);

        new Chart(portCtx, {
            type: 'bar',
            data: {
                labels: labels.map(p => `Port ${p}`),
                datasets: [{
                    label: 'Packets',
                    data: data,
                    backgroundColor: '#00b4d8',
                    borderRadius: 4
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(255, 255, 255, 0.05)' } },
                    y: { ticks: { color: '#94a3b8', font: { family: 'Fira Code' } }, grid: { display: false } }
                },
                plugins: {
                    legend: { display: false }
                }
            }
        });
    }
}

async function loadEventsData() {
    try {
        const res = await fetch(`/api/events/${ANALYSIS_ID}`);
        if (res.ok) {
            eventsCache = await res.json();
        }
    } catch (err) {
        console.error('Failed to pre-fetch threat events:', err);
    }
}

function openEvidenceModal(eventId) {
    const event = eventsCache.find(e => e.id === eventId);
    if (!event) return;

    document.getElementById('modalEventTitle').textContent = `Evidence Details — [${event.event_type}]`;
    document.getElementById('modalEventType').textContent = event.event_type.replace(/_/g, ' ');
    
    // Severity badge
    const sevBadgeClass = event.severity === 'CRITICAL' ? 'badge-critical' :
                          event.severity === 'HIGH' ? 'badge-high' :
                          event.severity === 'MEDIUM' ? 'badge-medium' : 'badge-low';
    document.getElementById('modalSeverity').innerHTML = `<span class="badge ${sevBadgeClass}">${event.severity}</span>`;

    // Risk score color
    const scoreColor = event.risk_score >= 80 ? 'text-danger' :
                       event.risk_score >= 60 ? 'text-warning' : 'text-info';
    document.getElementById('modalRiskScore').innerHTML = `<span class="${scoreColor}">${Math.round(event.risk_score)}/100</span>`;

    document.getElementById('modalSource').textContent = event.source_ip || 'N/A';
    document.getElementById('modalDestination').textContent = event.destination_ip || 'N/A';
    document.getElementById('modalDescription').textContent = event.description || 'No description available.';

    // Format Evidence JSON
    try {
        const evidenceObj = typeof event.evidence === 'string' ? JSON.parse(event.evidence) : event.evidence;
        document.getElementById('modalEvidenceJson').textContent = JSON.stringify(evidenceObj, null, 2);
    } catch (e) {
        document.getElementById('modalEvidenceJson').textContent = String(event.evidence);
    }

    // Generate Wireshark display filter
    let filter = `ip.addr == ${event.source_ip}`;
    if (event.event_type === 'PORT_SCAN') {
        filter = `ip.src == ${event.source_ip} && tcp.flags.syn == 1 && tcp.flags.ack == 0`;
    } else if (event.event_type === 'SSH_BRUTE_FORCE') {
        filter = `ip.src == ${event.source_ip} && tcp.port == 22`;
    } else if (event.event_type === 'DNS_ANOMALY') {
        filter = `ip.src == ${event.source_ip} && dns`;
    } else if (event.event_type === 'SUSPICIOUS_OUTBOUND') {
        filter = `ip.src == ${event.source_ip} && (tcp.port == 4444 || tcp.port == 31337)`;
    } else if (event.event_type === 'ICMP_ANOMALY') {
        filter = `ip.src == ${event.source_ip} && icmp`;
    } else if (event.event_type === 'HTTP_ANOMALY') {
        filter = `ip.src == ${event.source_ip} && http`;
    }
    document.getElementById('modalWiresharkFilter').textContent = filter;

    const modal = new bootstrap.Modal(document.getElementById('evidenceModal'));
    modal.show();
}

function copyWiresharkFilter() {
    const filterText = document.getElementById('modalWiresharkFilter').textContent;
    navigator.clipboard.writeText(filterText).then(() => {
        alert('Wireshark filter copied to clipboard:\n' + filterText);
    });
}
