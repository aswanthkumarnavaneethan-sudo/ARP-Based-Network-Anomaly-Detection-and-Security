/**
 * NETGUARD — Network Security & ARP Threat Detection System
 * Frontend Interactive Controller & Real-Time Telemetry Client
 */

(function () {
    'use strict';

    // -------------------------------------------------------------------------
    // 1. State Management & Constants
    // -------------------------------------------------------------------------
    const state = {
        interfaces: [],
        status: { running: false, interface: null, error: null, packet_count: 0, start_time: null },
        stats: { devices: 0, events: 0, alerts: 0, mapping_changes: 0, active_devices: 0 },
        devices: [],
        events: [],
        liveStream: [],
        chart: null,
        chartRange: '1h',
        pollingIntervalMs: 3000,
        pollingTimer: null,
        audioAlerts: true,
        lastAlertCount: 0,
        
        // Devices Table State
        deviceSearch: '',
        deviceFilter: 'all',
        deviceSortCol: 'last_seen',
        deviceSortAsc: false,
        devicePage: 1,
        devicePageSize: 25,
        
        // Events Table State
        eventSearch: '',
        eventSeverityFilter: 'ALL',
        eventStatusFilter: 'ALL',
        eventPage: 1,
        eventPageSize: 25,
        
        // Modals
        selectedEvent: null
    };

    // Helper shorthand for DOM selection
    const $ = id => document.getElementById(id);
    const $$ = selector => document.querySelectorAll(selector);

    // -------------------------------------------------------------------------
    // 2. API Helper
    // -------------------------------------------------------------------------
    async function api(url, options = {}) {
        try {
            const response = await fetch(url, options);
            const data = await response.json().catch(() => ({}));
            if (!response.ok) {
                throw new Error(data.message || `HTTP ${response.status}: Request failed`);
            }
            return data;
        } catch (error) {
            console.warn(`[NETGUARD API] Request to ${url} failed:`, error.message);
            throw error;
        }
    }

    // -------------------------------------------------------------------------
    // 3. UI Notification & Feedback Banner
    // -------------------------------------------------------------------------
    let feedbackTimeout = null;

    function showFeedback(message, type = 'info', duration = 5000) {
        const banner = $('feedbackBanner');
        const text = $('feedbackText');
        const icon = $('feedbackIcon');

        if (!banner || !text) return;

        banner.className = `feedback-banner ${type}`;
        text.textContent = message;

        // Configure icon
        if (icon) {
            let iconName = 'info';
            if (type === 'success') iconName = 'check-circle';
            if (type === 'error') iconName = 'alert-triangle';
            if (type === 'warning') iconName = 'alert-circle';
            icon.innerHTML = `<i data-lucide="${iconName}"></i>`;
            if (window.lucide) window.lucide.createIcons();
        }

        banner.style.display = 'flex';

        if (feedbackTimeout) clearTimeout(feedbackTimeout);
        if (duration > 0) {
            feedbackTimeout = setTimeout(() => {
                banner.style.display = 'none';
            }, duration);
        }
    }

    // Metallic chime audio alert using Web Audio API
    function playAlertChime() {
        if (!state.audioAlerts) return;
        try {
            const ctx = new (window.AudioContext || window.webkitAudioContext)();
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();

            osc.type = 'triangle';
            osc.frequency.setValueAtTime(880, ctx.currentTime); // A5
            osc.frequency.exponentialRampToValueAtTime(440, ctx.currentTime + 0.3);

            gain.gain.setValueAtTime(0.12, ctx.currentTime);
            gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.35);

            osc.connect(gain);
            gain.connect(ctx.destination);

            osc.start();
            osc.stop(ctx.currentTime + 0.35);
        } catch (e) {
            // AudioContext might be blocked until user interacts
        }
    }

    // -------------------------------------------------------------------------
    // 4. Interfaces & Control Center
    // -------------------------------------------------------------------------
    async function loadInterfaces() {
        try {
            const interfaces = await api('/api/interfaces');
            state.interfaces = interfaces || [];

            const populate = selectEl => {
                if (!selectEl) return;
                const prevVal = selectEl.value;
                selectEl.innerHTML = '';

                if (state.interfaces.length === 0) {
                    selectEl.add(new Option('No network adapters detected', ''));
                    return;
                }

                state.interfaces.forEach(iface => {
                    const opt = new Option(iface, iface);
                    selectEl.add(opt);
                });

                if (prevVal && state.interfaces.includes(prevVal)) {
                    selectEl.value = prevVal;
                }
            };

            populate($('interfaceSelect'));
            populate($('interfaceSelect2'));

            if (state.interfaces.length > 0) {
                $('telInterface').textContent = state.status.interface || state.interfaces[0];
            }
        } catch (error) {
            showFeedback('Failed to query host network interfaces: ' + error.message, 'error');
        }
    }

    async function startMonitoring() {
        const select = $('interfaceSelect');
        const iface = select ? select.value : '';

        if (!iface) {
            showFeedback('Please select a network interface from the dropdown list.', 'warning');
            return;
        }

        try {
            const res = await api('/api/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ interface: iface })
            });

            showFeedback(res.message || 'Capture engine initialized.', 'success');
            await refreshAll();
        } catch (error) {
            showFeedback('Could not start monitoring: ' + error.message, 'error');
            await refreshAll();
        }
    }

    async function stopMonitoring() {
        try {
            const res = await api('/api/stop', { method: 'POST' });
            showFeedback(res.message || 'Capture engine stopped.', 'info');
            await refreshAll();
        } catch (error) {
            showFeedback('Could not stop monitoring: ' + error.message, 'error');
            await refreshAll();
        }
    }

    async function triggerDemoData() {
        try {
            showFeedback('Scanning local network and live ARP cache for real devices...', 'info', 2000);
            const res = await api('/api/scan', { method: 'POST' });
            showFeedback(res.message || 'Live network devices synchronized.', 'success');
            await refreshAll();
        } catch (error) {
            showFeedback('Failed to scan network: ' + error.message, 'error');
        }
    }

    async function triggerSimulateAttack() {
        try {
            showFeedback('Simulating ARP Cache Poisoning attack against Gateway (172.100.0.1)...', 'warning', 2500);
            const res = await api('/api/simulate-attack', { method: 'POST' });
            playAlertChime();
            showFeedback(res.message || 'ARP conflict detected on Gateway!', 'error', 7000);
            await refreshAll();
        } catch (error) {
            showFeedback('Simulation error: ' + error.message, 'error');
        }
    }

    async function triggerResetDatabase() {
        try {
            const res = await api('/api/reset', { method: 'POST' });
            showFeedback(res.message || 'Database cleared.', 'info');
            closeClearModal();
            await refreshAll();
        } catch (error) {
            showFeedback('Failed to clear database: ' + error.message, 'error');
        }
    }

    // -------------------------------------------------------------------------
    // 5. Status & Telemetry Updates
    // -------------------------------------------------------------------------
    async function loadStatus() {
        try {
            const status = await api('/api/status');
            state.status = status;

            const isRunning = Boolean(status.running);

            // Update Start/Stop buttons
            if ($('startBtn')) $('startBtn').disabled = isRunning;
            if ($('stopBtn')) $('stopBtn').disabled = !isRunning;
            if ($('startBtn2')) $('startBtn2').disabled = isRunning;
            if ($('stopBtn2')) $('stopBtn2').disabled = !isRunning;

            // Status Pill in Topbar
            const topPill = $('topbarMonitorPill');
            const topText = $('topbarMonitorText');
            if (topPill && topText) {
                topPill.className = isRunning ? 'monitor-pill live' : 'monitor-pill standby';
                topText.textContent = isRunning ? 'MONITORING LIVE' : 'STANDBY';
            }

            // Topbar Interface Badge
            const ifBadge = $('topbarInterfaceBadge');
            const ifLabel = $('topbarInterfaceLabel');
            if (ifBadge && ifLabel) {
                if (isRunning && status.interface) {
                    ifBadge.classList.add('connected');
                    ifLabel.textContent = status.interface.toUpperCase();
                } else {
                    ifBadge.classList.remove('connected');
                    ifLabel.textContent = 'DISCONNECTED';
                }
            }

            // Sidebar Status Elements
            const sideLight = $('sidebarStatusLight');
            const sideText = $('sidebarStatusText');
            const sideIf = $('sidebarInterfaceText');
            const sidePill = $('sidebarLivePill');

            if (sideLight) sideLight.className = isRunning ? 'status-light-pulse active' : 'status-light-pulse';
            if (sideText) sideText.textContent = isRunning ? 'Active Sniffing' : 'Passive Standby';
            if (sideIf) sideIf.textContent = status.interface || 'No interface bound';
            if (sidePill) {
                sidePill.className = isRunning ? 'nav-badge live-pulse-badge live' : 'nav-badge live-pulse-badge';
                sidePill.textContent = isRunning ? 'LIVE' : 'OFFLINE';
            }

            // Overview Card 4: Monitoring Status
            const statStatus = $('statMonitorStatus');
            const statPackets = $('statPacketCounter');
            const statIfInfo = $('statInterfaceInfo');
            if (statStatus) {
                statStatus.textContent = isRunning ? 'RUNNING' : 'STOPPED';
                statStatus.style.color = isRunning ? '#059669' : '#252B32';
            }
            if (statPackets) statPackets.textContent = `${status.packet_count || 0} Pkts`;
            if (statIfInfo) statIfInfo.textContent = status.interface ? `Bound: ${status.interface}` : 'Waiting to start';

            // Telemetry Strip
            if ($('telInterface')) $('telInterface').textContent = status.interface || 'None';
            if ($('telPackets')) $('telPackets').textContent = (status.packet_count || 0).toLocaleString();
            if ($('controlEngineBadge')) {
                $('controlEngineBadge').textContent = isRunning ? 'ENGINE: ACTIVE' : 'ENGINE: STANDBY';
            }
            if ($('monitoringViewStatus')) {
                $('monitoringViewStatus').textContent = isRunning ? 'ACTIVE' : 'STANDBY';
            }

            // Error display if capture loop encountered an issue
            if (status.error) {
                showFeedback(`Engine Notice: ${status.error}`, 'warning', 10000);
            }
        } catch (error) {
            // Backend offline
            if ($('topbarMonitorText')) $('topbarMonitorText').textContent = 'OFFLINE';
        }
    }

    // -------------------------------------------------------------------------
    // 6. Statistics Metric Cards
    // -------------------------------------------------------------------------
    async function loadStats() {
        try {
            const stats = await api('/api/stats');
            state.stats = stats;

            if ($('statDeviceCount')) $('statDeviceCount').textContent = stats.devices || 0;
            if ($('statEventCount')) $('statEventCount').textContent = stats.events || 0;
            if ($('statArpChanges')) $('statArpChanges').textContent = stats.mapping_changes || 0;
            if ($('statAlertsUnack')) $('statAlertsUnack').textContent = `${stats.alerts || 0} Unreviewed`;
            if ($('statActiveRatio')) $('statActiveRatio').textContent = `${stats.active_devices || stats.devices || 0} Active in Database`;

            // Sidebar counters
            if ($('sidebarDeviceCount')) $('sidebarDeviceCount').textContent = stats.devices || 0;
            if ($('sidebarEventCount')) $('sidebarEventCount').textContent = stats.events || 0;
            if ($('sidebarArpCount')) $('sidebarArpCount').textContent = stats.mapping_changes || 0;

            // Notification Bell Badge
            const badge = $('notificationBadge');
            if (badge) {
                const count = stats.alerts || 0;
                badge.textContent = count;
                badge.style.display = count > 0 ? 'flex' : 'none';

                // Play audio chime if new alerts emerged
                if (count > state.lastAlertCount && count > 0) {
                    playAlertChime();
                }
                state.lastAlertCount = count;
            }

            // Dossier preview metrics
            if ($('dossierHosts')) $('dossierHosts').textContent = stats.devices || 0;
            if ($('dossierIncidents')) $('dossierIncidents').textContent = stats.events || 0;
            if ($('dossierConflicts')) $('dossierConflicts').textContent = stats.mapping_changes || 0;
            if ($('dossierIf')) $('dossierIf').textContent = state.status.interface || 'None Selected';
            if ($('dossierTimestamp')) $('dossierTimestamp').textContent = new Date().toLocaleString();
            if ($('dossierStatusPill')) {
                const isThreat = (stats.mapping_changes || 0) > 0;
                $('dossierStatusPill').textContent = isThreat ? 'ANOMALIES OBSERVED' : 'SYSTEM INTEGRITY: SECURE';
                $('dossierStatusPill').style.backgroundColor = isThreat ? 'rgba(220, 38, 38, 0.15)' : 'rgba(16, 185, 129, 0.15)';
                $('dossierStatusPill').style.color = isThreat ? '#DC2626' : '#059669';
            }
        } catch (error) {
            console.error('Error loading stats:', error);
        }
    }

    // -------------------------------------------------------------------------
    // 7. Device Inventory & Filtering
    // -------------------------------------------------------------------------
    async function loadDevices() {
        try {
            const devices = await api('/api/devices');
            state.devices = devices || [];
            renderDevices();
            renderOverviewDevices();
        } catch (error) {
            console.error('Error loading devices:', error);
        }
    }

    function renderDevices() {
        const tbody = $('deviceTableBody');
        if (!tbody) return;

        // Filter devices
        let filtered = state.devices.filter(d => {
            const search = state.deviceSearch.toLowerCase();
            const matchesSearch = !search ||
                (d.ip && d.ip.toLowerCase().includes(search)) ||
                (d.mac && d.mac.toLowerCase().includes(search)) ||
                (d.hostname && d.hostname.toLowerCase().includes(search)) ||
                (d.vendor && d.vendor.toLowerCase().includes(search));

            const matchesStatus = state.deviceFilter === 'all' || d.status === state.deviceFilter;

            return matchesSearch && matchesStatus;
        });

        // Sort devices
        filtered.sort((a, b) => {
            let valA = a[state.deviceSortCol] ?? '';
            let valB = b[state.deviceSortCol] ?? '';

            if (typeof valA === 'string') valA = valA.toLowerCase();
            if (typeof valB === 'string') valB = valB.toLowerCase();

            if (valA < valB) return state.deviceSortAsc ? -1 : 1;
            if (valA > valB) return state.deviceSortAsc ? 1 : -1;
            return 0;
        });

        // Pagination
        const total = filtered.length;
        const totalPages = Math.ceil(total / state.devicePageSize) || 1;
        if (state.devicePage > totalPages) state.devicePage = totalPages;
        if (state.devicePage < 1) state.devicePage = 1;

        const startIdx = (state.devicePage - 1) * state.devicePageSize;
        const pageItems = filtered.slice(startIdx, startIdx + state.devicePageSize);

        // Update pagination UI
        if ($('devicePaginationInfo')) {
            const startDisplay = total === 0 ? 0 : startIdx + 1;
            const endDisplay = Math.min(startIdx + state.devicePageSize, total);
            $('devicePaginationInfo').textContent = `Showing ${startDisplay}-${endDisplay} of ${total} devices`;
        }
        if ($('devicePageNum')) $('devicePageNum').textContent = `Page ${state.devicePage} of ${totalPages}`;
        if ($('devicePrevBtn')) $('devicePrevBtn').disabled = state.devicePage <= 1;
        if ($('deviceNextBtn')) $('deviceNextBtn').disabled = state.devicePage >= totalPages;

        tbody.innerHTML = '';

        if (pageItems.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="8" class="empty-cell">
                        No devices match current criteria. Start monitoring or click "⚡ Demo Data" to load endpoints.
                    </td>
                </tr>
            `;
            return;
        }

        pageItems.forEach(d => {
            const tr = document.createElement('tr');

            const isSuspicious = d.status === 'Suspicious';
            const statusClass = isSuspicious ? 'status-badge suspicious-status' : 'status-badge active-status';
            const statusDot = isSuspicious ? '🔴' : '🟢';

            tr.innerHTML = `
                <td class="font-mono">
                    <strong>${escapeHtml(d.ip)}</strong>
                    <button class="copy-ip-btn" data-copy="${escapeHtml(d.ip)}" title="Copy IP address">&#x2398;</button>
                </td>
                <td class="font-mono">${escapeHtml(d.mac)}</td>
                <td>
                    <div><strong>${escapeHtml(d.hostname || '—')}</strong></div>
                    <small style="color: var(--text-slate);">${escapeHtml(d.vendor || 'Unknown Vendor')}</small>
                </td>
                <td class="font-mono">${escapeHtml(d.first_seen || '—')}</td>
                <td class="font-mono">${escapeHtml(d.last_seen || '—')}</td>
                <td class="text-center font-mono">
                    <span class="nav-counter">${(d.observations || 1).toLocaleString()}</span>
                </td>
                <td>
                    <span class="${statusClass}">${statusDot} ${escapeHtml(d.status || 'Active')}</span>
                </td>
                <td class="text-right">
                    <button class="chrome-btn btn-silver btn-sm investigate-device-btn" data-ip="${escapeHtml(d.ip)}">
                        Analyze
                    </button>
                </td>
            `;

            tbody.appendChild(tr);
        });

        // Bind copy buttons
        tbody.querySelectorAll('.copy-ip-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const ip = btn.getAttribute('data-copy');
                if (ip) {
                    navigator.clipboard.writeText(ip);
                    btn.textContent = '✓';
                    setTimeout(() => { btn.textContent = '⎘'; }, 1500);
                }
            });
        });

        // Bind investigate buttons
        tbody.querySelectorAll('.investigate-device-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const ip = btn.getAttribute('data-ip');
                switchView('arp-detection');
                if ($('eventSearchInput')) {
                    $('eventSearchInput').value = ip;
                    state.eventSearch = ip;
                    renderEvents();
                }
            });
        });
    }

    function renderOverviewDevices() {
        const tbody = $('overviewDeviceRows');
        if (!tbody) return;

        const slice = state.devices.slice(0, 5);
        tbody.innerHTML = '';

        if (slice.length === 0) {
            tbody.innerHTML = `<tr><td colspan="4" class="empty-cell">No network devices recorded yet.</td></tr>`;
            return;
        }

        slice.forEach(d => {
            const tr = document.createElement('tr');
            const isSuspicious = d.status === 'Suspicious';
            tr.innerHTML = `
                <td class="font-mono"><strong>${escapeHtml(d.ip)}</strong></td>
                <td class="font-mono">${escapeHtml(d.mac)}</td>
                <td class="font-mono">${escapeHtml(d.last_seen || '—')}</td>
                <td>
                    <span class="status-badge ${isSuspicious ? 'suspicious-status' : 'active-status'}">
                        ${escapeHtml(d.status || 'Active')}
                    </span>
                </td>
            `;
            tbody.appendChild(tr);
        });
    }

    // -------------------------------------------------------------------------
    // 8. Security Events & ARP Detection
    // -------------------------------------------------------------------------
    async function loadEvents() {
        try {
            const events = await api('/api/events');
            state.events = events || [];
            renderEvents();
            renderOverviewAlerts();
            renderArpTable();
            renderNotificationDrawer();
        } catch (error) {
            console.error('Error loading events:', error);
        }
    }

    function renderEvents() {
        const tbody = $('eventTableBody');
        if (!tbody) return;

        // Filter events
        let filtered = state.events.filter(e => {
            const search = state.eventSearch.toLowerCase();
            const matchesSearch = !search ||
                (e.ip && e.ip.toLowerCase().includes(search)) ||
                (e.mac && e.mac.toLowerCase().includes(search)) ||
                (e.previous_mac && e.previous_mac.toLowerCase().includes(search)) ||
                (e.type && e.type.toLowerCase().includes(search)) ||
                (e.description && e.description.toLowerCase().includes(search));

            const matchesSeverity = state.eventSeverityFilter === 'ALL' || e.severity === state.eventSeverityFilter;

            let matchesStatus = true;
            if (state.eventStatusFilter === 'UNACK') matchesStatus = !e.acknowledged;
            if (state.eventStatusFilter === 'ACK') matchesStatus = Boolean(e.acknowledged);

            return matchesSearch && matchesSeverity && matchesStatus;
        });

        // Pagination
        const total = filtered.length;
        const totalPages = Math.ceil(total / state.eventPageSize) || 1;
        if (state.eventPage > totalPages) state.eventPage = totalPages;
        if (state.eventPage < 1) state.eventPage = 1;

        const startIdx = (state.eventPage - 1) * state.eventPageSize;
        const pageItems = filtered.slice(startIdx, startIdx + state.eventPageSize);

        if ($('eventPaginationInfo')) {
            const startDisplay = total === 0 ? 0 : startIdx + 1;
            const endDisplay = Math.min(startIdx + state.eventPageSize, total);
            $('eventPaginationInfo').textContent = `Showing ${startDisplay}-${endDisplay} of ${total} events`;
        }
        if ($('eventPageNum')) $('eventPageNum').textContent = `Page ${state.eventPage} of ${totalPages}`;
        if ($('eventPrevBtn')) $('eventPrevBtn').disabled = state.eventPage <= 1;
        if ($('eventNextBtn')) $('eventNextBtn').disabled = state.eventPage >= totalPages;

        tbody.innerHTML = '';

        if (pageItems.length === 0) {
            tbody.innerHTML = `<tr><td colspan="10" class="empty-cell">No security events found matching criteria.</td></tr>`;
            return;
        }

        pageItems.forEach(e => {
            const tr = document.createElement('tr');

            const severityClass = `severity-badge ${e.severity}`;
            const isAck = Boolean(e.acknowledged);

            tr.innerHTML = `
                <td class="font-mono"><strong>#EVT-${String(e.id).padStart(3, '0')}</strong></td>
                <td class="font-mono">${escapeHtml(e.timestamp || '—')}</td>
                <td><span class="font-mono">${escapeHtml(e.type)}</span></td>
                <td><span class="${severityClass}">${escapeHtml(e.severity)}</span></td>
                <td class="font-mono"><strong>${escapeHtml(e.ip || '—')}</strong></td>
                <td class="font-mono">${escapeHtml(e.previous_mac || '—')}</td>
                <td class="font-mono">${escapeHtml(e.mac || '—')}</td>
                <td style="max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(e.description)}">
                    ${escapeHtml(e.description)}
                </td>
                <td>
                    <span class="status-badge ${isAck ? 'active-status' : 'suspicious-status'}">
                        ${escapeHtml(e.investigation_status || (isAck ? 'Acknowledged' : 'Pending'))}
                    </span>
                </td>
                <td class="text-right">
                    ${!isAck ? `
                        <button class="chrome-btn btn-primary btn-sm ack-event-btn" data-id="${e.id}">
                            Acknowledge
                        </button>
                    ` : `
                        <button class="chrome-btn btn-silver btn-sm review-event-btn" data-id="${e.id}">
                            Investigate
                        </button>
                    `}
                </td>
            `;

            tbody.appendChild(tr);
        });

        // Bind action buttons
        tbody.querySelectorAll('.ack-event-btn').forEach(btn => {
            btn.addEventListener('click', async () => {
                const id = btn.getAttribute('data-id');
                await acknowledgeEvent(id);
            });
        });

        tbody.querySelectorAll('.review-event-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const id = btn.getAttribute('data-id');
                openInvestigationModal(id);
            });
        });
    }

    function renderOverviewAlerts() {
        const tbody = $('overviewAlertRows');
        if (!tbody) return;

        const alerts = state.events.filter(e => e.severity === 'HIGH').slice(0, 5);
        tbody.innerHTML = '';

        if (alerts.length === 0) {
            tbody.innerHTML = `<tr><td colspan="4" class="empty-cell">No high-severity alerts logged. Baseline normal.</td></tr>`;
            return;
        }

        alerts.forEach(e => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td class="font-mono">${escapeHtml(e.timestamp || '—')}</td>
                <td><span class="severity-badge HIGH">HIGH</span></td>
                <td class="font-mono">${escapeHtml(e.ip || '—')}: ${escapeHtml(e.type)}</td>
                <td class="text-right">
                    ${!e.acknowledged ? `
                        <button class="chrome-btn btn-primary btn-sm ack-overview-btn" data-id="${e.id}">
                            Ack
                        </button>
                    ` : `
                        <span class="status-badge active-status">Reviewed</span>
                    `}
                </td>
            `;
            tbody.appendChild(tr);
        });

        tbody.querySelectorAll('.ack-overview-btn').forEach(btn => {
            btn.addEventListener('click', async () => {
                const id = btn.getAttribute('data-id');
                await acknowledgeEvent(id);
            });
        });
    }

    function renderArpTable() {
        const tbody = $('arpTableBody');
        const counter = $('arpAnomaliesCount');
        if (!tbody) return;

        const arpEvents = state.events.filter(e => e.type === 'ARP_MAPPING_CHANGE');
        if (counter) counter.textContent = `${arpEvents.length} Anomalies Detected`;

        tbody.innerHTML = '';

        if (arpEvents.length === 0) {
            tbody.innerHTML = `<tr><td colspan="8" class="empty-cell">No ARP mapping changes observed. Network baseline is stable.</td></tr>`;
            return;
        }

        arpEvents.forEach(e => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td class="font-mono"><strong>#ARP-${String(e.id).padStart(3, '0')}</strong></td>
                <td class="font-mono">${escapeHtml(e.timestamp || '—')}</td>
                <td class="font-mono"><strong>${escapeHtml(e.ip)}</strong></td>
                <td class="font-mono" style="color: #59636D;">${escapeHtml(e.previous_mac)}</td>
                <td class="font-mono" style="color: #DC2626; font-weight: 700;">${escapeHtml(e.mac)}</td>
                <td><span class="severity-badge HIGH">CRITICAL</span></td>
                <td>
                    <span class="status-badge ${e.acknowledged ? 'active-status' : 'suspicious-status'}">
                        ${escapeHtml(e.investigation_status || 'Pending Review')}
                    </span>
                </td>
                <td class="text-right">
                    <button class="chrome-btn btn-silver btn-sm arp-review-btn" data-id="${e.id}">
                        Forensic Review
                    </button>
                </td>
            `;
            tbody.appendChild(tr);
        });

        tbody.querySelectorAll('.arp-review-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const id = btn.getAttribute('data-id');
                openInvestigationModal(id);
            });
        });
    }

    function renderNotificationDrawer() {
        const list = $('notificationList');
        if (!list) return;

        const unacked = state.events.filter(e => e.severity === 'HIGH' && !e.acknowledged);
        list.innerHTML = '';

        if (unacked.length === 0) {
            list.innerHTML = `<div class="drawer-empty">No unacknowledged critical alerts.</div>`;
            return;
        }

        unacked.forEach(e => {
            const item = document.createElement('div');
            item.className = 'drawer-item';
            item.innerHTML = `
                <div class="drawer-item-title">
                    <span>${escapeHtml(e.type)}</span>
                    <span class="drawer-item-time">${escapeHtml(e.timestamp)}</span>
                </div>
                <div class="drawer-item-desc">${escapeHtml(e.description)}</div>
                <button class="chrome-btn btn-primary btn-sm ack-drawer-btn" data-id="${e.id}" style="margin-top: 6px;">
                    Acknowledge
                </button>
            `;
            list.appendChild(item);
        });

        list.querySelectorAll('.ack-drawer-btn').forEach(btn => {
            btn.addEventListener('click', async () => {
                const id = btn.getAttribute('data-id');
                await acknowledgeEvent(id);
            });
        });
    }

    async function acknowledgeEvent(id) {
        try {
            await api(`/api/events/${id}/ack`, { method: 'POST' });
            showFeedback(`Security event #${id} acknowledged.`, 'success');
            await refreshAll();
        } catch (error) {
            showFeedback('Failed to acknowledge event: ' + error.message, 'error');
        }
    }

    // -------------------------------------------------------------------------
    // 9. Modals (Investigation & Confirmation)
    // -------------------------------------------------------------------------
    function openInvestigationModal(eventId) {
        const event = state.events.find(e => String(e.id) === String(eventId));
        if (!event) return;

        state.selectedEvent = event;

        if ($('modalEventTitle')) $('modalEventTitle').textContent = `Investigate Security Event #${event.id}`;
        if ($('modalEventType')) $('modalEventType').textContent = event.type;
        if ($('modalEventTime')) $('modalEventTime').textContent = event.timestamp;
        if ($('modalEventIp')) $('modalEventIp').textContent = event.ip || '—';
        if ($('modalEventPrevMac')) $('modalEventPrevMac').textContent = event.previous_mac || '—';
        if ($('modalEventNewMac')) $('modalEventNewMac').textContent = event.mac || '—';
        if ($('modalEventDesc')) $('modalEventDesc').textContent = event.description || '—';

        const statusSelect = $('modalStatusSelect');
        if (statusSelect) {
            statusSelect.value = event.investigation_status || 'Pending Review';
        }

        const modal = $('investigationModal');
        if (modal) modal.style.display = 'flex';
    }

    function closeInvestigationModal() {
        const modal = $('investigationModal');
        if (modal) modal.style.display = 'none';
        state.selectedEvent = null;
    }

    async function saveInvestigationStatus() {
        if (!state.selectedEvent) return;

        const statusSelect = $('modalStatusSelect');
        const newStatus = statusSelect ? statusSelect.value : 'Acknowledged';

        try {
            await api(`/api/events/${state.selectedEvent.id}/status`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ status: newStatus })
            });

            showFeedback(`Event #${state.selectedEvent.id} updated to "${newStatus}".`, 'success');
            closeInvestigationModal();
            await refreshAll();
        } catch (error) {
            showFeedback('Failed to update event: ' + error.message, 'error');
        }
    }

    function openClearModal() {
        const modal = $('confirmClearModal');
        if (modal) modal.style.display = 'flex';
    }

    function closeClearModal() {
        const modal = $('confirmClearModal');
        if (modal) modal.style.display = 'none';
    }

    // -------------------------------------------------------------------------
    // 10. Network Activity Chart (Metallic Silver Visualization)
    // -------------------------------------------------------------------------
    function initChart() {
        const canvas = $('activityChart');
        if (!canvas) return;

        if (typeof Chart === 'undefined') {
            const fallback = $('chartFallback');
            if (fallback) fallback.style.display = 'block';
            return;
        }

        const ctx = canvas.getContext('2d');

        // Create metallic silver gradient fills
        const gradSilver = ctx.createLinearGradient(0, 0, 0, 260);
        gradSilver.addColorStop(0, 'rgba(89, 99, 109, 0.45)');
        gradSilver.addColorStop(0.5, 'rgba(197, 201, 206, 0.2)');
        gradSilver.addColorStop(1, 'rgba(197, 201, 206, 0.0)');

        const gradGreen = ctx.createLinearGradient(0, 0, 0, 260);
        gradGreen.addColorStop(0, 'rgba(16, 185, 129, 0.35)');
        gradGreen.addColorStop(1, 'rgba(16, 185, 129, 0.0)');

        const labels = ['-50m', '-40m', '-30m', '-20m', '-10m', 'Now'];
        const obsData = [12, 19, 28, 42, 65, 84];
        const devData = [1, 2, 4, 5, 7, 8];
        const alertData = [0, 0, 1, 0, 2, 1];

        state.chart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [
                    {
                        label: 'ARP Observations',
                        data: obsData,
                        borderColor: '#252B32',
                        backgroundColor: gradSilver,
                        borderWidth: 2,
                        tension: 0.35,
                        fill: true,
                        pointBackgroundColor: '#FFFFFF',
                        pointBorderColor: '#252B32',
                        pointRadius: 4
                    },
                    {
                        label: 'Host Discoveries',
                        data: devData,
                        borderColor: '#059669',
                        backgroundColor: gradGreen,
                        borderWidth: 2,
                        tension: 0.35,
                        fill: true,
                        pointBackgroundColor: '#10B981',
                        pointBorderColor: '#FFFFFF',
                        pointRadius: 4
                    },
                    {
                        label: 'Suspicious Anomalies',
                        data: alertData,
                        borderColor: '#DC2626',
                        backgroundColor: 'rgba(220, 38, 38, 0.2)',
                        borderWidth: 2,
                        borderDash: [4, 4],
                        tension: 0.2,
                        fill: false,
                        pointBackgroundColor: '#DC2626',
                        pointRadius: 5
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: '#252B32',
                        titleColor: '#FFFFFF',
                        bodyColor: '#DCE0E5',
                        borderColor: '#8C949D',
                        borderWidth: 1,
                        padding: 10,
                        bodyFont: { family: 'JetBrains Mono' }
                    }
                },
                scales: {
                    x: {
                        grid: { color: 'rgba(140, 148, 157, 0.25)' },
                        ticks: { color: '#59636D', font: { family: 'JetBrains Mono', size: 10.5 } }
                    },
                    y: {
                        grid: { color: 'rgba(140, 148, 157, 0.25)' },
                        ticks: { color: '#59636D', font: { family: 'JetBrains Mono', size: 10.5 } },
                        beginAtZero: true
                    }
                }
            }
        });
    }

    function updateChartData() {
        if (!state.chart) return;

        // Base points on actual devices & events
        const totalDev = state.devices.length || 0;
        const totalEvents = state.events.length || 0;
        const totalAlerts = state.events.filter(e => e.severity === 'HIGH').length || 0;

        const lastObs = (state.status.packet_count || 0) + (totalDev * 12);

        const newObs = [
            Math.max(2, Math.floor(lastObs * 0.2)),
            Math.max(5, Math.floor(lastObs * 0.4)),
            Math.max(10, Math.floor(lastObs * 0.6)),
            Math.max(15, Math.floor(lastObs * 0.75)),
            Math.max(20, Math.floor(lastObs * 0.9)),
            lastObs
        ];

        const newDev = [
            Math.max(1, Math.floor(totalDev * 0.3)),
            Math.max(1, Math.floor(totalDev * 0.5)),
            Math.max(2, Math.floor(totalDev * 0.7)),
            Math.max(2, Math.floor(totalDev * 0.85)),
            totalDev,
            totalDev
        ];

        const newAlerts = [0, 0, Math.min(1, totalAlerts), 0, Math.floor(totalAlerts * 0.8), totalAlerts];

        state.chart.data.datasets[0].data = newObs;
        state.chart.data.datasets[1].data = newDev;
        state.chart.data.datasets[2].data = newAlerts;
        state.chart.update('none');
    }

    // -------------------------------------------------------------------------
    // 11. Navigation & View Switching
    // -------------------------------------------------------------------------
    function switchView(viewName) {
        // Hide all views
        $$('.dashboard-view').forEach(view => {
            view.style.display = 'none';
            view.classList.remove('active-view');
        });

        // Show selected view
        const targetView = $(`view-${viewName}`);
        if (targetView) {
            targetView.style.display = 'block';
            targetView.classList.add('active-view');
        }

        // Update active nav link
        $$('.sidebar-nav .nav-link').forEach(link => {
            if (link.getAttribute('data-view') === viewName) {
                link.classList.add('active');
            } else {
                link.classList.remove('active');
            }
        });

        // Update Breadcrumb text
        const breadcrumbMap = {
            'overview': 'Dashboard Overview',
            'monitoring': 'Live Network Monitoring Center',
            'devices': 'Network Device Inventory',
            'events': 'Security Event Center',
            'arp-detection': 'ARP Threat & Mapping Anomaly Analysis',
            'reports': 'Forensic Reports & Data Export',
            'settings': 'Operational Settings & Controls'
        };
        if ($('breadcrumbActive')) {
            $('breadcrumbActive').textContent = breadcrumbMap[viewName] || 'Dashboard';
        }

        // Close mobile sidebar if open
        const sidebar = $('sidebar');
        if (sidebar) sidebar.classList.remove('open');

        // Close notification drawer
        const drawer = $('notificationDrawer');
        if (drawer) drawer.style.display = 'none';
    }

    // -------------------------------------------------------------------------
    // 12. Full Telemetry Refresh
    // -------------------------------------------------------------------------
    async function refreshAll() {
        const refreshIcon = $('refreshIcon');
        if (refreshIcon) refreshIcon.style.animation = 'spin 0.6s linear';

        try {
            await Promise.all([
                loadStatus(),
                loadStats(),
                loadDevices(),
                loadEvents()
            ]);

            updateChartData();

            if ($('footerLastSync')) {
                $('footerLastSync').textContent = `Synced: ${new Date().toLocaleTimeString()}`;
            }
        } catch (error) {
            console.warn('Periodic refresh partial error:', error);
        } finally {
            if (refreshIcon) {
                setTimeout(() => { refreshIcon.style.animation = ''; }, 600);
            }
        }
    }

    // -------------------------------------------------------------------------
    // 13. Event Listeners & Hotkeys
    // -------------------------------------------------------------------------
    function bindEventListeners() {
        // Navigation links
        $$('[data-view]').forEach(elem => {
            elem.addEventListener('click', e => {
                const view = elem.getAttribute('data-view');
                if (view) {
                    e.preventDefault();
                    switchView(view);
                }
            });
        });

        // Hash change support
        window.addEventListener('hashchange', () => {
            const hash = window.location.hash.replace('#', '') || 'overview';
            switchView(hash);
        });

        // Mobile Menu Toggle
        const menuBtn = $('mobileMenuBtn');
        if (menuBtn) {
            menuBtn.addEventListener('click', () => {
                const sidebar = $('sidebar');
                if (sidebar) sidebar.classList.toggle('open');
            });
        }

        // Global Refresh buttons
        const globalRef = $('globalRefreshBtn');
        if (globalRef) globalRef.addEventListener('click', () => {
            refreshAll();
            showFeedback('Dashboard data refreshed.', 'info', 2000);
        });

        const sectionRef = $('refreshBtn');
        if (sectionRef) sectionRef.addEventListener('click', () => {
            refreshAll();
            showFeedback('Refreshed telemetry.', 'info', 2000);
        });

        // Start / Stop / Demo / Threat Simulation
        if ($('startBtn')) $('startBtn').addEventListener('click', startMonitoring);
        if ($('stopBtn')) $('stopBtn').addEventListener('click', stopMonitoring);
        if ($('startBtn2')) $('startBtn2').addEventListener('click', startMonitoring);
        if ($('stopBtn2')) $('stopBtn2').addEventListener('click', stopMonitoring);
        if ($('demoBtn')) $('demoBtn').addEventListener('click', triggerDemoData);
        if ($('simulateAttackBtn')) $('simulateAttackBtn').addEventListener('click', triggerSimulateAttack);

        // Global Search
        const searchInput = $('globalSearchInput');
        const clearBtn = $('searchClearBtn');

        if (searchInput) {
            searchInput.addEventListener('input', () => {
                const val = searchInput.value.trim();
                state.deviceSearch = val;
                state.eventSearch = val;

                if (clearBtn) clearBtn.style.display = val ? 'inline-block' : 'none';

                renderDevices();
                renderEvents();
            });
        }

        if (clearBtn) {
            clearBtn.addEventListener('click', () => {
                if (searchInput) searchInput.value = '';
                state.deviceSearch = '';
                state.eventSearch = '';
                clearBtn.style.display = 'none';
                renderDevices();
                renderEvents();
            });
        }

        // Keyboard Shortcut: Ctrl + K
        window.addEventListener('keydown', e => {
            if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
                e.preventDefault();
                if (searchInput) {
                    searchInput.focus();
                    searchInput.select();
                }
            }
            if (e.key === 'Escape') {
                closeInvestigationModal();
                closeClearModal();
                const drawer = $('notificationDrawer');
                if (drawer) drawer.style.display = 'none';
            }
        });

        // Notification Bell Toggle
        const notifBtn = $('notificationBtn');
        const notifDrawer = $('notificationDrawer');
        if (notifBtn && notifDrawer) {
            notifBtn.addEventListener('click', () => {
                const isHidden = notifDrawer.style.display === 'none';
                notifDrawer.style.display = isHidden ? 'flex' : 'none';
            });
        }

        if ($('closeNotificationDrawer')) {
            $('closeNotificationDrawer').addEventListener('click', () => {
                if (notifDrawer) notifDrawer.style.display = 'none';
            });
        }

        if ($('viewAllEventsBtn')) {
            $('viewAllEventsBtn').addEventListener('click', () => {
                switchView('events');
            });
        }

        // Defensive Advisory Banner Dismiss
        if ($('dismissAdvisory')) {
            $('dismissAdvisory').addEventListener('click', () => {
                const bar = document.querySelector('.defensive-advisory-bar');
                if (bar) bar.style.display = 'none';
            });
        }

        if ($('feedbackClose')) {
            $('feedbackClose').addEventListener('click', () => {
                const banner = $('feedbackBanner');
                if (banner) banner.style.display = 'none';
            });
        }

        // Device Inventory Toolbar
        if ($('deviceSearchInput')) {
            $('deviceSearchInput').addEventListener('input', e => {
                state.deviceSearch = e.target.value.trim();
                state.devicePage = 1;
                renderDevices();
            });
        }

        $$('.toolbar-filters .filter-chip').forEach(chip => {
            chip.addEventListener('click', () => {
                $$('.toolbar-filters .filter-chip').forEach(c => c.classList.remove('active'));
                chip.classList.add('active');
                state.deviceFilter = chip.getAttribute('data-filter') || 'all';
                state.devicePage = 1;
                renderDevices();
            });
        });

        if ($('devicePageSize')) {
            $('devicePageSize').addEventListener('change', e => {
                state.devicePageSize = parseInt(e.target.value, 10) || 25;
                state.devicePage = 1;
                renderDevices();
            });
        }

        if ($('devicePrevBtn')) {
            $('devicePrevBtn').addEventListener('click', () => {
                if (state.devicePage > 1) {
                    state.devicePage--;
                    renderDevices();
                }
            });
        }

        if ($('deviceNextBtn')) {
            $('deviceNextBtn').addEventListener('click', () => {
                state.devicePage++;
                renderDevices();
            });
        }

        if ($('refreshDevicesBtn')) {
            $('refreshDevicesBtn').addEventListener('click', () => {
                loadDevices();
                showFeedback('Device inventory refreshed.', 'info', 2000);
            });
        }

        // Sortable Device Columns
        $$('#devicesTable th.sortable').forEach(th => {
            th.addEventListener('click', () => {
                const col = th.getAttribute('data-sort');
                if (state.deviceSortCol === col) {
                    state.deviceSortAsc = !state.deviceSortAsc;
                } else {
                    state.deviceSortCol = col;
                    state.deviceSortAsc = true;
                }
                renderDevices();
            });
        });

        // Security Events Toolbar
        if ($('eventSearchInput')) {
            $('eventSearchInput').addEventListener('input', e => {
                state.eventSearch = e.target.value.trim();
                state.eventPage = 1;
                renderEvents();
            });
        }

        if ($('eventSeveritySelect')) {
            $('eventSeveritySelect').addEventListener('change', e => {
                state.eventSeverityFilter = e.target.value;
                state.eventPage = 1;
                renderEvents();
            });
        }

        if ($('eventStatusSelect')) {
            $('eventStatusSelect').addEventListener('change', e => {
                state.eventStatusFilter = e.target.value;
                state.eventPage = 1;
                renderEvents();
            });
        }

        if ($('eventPrevBtn')) {
            $('eventPrevBtn').addEventListener('click', () => {
                if (state.eventPage > 1) {
                    state.eventPage--;
                    renderEvents();
                }
            });
        }

        if ($('eventNextBtn')) {
            $('eventNextBtn').addEventListener('click', () => {
                state.eventPage++;
                renderEvents();
            });
        }

        if ($('refreshEventsBtn')) {
            $('refreshEventsBtn').addEventListener('click', () => {
                loadEvents();
                showFeedback('Security events refreshed.', 'info', 2000);
            });
        }

        // Chart Filter Buttons
        $$('.chart-filter-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                $$('.chart-filter-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                state.chartRange = btn.getAttribute('data-range') || '1h';
                updateChartData();
            });
        });

        // Modals Buttons
        if ($('closeModalBtn')) $('closeModalBtn').addEventListener('click', closeInvestigationModal);
        if ($('modalCancelBtn')) $('modalCancelBtn').addEventListener('click', closeInvestigationModal);
        if ($('modalSaveBtn')) $('modalSaveBtn').addEventListener('click', saveInvestigationStatus);

        if ($('settingsClearBtn')) $('settingsClearBtn').addEventListener('click', openClearModal);
        if ($('closeClearModalBtn')) $('closeClearModalBtn').addEventListener('click', closeClearModal);
        if ($('cancelClearBtn')) $('cancelClearBtn').addEventListener('click', closeClearModal);
        if ($('executeClearBtn')) $('executeClearBtn').addEventListener('click', triggerResetDatabase);
        if ($('settingsSeedBtn')) $('settingsSeedBtn').addEventListener('click', triggerDemoData);

        // Reports View Actions
        if ($('printReportBtn')) {
            $('printReportBtn').addEventListener('click', () => {
                window.print();
            });
        }

        if ($('exportJsonBtn')) {
            $('exportJsonBtn').addEventListener('click', () => {
                const bundle = {
                    metadata: {
                        system: 'NETGUARD Network Security & ARP Threat Detection',
                        exported_at: new Date().toISOString(),
                        version: '2.4-Metallic'
                    },
                    status: state.status,
                    stats: state.stats,
                    devices: state.devices,
                    events: state.events
                };

                const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `netguard_forensic_bundle_${Date.now()}.json`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                showFeedback('Forensic JSON bundle generated and downloaded.', 'success');
            });
        }

        // Settings View Actions
        if ($('settingPollingInterval')) {
            $('settingPollingInterval').addEventListener('change', e => {
                const interval = parseInt(e.target.value, 10);
                state.pollingIntervalMs = interval;
                resetPollingLoop();
                showFeedback(`Polling frequency updated to ${interval === 0 ? 'Manual' : interval / 1000 + 's'}.`, 'info');
            });
        }

        if ($('settingAudioAlerts')) {
            $('settingAudioAlerts').addEventListener('change', e => {
                state.audioAlerts = e.target.checked;
                showFeedback(`Audible chime alerts ${state.audioAlerts ? 'enabled' : 'disabled'}.`, 'info');
            });
        }
    }

    // -------------------------------------------------------------------------
    // 14. Polling Loop
    // -------------------------------------------------------------------------
    function resetPollingLoop() {
        if (state.pollingTimer) clearInterval(state.pollingTimer);

        if (state.pollingIntervalMs > 0) {
            state.pollingTimer = setInterval(refreshAll, state.pollingIntervalMs);
        }
    }

    // Utility: HTML Sanitizer
    function escapeHtml(str) {
        if (str === null || str === undefined) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    // -------------------------------------------------------------------------
    // 15. System Initialization
    // -------------------------------------------------------------------------
    async function init() {
        console.log('%c NETGUARD %c Metallic Silver Cybersecurity Core Loaded ',
            'background: #252B32; color: #FFFFFF; font-weight: bold; padding: 4px;',
            'background: #C5C9CE; color: #252B32; font-weight: bold; padding: 4px;');

        bindEventListeners();
        initChart();

        // Initial view resolution from hash
        const initialHash = window.location.hash.replace('#', '') || 'overview';
        switchView(initialHash);

        // Load data
        await loadInterfaces();
        await refreshAll();

        // Start background polling
        resetPollingLoop();

        // Initialize Lucide icons
        if (window.lucide) {
            window.lucide.createIcons();
        }
    }

    // Run on DOM ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

})();
