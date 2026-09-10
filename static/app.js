/**
 * Network Security Port Scanner - Frontend Controller
 * Handles UI interactions, scan requests, live timer, and table filtering.
 */

document.addEventListener("DOMContentLoaded", () => {
    // Form & Controls
    const scanForm = document.getElementById("scanForm");
    const targetInput = document.getElementById("targetInput");
    const startPortInput = document.getElementById("startPort");
    const endPortInput = document.getElementById("endPort");
    const customPortsInput = document.getElementById("customPortsInput");
    const timeoutSlider = document.getElementById("timeoutSlider");
    const timeoutValue = document.getElementById("timeoutValue");
    const startScanBtn = document.getElementById("startScanBtn");
    const resetBtn = document.getElementById("resetBtn");

    // Sections & Cards
    const errorAlert = document.getElementById("errorAlert");
    const errorMessage = document.getElementById("errorMessage");
    const dismissError = document.getElementById("dismissError");
    const progressCard = document.getElementById("progressCard");
    const elapsedTimer = document.getElementById("elapsedTimer");
    const progressStatus = document.getElementById("progressStatus");
    const summaryCards = document.getElementById("summaryCards");

    // Metric Elements
    const metricIp = document.getElementById("metricIp");
    const metricTotal = document.getElementById("metricTotal");
    const metricOpen = document.getElementById("metricOpen");
    const metricClosed = document.getElementById("metricClosed");
    const metricTime = document.getElementById("metricTime");

    // Table & Filters
    const resultsTable = document.getElementById("resultsTable");
    const tableBody = document.getElementById("tableBody");
    const resultsCount = document.getElementById("resultsCount");
    const filterOpenCount = document.getElementById("filterOpenCount");
    const tableSearch = document.getElementById("tableSearch");
    const filterButtons = document.querySelectorAll(".filter-btn");

    // State
    let currentMode = "range";
    let scanResults = [];
    let currentFilter = "all";
    let timerInterval = null;
    let scanStartTime = 0;

    // Timeout slider feedback
    timeoutSlider.addEventListener("input", (e) => {
        timeoutValue.textContent = `${e.target.value}s`;
    });

    // Mode tab selection
    const modeTabs = document.querySelectorAll(".tab-btn");
    const modeSections = {
        range: document.getElementById("rangeInputs"),
        preset: document.getElementById("presetInputs"),
        custom: document.getElementById("customInputs"),
    };

    modeTabs.forEach((tab) => {
        tab.addEventListener("click", () => {
            modeTabs.forEach((t) => t.classList.remove("active"));
            tab.classList.add("active");
            currentMode = tab.dataset.mode;

            Object.entries(modeSections).forEach(([mode, el]) => {
                if (mode === currentMode) {
                    el.classList.remove("hidden");
                } else {
                    el.classList.add("hidden");
                }
            });
        });
    });

    // Target presets
    document.querySelectorAll(".preset-btn").forEach((btn) => {
        btn.addEventListener("click", () => {
            targetInput.value = btn.dataset.target;
            targetInput.focus();
        });
    });

    // Range presets
    document.querySelectorAll(".range-chip").forEach((chip) => {
        chip.addEventListener("click", () => {
            startPortInput.value = chip.dataset.start;
            endPortInput.value = chip.dataset.end;
        });
    });

    // Error dismiss
    dismissError.addEventListener("click", () => {
        errorAlert.classList.add("hidden");
    });

    function showError(msg) {
        errorMessage.textContent = msg;
        errorAlert.classList.remove("hidden");
    }

    function clearError() {
        errorAlert.classList.add("hidden");
    }

    // Reset button
    resetBtn.addEventListener("click", () => {
        targetInput.value = "127.0.0.1";
        startPortInput.value = "20";
        endPortInput.value = "100";
        customPortsInput.value = "21, 22, 80, 135, 443, 445, 3306, 5000";
        timeoutSlider.value = "0.4";
        timeoutValue.textContent = "0.4s";
        clearError();
    });

    // Form Submission / Start Scan
    scanForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        clearError();

        const target = targetInput.value.trim();
        if (!target) {
            showError("Please specify a target hostname or IP address.");
            return;
        }

        const payload = {
            target,
            mode: currentMode,
            timeout: parseFloat(timeoutSlider.value),
        };

        if (currentMode === "range") {
            const start = parseInt(startPortInput.value, 10);
            const end = parseInt(endPortInput.value, 10);

            if (isNaN(start) || isNaN(end) || start < 1 || end > 65535) {
                showError("Invalid port range. Ports must be between 1 and 65535.");
                return;
            }
            if (start > end) {
                showError("Start port cannot be greater than end port.");
                return;
            }
            if ((end - start + 1) > 1024) {
                showError("Maximum range limit is 1024 ports per scan for rapid demo performance.");
                return;
            }

            payload.start_port = start;
            payload.end_port = end;
        } else if (currentMode === "preset") {
            const checkedProfile = document.querySelector('input[name="presetProfile"]:checked');
            payload.preset = checkedProfile ? checkedProfile.value : "top20";
        } else if (currentMode === "custom") {
            const customVal = customPortsInput.value.trim();
            if (!customVal) {
                showError("Please enter at least one port number or sub-range.");
                return;
            }
            payload.custom_ports = customVal;
        }

        // Start scanning UI state
        startScanBtn.disabled = true;
        startScanBtn.querySelector("span").textContent = "Scanning...";
        progressStatus.textContent = `Scanning target '${target}'...`;
        progressCard.classList.remove("hidden");
        elapsedTimer.textContent = "0.0s";

        scanStartTime = performance.now();
        clearInterval(timerInterval);
        timerInterval = setInterval(() => {
            const elapsed = ((performance.now() - scanStartTime) / 1000).toFixed(1);
            elapsedTimer.textContent = `${elapsed}s`;
        }, 100);

        try {
            const response = await fetch("/api/scan", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload),
            });

            const data = await response.json();

            if (!response.ok || !data.success) {
                throw new Error(data.error || `HTTP Error ${response.status}`);
            }

            // Success: Update state & UI
            scanResults = data.results || [];
            updateSummaryMetrics(data);
            renderTable();

        } catch (err) {
            showError(err.message || "Failed to execute scan. Check target reachability or backend connection.");
        } finally {
            clearInterval(timerInterval);
            progressCard.classList.add("hidden");
            startScanBtn.disabled = false;
            startScanBtn.querySelector("span").textContent = "Execute Port Scan";
        }
    });

    function updateSummaryMetrics(data) {
        summaryCards.classList.remove("hidden");
        metricIp.textContent = data.ip;
        metricTotal.textContent = data.total_ports;
        metricOpen.textContent = data.open_count;
        metricClosed.textContent = data.closed_count;
        metricTime.textContent = `${data.duration_seconds}s`;
        filterOpenCount.textContent = data.open_count;
    }

    // Filter switching (All vs Open)
    filterButtons.forEach((btn) => {
        btn.addEventListener("click", () => {
            filterButtons.forEach((b) => b.classList.remove("active"));
            btn.classList.add("active");
            currentFilter = btn.dataset.filter;
            renderTable();
        });
    });

    // Search input filtering
    tableSearch.addEventListener("input", () => {
        renderTable();
    });

    function renderTable() {
        const query = tableSearch.value.toLowerCase().trim();

        const filtered = scanResults.filter((item) => {
            // Status filter
            if (currentFilter === "open" && item.status !== "OPEN") {
                return false;
            }
            // Search query filter
            if (query) {
                const portMatch = item.port.toString().includes(query);
                const serviceMatch = (item.service || "").toLowerCase().includes(query);
                const bannerMatch = (item.banner || "").toLowerCase().includes(query);
                return portMatch || serviceMatch || bannerMatch;
            }
            return true;
        });

        resultsCount.textContent = `${filtered.length} of ${scanResults.length} ports`;

        if (filtered.length === 0) {
            tableBody.innerHTML = `
                <tr class="empty-row">
                    <td colspan="5">
                        <div class="empty-state">
                            <p>${scanResults.length === 0 ? "No active scan yet." : "No ports match the selected filter or search term."}</p>
                        </div>
                    </td>
                </tr>
            `;
            return;
        }

        tableBody.innerHTML = filtered.map((item) => {
            const isOpen = item.status === "OPEN";
            const statusClass = isOpen ? "status-open" : "status-closed";
            const bannerText = item.banner ? escapeHtml(item.banner) : (item.error ? `<span style="color:var(--text-muted);">${escapeHtml(item.error)}</span>` : "-");

            return `
                <tr>
                    <td class="port-num">${item.port}</td>
                    <td class="service-name">${escapeHtml(item.service)}</td>
                    <td>
                        <span class="status-pill ${statusClass}">${item.status}</span>
                    </td>
                    <td class="latency-val">${item.latency_ms} ms</td>
                    <td class="banner-val" title="${escapeHtml(item.banner || item.error || '')}">${bannerText}</td>
                </tr>
            `;
        }).join("");
    }

    function escapeHtml(str) {
        if (!str) return "";
        return str
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
});
