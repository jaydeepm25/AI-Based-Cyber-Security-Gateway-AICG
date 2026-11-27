/* ==========================================================================
   AICG • INDUSTRIAL SOC & OT SECURITY OPERATIONS HMI
   AI-Based Cyber Security Gateway for Industry 4.0
   Client Runtime, Zero-Dependency Canvas Visualizations, SSE Integration
   ========================================================================== */

const startTimeMonotonic = Date.now();
window.currentAutoResponse = true;

/* ==========================================================================
   1. TIME & UPTIME UTILITY
   ========================================================================== */
function updateClockAndUptime() {
    const clockEl = document.getElementById("liveClock");
    const uptimeEl = document.getElementById("liveUptime");
    
    const now = new Date();
    const utcStr = now.toUTCString().split(" ")[4] + " UTC";
    if (clockEl) clockEl.textContent = utcStr;
    
    const elapsedSec = Math.floor((Date.now() - startTimeMonotonic) / 1000);
    const hrs = String(Math.floor(elapsedSec / 3600)).padStart(2, "0");
    const mins = String(Math.floor((elapsedSec % 3600) / 60)).padStart(2, "0");
    const secs = String(elapsedSec % 60).padStart(2, "0");
    if (uptimeEl) uptimeEl.textContent = `Uptime: ${hrs}h ${mins}m ${secs}s`;
}
setInterval(updateClockAndUptime, 1000);
updateClockAndUptime();


/* ==========================================================================
   2. TOP KPI STRIP & STATUS SUMMARY
   ========================================================================== */
function updateSummary(summary, fullStatus) {
    if (!summary || typeof summary !== "object") return;

    const pred = summary.latest_prediction || "NORMAL";
    const isAttack = pred === "ATTACK";
    const activeInc = summary.active_incident;
    const hasActiveIncident = Boolean(activeInc && !["RESOLVED", "CLOSED"].includes(activeInc.lifecycle_state));
    const activeState = hasActiveIncident ? String(activeInc.lifecycle_state).toUpperCase() : null;
    const isThreatActive = isAttack || hasActiveIncident;
    const ddosProb = Number(summary.latest_ddos_probability ?? (isAttack ? 0.99 : 0.05));
    const pps = Number(summary.latest_packet_rate ?? 18.0);
    const byteRate = Number(summary.latest_bytes_per_second ?? 4140.0);
    const secAction = summary.latest_security_action || (isAttack ? "BLOCK" : (isThreatActive ? "ALERT" : "MONITOR"));
    const mitAction = isThreatActive ? (summary.latest_mitigation_action || (isAttack ? "BLOCK" : "NONE")) : "NONE";
    const trustScore = Number(summary.trust_score ?? (isAttack ? 15.0 : 100.0));

    // Card 1: Throughput
    const packetRateEl = document.getElementById("packetRate");
    const throughputEl = document.getElementById("throughput");
    const rateStatusTag = document.getElementById("rateStatusTag");
    if (packetRateEl) packetRateEl.textContent = pps.toFixed(1);
    if (throughputEl) throughputEl.textContent = (byteRate / 1024).toFixed(2);
    if (rateStatusTag) {
        rateStatusTag.textContent = pps > 60 ? "HIGH LOAD" : "NORMAL";
        rateStatusTag.className = `kpi-status-tag ${pps > 60 ? "tag-red" : "tag-blue"}`;
    }

    // Card 2: DDoS Risk Index
    const ddosProbEl = document.getElementById("ddosProbability");
    const threatStatusEl = document.getElementById("threatStatus");
    const threatMetaEl = document.getElementById("threatMeta");
    const classificationEl = document.getElementById("classification");
    const kpiRiskTag = document.getElementById("kpiRiskTag");
    const headerThreatPill = document.getElementById("headerThreatPill");

    const pctStr = `${(ddosProb * 100).toFixed(1)}%`;
    if (ddosProbEl) ddosProbEl.textContent = pctStr;
    if (classificationEl) classificationEl.textContent = pred;

    if (threatStatusEl) {
        threatStatusEl.textContent = isAttack ? "ATTACK" : (hasActiveIncident ? activeState : "CLEAR");
        threatStatusEl.style.color = isThreatActive ? (isAttack ? "var(--red)" : "var(--amber)") : "var(--green)";
    }
    if (threatMetaEl) {
        threatMetaEl.textContent = isAttack
            ? "DDoS Attack Vector Active"
            : (hasActiveIncident ? `Incident ${activeInc.incident_id} (${activeState})` : "Baseline Normal");
    }
    if (kpiRiskTag) {
        kpiRiskTag.textContent = isAttack ? "CRITICAL" : (hasActiveIncident ? activeState : "CLEAR");
        kpiRiskTag.className = `kpi-status-tag ${isAttack ? "tag-red" : (hasActiveIncident ? "tag-amber" : "tag-green")}`;
    }
    if (headerThreatPill) {
        headerThreatPill.className = `threat-state-pill ${isAttack ? "attack" : (hasActiveIncident ? "recovering" : "clear")}`;
        const pillText = isAttack ? "Attack Active" : (hasActiveIncident ? `Threat ${activeState}` : "System Secure");
        headerThreatPill.innerHTML = `<span style="font-size: 8px;">●</span> <span id="threatStatus">${pillText}</span>`;
    }

    // Card 3: Plant State
    const plantStateVal = document.getElementById("plantStateVal");
    if (plantStateVal) {
        plantStateVal.textContent = isAttack ? "ATTACKED" : (hasActiveIncident ? activeState : "CLEAR");
        plantStateVal.style.color = isThreatActive ? (isAttack ? "var(--red)" : "var(--amber)") : "var(--green)";
    }

    // Card 4: Mitigation State
    const securityActionEl = document.getElementById("securityAction");
    const mitigationActionEl = document.getElementById("mitigationAction");
    const mitModeTag = document.getElementById("mitigationModeTag");
    const respPolicyEl = document.getElementById("respPolicyMode");
    const btnRespEl = document.getElementById("btnResponseModeText");

    if (securityActionEl) securityActionEl.textContent = secAction;
    if (mitigationActionEl) {
        mitigationActionEl.textContent = mitAction;
        mitigationActionEl.style.color = isThreatActive ? "var(--red)" : "var(--cyan)";
    }
    if (fullStatus) {
        const mode = (fullStatus.response_mode || "DRY_RUN").replace(/_/g, "-");
        if (mitModeTag) mitModeTag.textContent = mode;
        if (respPolicyEl) respPolicyEl.textContent = `${fullStatus.auto_response ? "AUTO" : "MANUAL"} (${fullStatus.response_mode || "DRY_RUN"})`;
        if (btnRespEl) btnRespEl.textContent = fullStatus.auto_response ? "AUTO: ON" : "MANUAL: ON";
    }

    // Security Status Banner
    updateStatusBanner(pred, ddosProb, summary);

    // Circular Percentage Gauges
    updateCircularGauges(ddosProb, trustScore);
}

function updateStatusBanner(prediction, ddosProb, summary) {
    const banner = document.getElementById("securityStatusBanner");
    const badge = document.getElementById("bannerIconBadge");
    const headline = document.getElementById("bannerHeadline");
    const detail = document.getElementById("bannerDetail");
    const target = document.getElementById("bannerTarget");
    const severity = document.getElementById("severity");

    if (!banner || !headline) return;

    const isAttack = prediction === "ATTACK";
    const activeInc = summary.active_incident;
    const hasActiveIncident = Boolean(activeInc && !["RESOLVED", "CLOSED"].includes(activeInc.lifecycle_state));
    const activeState = hasActiveIncident ? String(activeInc.lifecycle_state).toUpperCase() : (summary.lifecycle_state || "NORMAL");
    const isRecovering = activeState === "RECOVERING" || summary.lifecycle_state === "RECOVERING";

    if (isAttack) {
        banner.className = "security-status-banner banner-threat";
        if (badge) badge.innerHTML = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>';
        const atkType = summary.attack_type || (summary.latest && summary.latest.attack_type) || "UDP_FLOOD";
        headline.textContent = `Anomaly Identified • ${String(atkType).replace(/_/g, " ")} • Source 10.42.0.250 → Gateway-01`;
        if (detail) detail.textContent = "Abnormal packet exhaustion surge detected. Software containment active in dry-run mode.";
        if (target) target.textContent = "GATEWAY-01 (10.42.0.1:5683)";
        if (severity) {
            severity.textContent = summary.severity || "CRITICAL";
            severity.style.color = "var(--red)";
        }
    } else if (isRecovering) {
        banner.className = "security-status-banner banner-recovering";
        if (badge) badge.innerHTML = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>';
        headline.textContent = "Recovering • Traffic Returning to Baseline • Verifying Streak";
        if (detail) detail.textContent = "Telemetry within normal bounds. Awaiting consecutive normal verification windows.";
        if (target) target.textContent = (activeInc && activeInc.incident_id) || "GATEWAY-01";
        if (severity) {
            severity.textContent = "MEDIUM";
            severity.style.color = "var(--amber)";
        }
    } else if (hasActiveIncident) {
        banner.className = "security-status-banner banner-recovering";
        if (badge) badge.innerHTML = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>';
        headline.textContent = `Contained • ${activeState} • Observing Baseline Telemetry`;
        if (detail) detail.textContent = "Simulated software mitigation active. Observing device baseline for qualification.";
        if (target) target.textContent = (activeInc && activeInc.incident_id) || "GATEWAY-01";
        if (severity) {
            severity.textContent = activeInc.severity || "HIGH";
            severity.style.color = "var(--amber)";
        }
    } else {
        banner.className = "security-status-banner";
        if (badge) badge.innerHTML = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="20 6 9 17 4 12"/></svg>';
        headline.textContent = "Normal Baseline • No DDoS Anomaly Observed";
        if (detail) detail.textContent = "Baseline sensor telemetry active across 6LoWPAN mesh. In-process defense pipeline armed.";
        if (target) target.textContent = "GATEWAY (10.42.0.1)";
        if (severity) {
            severity.textContent = "INFO";
            severity.style.color = "var(--green)";
        }
    }
}

function updateCircularGauges(threatProb, trustScore) {
    const circumference = 213.62;

    // 1. AI Threat Confidence Gauge
    const threatCircle = document.getElementById("aiThreatGaugeCircle");
    const threatText = document.getElementById("aiThreatGaugeText");
    if (threatCircle && threatText) {
        const clampedThreat = Math.min(1, Math.max(0, threatProb));
        const offset = circumference - (circumference * clampedThreat);
        threatCircle.style.strokeDashoffset = offset;
        threatText.textContent = `${(clampedThreat * 100).toFixed(0)}%`;
        if (clampedThreat > 0.6) {
            threatCircle.setAttribute("class", "gauge-progress gauge-threat-progress high");
            threatText.style.color = "var(--red)";
        } else if (clampedThreat > 0.25) {
            threatCircle.setAttribute("class", "gauge-progress gauge-threat-progress mid");
            threatText.style.color = "var(--amber)";
        } else {
            threatCircle.setAttribute("class", "gauge-progress gauge-threat-progress");
            threatText.style.color = "var(--cyan)";
        }
    }

    // 2. Trust Posture Gauge
    const trustCircle = document.getElementById("trustGaugeCircle");
    const trustText = document.getElementById("trustGaugeText");
    if (trustCircle && trustText) {
        const clampedTrust = Math.min(100, Math.max(0, trustScore));
        const normTrust = clampedTrust / 100;
        const offset = circumference - (circumference * normTrust);
        trustCircle.style.strokeDashoffset = offset;
        trustText.textContent = `${clampedTrust.toFixed(0)}`;
        if (clampedTrust >= 70) {
            trustCircle.setAttribute("class", "gauge-progress gauge-trust-progress");
            trustText.style.color = "var(--green)";
        } else if (clampedTrust >= 40) {
            trustCircle.setAttribute("class", "gauge-progress gauge-trust-progress mid");
            trustText.style.color = "var(--amber)";
        } else {
            trustCircle.setAttribute("class", "gauge-progress gauge-trust-progress low");
            trustText.style.color = "var(--red)";
        }
    }
}


/* ==========================================================================
   3. OFFLINE-SAFE NATIVE CANVAS VISUALIZATIONS (EXACTLY TWO TIME-SERIES)
   ========================================================================== */

/**
 * Setup a high-DPI canvas context for razor-sharp rendering.
 */
function setupCanvas(canvas) {
    if (!canvas) return null;
    const rect = canvas.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    const parent = canvas.parentElement;
    const width = Math.max(20, Math.floor(rect.width || canvas.clientWidth || (parent ? parent.clientWidth : 300)));
    const height = Math.max(20, Math.floor(rect.height || canvas.clientHeight || (parent ? parent.clientHeight : 150)));

    const targetW = Math.round(width * dpr);
    const targetH = Math.round(height * dpr);

    if (canvas.width !== targetW || canvas.height !== targetH) {
        canvas.width = targetW;
        canvas.height = targetH;
    }
    const ctx = canvas.getContext("2d");
    if (ctx.setTransform) {
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    } else {
        ctx.resetTransform();
        ctx.scale(dpr, dpr);
    }
    return { ctx, width, height };
}

/**
 * Primary Chart #1: Historian • Live OT Network Traffic (Packets / Second)
 * Displays continuous legitimate OT baseline (~18 pps) vs live traffic vs attack surge
 */
function renderHistorianChart(canvas, rows) {
    const setup = setupCanvas(canvas);
    if (!setup) return;
    const { ctx, width, height } = setup;

    ctx.clearRect(0, 0, width, height);

    const padLeft = 45;
    const padRight = 15;
    const padTop = 18;
    const padBottom = 25;
    const chartW = width - padLeft - padRight;
    const chartH = height - padTop - padBottom;

    const dataPoints = (rows && rows.length) ? rows.slice(-30) : [];
    if (!dataPoints.length) {
        ctx.fillStyle = "#64748b";
        ctx.font = "11px Inter, sans-serif";
        ctx.textAlign = "center";
        ctx.fillText("Awaiting live OT telemetry windows...", width / 2, height / 2);
        return;
    }

    const rates = dataPoints.map(r => Number(r.packets_per_second || r.packet_rate || 0));
    const maxVal = Math.max(60, ...rates) * 1.15;
    const baselinePps = 18.0;

    // Draw Grid Lines & Y-Axis Labels
    ctx.strokeStyle = "rgba(70, 100, 140, 0.18)";
    ctx.lineWidth = 1;
    ctx.fillStyle = "#7890a8";
    ctx.font = "9.5px 'JetBrains Mono', monospace";
    ctx.textAlign = "right";

    const ySteps = 4;
    for (let i = 0; i <= ySteps; i++) {
        const yVal = (maxVal / ySteps) * i;
        const yPos = padTop + chartH - (i / ySteps) * chartH;
        ctx.beginPath();
        ctx.moveTo(padLeft, yPos);
        ctx.lineTo(padLeft + chartW, yPos);
        ctx.stroke();
        ctx.fillText(yVal.toFixed(0), padLeft - 6, yPos + 3);
    }

    const xStep = chartW / Math.max(1, dataPoints.length - 1);

    // 1. Draw Legitimate OT Baseline Band (15-20 pps shaded zone)
    const baseBandTopY = padTop + chartH - (20.0 / maxVal) * chartH;
    const baseBandBottomY = padTop + chartH - (14.0 / maxVal) * chartH;
    ctx.fillStyle = "rgba(16, 185, 129, 0.08)";
    ctx.fillRect(padLeft, baseBandTopY, chartW, baseBandBottomY - baseBandTopY);

    // 2. Draw Legitimate Baseline Line (~18 pps dashed green)
    const baseYPos = padTop + chartH - (baselinePps / maxVal) * chartH;
    ctx.save();
    ctx.beginPath();
    ctx.setLineDash([4, 4]);
    ctx.strokeStyle = "#10b981";
    ctx.lineWidth = 1.4;
    ctx.moveTo(padLeft, baseYPos);
    ctx.lineTo(padLeft + chartW, baseYPos);
    ctx.stroke();
    ctx.fillStyle = "#10b981";
    ctx.font = "9px 'JetBrains Mono', monospace";
    ctx.textAlign = "left";
    ctx.fillText("Normal OT Baseline (~18 pps)", padLeft + 6, baseYPos - 4);
    ctx.restore();

    // 3. Check for Attack Surge condition
    const hasAttackSurge = rates.some(r => r > 30.0);

    // 4. Draw Area Fill Under Live Traffic
    ctx.beginPath();
    dataPoints.forEach((r, idx) => {
        const val = Number(r.packets_per_second || r.packet_rate || 0);
        const x = padLeft + idx * xStep;
        const y = padTop + chartH - (val / maxVal) * chartH;
        if (idx === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
    });
    ctx.lineTo(padLeft + (dataPoints.length - 1) * xStep, padTop + chartH);
    ctx.lineTo(padLeft, padTop + chartH);
    ctx.closePath();

    const areaGrad = ctx.createLinearGradient(0, padTop, 0, padTop + chartH);
    if (hasAttackSurge) {
        areaGrad.addColorStop(0, "rgba(244, 63, 94, 0.32)");
        areaGrad.addColorStop(0.6, "rgba(56, 189, 248, 0.12)");
        areaGrad.addColorStop(1, "rgba(16, 185, 129, 0.04)");
    } else {
        areaGrad.addColorStop(0, "rgba(56, 189, 248, 0.22)");
        areaGrad.addColorStop(1, "rgba(56, 189, 248, 0.02)");
    }
    ctx.fillStyle = areaGrad;
    ctx.fill();

    // 5. Draw Live Traffic Curve
    ctx.beginPath();
    dataPoints.forEach((r, idx) => {
        const val = Number(r.packets_per_second || r.packet_rate || 0);
        const x = padLeft + idx * xStep;
        const y = padTop + chartH - (val / maxVal) * chartH;
        if (idx === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = hasAttackSurge ? "#f43f5e" : "#38bdf8";
    ctx.lineWidth = 2.2;
    ctx.stroke();

    // 6. Draw Data Points (color-coded by rate)
    dataPoints.forEach((r, idx) => {
        const val = Number(r.packets_per_second || r.packet_rate || 0);
        const x = padLeft + idx * xStep;
        const y = padTop + chartH - (val / maxVal) * chartH;
        const isSpike = val > 30.0;
        ctx.beginPath();
        ctx.arc(x, y, isSpike ? 3.5 : 2, 0, Math.PI * 2);
        ctx.fillStyle = isSpike ? "#f43f5e" : "#38bdf8";
        ctx.fill();
    });

    // 7. Draw Simulated Throttle Line if active (DRY_RUN)
    const hasThrottle = dataPoints.some(r => ["BLOCK", "RATE_LIMIT", "ISOLATE"].includes(r.security_action || r.mitigation_action || ""));
    if (hasThrottle) {
        ctx.save();
        ctx.beginPath();
        ctx.setLineDash([4, 4]);
        ctx.strokeStyle = "#f59e0b";
        ctx.lineWidth = 1.6;
        dataPoints.forEach((r, idx) => {
            const isMit = ["BLOCK", "RATE_LIMIT", "ISOLATE"].includes(r.security_action || r.mitigation_action || "");
            const raw = Number(r.packets_per_second || r.packet_rate || 0);
            const val = isMit ? Math.max(0, raw - baselinePps) : 0;
            const x = padLeft + idx * xStep;
            const y = padTop + chartH - (val / maxVal) * chartH;
            if (idx === 0) ctx.moveTo(x, y);
            else ctx.lineTo(x, y);
        });
        ctx.stroke();
        ctx.restore();
    }

    // 8. Draw X-Axis Time Labels
    ctx.fillStyle = "#64748b";
    ctx.textAlign = "center";
    ctx.font = "9.5px 'JetBrains Mono', monospace";
    const labelStep = Math.max(1, Math.floor(dataPoints.length / 5));
    for (let i = 0; i < dataPoints.length; i += labelStep) {
        const ts = dataPoints[i].window_start || "";
        const label = ts.includes("T") ? ts.split("T")[1].split(".")[0] : ts.slice(-8);
        const x = padLeft + i * xStep;
        ctx.fillText(label, x, padTop + chartH + 16);
    }
}

/**
 * Primary Chart #2: Resource Impact • Modelled Power Dissipation (mW)
 * Derived software model: Nominal quiescent baseline (~55 mW) vs attack-induced resource dissipation
 */
function renderEnergyChart(canvas, rows) {
    const setup = setupCanvas(canvas);
    if (!setup) return;
    const { ctx, width, height } = setup;

    ctx.clearRect(0, 0, width, height);

    const padLeft = 45;
    const padRight = 15;
    const padTop = 18;
    const padBottom = 25;
    const chartW = width - padLeft - padRight;
    const chartH = height - padTop - padBottom;

    const dataPoints = (rows && rows.length) ? rows.slice(-30) : [];
    if (!dataPoints.length) {
        ctx.fillStyle = "#64748b";
        ctx.font = "11px Inter, sans-serif";
        ctx.textAlign = "center";
        ctx.fillText("Awaiting modelled power dissipation data...", width / 2, height / 2);
        return;
    }

    // Extract energy rate (mW), fallback to cause-based model formula if not present
    const energyVals = dataPoints.map(r => {
        if (r.energy_rate !== undefined && r.energy_rate !== null && Number(r.energy_rate) > 0) {
            return Number(r.energy_rate);
        }
        const pps = Number(r.packets_per_second || r.packet_rate || 18.0);
        return 50.0 + pps * 0.35 + 5.0;
    });

    const baselineVal = 55.0; // Quiescent baseline in mW
    const maxVal = Math.max(100.0, ...energyVals) * 1.15;

    // Draw Grid Lines & Y-Axis Labels (mW)
    ctx.strokeStyle = "rgba(70, 100, 140, 0.18)";
    ctx.lineWidth = 1;
    ctx.fillStyle = "#7890a8";
    ctx.font = "9.5px 'JetBrains Mono', monospace";
    ctx.textAlign = "right";

    const ySteps = 4;
    for (let i = 0; i <= ySteps; i++) {
        const yVal = (maxVal / ySteps) * i;
        const yPos = padTop + chartH - (i / ySteps) * chartH;
        ctx.beginPath();
        ctx.moveTo(padLeft, yPos);
        ctx.lineTo(padLeft + chartW, yPos);
        ctx.stroke();
        ctx.fillText(`${yVal.toFixed(0)} mW`, padLeft - 6, yPos + 3);
    }

    const xStep = chartW / Math.max(1, dataPoints.length - 1);

    // Draw Baseline Reference Line (55 mW dashed green)
    const baseNorm = Math.min(1, baselineVal / maxVal);
    const baseYPos = padTop + chartH - baseNorm * chartH;
    ctx.save();
    ctx.beginPath();
    ctx.setLineDash([4, 4]);
    ctx.strokeStyle = "#10b981";
    ctx.lineWidth = 1.4;
    ctx.moveTo(padLeft, baseYPos);
    ctx.lineTo(padLeft + chartW, baseYPos);
    ctx.stroke();
    ctx.fillStyle = "#10b981";
    ctx.font = "9px 'JetBrains Mono', monospace";
    ctx.textAlign = "left";
    ctx.fillText("Nominal Baseline (55 mW)", padLeft + 6, baseYPos - 4);
    ctx.restore();

    // Draw Critical Saturation Line (110 mW dashed red) if within maxVal
    if (110.0 < maxVal) {
        const critYPos = padTop + chartH - (110.0 / maxVal) * chartH;
        ctx.save();
        ctx.beginPath();
        ctx.setLineDash([3, 3]);
        ctx.strokeStyle = "rgba(244, 63, 94, 0.7)";
        ctx.lineWidth = 1;
        ctx.moveTo(padLeft, critYPos);
        ctx.lineTo(padLeft + chartW, critYPos);
        ctx.stroke();
        ctx.fillStyle = "rgba(244, 63, 94, 0.85)";
        ctx.font = "9px 'JetBrains Mono', monospace";
        ctx.textAlign = "right";
        ctx.fillText("Saturation Threshold (110 mW)", padLeft + chartW - 6, critYPos - 4);
        ctx.restore();
    }

    // Draw Live Modelled Power Dissipation Area Fill
    ctx.beginPath();
    energyVals.forEach((val, idx) => {
        const norm = Math.min(1, Math.max(0, val / maxVal));
        const x = padLeft + idx * xStep;
        const y = padTop + chartH - norm * chartH;
        if (idx === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
    });
    ctx.lineTo(padLeft + (dataPoints.length - 1) * xStep, padTop + chartH);
    ctx.lineTo(padLeft, padTop + chartH);
    ctx.closePath();

    const isHighEnergy = energyVals.some(v => v > 80.0);
    const grad = ctx.createLinearGradient(0, padTop, 0, padTop + chartH);
    if (isHighEnergy) {
        grad.addColorStop(0, "rgba(245, 158, 11, 0.35)");
        grad.addColorStop(0.7, "rgba(245, 158, 11, 0.1)");
        grad.addColorStop(1, "rgba(16, 185, 129, 0.03)");
    } else {
        grad.addColorStop(0, "rgba(16, 185, 129, 0.2)");
        grad.addColorStop(1, "rgba(16, 185, 129, 0.02)");
    }
    ctx.fillStyle = grad;
    ctx.fill();

    // Draw Live Modelled Power Dissipation Curve Line
    ctx.beginPath();
    energyVals.forEach((val, idx) => {
        const norm = Math.min(1, Math.max(0, val / maxVal));
        const x = padLeft + idx * xStep;
        const y = padTop + chartH - norm * chartH;
        if (idx === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = isHighEnergy ? "#f59e0b" : "#10b981";
    ctx.lineWidth = 2.2;
    ctx.stroke();

    // Draw points for each reading
    energyVals.forEach((val, idx) => {
        const norm = Math.min(1, Math.max(0, val / maxVal));
        const x = padLeft + idx * xStep;
        const y = padTop + chartH - norm * chartH;
        const isElevated = val > 75.0;
        ctx.beginPath();
        ctx.arc(x, y, isElevated ? 3.5 : 2, 0, Math.PI * 2);
        ctx.fillStyle = isElevated ? "#f43f5e" : "#f59e0b";
        ctx.fill();
    });

    // Draw X-Axis Time Labels
    ctx.fillStyle = "#64748b";
    ctx.textAlign = "center";
    ctx.font = "9.5px 'JetBrains Mono', monospace";
    const labelStep = Math.max(1, Math.floor(dataPoints.length / 5));
    for (let i = 0; i < dataPoints.length; i += labelStep) {
        const ts = dataPoints[i].window_start || "";
        const label = ts.includes("T") ? ts.split("T")[1].split(".")[0] : ts.slice(-8);
        const x = padLeft + i * xStep;
        ctx.fillText(label, x, padTop + chartH + 16);
    }
}

/**
 * Primary Chart #2: AI Threat • DDoS Probability Curve
 */
function renderThreatChart(canvas, rows) {
    const setup = setupCanvas(canvas);
    if (!setup) return;
    const { ctx, width, height } = setup;

    ctx.clearRect(0, 0, width, height);

    const padLeft = 40;
    const padRight = 15;
    const padTop = 15;
    const padBottom = 25;
    const chartW = width - padLeft - padRight;
    const chartH = height - padTop - padBottom;

    const dataPoints = (rows && rows.length) ? rows.slice(-30) : [];
    if (!dataPoints.length) {
        ctx.fillStyle = "#64748b";
        ctx.font = "11px Inter, sans-serif";
        ctx.textAlign = "center";
        ctx.fillText("Awaiting inference classifications...", width / 2, height / 2);
        return;
    }

    // Draw Grid Lines & Y-Axis Percentage Labels (0% to 100%)
    ctx.strokeStyle = "rgba(70, 100, 140, 0.18)";
    ctx.lineWidth = 1;
    ctx.fillStyle = "#7890a8";
    ctx.font = "9.5px 'JetBrains Mono', monospace";
    ctx.textAlign = "right";

    [0, 25, 50, 75, 100].forEach(pct => {
        const yPos = padTop + chartH - (pct / 100) * chartH;
        ctx.beginPath();
        ctx.moveTo(padLeft, yPos);
        ctx.lineTo(padLeft + chartW, yPos);
        ctx.stroke();
        ctx.fillText(`${pct}%`, padLeft - 6, yPos + 3);
    });

    const xStep = chartW / Math.max(1, dataPoints.length - 1);

    // Draw Mitigation Threshold Line (62% dashed)
    const thresholdY = padTop + chartH - (62 / 100) * chartH;
    ctx.beginPath();
    ctx.setLineDash([5, 4]);
    ctx.strokeStyle = "#f59e0b";
    ctx.lineWidth = 1.5;
    ctx.moveTo(padLeft, thresholdY);
    ctx.lineTo(padLeft + chartW, thresholdY);
    ctx.stroke();
    ctx.setLineDash([]);

    // Draw Normal Baseline Threshold Area (< 10%)
    const baselineY = padTop + chartH - (10 / 100) * chartH;
    ctx.fillStyle = "rgba(16, 185, 129, 0.06)";
    ctx.fillRect(padLeft, baselineY, chartW, (10 / 100) * chartH);

    // Draw DDoS Probability Area Fill
    ctx.beginPath();
    dataPoints.forEach((r, idx) => {
        const prob = Math.min(100, Math.max(0, (r.ddos_probability || 0) * 100));
        const x = padLeft + idx * xStep;
        const y = padTop + chartH - (prob / 100) * chartH;
        if (idx === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
    });
    ctx.lineTo(padLeft + (dataPoints.length - 1) * xStep, padTop + chartH);
    ctx.lineTo(padLeft, padTop + chartH);
    ctx.closePath();
    const grad = ctx.createLinearGradient(0, padTop, 0, padTop + chartH);
    grad.addColorStop(0, "rgba(56, 189, 248, 0.35)");
    grad.addColorStop(1, "rgba(56, 189, 248, 0.02)");
    ctx.fillStyle = grad;
    ctx.fill();

    // Draw DDoS Probability Curve Line
    ctx.beginPath();
    dataPoints.forEach((r, idx) => {
        const prob = Math.min(100, Math.max(0, (r.ddos_probability || 0) * 100));
        const x = padLeft + idx * xStep;
        const y = padTop + chartH - (prob / 100) * chartH;
        if (idx === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = "#38bdf8";
    ctx.lineWidth = 2.2;
    ctx.stroke();

    // Draw Data Point Dots
    dataPoints.forEach((r, idx) => {
        const prob = Math.min(100, Math.max(0, (r.ddos_probability || 0) * 100));
        const x = padLeft + idx * xStep;
        const y = padTop + chartH - (prob / 100) * chartH;
        ctx.beginPath();
        ctx.arc(x, y, 2.5, 0, Math.PI * 2);
        ctx.fillStyle = prob >= 62 ? "#f43f5e" : "#38bdf8";
        ctx.fill();
    });

    // Draw X-Axis Time Labels
    ctx.fillStyle = "#64748b";
    ctx.textAlign = "center";
    const labelStep = Math.max(1, Math.floor(dataPoints.length / 5));
    for (let i = 0; i < dataPoints.length; i += labelStep) {
        const ts = dataPoints[i].window_start || "";
        const label = ts.includes("T") ? ts.split("T")[1].split(".")[0] : ts.slice(-8);
        const x = padLeft + i * xStep;
        ctx.fillText(label, x, padTop + chartH + 16);
    }
}

/**
 * Supporting Non-Time-Series: Protocol Mix Segmented Donut
 * Enterprise SOC analytics visualization with tactile depth, clean segment separation,
 * interactive hover telemetry inspection, and smooth cubic-eased distribution transitions.
 */
const protocolChartState = {
    canvas: null,
    listenersAttached: false,
    categories: [],
    slices: [], // { key, label, count, pct, color, deepColor, currentStart, currentEnd, fromStart, fromEnd, targetStart, targetEnd }
    dominant: null,
    totalCount: 0,
    hoveredKey: null,
    animating: false,
    startTime: 0,
    duration: 320,
    animFrameId: null
};

function renderProtocolDonut(canvas, protocolsData) {
    if (!canvas) return;
    protocolChartState.canvas = canvas;

    const mix = (protocolsData && protocolsData.mix) ? protocolsData.mix : { "UDP": 212, "TCP": 20, "ICMP": 9 };

    // Canonical categories matching the UI legend
    const udpCount = Number(mix["UDP"] || 0);
    const tcpCount = Number(mix["TCP"] || 0);
    const icmpCount = Number(mix["ICMP"] || 0) + Number(mix["ICMPV6"] || 0);
    const mqttCount = Number(mix["MQTT"] || 0);

    let otherCount = 0;
    for (const [k, v] of Object.entries(mix)) {
        const uk = k.toUpperCase();
        if (uk !== "UDP" && uk !== "TCP" && uk !== "ICMP" && uk !== "ICMPV6" && uk !== "MQTT") {
            otherCount += Number(v || 0);
        }
    }

    const categories = [
        { key: "UDP", label: "UDP", desc: "CoAP / Floods", count: udpCount, elId: "protoCountUDP", pktsId: "protoPktsUDP", rowId: "protoRowUDP", color: "#38bdf8", deepColor: "#0284c7" },
        { key: "TCP", label: "TCP", desc: "SYN / Modbus", count: tcpCount, elId: "protoCountTCP", pktsId: "protoPktsTCP", rowId: "protoRowTCP", color: "#818cf8", deepColor: "#4f46e5" },
        { key: "ICMP", label: "ICMP", desc: "ICMPv6 / RPL", count: icmpCount, elId: "protoCountICMP", pktsId: "protoPktsICMP", rowId: "protoRowICMP", color: "#f43f5e", deepColor: "#be123c" },
        { key: "MQTT", label: "MQTT", desc: "Field Telemetry", count: mqttCount, elId: "protoCountMQTT", pktsId: "protoPktsMQTT", rowId: "protoRowMQTT", color: "#10b981", deepColor: "#047857" }
    ];
    if (otherCount > 0) {
        categories.push({ key: "OTHER", label: "OTHER", desc: "Other Traffic", count: otherCount, elId: null, pktsId: null, rowId: null, color: "#f59e0b", deepColor: "#b45309" });
    }

    const totalCount = categories.reduce((sum, c) => sum + c.count, 0);
    protocolChartState.totalCount = totalCount;
    protocolChartState.categories = categories;

    // Compute normalized integer percentages summing to 100% using Largest Remainder Method (Hamilton-Hare)
    let normPcts = categories.map(() => 0);
    if (totalCount > 0) {
        const rawPcts = categories.map(c => (c.count / totalCount) * 100);
        const floorPcts = rawPcts.map(p => Math.floor(p));
        let remainder = 100 - floorPcts.reduce((a, b) => a + b, 0);

        const indexedRemainders = rawPcts.map((p, i) => ({ index: i, frac: p - floorPcts[i], count: categories[i].count }))
            .filter(item => item.count > 0)
            .sort((a, b) => b.frac - a.frac);

        normPcts = [...floorPcts];
        for (let i = 0; i < remainder && i < indexedRemainders.length; i++) {
            normPcts[indexedRemainders[i].index]++;
        }
    }

    // Update Pills and legend with aligned percentages and packet counts
    categories.forEach((cat, idx) => {
        cat.pct = normPcts[idx];
        if (cat.elId) {
            const el = document.getElementById(cat.elId);
            if (el) el.textContent = `${cat.pct}%`;
        }
        if (cat.pktsId) {
            const pktsEl = document.getElementById(cat.pktsId);
            if (pktsEl) pktsEl.textContent = `${cat.count.toLocaleString()} pkts`;
        }
    });

    // Determine actual dominant protocol
    let dominant = categories[0];
    for (const c of categories) {
        if (c.count > dominant.count) {
            dominant = c;
        }
    }
    protocolChartState.dominant = dominant;

    // Determine dynamic protocol distribution classification badge
    const badgeEl = document.getElementById("protocolMixBadge");
    if (badgeEl) {
        if (totalCount <= 0) {
            badgeEl.textContent = "Standby";
            badgeEl.style.color = "#64748b";
            badgeEl.style.borderColor = "var(--border-subtle)";
            badgeEl.style.background = "var(--bg-panel-elevated)";
        } else {
            // Sort categories by percentage descending
            const sortedPcts = categories.map(c => c.pct).sort((a, b) => b - a);
            const topPct = sortedPcts[0] || 0;
            const secondPct = sortedPcts[1] || 0;
            const activeCatsCount = categories.filter(c => c.count > 0 && c.pct >= 5).length;

            if (topPct >= 70) {
                // Highly concentrated single protocol (e.g. UDP-Dominant, TCP-Dominant)
                badgeEl.textContent = `${dominant.label}-Dominant`;
                badgeEl.style.color = dominant.color;
                badgeEl.style.borderColor = `${dominant.color}40`;
                badgeEl.style.background = `${dominant.color}14`;
            } else if (topPct <= 45 && (activeCatsCount >= 3 || (topPct - secondPct) <= 12)) {
                // Well-balanced across multiple protocols without a runaway leader
                badgeEl.textContent = "Balanced";
                badgeEl.style.color = "#10b981";
                badgeEl.style.borderColor = "rgba(16, 185, 129, 0.3)";
                badgeEl.style.background = "rgba(16, 185, 129, 0.08)";
            } else {
                // Multiple protocols with meaningful distribution
                badgeEl.textContent = "Diversified";
                badgeEl.style.color = "#818cf8";
                badgeEl.style.borderColor = "rgba(129, 140, 248, 0.3)";
                badgeEl.style.background = "rgba(129, 140, 248, 0.08)";
            }
        }
    }

    // Calculate target angles for each category (starting at -PI/2, 12 o'clock)
    let angleCursor = -Math.PI / 2;
    const targetSlices = categories.map(cat => {
        const span = totalCount > 0 ? (cat.count / totalCount) * (Math.PI * 2) : 0;
        const targetStart = angleCursor;
        const targetEnd = angleCursor + span;
        angleCursor = targetEnd;
        return {
            key: cat.key,
            label: cat.label,
            count: cat.count,
            pct: cat.pct,
            color: cat.color,
            deepColor: cat.deepColor,
            targetStart,
            targetEnd
        };
    });

    // Check if smooth transition interpolation is needed
    if (!protocolChartState.slices || protocolChartState.slices.length === 0) {
        // Initial setup
        protocolChartState.slices = targetSlices.map(s => ({
            ...s,
            currentStart: s.targetStart,
            currentEnd: s.targetEnd,
            fromStart: s.targetStart,
            fromEnd: s.targetEnd
        }));
        drawSegmentedDonut(canvas);
        updateProtocolCenterHUD();
    } else {
        // Check if slice angles have changed significantly
        let hasChanged = false;
        const updatedSlices = targetSlices.map(target => {
            const existing = protocolChartState.slices.find(s => s.key === target.key);
            const curStart = existing ? existing.currentStart : target.targetStart;
            const curEnd = existing ? existing.currentEnd : target.targetEnd;
            if (Math.abs(curStart - target.targetStart) > 0.005 || Math.abs(curEnd - target.targetEnd) > 0.005) {
                hasChanged = true;
            }
            return {
                ...target,
                currentStart: curStart,
                currentEnd: curEnd,
                fromStart: curStart,
                fromEnd: curEnd
            };
        });

        protocolChartState.slices = updatedSlices;

        if (hasChanged && !protocolChartState.animating) {
            protocolChartState.animating = true;
            protocolChartState.startTime = performance.now();
            if (protocolChartState.animFrameId) {
                cancelAnimationFrame(protocolChartState.animFrameId);
            }

            function animateStep(now) {
                const elapsed = now - protocolChartState.startTime;
                const progress = Math.min(1, elapsed / protocolChartState.duration);
                // Cubic ease-out: 1 - (1 - t)^3
                const ease = 1 - Math.pow(1 - progress, 3);

                protocolChartState.slices.forEach(s => {
                    s.currentStart = s.fromStart + (s.targetStart - s.fromStart) * ease;
                    s.currentEnd = s.fromEnd + (s.targetEnd - s.fromEnd) * ease;
                });

                drawSegmentedDonut(canvas);
                updateProtocolCenterHUD();

                if (progress < 1) {
                    protocolChartState.animFrameId = requestAnimationFrame(animateStep);
                } else {
                    protocolChartState.slices.forEach(s => {
                        s.currentStart = s.targetStart;
                        s.currentEnd = s.targetEnd;
                    });
                    drawSegmentedDonut(canvas);
                    updateProtocolCenterHUD();
                    protocolChartState.animating = false;
                    protocolChartState.animFrameId = null;
                }
            }

            protocolChartState.animFrameId = requestAnimationFrame(animateStep);
        } else {
            drawSegmentedDonut(canvas);
            updateProtocolCenterHUD();
        }
    }

    // Attach interactive event listeners on canvas and legend pills once
    attachProtocolListeners(canvas);
}

/**
 * Draw modern segmented donut with micro-scale ticks, recessed groove track,
 * clean segment angular separation, subtle depth radial gradients, and interactive elevation.
 */
function drawSegmentedDonut(canvas) {
    const setup = setupCanvas(canvas);
    if (!setup) return;
    const { ctx, width, height } = setup;

    ctx.clearRect(0, 0, width, height);

    const centerX = width / 2;
    const centerY = height / 2;
    const outerRadius = Math.min(centerX, centerY) - 12;
    const innerRadius = outerRadius * 0.67;

    // 1. Precision Micro-Scale Outer Dial Ring
    const tickRadius = outerRadius + 8;
    ctx.save();
    for (let i = 0; i < 36; i++) {
        const angle = (i * Math.PI * 2) / 36 - Math.PI / 2;
        const isCardinal = (i % 9 === 0);
        const innerT = isCardinal ? tickRadius - 5 : tickRadius - 3;
        const outerT = tickRadius;
        const x1 = centerX + Math.cos(angle) * innerT;
        const y1 = centerY + Math.sin(angle) * innerT;
        const x2 = centerX + Math.cos(angle) * outerT;
        const y2 = centerY + Math.sin(angle) * outerT;

        ctx.beginPath();
        ctx.moveTo(x1, y1);
        ctx.lineTo(x2, y2);
        ctx.strokeStyle = isCardinal ? "rgba(148, 163, 184, 0.35)" : "rgba(148, 163, 184, 0.12)";
        ctx.lineWidth = isCardinal ? 1.75 : 1.2;
        ctx.stroke();
    }
    ctx.restore();

    // 2. Recessed Background Instrument Groove Track
    ctx.save();
    ctx.beginPath();
    ctx.arc(centerX, centerY, outerRadius, 0, Math.PI * 2);
    ctx.arc(centerX, centerY, innerRadius, Math.PI * 2, 0, true);
    ctx.closePath();
    ctx.fillStyle = "rgba(15, 23, 42, 0.7)";
    ctx.fill();
    ctx.lineWidth = 1;
    ctx.strokeStyle = "rgba(51, 65, 85, 0.35)";
    ctx.stroke();
    ctx.restore();

    const slices = protocolChartState.slices || [];
    const activeSlices = slices.filter(s => s.count > 0 && (s.currentEnd - s.currentStart) > 0.01);

    // 3. Segmented Arcs with Clean Angular Gap & Subtle Depth
    if (activeSlices.length > 0) {
        // Gap angle: ~2.5 degrees when multiple segments exist
        const gap = activeSlices.length >= 2 ? Math.min(0.048, 0.36 / activeSlices.length) : 0;

        slices.forEach(slice => {
            if (slice.count <= 0) return;
            const span = slice.currentEnd - slice.currentStart;
            if (span <= 0.005) return;

            let aStart = slice.currentStart;
            let aEnd = slice.currentEnd;

            if (activeSlices.length >= 2 && span > gap) {
                aStart += gap / 2;
                aEnd -= gap / 2;
            }

            const isHovered = (protocolChartState.hoveredKey === slice.key);
            const anyHovered = Boolean(protocolChartState.hoveredKey);

            // Subtle interactive elevation: hovered slice expands radially
            const rOut = isHovered ? outerRadius + 5 : outerRadius;
            const rIn = isHovered ? innerRadius - 2 : innerRadius;
            const alpha = isHovered ? 1.0 : (anyHovered ? 0.32 : 0.95);

            ctx.save();
            ctx.globalAlpha = alpha;

            // Radial gradient providing subtle tactile depth
            const grad = ctx.createRadialGradient(centerX, centerY, rIn, centerX, centerY, rOut);
            grad.addColorStop(0, slice.deepColor);
            grad.addColorStop(1, slice.color);

            ctx.beginPath();
            ctx.arc(centerX, centerY, rOut, aStart, aEnd, false);
            ctx.arc(centerX, centerY, rIn, aEnd, aStart, true);
            ctx.closePath();

            ctx.fillStyle = grad;
            ctx.fill();

            // Segment boundary separation stroke
            ctx.lineWidth = 1.5;
            ctx.strokeStyle = "rgba(10, 15, 29, 0.95)";
            ctx.stroke();

            // Crisp accent highlight on hovered slice outer perimeter
            if (isHovered) {
                ctx.beginPath();
                ctx.arc(centerX, centerY, rOut, aStart, aEnd, false);
                ctx.lineWidth = 2.5;
                ctx.strokeStyle = slice.color;
                ctx.stroke();
            }

            ctx.restore();
        });
    }

    // 4. Center Recessed Lens / Hub
    ctx.save();
    ctx.beginPath();
    ctx.arc(centerX, centerY, innerRadius - 2, 0, Math.PI * 2);
    ctx.fillStyle = "#0a0f1d";
    ctx.fill();
    ctx.lineWidth = 1;
    ctx.strokeStyle = "rgba(148, 163, 184, 0.12)";
    ctx.stroke();
    ctx.restore();
}

/**
 * Update Center HUD Display based on active hover or dominant protocol.
 */
function updateProtocolCenterHUD() {
    const captionEl = document.getElementById("donutCenterCaption");
    const valEl = document.getElementById("donutPrimaryProto");
    const pctEl = document.getElementById("donutPrimaryPct");
    const pktsEl = document.getElementById("donutPrimaryPkts");
    const displayWrap = document.getElementById("donutCenterDisplay");

    const hovered = protocolChartState.hoveredKey
        ? protocolChartState.slices.find(s => s.key === protocolChartState.hoveredKey)
        : null;

    if (hovered) {
        if (captionEl) {
            captionEl.textContent = "INSPECTING";
            captionEl.style.color = hovered.color;
        }
        if (valEl) {
            valEl.textContent = hovered.label;
            valEl.style.color = hovered.color;
        }
        if (pctEl) {
            pctEl.textContent = `${hovered.pct}%`;
            pctEl.style.color = hovered.color;
        }
        if (pktsEl) {
            pktsEl.textContent = `${hovered.count.toLocaleString()} pkts`;
            pktsEl.style.color = "#cbd5e1";
        }
        if (displayWrap) {
            displayWrap.style.boxShadow = `inset 0 0 14px rgba(0, 0, 0, 0.7), 0 0 0 1px ${hovered.color}40`;
        }
    } else {
        const dom = protocolChartState.dominant;
        const total = protocolChartState.totalCount;
        if (captionEl) {
            captionEl.textContent = "DOMINANT";
            captionEl.style.color = "#64748b";
        }
        if (valEl) {
            valEl.textContent = total > 0 && dom ? dom.label : "IDLE";
            valEl.style.color = dom ? dom.color : "#f8fafc";
        }
        if (pctEl) {
            pctEl.textContent = total > 0 && dom ? `${dom.pct}%` : "0%";
            pctEl.style.color = dom ? dom.color : "#38bdf8";
        }
        if (pktsEl) {
            pktsEl.textContent = total > 0 && dom ? `${dom.count.toLocaleString()} pkts` : "0 pkts";
            pktsEl.style.color = "#64748b";
        }
        if (displayWrap) {
            displayWrap.style.boxShadow = "inset 0 0 12px rgba(0, 0, 0, 0.6), 0 0 0 1px rgba(148, 163, 184, 0.12)";
        }
    }
}

/**
 * Synchronize Legend Highlight state with active hover inspection.
 */
function updateProtocolLegendHighlights() {
    const keys = ["UDP", "TCP", "ICMP", "MQTT"];
    keys.forEach(k => {
        const row = document.getElementById(`protoRow${k}`);
        if (row) {
            const isHovered = (protocolChartState.hoveredKey === k);
            row.classList.toggle("is-active-hover", isHovered);
        }
    });
}

/**
 * Attach bidirectional hover interactions between canvas segments and legend pills.
 */
function attachProtocolListeners(canvas) {
    if (!canvas || protocolChartState.listenersAttached) return;
    protocolChartState.listenersAttached = true;

    // Canvas mouse interactions
    canvas.addEventListener("mousemove", (e) => {
        const rect = canvas.getBoundingClientRect();
        const x = (e.clientX - rect.left);
        const y = (e.clientY - rect.top);

        const width = rect.width;
        const height = rect.height;
        const centerX = width / 2;
        const centerY = height / 2;
        const outerRadius = Math.min(centerX, centerY) - 12;
        const innerRadius = outerRadius * 0.67;

        const dx = x - centerX;
        const dy = y - centerY;
        const dist = Math.sqrt(dx * dx + dy * dy);

        let matchKey = null;
        if (dist >= innerRadius - 4 && dist <= outerRadius + 8) {
            // Angle clockwise from -PI/2 (12 o'clock)
            let angle = Math.atan2(dy, dx);
            if (angle < -Math.PI / 2) {
                angle += Math.PI * 2;
            }

            for (const s of protocolChartState.slices) {
                if (s.count <= 0) continue;
                if (angle >= s.currentStart && angle <= s.currentEnd) {
                    matchKey = s.key;
                    break;
                }
            }
        }

        if (matchKey !== protocolChartState.hoveredKey) {
            protocolChartState.hoveredKey = matchKey;
            canvas.style.cursor = matchKey ? "pointer" : "default";
            drawSegmentedDonut(canvas);
            updateProtocolCenterHUD();
            updateProtocolLegendHighlights();
        }
    });

    canvas.addEventListener("mouseleave", () => {
        if (protocolChartState.hoveredKey !== null) {
            protocolChartState.hoveredKey = null;
            canvas.style.cursor = "default";
            drawSegmentedDonut(canvas);
            updateProtocolCenterHUD();
            updateProtocolLegendHighlights();
        }
    });

    // Legend pills bidirectional mouse interactions
    const rows = document.querySelectorAll(".proto-pill[data-proto]");
    rows.forEach(row => {
        const protoKey = row.dataset.proto;
        row.addEventListener("mouseenter", () => {
            protocolChartState.hoveredKey = protoKey;
            drawSegmentedDonut(protocolChartState.canvas || canvas);
            updateProtocolCenterHUD();
            updateProtocolLegendHighlights();
        });
        row.addEventListener("mouseleave", () => {
            protocolChartState.hoveredKey = null;
            drawSegmentedDonut(protocolChartState.canvas || canvas);
            updateProtocolCenterHUD();
            updateProtocolLegendHighlights();
        });
    });
}


/* ==========================================================================
   4. PLANT MIMIC TOPOLOGY VISUALIZER (6 DDoS ATTACKER SOURCES + 4 OT NODES)
   ========================================================================== */
const ATTACKER_CONFIG = [
    { index: 1, id: "ATTACKER-01", ip: "10.42.0.250", role: "UDP Flood Bot", vector: "udp_flood" },
    { index: 2, id: "ATTACKER-02", ip: "10.42.0.251", role: "TCP SYN Bot", vector: "syn_flood" },
    { index: 3, id: "ATTACKER-03", ip: "10.42.0.252", role: "ICMP Echo Bot", vector: "icmp_flood" },
    { index: 4, id: "ATTACKER-04", ip: "10.42.0.253", role: "CoAP Anomaly Bot", vector: "coap_anomaly" },
    { index: 5, id: "ATTACKER-05", ip: "10.42.0.254", role: "Slowloris Bot", vector: "slow_rate" },
    { index: 6, id: "ATTACKER-06", ip: "10.42.0.249", role: "Modbus Exploit Bot", vector: "modbus_anomaly" },
];

let cachedTopologyContext = null;
let lastKnownAttackState = false;
let lastKnownAttackVector = "udp_flood";

function updateTopology(topologyContext) {
    if (!topologyContext) return;
    cachedTopologyContext = topologyContext;

    const otNodeCountEl = document.getElementById("topologyOtNodeCount");
    const ddosCountEl = document.getElementById("topologyDdosSourceCount");
    const deviceCountEl = document.getElementById("topologyDeviceCount");
    const linkCountEl = document.getElementById("topologyLinkCount");
    const statusEl = document.getElementById("topologyStatus");
    const envEl = document.getElementById("topologyEnvironment");

    // Dynamic counts calculated from the topology data structure
    const counts = topologyContext.counts || {};
    const otNodes = counts.ot_nodes ?? (
        (topologyContext.sensors || []).length +
        (topologyContext.gateway ? 1 : 0) +
        (topologyContext.ot_servers || []).length
    );
    const ddosSources = counts.ddos_sources ?? (topologyContext.attack_nodes || []).length;
    const totalNodes = counts.total_nodes ?? (topologyContext.nodes || []).length;
    const linkCount = counts.links ?? (topologyContext.links || []).length;

    if (otNodeCountEl) otNodeCountEl.textContent = otNodes || 4;
    if (ddosCountEl) ddosCountEl.textContent = ddosSources || 6;
    if (deviceCountEl) deviceCountEl.textContent = totalNodes || 10;
    if (linkCountEl) linkCountEl.textContent = linkCount || 9;
    if (statusEl) statusEl.textContent = topologyContext.status || "ONLINE";
    if (envEl) envEl.textContent = (topologyContext.environment || "CONTROLLED SIMULATION").replace(/_/g, " ");

    // Update sensor trust scores if returned
    if (Array.isArray(topologyContext.sensors)) {
        const s1 = topologyContext.sensors.find(s => s.id === "SENSOR-01");
        const s2 = topologyContext.sensors.find(s => s.id === "SENSOR-02");
        const t1El = document.getElementById("trustSensor1");
        const t2El = document.getElementById("trustSensor2");
        if (s1 && t1El) t1El.textContent = `TRUST: ${Math.round(s1.trust ?? 100)}`;
        if (s2 && t2El) t2El.textContent = `TRUST: ${Math.round(s2.trust ?? 100)}`;
    }

    // Refresh visuals with latest topology
    updatePlantMimicVisuals(lastKnownAttackState, lastKnownAttackVector);
}

function updatePlantMimicVisuals(isAttack, attackVector) {
    if (typeof isAttack === "boolean") lastKnownAttackState = isAttack;
    if (attackVector) lastKnownAttackVector = attackVector;

    const effAttack = typeof isAttack === "boolean" ? isAttack : lastKnownAttackState;
    const effVector = attackVector || lastKnownAttackVector || "udp_flood";

    const gatewayRing = document.getElementById("gatewayPulseRing");
    const gatewayCircle = document.getElementById("gatewayCircle");
    const gatewaySubtext = document.getElementById("gatewaySubtext");

    const attackNodesData = (cachedTopologyContext && Array.isArray(cachedTopologyContext.attack_nodes))
        ? cachedTopologyContext.attack_nodes
        : [];

    // Global mitigation state checks
    const activeMitigation = attackNodesData.some(n => n.mitigated);
    const anyActiveAttacker = attackNodesData.some(n => n.active) || (effAttack && !activeMitigation);

    // Dynamic data-driven iteration over all six simulated attacker sources
    ATTACKER_CONFIG.forEach(cfg => {
        const idx = cfg.index;
        const linkActive = document.getElementById(`linkAttack${idx}`);
        const linkBack = document.getElementById(`linkAttackBack${idx}`);
        const circle = document.getElementById(`atkCircle${idx}`);
        const titleEl = document.getElementById(`atkTitle${idx}`);
        const ipEl = document.getElementById(`atkIp${idx}`);
        const statusText = document.getElementById(`atkStatusText${idx}`);
        const vectorEl = document.getElementById(`atkVector${idx}`);

        // Match with backend telemetry/topology state
        const liveData = attackNodesData.find(n => n.id === cfg.id);
        const isNodeMitigated = liveData ? Boolean(liveData.mitigated) : activeMitigation;
        const isNodeActive = liveData ? Boolean(liveData.active) : (effAttack && !isNodeMitigated);

        const roleLabel = (liveData && liveData.vector) ? liveData.vector.replace(/_/g, " ").toUpperCase() : cfg.vector.replace(/_/g, " ").toUpperCase();
        if (vectorEl) vectorEl.textContent = roleLabel;

        if (isNodeMitigated) {
            // STATE 3: MITIGATION ACTIVE (Blocked/Isolated/Interrupted state)
            if (linkActive) {
                linkActive.style.display = "block";
                linkActive.setAttribute("stroke", "#f59e0b");
                linkActive.setAttribute("stroke-dasharray", "3,8");
                linkActive.setAttribute("marker-end", "url(#arrowAttackMitigated)");
                linkActive.classList.remove("flow-packet-anim");
                linkActive.style.animation = "none";
            }
            if (linkBack) linkBack.setAttribute("stroke", "rgba(245, 158, 11, 0.25)");
            if (circle) {
                circle.setAttribute("stroke", "#f59e0b");
                circle.setAttribute("fill", "rgba(245, 158, 11, 0.2)");
            }
            if (titleEl) titleEl.setAttribute("fill", "#f59e0b");
            if (ipEl) ipEl.setAttribute("fill", "#fef3c7");
            if (vectorEl) vectorEl.setAttribute("fill", "#fde68a");
            if (statusText) {
                statusText.textContent = "CONTAINED";
                statusText.setAttribute("fill", "#f59e0b");
            }
        } else if (isNodeActive) {
            // STATE 2: DDOS ATTACK DETECTED (Active attack state)
            if (linkActive) {
                linkActive.style.display = "block";
                linkActive.setAttribute("stroke", "#f43f5e");
                linkActive.setAttribute("stroke-dasharray", "5,5");
                linkActive.setAttribute("marker-end", "url(#arrowAttack)");
                linkActive.classList.add("flow-packet-anim");
                linkActive.style.animation = "";
            }
            if (linkBack) linkBack.setAttribute("stroke", "rgba(244, 63, 94, 0.4)");
            if (circle) {
                circle.setAttribute("stroke", "var(--red)");
                circle.setAttribute("fill", "rgba(244, 63, 94, 0.28)");
            }
            if (titleEl) titleEl.setAttribute("fill", "var(--red)");
            if (ipEl) ipEl.setAttribute("fill", "#fecdd3");
            if (vectorEl) vectorEl.setAttribute("fill", "#fda4af");
            if (statusText) {
                statusText.textContent = "ATTACKING";
                statusText.setAttribute("fill", "var(--red)");
            }
        } else {
            // STATE 1: NORMAL (Dimmed/Inactive state)
            if (linkActive) {
                linkActive.style.display = "none";
                linkActive.classList.remove("flow-packet-anim");
                linkActive.style.animation = "none";
            }
            if (linkBack) linkBack.setAttribute("stroke", "rgba(244, 63, 94, 0.12)");
            if (circle) {
                circle.setAttribute("stroke", "#475569");
                circle.setAttribute("fill", "#141824");
            }
            if (titleEl) titleEl.setAttribute("fill", "#94a3b8");
            if (ipEl) ipEl.setAttribute("fill", "#cbd5e1");
            if (vectorEl) vectorEl.setAttribute("fill", "#94a3b8");
            if (statusText) {
                statusText.textContent = "IDLE (LAB)";
                statusText.setAttribute("fill", "#64748b");
            }
        }
    });

    // Gateway Central Node State: Normal Purple, Alert Red, or Mitigating Shield Green
    if (activeMitigation) {
        if (gatewayRing) gatewayRing.setAttribute("stroke", "#10b981");
        if (gatewayCircle) gatewayCircle.setAttribute("stroke", "#10b981");
        if (gatewaySubtext) {
            gatewaySubtext.textContent = "MITIGATING (SHIELD)";
            gatewaySubtext.setAttribute("fill", "#10b981");
        }
    } else if (anyActiveAttacker) {
        if (gatewayRing) gatewayRing.setAttribute("stroke", "var(--red)");
        if (gatewayCircle) gatewayCircle.setAttribute("stroke", "var(--red)");
        if (gatewaySubtext) {
            gatewaySubtext.textContent = "UNDER ATTACK (ALERT)";
            gatewaySubtext.setAttribute("fill", "var(--red)");
        }
    } else {
        if (gatewayRing) gatewayRing.setAttribute("stroke", "#6366f1");
        if (gatewayCircle) gatewayCircle.setAttribute("stroke", "#818cf8");
        if (gatewaySubtext) {
            gatewaySubtext.textContent = "ONLINE (ENFORCING)";
            gatewaySubtext.setAttribute("fill", "#38bdf8");
        }
    }

    // Maintain backward-compatible handles for any single-node queries
    const legacyLink = document.getElementById("linkAttack");
    const legacyBack = document.getElementById("linkAttackBack");
    const legacyCircle = document.getElementById("atkCircle");
    const legacyText = document.getElementById("atkStatusText");
    const atk1Active = attackNodesData.length ? attackNodesData[0].active : effAttack;
    const atk1Mit = attackNodesData.length ? attackNodesData[0].mitigated : activeMitigation;
    if (legacyLink) legacyLink.style.display = (atk1Active || atk1Mit) ? "block" : "none";
    if (legacyBack) legacyBack.setAttribute("stroke", atk1Active ? "rgba(244,63,94,0.4)" : "rgba(244,63,94,0.12)");
    if (legacyCircle) {
        legacyCircle.setAttribute("stroke", atk1Mit ? "#f59e0b" : (atk1Active ? "var(--red)" : "#64748b"));
        legacyCircle.setAttribute("fill", atk1Mit ? "rgba(245,158,11,0.2)" : (atk1Active ? "rgba(244,63,94,0.28)" : "#161b26"));
    }
    if (legacyText) {
        legacyText.textContent = atk1Mit ? "CONTAINED" : (atk1Active ? `ATTACK: ${effVector.toUpperCase()}` : "IDLE (LAB)");
        legacyText.setAttribute("fill", atk1Mit ? "#f59e0b" : (atk1Active ? "var(--red)" : "#64748b"));
    }
}


/* ==========================================================================
   5. ENERGY VS BASELINE (CANONICAL BACKEND CONTRACT)
   ========================================================================== */
function updateEnergy(energyData) {
    if (!energyData) return;
    const latest = Array.isArray(energyData.rows) && energyData.rows.length 
        ? energyData.rows[energyData.rows.length - 1] 
        : energyData;

    // Synchronized canonical fields: baseline_energy, tx_activity, rx_activity, cpu_activity
    const rate = Number(latest.energy_rate ?? 55.0);
    const base = Number(latest.baseline_energy ?? 55.0);
    const dev = Number(latest.energy_deviation ?? 0.0);
    const cause = latest.energy_cause || "MODELLED: baseline sensor activity (idle power state)";
    const tx = Number(latest.tx_activity ?? 4.0);
    const rx = Number(latest.rx_activity ?? 5.0);
    const cpu = Number(latest.cpu_activity ?? 6.0);

    const rateEl = document.getElementById("energyRate");
    const baseEl = document.getElementById("energyBaseline");
    const devEl = document.getElementById("energyDeviation");
    const devStat = document.getElementById("energyDevStat");
    const causeEl = document.getElementById("energyCause");

    if (rateEl) rateEl.textContent = rate.toFixed(1);
    if (baseEl) baseEl.textContent = base.toFixed(1);
    if (devEl) devEl.textContent = `${dev >= 0 ? "+" : ""}${(dev * 100).toFixed(1)}%`;
    if (devStat) {
        devStat.className = `energy-stat deviation ${dev > 0.5 ? "alert" : ""}`;
    }
    if (causeEl) causeEl.textContent = cause;

    // Contribution Progress Bars
    const txVal = document.getElementById("energyTxVal");
    const rxVal = document.getElementById("energyRxVal");
    const cpuVal = document.getElementById("energyCpuVal");
    const barTx = document.getElementById("barEnergyTx");
    const barRx = document.getElementById("barEnergyRx");
    const barCpu = document.getElementById("barEnergyCpu");

    if (txVal) txVal.textContent = `${tx.toFixed(1)}%`;
    if (rxVal) rxVal.textContent = `${rx.toFixed(1)}%`;
    if (cpuVal) cpuVal.textContent = `${cpu.toFixed(1)}%`;
    if (barTx) barTx.style.width = `${Math.min(100, Math.max(4, tx))}%`;
    if (barRx) barRx.style.width = `${Math.min(100, Math.max(5, rx))}%`;
    if (barCpu) barCpu.style.width = `${Math.min(100, Math.max(5, cpu))}%`;

    // Gateway Load KPI Card Sync
    const gwCpu = document.getElementById("gatewayCpuVal");
    const gwRam = document.getElementById("gatewayRamVal");
    const gwRadio = document.getElementById("gatewayRadioVal");
    if (gwCpu) gwCpu.textContent = cpu.toFixed(1);
    if (gwRam) gwRam.textContent = Number(latest.memory_activity ?? 22.0).toFixed(0);
    if (gwRadio) gwRadio.textContent = rx.toFixed(0);
}


/* ==========================================================================
   6. DETECTION & XAI EXPLAINABILITY
   ========================================================================== */
function updateDetection(latest) {
    if (!latest) return;

    const patternEl = document.getElementById("detPatternVal");
    const protocolEl = document.getElementById("detProtocolVal");
    const sourceEl = document.getElementById("detSourceVal");
    const intensityEl = document.getElementById("detIntensityVal");
    const anomalyEl = document.getElementById("detAnomalyScore");

    const scenario = latest.scenario_id || "normal";
    const isAttack = latest.prediction === "ATTACK" || latest.label === "ATTACK";
    const proto = latest.protocol || "UDP";
    const srcIp = latest.src_ip || (isAttack ? "10.42.0.250" : "10.42.0.11");
    const dstIp = latest.dst_ip || "10.42.0.1";
    const pps = Number(latest.packets_per_second || latest.packet_rate || 18.0);
    const prob = Number(latest.ddos_probability || (isAttack ? 0.99 : 0.05));

    if (patternEl) patternEl.textContent = scenario.toUpperCase();
    if (protocolEl) protocolEl.textContent = `${proto} (${proto === "UDP" ? "Port 5683 CoAP" : "Port 1883 MQTT"})`;
    if (sourceEl) sourceEl.textContent = `${srcIp} → ${dstIp}`;
    if (intensityEl) intensityEl.textContent = isAttack ? `SURGE (${pps.toFixed(0)} pkts/s)` : `BASELINE (${pps.toFixed(0)} pkts/s)`;
    if (anomalyEl) {
        anomalyEl.textContent = `${prob.toFixed(2)} (${isAttack ? "ANOMALOUS" : "BENIGN"})`;
        anomalyEl.className = `detail-val ${isAttack ? "threat" : "safe"}`;
    }

    updatePlantMimicVisuals(isAttack, scenario);
}

function updateExplainability(exp) {
    if (!exp) return;
    const container = document.getElementById("evidenceItemsContainer");
    if (!container) return;

    const evidence = exp.observed_evidence || [];
    if (!evidence.length) {
        container.innerHTML = `
            <div class="evidence-item">Packet rate conforms to baseline (20.0 pps nominal).</div>
            <div class="evidence-item">Source identity matches authenticated sensor registry.</div>
            <div class="evidence-item">No protocol ratio or byte spike detected.</div>
        `;
        return;
    }

    container.innerHTML = evidence.map(item => `
        <div class="evidence-item">${escapeHtml(item)}</div>
    `).join("");
}


/* ==========================================================================
   7. DYNAMIC ZERO-TRUST IAM TABLE
   ========================================================================== */
function updateIAM(iamData) {
    const listBody = document.getElementById("iamDeviceList");
    const atkTrustVal = document.getElementById("atkTrustScoreVal");
    if (!iamData || !iamData.identities) return;

    const identities = iamData.identities;
    const atk = identities.find(i => i.identity === "ATK-01");
    if (atk && atkTrustVal) {
        atkTrustVal.textContent = atk.trust_score.toFixed(1);
    }

    if (!listBody) return;
    listBody.innerHTML = identities.map(dev => {
        const isAuth = Boolean(dev.authenticated);
        const isAllow = isAuth && dev.role !== "untrusted" && dev.trust_score >= 40.0;
        const trustColor = dev.trust_score >= 70 ? "var(--green)" : (dev.trust_score >= 40 ? "var(--amber)" : "var(--red)");
        const mfa = dev.mfa_status || (dev.role === "operator" ? "VERIFIED" : (dev.role === "untrusted" ? "FAILED" : "NOT_REQUIRED"));
        const mfaBadgeClass = (mfa === "VERIFIED" || mfa === "NOT_REQUIRED") ? "iam-allow" : "iam-deny";
        
        return `
            <tr>
                <td><strong>${escapeHtml(dev.identity)}</strong></td>
                <td style="text-transform: capitalize;">${escapeHtml(dev.role)}</td>
                <td><span class="iam-badge ${isAuth ? 'iam-allow' : 'iam-deny'}">${isAuth ? 'VERIFIED' : 'UNVERIFIED'}</span></td>
                <td><span class="iam-badge ${mfaBadgeClass}">${escapeHtml(mfa.replace('_', ' '))}</span></td>
                <td><span class="iam-badge ${isAllow ? 'iam-allow' : 'iam-deny'}">${isAllow ? 'ALLOW' : 'DENY'}</span></td>
                <td><strong style="color: ${trustColor}; font-family: var(--font-mono);">${dev.trust_score.toFixed(1)}</strong></td>
            </tr>
        `;
    }).join("");
}


/* ==========================================================================
   8. INCIDENT LIFECYCLE (HORIZONTAL 7-STEP STEPPER)
   ========================================================================== */
const LIFECYCLE_STEP_MAP = {
    "DETECTED": 0,
    "ANALYZING": 1,
    "TRIAGED": 1,
    "RESPONDING": 2,
    "CONTAINED": 3,
    "RECOVERING": 4,
    "RESOLVED": 5,
    "CLOSED": 6
};

function isBaselineState(state) {
    if (!state) return true;
    const s = String(state).toUpperCase();
    return ["NORMAL", "IDLE", "OBSERVED", "BASELINE", "NONE"].includes(s);
}

// Session reference to prevent replaying intro on page reload
const pageSessionStartTime = Date.now();

// Global reference to track active or transitioning incident in HMI session
let hmiTargetIncident = null;

const lifecycleVisualController = {
    activeIncidentId: null,
    currentVisualStage: null,
    targetStage: null,
    timer: null,
    isAnimating: false,
    queue: [],
    cachedIncident: null,
    cachedSummary: null,
    cachedTelemetryContext: null
};

function shouldAnimateIntro(inc) {
    if (!inc || !inc.created_at) return false;
    const createdAtMs = new Date(inc.created_at).getTime();
    if (isNaN(createdAtMs)) return false;
    const ageMs = Date.now() - createdAtMs;
    // Paced intro only plays for newly opened incidents (< 4000 ms old) created in this page session
    if (ageMs > 4000) return false;
    if (createdAtMs < (pageSessionStartTime - 1000)) return false;
    const state = (inc.lifecycle_state || "").toUpperCase();
    return ["DETECTED", "TRIAGED", "ANALYZING", "RESPONDING", "CONTAINED"].includes(state);
}

function startLifecycleIntroAnimation(inc, summary, telemetryContext) {
    if (lifecycleVisualController.timer) {
        clearTimeout(lifecycleVisualController.timer);
        lifecycleVisualController.timer = null;
    }
    lifecycleVisualController.activeIncidentId = inc.incident_id;
    lifecycleVisualController.isAnimating = true;
    lifecycleVisualController.cachedIncident = inc;
    lifecycleVisualController.cachedSummary = summary;
    lifecycleVisualController.cachedTelemetryContext = telemetryContext;

    const rawState = (inc.lifecycle_state || "").toUpperCase();
    const normTarget = rawState === "TRIAGED" ? "ANALYZING" : rawState;
    lifecycleVisualController.targetStage = normTarget;

    const introStages = ["DETECTED", "ANALYZING", "RESPONDING", "CONTAINED"];
    let targetIdx = introStages.indexOf(normTarget);
    if (targetIdx < 0) targetIdx = introStages.length - 1;

    const stagesToPlay = introStages.slice(0, targetIdx + 1);
    lifecycleVisualController.currentVisualStage = stagesToPlay[0];
    lifecycleVisualController.queue = stagesToPlay.slice(1);

    // Immediately display stage 1 (DETECTED)
    renderLifecycleStage(lifecycleVisualController.currentVisualStage, inc, summary, telemetryContext);

    function step() {
        if (lifecycleVisualController.queue.length === 0) {
            lifecycleVisualController.isAnimating = false;
            lifecycleVisualController.timer = null;
            const finalStage = lifecycleVisualController.targetStage || lifecycleVisualController.currentVisualStage;
            renderLifecycleStage(
                finalStage,
                lifecycleVisualController.cachedIncident,
                lifecycleVisualController.cachedSummary,
                lifecycleVisualController.cachedTelemetryContext
            );
            return;
        }

        lifecycleVisualController.timer = setTimeout(() => {
            const nextStage = lifecycleVisualController.queue.shift();
            lifecycleVisualController.currentVisualStage = nextStage;
            renderLifecycleStage(
                nextStage,
                lifecycleVisualController.cachedIncident,
                lifecycleVisualController.cachedSummary,
                lifecycleVisualController.cachedTelemetryContext
            );
            step();
        }, 400);
    }

    step();
}

function renderLifecycleStage(rawState, inc, summary, telemetryContext) {
    const isNormal = isBaselineState(rawState);
    let state = (rawState || "NORMAL").toUpperCase();
    if (state === "TRIAGED") state = "ANALYZING";

    const stateBadge = document.getElementById("lifecycleState");
    const stageText = document.getElementById("lifecycleStage");
    const recoveryText = document.getElementById("lifecycleRecovery");
    const normalBadge = document.getElementById("lifecycleNormalBadge");
    const activeIdEl = document.getElementById("activeIncId");

    if (isNormal) {
        if (stateBadge) {
            stateBadge.textContent = "NORMAL";
            stateBadge.style.color = "var(--green)";
        }
        if (stageText) {
            stageText.textContent = "BASELINE OBSERVATION";
        }
        if (recoveryText) {
            recoveryText.textContent = (summary && summary.recovery_state) || "MONITORING";
            recoveryText.style.color = "var(--green)";
        }
        if (normalBadge) {
            normalBadge.classList.add("active");
        }
        if (activeIdEl && (!inc || ["RESOLVED", "CLOSED"].includes(inc.lifecycle_state))) {
            activeIdEl.innerHTML = `<span style="color: var(--green);">NONE (BASELINE / SYSTEM CLEAR)</span>`;
        }
    } else {
        if (stateBadge) {
            stateBadge.textContent = state;
            if (["DETECTED", "CONTAINED"].includes(state)) {
                stateBadge.style.color = "var(--red)";
            } else if (["ANALYZING", "RESPONDING", "RECOVERING"].includes(state)) {
                stateBadge.style.color = "var(--amber)";
            } else {
                stateBadge.style.color = "var(--green)";
            }
        }
        if (stageText) {
            const stageDesc = {
                "DETECTED": "THREAT DETECTED • TRIAGING",
                "ANALYZING": "EVIDENCE CORRELATION",
                "RESPONDING": "AUTONOMOUS RESPONSE ENGAGED",
                "CONTAINED": "SIMULATED MITIGATION ACTIVE (DRY_RUN)",
                "RECOVERING": "OBSERVING RECOVERY STREAK",
                "RESOLVED": "TELEMETRY RECOVERED • VERIFIED",
                "CLOSED": "INCIDENT CLOSED • AUDIT FINALIZED"
            }[state] || (telemetryContext && telemetryContext.lifecycle_stage ? telemetryContext.lifecycle_stage.replace(/_/g, " ") : "AUTONOMOUS RESPONSE");
            stageText.textContent = stageDesc;
        }
        if (recoveryText) {
            if (inc && inc.recovery_state) {
                recoveryText.textContent = inc.recovery_state;
                recoveryText.style.color = inc.recovery_state === "VERIFIED" ? "var(--green)" : "var(--amber)";
            } else {
                const recVal = (state === "RESOLVED" || state === "CLOSED") ? "VERIFIED" : (state === "RECOVERING" ? "PENDING" : "CONTAINED_IN_SOFTWARE");
                recoveryText.textContent = recVal;
                recoveryText.style.color = (state === "RESOLVED" || state === "CLOSED") ? "var(--green)" : "var(--amber)";
            }
        }
        if (normalBadge) {
            normalBadge.classList.remove("active");
        }
        if (activeIdEl && inc && inc.incident_id) {
            if (["RESOLVED", "CLOSED"].includes(state)) {
                activeIdEl.innerHTML = `<strong style="color: var(--green);">${escapeHtml(inc.incident_id)} (${escapeHtml(state)})</strong>`;
            } else {
                activeIdEl.innerHTML = `<strong style="color: var(--red);">${escapeHtml(inc.incident_id)} (${escapeHtml(state)})</strong>`;
            }
        }
    }

    // Horizontal 7-Step Progression
    const stepOrder = ["DETECTED", "ANALYZING", "RESPONDING", "CONTAINED", "RECOVERING", "RESOLVED", "CLOSED"];
    const currentIdx = LIFECYCLE_STEP_MAP.hasOwnProperty(state) ? LIFECYCLE_STEP_MAP[state] : -1;

    stepOrder.forEach((step, idx) => {
        const id = `stepNode${step.charAt(0) + step.slice(1).toLowerCase()}`;
        const node = document.getElementById(id);
        if (!node) return;

        node.className = "step-node";
        if (isNormal || currentIdx < 0) {
            // In baseline normal, stepper rests in ready/idle state
            return;
        }

        if (idx === currentIdx) {
            if (["DETECTED", "CONTAINED"].includes(step)) {
                node.classList.add("threat-active");
            } else if (["ANALYZING", "RESPONDING", "RECOVERING"].includes(step)) {
                node.classList.add("stage-active-amber");
            } else {
                node.classList.add("resolved-active");
            }
        } else if (idx < currentIdx) {
            if (currentIdx >= 5) {
                node.classList.add("resolved-active");
            } else {
                node.classList.add("pipeline-done");
            }
        }
    });

    // Update Autonomous Mitigation Pipeline Flow Steps
    const pipeCard = document.querySelector(".auto-pipeline-card");
    if (pipeCard) {
        const flowSteps = pipeCard.querySelectorAll(".flow-step");
        if (flowSteps && flowSteps.length >= 7) {
            const pipeIdx = {
                "DETECTED": 1,
                "ANALYZING": 2,
                "RESPONDING": 3,
                "CONTAINED": 4,
                "RECOVERING": 5,
                "RESOLVED": 6,
                "CLOSED": 7
            }[state] || (isNormal ? 0 : 1);

            flowSteps.forEach((s, idx) => {
                s.classList.remove("auto-done", "active", "manual-req", "pending");
                if (idx === 6) { // Step 7: Operator Audit Closure
                    if (pipeIdx >= 7) {
                        s.classList.add("auto-done");
                        s.textContent = "Operator Audit Closed";
                    } else if (pipeIdx === 6) {
                        s.classList.add("manual-req", "active");
                        s.textContent = "● Operator Closure Required";
                    } else {
                        s.classList.add("manual-req");
                        s.textContent = "○ Operator Audit Closure";
                    }
                } else {
                    if (pipeIdx > idx) {
                        s.classList.add("auto-done");
                    } else if (pipeIdx === idx + 1) {
                        s.classList.add("active");
                    } else {
                        s.classList.add("pending");
                    }
                }
            });
        }
    }
}

function updateLifecycle(targetIncident, summary, telemetryContext) {
    let state = "NORMAL";
    let isNormal = true;
    let inc = targetIncident || (summary && summary.active_incident ? summary.active_incident : null);

    if (inc && inc.lifecycle_state && !isBaselineState(inc.lifecycle_state)) {
        state = inc.lifecycle_state.toUpperCase();
        isNormal = false;
    } else if (summary && summary.lifecycle_state && !isBaselineState(summary.lifecycle_state)) {
        state = summary.lifecycle_state.toUpperCase();
        isNormal = false;
    }

    if (isNormal) {
        if (lifecycleVisualController.timer) {
            clearTimeout(lifecycleVisualController.timer);
            lifecycleVisualController.timer = null;
        }
        lifecycleVisualController.isAnimating = false;
        lifecycleVisualController.activeIncidentId = null;
        lifecycleVisualController.currentVisualStage = null;
        renderLifecycleStage("NORMAL", null, summary, telemetryContext);
        return;
    }

    // If an intro animation is already playing for this incident, update cache but don't disrupt
    if (lifecycleVisualController.isAnimating && inc && inc.incident_id === lifecycleVisualController.activeIncidentId) {
        lifecycleVisualController.cachedIncident = inc;
        lifecycleVisualController.cachedSummary = summary;
        lifecycleVisualController.cachedTelemetryContext = telemetryContext;
        const norm = state === "TRIAGED" ? "ANALYZING" : state;
        lifecycleVisualController.targetStage = norm;
        return;
    }

    // If this is a newly opened incident eligible for visual intro pacing:
    if (inc && inc.incident_id !== lifecycleVisualController.activeIncidentId && shouldAnimateIntro(inc)) {
        startLifecycleIntroAnimation(inc, summary, telemetryContext);
        return;
    }

    // Authoritative direct render (reload, reconnect, recovery, resolved, closed, or post-animation)
    lifecycleVisualController.activeIncidentId = inc ? inc.incident_id : null;
    lifecycleVisualController.currentVisualStage = state;
    lifecycleVisualController.targetStage = state;
    renderLifecycleStage(state, inc, summary, telemetryContext);
}

window.updateLifecycle = updateLifecycle;
window.lifecycleVisualController = lifecycleVisualController;


/* ==========================================================================
   9. INCIDENT JOURNAL & THREAT EVENTS
   ========================================================================== */
function updateIncidents(incidents) {
    const table = document.getElementById("incidentsTable");
    const countEl = document.getElementById("incidentCount");
    const activeIdEl = document.getElementById("activeIncId");
    const actionControls = document.getElementById("incidentActionControls");
    const activeCountEl = document.getElementById("activeIncidentCount");
    const histCountEl = document.getElementById("historicalIncidentCount");

    const activeIncs = (incidents || []).filter(i => !["RESOLVED", "CLOSED"].includes(i.lifecycle_state));
    const histIncs = (incidents || []).filter(i => ["RESOLVED", "CLOSED"].includes(i.lifecycle_state));

    if (countEl) countEl.textContent = incidents ? incidents.length : 0;
    if (activeCountEl) activeCountEl.textContent = activeIncs.length;
    if (histCountEl) histCountEl.textContent = histIncs.length;

    if (!incidents || !incidents.length) {
        if (table) {
            table.innerHTML = `<tr><td colspan="10" style="text-align: center; color: var(--text-muted); padding: 18px;">No active or historical incidents recorded in historian.</td></tr>`;
        }
        if (activeIdEl) activeIdEl.innerHTML = `<span style="color: var(--green);">NONE (BASELINE / OPERATIONAL)</span>`;
        if (actionControls) actionControls.innerHTML = "";
        return;
    }

    // Explicitly distinguish current active incident from historical audit log
    const activeInc = incidents.find(i => !["RESOLVED", "CLOSED"].includes(i.lifecycle_state));
    const latest = incidents[0];

    if (activeIdEl) {
        if (activeInc) {
            activeIdEl.innerHTML = `<strong style="color: var(--red);">${escapeHtml(activeInc.incident_id)} (${escapeHtml(activeInc.lifecycle_state)})</strong>`;
        } else {
            activeIdEl.innerHTML = `<span style="color: var(--green);">NONE (BASELINE / SYSTEM CLEAR)</span>`;
        }
    }

    // Operator Action Quick Controls for active incident or latest resolved
    if (actionControls) {
        const targetInc = activeInc || (hmiTargetIncident && ["RESOLVED", "CLOSED"].includes(hmiTargetIncident.lifecycle_state) ? hmiTargetIncident : (latest && latest.lifecycle_state === "RESOLVED" ? latest : null));
        const st = targetInc ? targetInc.lifecycle_state : "";
        if (["CONTAINED", "RECOVERING", "RESPONDING", "DETECTED"].includes(st)) {
            actionControls.innerHTML = `<button class="btn-sim-action btn-recover" type="button" onclick="transitionIncidentState('${targetInc.incident_id}', 'RESOLVED')">Resolve ${targetInc.incident_id}</button>`;
        } else if (st === "RESOLVED") {
            actionControls.innerHTML = `<button class="btn-sim-action" type="button" onclick="transitionIncidentState('${targetInc.incident_id}', 'CLOSED')">Close ${targetInc.incident_id}</button>`;
        } else if (st === "CLOSED" && hmiTargetIncident && hmiTargetIncident.incident_id === targetInc.incident_id) {
            actionControls.innerHTML = `<button class="btn-sim-action btn-recover" type="button" onclick="resetLifecycleToBaseline()">Reset Stepper to Baseline</button>`;
        } else {
            actionControls.innerHTML = "";
        }
    }

    if (!table) return;
    table.innerHTML = incidents.map(inc => {
        const state = inc.lifecycle_state || "UNKNOWN";
        const isActive = !["RESOLVED", "CLOSED"].includes(state);
        const sev = inc.severity || "MEDIUM";
        const sevClass = (sev === "CRITICAL" || sev === "HIGH") ? "color: var(--red);" : "color: var(--green);";
        const dt = (inc.updated_at || inc.created_at || "").replace("T", " ").split(".")[0];

        let actionBtn = "—";
        if (["CONTAINED", "RECOVERING", "RESPONDING", "DETECTED"].includes(state)) {
            actionBtn = `<button class="btn-sim-action btn-recover" type="button" onclick="transitionIncidentState('${inc.incident_id}', 'RESOLVED')">Resolve</button>`;
        } else if (state === "RESOLVED") {
            actionBtn = `<button class="btn-sim-action" type="button" onclick="transitionIncidentState('${inc.incident_id}', 'CLOSED')">Close</button>`;
        }

        let stateBadge;
        if (isActive) {
            stateBadge = `<span class="iam-badge iam-deny">ACTIVE: ${escapeHtml(state)}</span>`;
        } else if (state === "RESOLVED") {
            stateBadge = `<span class="iam-badge iam-allow">RESOLVED</span>`;
        } else {
            stateBadge = `<span class="iam-badge" style="background: rgba(100, 116, 139, 0.2); color: var(--text-muted); border: 1px solid rgba(100, 116, 139, 0.3);">CLOSED</span>`;
        }

        return `
            <tr class="${isActive ? 'active-incident-row' : ''}">
                <td style="font-family: var(--font-mono); color: var(--cyan);">${escapeHtml(inc.incident_id)}</td>
                <td style="font-size: 10px; color: var(--text-muted);">${dt}</td>
                <td><strong>${escapeHtml(inc.device_id || "10.42.0.250")}</strong></td>
                <td>${escapeHtml(inc.attack_type || "udp_flood")}</td>
                <td><strong style="${sevClass}">${sev}</strong></td>
                <td style="font-family: var(--font-mono);">${inc.confidence ? (inc.confidence * 100).toFixed(0) + "%" : "—"}</td>
                <td>
                    <div style="display: flex; align-items: center; gap: 4px;">
                        ${stateBadge}
                        <span class="safety-tag" style="font-size: 8px;">SIM</span>
                    </div>
                </td>
                <td style="color: ${inc.recovery_state === 'VERIFIED' ? 'var(--green)' : 'var(--amber)'}; font-size: 10px;">${inc.recovery_state || "PENDING"}</td>
                <td style="color: var(--cyan);">${escapeHtml(inc.response_action || "ISOLATE")}</td>
                <td>${actionBtn}</td>
            </tr>
        `;
    }).join("");
}

function updateEvents(events) {
    const table = document.getElementById("eventsTable");
    const countEl = document.getElementById("eventCount");
    if (!table) return;
    if (countEl) countEl.textContent = events ? events.length : 0;
    if (!events || !events.length) {
        table.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 12px;">No threat events recorded yet.</td></tr>`;
        return;
    }

    table.innerHTML = events.slice(0, 10).map(ev => {
        const dt = (ev.timestamp || "").replace("T", " ").split(".")[0];
        return `
            <tr>
                <td style="font-family: var(--font-mono); font-size: 10px; color: var(--text-muted);">${dt}</td>
                <td style="font-family: var(--font-mono);">${escapeHtml(ev.src_ip || "10.42.0.250")}</td>
                <td style="font-family: var(--font-mono);">${escapeHtml(ev.dst_ip || "10.42.0.1")}</td>
                <td style="font-family: var(--font-mono); color: var(--red);">${(ev.packet_rate || ev.packets_per_second || 0).toFixed(1)}</td>
                <td><span class="iam-badge iam-deny">${escapeHtml(ev.prediction || "ATTACK")}</span></td>
                <td style="font-family: var(--font-mono);">${((ev.ddos_probability || 0.99) * 100).toFixed(0)}%</td>
                <td style="color: var(--cyan);">${escapeHtml(ev.security_action || "ISOLATE")}</td>
                <td><strong style="color: var(--red);">${escapeHtml(ev.severity || "HIGH")}</strong></td>
            </tr>
        `;
    }).join("");
}


/* ==========================================================================
   10. MODEL ASSURANCE & 2x2 CONFUSION MATRIX
   ========================================================================== */
function updateModelAssurance(maData) {
    if (!maData) return;
    const setT = (id, text) => {
        const el = document.getElementById(id);
        if (el) el.textContent = text;
    };

    const metrics = maData.metrics || {};
    if (metrics.f1 !== null && metrics.f1 !== undefined) {
        setT("metricF1", `${(metrics.f1 * 100).toFixed(1)}%`);
    }
    if (metrics.precision !== null && metrics.precision !== undefined) {
        setT("metricPrecision", `${(metrics.precision * 100).toFixed(1)}%`);
    }
    if (metrics.recall !== null && metrics.recall !== undefined) {
        setT("metricRecall", `${(metrics.recall * 100).toFixed(1)}%`);
    }
    if (metrics.false_positive_rate !== null && metrics.false_positive_rate !== undefined) {
        setT("metricFPR", `${(metrics.false_positive_rate * 100).toFixed(1)}%`);
    }
    if (metrics.roc_auc !== null && metrics.roc_auc !== undefined) {
        setT("metricAUC", metrics.roc_auc.toFixed(3));
    }
    if (metrics.brier_score_calibrated !== null && metrics.brier_score_calibrated !== undefined) {
        setT("metricBrier", metrics.brier_score_calibrated.toFixed(5));
    }
    if (metrics.scenario_held_out_f1 !== null && metrics.scenario_held_out_f1 !== undefined) {
        setT("metricHeldOut", `${(metrics.scenario_held_out_f1 * 100).toFixed(1)}% F1`);
    }
    if (maData.model_architecture) {
        setT("metricModelName", maData.model_architecture);
    }

    // Update 2x2 Confusion Matrix
    const cm = maData.confusion_matrix || {};
    if (cm.true_negative !== null && cm.true_negative !== undefined) {
        setT("cmTN", cm.true_negative);
    }
    if (cm.false_positive !== null && cm.false_positive !== undefined) {
        setT("cmFP", cm.false_positive);
    }
    if (cm.false_negative !== null && cm.false_negative !== undefined) {
        setT("cmFN", cm.false_negative);
    }
    if (cm.true_positive !== null && cm.true_positive !== undefined) {
        setT("cmTP", cm.true_positive);
    }
}


/* ==========================================================================
   11. RAW SAMPLE FLOWS TABLE (DYNAMIC FROM TELEMETRY)
   ========================================================================== */
function updateSampleFlows(rows) {
    const tbody = document.getElementById("sampleFlowsTableBody");
    if (!tbody) return;

    if (!rows || !rows.length) {
        tbody.innerHTML = `<tr><td colspan="10" style="text-align: center; color: var(--text-muted); padding: 14px;">No sample telemetry flows recorded.</td></tr>`;
        return;
    }

    // Display most recent 12 flows
    const sample = rows.slice(-12).reverse();
    tbody.innerHTML = sample.map(r => {
        const dt = (r.window_start || "").replace("T", " ").split(".")[0];
        const isAtk = r.prediction === "ATTACK";
        const proto = r.protocol || "UDP";
        const port = proto === "UDP" ? 5683 : (proto === "TCP" ? 1883 : 0);
        const prob = ((r.ddos_probability || 0) * 100).toFixed(0);
        const prov = String(r.provenance || "SIMULATED").toUpperCase();
        let provBadgeClass = "tag-provenance-simulated";
        if (prov.includes("LIVE")) provBadgeClass = "tag-provenance-live";
        else if (prov.includes("MODEL")) provBadgeClass = "tag-provenance-modelled";
        else if (prov.includes("DRY")) provBadgeClass = "tag-provenance-dryrun";

        return `
            <tr>
                <td style="font-family: var(--font-mono); font-size: 10px; color: var(--text-muted);">${dt}</td>
                <td style="font-family: var(--font-mono);">${escapeHtml(r.src_ip || "10.42.0.11")}</td>
                <td style="font-family: var(--font-mono);">${escapeHtml(r.dst_ip || "10.42.0.1")}</td>
                <td>${escapeHtml(proto)}</td>
                <td style="font-family: var(--font-mono); color: ${isAtk ? 'var(--red)' : 'var(--green)'};">${(r.packets_per_second || 0).toFixed(1)}</td>
                <td style="font-family: var(--font-mono);">${(r.average_packet_size || 64).toFixed(0)} B</td>
                <td><span class="iam-badge ${isAtk ? 'iam-deny' : 'iam-allow'}">${isAtk ? 'ATTACK' : 'NORMAL'}</span></td>
                <td style="font-family: var(--font-mono);">${prob}%</td>
                <td style="color: ${isAtk ? 'var(--red)' : 'var(--green)'};">${escapeHtml(r.security_action || 'PASS')}</td>
                <td style="font-size: 9.5px;"><span class="tag ${provBadgeClass}">${escapeHtml(prov)}</span></td>
            </tr>
        `;
    }).join("");
}


/* ==========================================================================
   12. CONTROLLED ATTACK CONSOLE (100% IN-PROCESS SIMULATION)
   ========================================================================== */
async function runControlledDemo() {
    const button = document.getElementById("run-demo-btn");
    const banner = document.getElementById("simStatusBanner");
    const detail = document.getElementById("simStatusDetail");

    if (button) {
        button.disabled = true;
        button.textContent = "LAUNCHING CONTROLLED DEMO...";
    }
    if (banner) {
        banner.textContent = "STARTING DEMO...";
        banner.style.color = "var(--amber)";
    }

    try {
        // Stop any active simulations
        try {
            await fetch("/api/simulations/stop", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({})
            });
        } catch (_) {}

        // Launch in-process UDP Flood profile (Canonical endpoint: POST /api/simulations/start)
        const response = await fetch("/api/simulations/start", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                scenario_id: "udp_flood",
                intensity: 3,
                duration: 10
            })
        });

        if (response.status === 401) {
            window.location.href = "/login?expired=1";
            return;
        }
        if (response.status === 403) {
            const errData = await response.json().catch(() => ({}));
            if (banner) {
                banner.textContent = "DEMO FORBIDDEN";
                banner.style.color = "var(--red)";
            }
            if (detail) detail.textContent = errData.error || "Forbidden: Insufficient privileges";
            alert(errData.error || "Forbidden: ADMIN role required to run simulations");
            return;
        }
        if (!response.ok) {
            const errData = await response.json().catch(() => ({}));
            throw new Error(errData.error || `HTTP ${response.status}`);
        }

        if (banner) {
            banner.textContent = "SIMULATING ATTACK (UDP FLOOD)";
            banner.style.color = "var(--red)";
        }
        if (detail) {
            detail.textContent = "Active profile: udp_flood (Intensity: 3, Duration: 10s) • In-process generator only";
        }

        await new Promise(r => setTimeout(r, 400));
        await refreshDashboard();

    } catch (error) {
        console.error("Controlled demo failed:", error);
        if (banner) {
            banner.textContent = "DEMO ERROR";
            banner.style.color = "var(--red)";
        }
        if (detail) detail.textContent = error.message;
    } finally {
        if (button) {
            button.disabled = false;
            button.innerHTML = '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg> <span>Run Controlled Demo</span>';
        }
    }
}

window.runControlledDemo = runControlledDemo;

window.triggerScenario = async function(scenarioId, intensity = 3, duration = 10) {
    const banner = document.getElementById("simStatusBanner");
    const detail = document.getElementById("simStatusDetail");
    if (banner) {
        banner.textContent = `STARTING ${scenarioId.toUpperCase()}...`;
        banner.style.color = "var(--amber)";
    }

    try {
        const res = await fetch("/api/simulations/start", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ scenario_id: scenarioId, intensity, duration })
        });
        if (res.status === 401) {
            window.location.href = "/login?expired=1";
            return;
        }
        if (res.status === 403) {
            const data = await res.json().catch(() => ({}));
            if (banner) {
                banner.textContent = "SIMULATION FORBIDDEN";
                banner.style.color = "var(--red)";
            }
            if (detail) detail.textContent = data.error || "Forbidden: Insufficient privileges";
            alert(data.error || "Forbidden: ADMIN role required to trigger simulations");
            return;
        }
        const data = await res.json();
        if (res.ok) {
            if (banner) {
                banner.textContent = scenarioId === "normal" ? "NORMAL RHYTHM ACTIVE" : `SIMULATING ${scenarioId.toUpperCase()}`;
                banner.style.color = scenarioId === "normal" ? "var(--green)" : "var(--red)";
            }
            if (detail) detail.textContent = `Profile: ${scenarioId} (Intensity: ${intensity}, Duration: ${duration}s)`;
            refreshDashboard();
        } else {
            if (banner) {
                banner.textContent = "SIMULATION FAILED";
                banner.style.color = "var(--red)";
            }
            if (detail) detail.textContent = data.error || "Request failed";
        }
    } catch (e) {
        console.error("Simulation trigger failed:", e);
    }
};

window.startSimulation = window.triggerScenario;

window.stopCurrentSimulation = async function() {
    const banner = document.getElementById("simStatusBanner");
    const detail = document.getElementById("simStatusDetail");
    try {
        const res = await fetch("/api/simulations/stop", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({})
        });
        if (res.status === 401) {
            window.location.href = "/login?expired=1";
            return;
        }
        if (res.status === 403) {
            const err = await res.json().catch(() => ({}));
            alert(err.error || "Forbidden: ADMIN role required to stop simulations");
            return;
        }
        if (banner) {
            banner.textContent = "SIMULATION STOPPED";
            banner.style.color = "var(--text-secondary)";
        }
        if (detail) detail.textContent = "Active profile halted. Baseline rhythm active.";
        refreshDashboard();
    } catch (e) {
        console.error("Stop simulation failed:", e);
    }
};

window.toggleResponseMode = async function() {
    const nextAuto = !window.currentAutoResponse;
    const mode = nextAuto ? "DRY_RUN" : "MANUAL";
    const textEl = document.getElementById("btnResponseModeText");
    const btnEl = document.getElementById("btnResponseMode");

    try {
        const res = await fetch("/api/settings/mode", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ mode: mode, auto: nextAuto })
        });
        if (res.status === 401) {
            window.location.href = "/login?expired=1";
            return;
        }
        if (res.status === 403) {
            const err = await res.json().catch(() => ({}));
            alert(err.error || "Forbidden: ADMIN role required to toggle response mode");
            return;
        }
        if (res.ok) {
            window.currentAutoResponse = nextAuto;
            if (textEl) textEl.textContent = window.currentAutoResponse ? "AUTO: ON" : "MANUAL: ACTIVE";
            if (btnEl) btnEl.className = `btn-mode-toggle ${window.currentAutoResponse ? 'active' : ''}`;
            const modeTag = document.getElementById("mitigationModeTag");
            if (modeTag) modeTag.textContent = mode;
            const respMode = document.getElementById("respPolicyMode");
            if (respMode) respMode.textContent = `${window.currentAutoResponse ? 'AUTO' : 'MANUAL'} (${mode})`;
        }
    } catch (e) {
        console.error("Mode toggle failed:", e);
    }
};

window.executeManualAction = async function(actionName) {
    try {
        const res = await fetch("/api/manual/action", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ action: actionName, actor: "operator" })
        });
        if (res.status === 401) {
            window.location.href = "/login?expired=1";
            return;
        }
        if (res.status === 403) {
            const err = await res.json().catch(() => ({}));
            alert(err.error || "Forbidden: Insufficient permissions for manual action");
            return;
        }
        if (res.ok) {
            refreshDashboard();
        } else {
            const err = await res.json().catch(() => ({}));
            alert(err.error || `Action failed with status ${res.status}`);
        }
    } catch (e) {
        console.error("Manual action failed:", e);
    }
};

window.resetLifecycleToBaseline = async function() {
    hmiTargetIncident = null;
    try {
        const res = await fetch("/api/simulations/reset", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({})
        });
        if (res.status === 401) {
            window.location.href = "/login?expired=1";
            return;
        }
    } catch (e) {
        console.error("Backend reset failed:", e);
    } finally {
        refreshDashboard();
        if (typeof refreshAdminAlerts === "function") {
            refreshAdminAlerts();
        }
    }
};

window.transitionIncidentState = async function(incidentId, targetState) {
    try {
        const res = await fetch(`/api/incidents/${incidentId}/transition`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ state: targetState, actor: "operator", note: "Operator transitioned state via HMI" })
        });
        if (res.status === 401) {
            window.location.href = "/login?expired=1";
            return;
        }
        if (res.status === 403) {
            const err = await res.json().catch(() => ({}));
            alert(err.error || `Forbidden: Cannot transition incident to ${targetState}`);
            return;
        }
        if (res.ok) {
            const updated = await res.json();
            hmiTargetIncident = updated;
            refreshDashboard();
        } else {
            const err = await res.json().catch(() => ({}));
            alert(err.error || `Transition failed with status ${res.status}`);
        }
    } catch (e) {
        console.error("Transition failed:", e);
    }
};


/* ==========================================================================
   13. MASTER REFRESH & SSE INTEGRATION
   ========================================================================== */
async function refreshDashboard() {
    if (isRefreshInFlight) {
        refreshPending = true;
        return;
    }
    isRefreshInFlight = true;
    try {
        // 1. Fetch core real-time endpoints in parallel
        const [statusRes, liveRes, incRes, energyRes] = await Promise.allSettled([
            fetch("/api/status", { cache: "no-store" }),
            fetch("/api/telemetry", { cache: "no-store" }),
            fetch("/api/incidents", { cache: "no-store" }),
            fetch("/api/energy", { cache: "no-store" }),
        ]);

        let statusObj = null;
        if (statusRes.status === "fulfilled" && statusRes.value.ok) {
            statusObj = await statusRes.value.json();
            const sysStatus = document.getElementById("systemStatus");
            const dot = document.getElementById("statusDot");
            const isOnline = statusObj.status === "ONLINE";
            if (sysStatus) sysStatus.textContent = isOnline ? "ONLINE" : "NO DATA";
            if (dot) {
                dot.classList.toggle("online", isOnline);
                dot.classList.toggle("offline", !isOnline);
            }
            updateSummary(statusObj.summary || {}, statusObj);
        }

        let latestTel = null;
        let liveRows = [];
        if (liveRes.status === "fulfilled" && liveRes.value.ok) {
            const liveData = await liveRes.value.json();
            liveRows = liveData.rows || [];
            window._cachedLiveRows = liveRows;
            if (liveRows.length) {
                latestTel = liveRows[liveRows.length - 1];
                updateDetection(latestTel);
                updateExplainability(latestTel.explainability_context);
                updateSampleFlows(liveRows);
            }
            renderHistorianChart(document.getElementById("trafficChart"), liveRows);
            renderEnergyChart(document.getElementById("energyChart"), liveRows);
            const threatCanvas = document.getElementById("threatChart");
            if (threatCanvas) renderThreatChart(threatCanvas, liveRows);
        }

        let incidentsList = [];
        if (incRes.status === "fulfilled" && incRes.value.ok) {
            const incData = await incRes.value.json();
            incidentsList = incData.incidents || [];
            updateIncidents(incidentsList);
        }

        // Determine active or transitioning incident for the 7-step stepper
        const activeUnclosed = incidentsList.find(i => !["RESOLVED", "CLOSED"].includes(i.lifecycle_state));
        let stepperIncident = null;
        if (activeUnclosed) {
            stepperIncident = activeUnclosed;
            hmiTargetIncident = activeUnclosed;
        } else if (hmiTargetIncident) {
            const refreshedTarget = incidentsList.find(i => i.incident_id === hmiTargetIncident.incident_id);
            if (refreshedTarget) {
                hmiTargetIncident = refreshedTarget;
                stepperIncident = refreshedTarget;
            } else {
                stepperIncident = hmiTargetIncident;
            }
        } else if (incidentsList.length && incidentsList[0].lifecycle_state === "RESOLVED") {
            stepperIncident = incidentsList[0];
            hmiTargetIncident = incidentsList[0];
        }

        updateLifecycle(stepperIncident, statusObj ? statusObj.summary : {}, latestTel ? latestTel.lifecycle_context : null);

        if (energyRes.status === "fulfilled" && energyRes.value.ok) {
            const energyData = await energyRes.value.json();
            updateEnergy(energyData);
        }

        // 2. Throttled auxiliary polls (Protocols, IAM, Topology, Events, Model Assurance, Admin)
        const now = Date.now();
        if (!window._lastAuxTime || (now - window._lastAuxTime) > 8000) {
            window._lastAuxTime = now;
            const [protoRes, iamRes, topoRes, evRes, maRes] = await Promise.allSettled([
                fetch("/api/protocols", { cache: "no-store" }),
                fetch("/api/iam", { cache: "no-store" }),
                fetch("/api/topology", { cache: "no-store" }),
                fetch("/api/events", { cache: "no-store" }),
                window._modelAssuranceLoaded ? Promise.resolve(null) : fetch("/api/model-assurance", { cache: "no-store" }),
            ]);

            if (protoRes.status === "fulfilled" && protoRes.value && protoRes.value.ok) {
                const protoData = await protoRes.value.json();
                renderProtocolDonut(document.getElementById("protocolDonutChart"), protoData);
            }
            if (iamRes.status === "fulfilled" && iamRes.value && iamRes.value.ok) {
                const iamData = await iamRes.value.json();
                updateIAM(iamData);
            }
            if (topoRes.status === "fulfilled" && topoRes.value && topoRes.value.ok) {
                const topoData = await topoRes.value.json();
                updateTopology(topoData);
            }
            if (evRes.status === "fulfilled" && evRes.value && evRes.value.ok) {
                const evData = await evRes.value.json();
                updateEvents(evData.events);
            }
            if (maRes.status === "fulfilled" && maRes.value && maRes.value.ok) {
                const maData = await maRes.value.json();
                updateModelAssurance(maData);
                window._modelAssuranceLoaded = true;
            }

            await refreshAdminSection();
        }

    } catch (error) {
        console.error("Dashboard refresh error:", error);
    } finally {
        isRefreshInFlight = false;
        if (refreshPending) {
            refreshPending = false;
            scheduleCoalescedRefresh();
        }
    }
}

function escapeHtml(str) {
    return String(str ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

/* ==========================================================================
   10. SIDEBAR NAVIGATION & COLLAPSIBLE CONTROLS
   ========================================================================== */
function toggleSidebar() {
    const sidebar = document.getElementById("hmiSidebar");
    const backdrop = document.getElementById("sidebarBackdrop");
    const toggleBtn = document.getElementById("sidebarToggle");
    if (!sidebar) return;

    if (window.innerWidth <= 1100) {
        const isOpen = sidebar.classList.toggle("mobile-open");
        if (backdrop) backdrop.classList.toggle("active", isOpen);
        if (toggleBtn) toggleBtn.setAttribute("aria-expanded", isOpen ? "true" : "false");
    } else {
        const isExpanded = sidebar.classList.toggle("expanded");
        if (backdrop) backdrop.classList.toggle("active", isExpanded);
        if (toggleBtn) toggleBtn.setAttribute("aria-expanded", isExpanded ? "true" : "false");
    }
}

function collapseSidebar() {
    const sidebar = document.getElementById("hmiSidebar");
    const backdrop = document.getElementById("sidebarBackdrop");
    const toggleBtn = document.getElementById("sidebarToggle");
    if (sidebar) {
        sidebar.classList.remove("expanded");
        sidebar.classList.remove("mobile-open");
    }
    if (backdrop) {
        backdrop.classList.remove("active");
    }
    if (toggleBtn) {
        toggleBtn.setAttribute("aria-expanded", "false");
    }
}

window.toggleSidebar = toggleSidebar;
window.collapseSidebar = collapseSidebar;

function initSidebarNavigation() {
    const sidebar = document.getElementById("hmiSidebar");
    if (!sidebar) return;

    const links = sidebar.querySelectorAll(".hmi-sidebar-link");
    links.forEach(link => {
        link.addEventListener("click", (e) => {
            const targetId = link.getAttribute("data-target") || (link.getAttribute("href") || "").replace("#", "");
            const targetEl = document.getElementById(targetId);
            if (targetEl) {
                e.preventDefault();
                targetEl.scrollIntoView({ behavior: "smooth", block: "start" });
                // Collapse expanded navigation drawer on desktop or mobile upon link selection
                collapseSidebar();
                links.forEach(l => l.classList.remove("active"));
                link.classList.add("active");
            }
        });
    });

    // Close expanded sidebar on Escape key
    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape") {
            collapseSidebar();
        }
    });

    // Scroll-Spy to highlight current section
    const sectionIds = [
        "sec-kpis",
        "sec-status-gauges",
        "sec-telemetry",
        "sec-topology",
        "sec-energy",
        "sec-iam",
        "sec-protocol-stack",
        "sec-lifecycle",
        "sec-incidents",
        "sec-comparison",
        "sec-assurance",
        "sec-controls",
        "sec-admin-overview",
        "sec-admin-alerts",
        "sec-admin-users",
        "sec-admin-audit",
        "sec-admin-posture"
    ];

    let ticking = false;
    window.addEventListener("scroll", () => {
        if (!ticking) {
            window.requestAnimationFrame(() => {
                const scrollPos = window.scrollY + 160;
                let activeSecId = "";
                for (const id of sectionIds) {
                    const el = document.getElementById(id);
                    if (el) {
                        const top = el.offsetTop;
                        const height = el.offsetHeight;
                        if (scrollPos >= top && scrollPos < top + height) {
                            activeSecId = id;
                            break;
                        }
                    }
                }
                if (activeSecId) {
                    links.forEach(l => {
                        const t = l.getAttribute("data-target") || (l.getAttribute("href") || "").replace("#", "");
                        if (t === activeSecId) {
                            l.classList.add("active");
                        } else {
                            l.classList.remove("active");
                        }
                    });
                }
                ticking = false;
            });
            ticking = true;
        }
    }, { passive: true });
}

/* ==========================================================================
   SERVER-SENT EVENTS (SSE) & REFRESH COALESCING
   ========================================================================== */

let refreshTimer = null;
let isRefreshInFlight = false;
let refreshPending = false;
const REFRESH_DEBOUNCE_WINDOW_MS = 250;
const REFRESH_MAX_DEBOUNCE_MS = 1000;
let refreshWindowStartTime = null;

function scheduleCoalescedRefresh() {
    if (isRefreshInFlight) {
        refreshPending = true;
        return;
    }

    const now = Date.now();
    if (!refreshWindowStartTime) {
        refreshWindowStartTime = now;
    }

    // Trailing-edge debounce: reset timer on new event within the debounce window
    if (refreshTimer) {
        if (now - refreshWindowStartTime < REFRESH_MAX_DEBOUNCE_MS) {
            clearTimeout(refreshTimer);
        } else {
            // Under sustained events, do not delay indefinitely to prevent UI starvation
            return;
        }
    }

    refreshTimer = setTimeout(async () => {
        refreshTimer = null;
        refreshWindowStartTime = null;
        await executeCoalescedRefresh();
    }, REFRESH_DEBOUNCE_WINDOW_MS);
}

async function executeCoalescedRefresh() {
    if (isRefreshInFlight) {
        refreshPending = true;
        return;
    }
    isRefreshInFlight = true;
    refreshPending = false;
    try {
        await refreshDashboard();
    } finally {
        isRefreshInFlight = false;
        if (refreshPending) {
            refreshPending = false;
            scheduleCoalescedRefresh();
        }
    }
}

/* Server-Sent Events (SSE) Stream */
function initSSE() {
    if (typeof EventSource === "undefined") return;
    try {
        const source = new EventSource("/events");
        source.addEventListener("telemetry", (e) => {
            try {
                if (e && e.data) {
                    const msg = JSON.parse(e.data);
                    if (msg && msg.event) {
                        const evt = msg.event;
                        if (window._cachedLiveRows) {
                            window._cachedLiveRows.push(evt);
                            if (window._cachedLiveRows.length > 50) {
                                window._cachedLiveRows.shift();
                            }
                            renderHistorianChart(document.getElementById("trafficChart"), window._cachedLiveRows);
                            renderEnergyChart(document.getElementById("energyChart"), window._cachedLiveRows);
                            const threatCanvas = document.getElementById("threatChart");
                            if (threatCanvas) renderThreatChart(threatCanvas, window._cachedLiveRows);
                            updateDetection(evt);
                            if (evt.explainability_context) updateExplainability(evt.explainability_context);
                        }
                        if (msg.decision || evt) {
                            const isAtk = evt.label === "ATTACK";
                            const summaryData = {
                                latest_prediction: evt.label || "NORMAL",
                                latest_ddos_probability: evt.confidence ?? (isAtk ? 0.99 : 0.05),
                                latest_packet_rate: evt.packet_rate ?? 18.0,
                                latest_bytes_per_second: evt.byte_rate ?? 4140.0,
                                latest_security_action: evt.response_action || (isAtk ? "BLOCK" : "MONITOR"),
                                latest_mitigation_action: evt.response_action || "NONE",
                                trust_score: evt.trust_score ?? 100.0,
                                active_incident: msg.incident,
                            };
                            updateSummary(summaryData);
                        }
                        return;
                    }
                }
            } catch (_) {}
            scheduleCoalescedRefresh();
        });
        source.addEventListener("incident", (e) => {
            try {
                if (e && e.data) {
                    const incData = JSON.parse(e.data);
                    if (incData && incData.incident_id) {
                        hmiTargetIncident = incData;
                        if (shouldAnimateIntro(incData) && lifecycleVisualController.activeIncidentId !== incData.incident_id) {
                            startLifecycleIntroAnimation(incData, null, null);
                        }
                    }
                }
            } catch (err) {
                console.warn("Error parsing incident SSE", err);
            }
            scheduleCoalescedRefresh();
        });
        source.addEventListener("response", () => scheduleCoalescedRefresh());
        source.addEventListener("trust", () => scheduleCoalescedRefresh());
        source.addEventListener("simulation", () => {
            window._lastAuxTime = 0;
            scheduleCoalescedRefresh();
        });
        source.addEventListener("alert", () => {
            scheduleCoalescedRefresh();
            refreshAdminAlerts();
            refreshAdminOverview();
        });
        source.onerror = () => {
            // Safe generic SSE error/reconnect handling without assuming error.status exists
        };
    } catch (err) {
        console.warn("SSE stream unavailable; polling active", err);
    }
}

// Window resize handler to re-draw canvas charts sharply (debounced)
let resizeDebounceTimer = null;
window.addEventListener("resize", () => {
    clearTimeout(resizeDebounceTimer);
    resizeDebounceTimer = setTimeout(() => {
        fetch("/api/telemetry", { cache: "no-store" })
            .then(r => r.json())
            .then(d => {
                if (d && d.rows) {
                    renderHistorianChart(document.getElementById("trafficChart"), d.rows);
                    renderEnergyChart(document.getElementById("energyChart"), d.rows);
                    const threatCanvas = document.getElementById("threatChart");
                    if (threatCanvas) renderThreatChart(threatCanvas, d.rows);
                }
            }).catch(() => {});

        fetch("/api/protocols", { cache: "no-store" })
            .then(r => r.json())
            .then(d => renderProtocolDonut(document.getElementById("protocolDonutChart"), d))
            .catch(() => {});
    }, 120);
});

/* ==========================================================================
   ADMINISTRATIVE SECURITY LAYER: AUTH, RBAC, ALERTS, AUDIT, USERS
   ========================================================================== */

let currentAuthSession = null;
let currentAlertFilterMode = "ALL";
let cachedAdminAlerts = [];

async function checkAuthStatus() {
    try {
        const res = await fetch("/api/auth/status", { cache: "no-store" });
        if (res.ok) {
            const data = await res.json();
            if (data.authenticated && data.must_change_password) {
                window.location.href = "/login?password_change_required=1";
                return;
            }
            currentAuthSession = data.authenticated ? data.user : null;
            renderAuthBadge(data);
        }
    } catch (e) {
        console.warn("Auth status fetch error:", e);
    }
}

function renderAuthBadge(authData) {
    const badge = document.getElementById("headerUserBadge");
    const userLabel = document.getElementById("headerUserLabel");
    const roleTag = document.getElementById("headerRoleTag");
    const dot = document.getElementById("headerAuthDot");
    const logoutBtn = document.getElementById("headerLogoutBtn");
    const addUserBtn = document.getElementById("btnOpenAddUserModal");
    const opNotice = document.getElementById("operatorUserNotice");
    const opAuditNotice = document.getElementById("operatorAuditNotice");

    if (!badge) return;

    if (authData.authenticated && authData.user) {
        const u = authData.user;
        if (userLabel) userLabel.textContent = u.username;
        if (roleTag) {
            roleTag.textContent = u.role;
            if (u.role === "ADMIN") {
                roleTag.style.color = "var(--cyan)";
                roleTag.style.borderColor = "rgba(56,189,248,0.4)";
                roleTag.style.background = "rgba(56,189,248,0.12)";
            } else {
                roleTag.style.color = "var(--amber)";
                roleTag.style.borderColor = "rgba(245,158,11,0.4)";
                roleTag.style.background = "rgba(245,158,11,0.12)";
            }
        }
        if (dot) dot.className = "indicator-dot green";
        if (logoutBtn) {
            logoutBtn.innerHTML = '<svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg> <span>Logout</span>';
            logoutBtn.title = "Terminate Administrative Session";
            const form = document.getElementById("headerLogoutForm");
            if (form) {
                form.action = "/logout";
                form.method = "POST";
            }
        }

        // RBAC UI constraints
        const isAdmin = u.role === "ADMIN";
        if (addUserBtn) addUserBtn.style.display = isAdmin ? "inline-block" : "none";
        if (opNotice) opNotice.style.display = isAdmin ? "none" : "block";
        if (opAuditNotice) opAuditNotice.style.display = isAdmin ? "none" : "block";

        const btnAuditCsv = document.getElementById("btnExportAuditCsv");
        const btnAuditJson = document.getElementById("btnExportAuditJson");
        if (btnAuditCsv) btnAuditCsv.style.display = isAdmin ? "inline-flex" : "none";
        if (btnAuditJson) btnAuditJson.style.display = isAdmin ? "inline-flex" : "none";

    } else {
        if (userLabel) userLabel.textContent = "ANONYMOUS";
        if (roleTag) {
            roleTag.textContent = "UNAUTHENTICATED";
            roleTag.style.color = "var(--text-muted)";
            roleTag.style.borderColor = "var(--border-subtle)";
        }
        if (dot) dot.className = "indicator-dot amber";
        if (logoutBtn) {
            logoutBtn.innerHTML = '<svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg> <span>Login</span>';
            logoutBtn.title = "Authenticate Session";
            const form = document.getElementById("headerLogoutForm");
            if (form) {
                form.action = "/login";
                form.method = "GET";
            }
        }
        if (addUserBtn) addUserBtn.style.display = "none";
        if (opNotice) opNotice.style.display = "block";
        if (opAuditNotice) opAuditNotice.style.display = "block";

        const btnAuditCsv = document.getElementById("btnExportAuditCsv");
        const btnAuditJson = document.getElementById("btnExportAuditJson");
        if (btnAuditCsv) btnAuditCsv.style.display = "none";
        if (btnAuditJson) btnAuditJson.style.display = "none";
    }
}

async function refreshAdminSection() {
    await checkAuthStatus();
    await Promise.all([
        refreshAdminOverview(),
        refreshAdminAlerts(),
        refreshAdminUsers(),
        refreshAdminAuditLogs()
    ]);
}

async function refreshAdminOverview() {
    try {
        const res = await fetch("/api/admin/overview", { cache: "no-store" });
        if (!res.ok) return;
        const data = await res.json();

        // Update Overview Cards
        const u = data.user;
        const userEl = document.getElementById("adminOverviewUser");
        const roleBadge = document.getElementById("adminOverviewRoleBadge");
        const loginTimeEl = document.getElementById("adminOverviewLoginTime");
        if (userEl && u) userEl.textContent = u.username;
        if (roleBadge && u) {
            roleBadge.textContent = u.role;
            roleBadge.className = `tag ${u.role === "ADMIN" ? "tag-cyan" : "tag-amber"}`;
        }
        if (loginTimeEl && u) {
            loginTimeEl.textContent = `MFA: ${u.mfa_status || "SIMULATED VERIFIED"}`;
        }

        const k = data.kpis || {};
        const actAlertsEl = document.getElementById("adminOverviewActiveAlerts");
        const unackBadge = document.getElementById("adminOverviewUnackBadge");
        const totalAlertsEl = document.getElementById("adminOverviewTotalAlerts");
        if (actAlertsEl) actAlertsEl.textContent = k.active_alerts ?? 0;
        if (unackBadge) {
            unackBadge.textContent = `${k.unacknowledged_alerts ?? 0} UNACK`;
            unackBadge.style.display = (k.unacknowledged_alerts > 0) ? "inline-block" : "none";
        }
        if (totalAlertsEl) totalAlertsEl.textContent = k.total_alerts ?? 0;

        const openIncEl = document.getElementById("adminOverviewOpenIncidents");
        const critBadge = document.getElementById("adminOverviewCritBadge");
        if (openIncEl) openIncEl.textContent = k.open_incidents ?? 0;
        if (critBadge) {
            critBadge.textContent = `${k.critical_incidents ?? 0} CRITICAL`;
            critBadge.style.display = (k.critical_incidents > 0) ? "inline-block" : "none";
        }

        // Mini Audit Log
        renderMiniAuditLogs(data.recent_audits || []);
    } catch (e) {
        console.warn("Admin overview error:", e);
    }
}

function renderMiniAuditLogs(audits) {
    const tbody = document.getElementById("adminOverviewAuditTbody");
    if (!tbody) return;
    if (!audits.length) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 10px;">No audit events recorded yet.</td></tr>';
        return;
    }
    tbody.innerHTML = audits.slice(0, 5).map(a => {
        const isSuccess = a.result === "SUCCESS";
        const resultColor = isSuccess ? "var(--green)" : (a.result === "DENIED" ? "var(--amber)" : "var(--red)");
        const timeFormatted = a.timestamp ? a.timestamp.substring(11, 19) : "--:--:--";
        return `<tr>
            <td style="font-family: var(--font-mono); color: var(--text-muted);">${timeFormatted}</td>
            <td style="font-weight: 600;">${escapeHtml(a.username)}</td>
            <td><span class="tag" style="font-size: 9px;">${escapeHtml(a.role)}</span></td>
            <td style="font-family: var(--font-mono); font-weight: 700; color: var(--cyan);">${escapeHtml(a.action)}</td>
            <td style="color: var(--text-muted);">${escapeHtml(a.resource || "system")}</td>
            <td><span class="tag" style="color: ${resultColor}; border-color: ${resultColor}44; font-size: 9px;">${escapeHtml(a.result)}</span></td>
            <td style="color: var(--text-secondary); max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(a.details)}">${escapeHtml(a.details)}</td>
        </tr>`;
    }).join("");
}

async function refreshAdminAlerts() {
    try {
        const res = await fetch("/api/admin/alerts?limit=200", { cache: "no-store" });
        if (!res.ok) return;
        const data = await res.json();
        cachedAdminAlerts = data.alerts || [];

        // Update counts
        const allCount = cachedAdminAlerts.length;
        const unackCount = cachedAdminAlerts.filter(a => a.acknowledgement_state === "UNACKNOWLEDGED").length;
        const activeCount = cachedAdminAlerts.filter(a => a.status === "ACTIVE").length;
        const resolvedCount = cachedAdminAlerts.filter(a => a.status === "RESOLVED" || a.status === "CLOSED").length;

        const cAll = document.getElementById("countAlertsAll");
        const cUnack = document.getElementById("countAlertsUnack");
        const cActive = document.getElementById("countAlertsActive");
        const cResolved = document.getElementById("countAlertsResolved");
        const sbBadge = document.getElementById("sidebarAlertCounter");

        if (cAll) cAll.textContent = allCount;
        if (cUnack) cUnack.textContent = unackCount;
        if (cActive) cActive.textContent = activeCount;
        if (cResolved) cResolved.textContent = resolvedCount;

        if (sbBadge) {
            sbBadge.textContent = unackCount;
            sbBadge.style.display = unackCount > 0 ? "inline-block" : "none";
        }

        renderFilteredAlerts();
    } catch (e) {
        console.warn("Admin alerts error:", e);
    }
}

function filterAdminAlerts(mode) {
    currentAlertFilterMode = mode;
    ["filterAlertsAll", "filterAlertsUnack", "filterAlertsActive", "filterAlertsResolved"].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.classList.remove("active");
    });
    const map = {
        "ALL": "filterAlertsAll",
        "UNACK": "filterAlertsUnack",
        "ACTIVE": "filterAlertsActive",
        "RESOLVED": "filterAlertsResolved"
    };
    const activeEl = document.getElementById(map[mode]);
    if (activeEl) activeEl.classList.add("active");
    renderFilteredAlerts();
}

function renderFilteredAlerts() {
    const tbody = document.getElementById("adminAlertsTableBody");
    if (!tbody) return;

    let filtered = cachedAdminAlerts;
    if (currentAlertFilterMode === "UNACK") {
        filtered = cachedAdminAlerts.filter(a => a.acknowledgement_state === "UNACKNOWLEDGED");
    } else if (currentAlertFilterMode === "ACTIVE") {
        filtered = cachedAdminAlerts.filter(a => a.status === "ACTIVE");
    } else if (currentAlertFilterMode === "RESOLVED") {
        filtered = cachedAdminAlerts.filter(a => a.status === "RESOLVED" || a.status === "CLOSED");
    }

    if (!filtered.length) {
        tbody.innerHTML = `<tr><td colspan="10" style="text-align: center; color: var(--text-muted); padding: 20px;">
            No alerts matching filter '${currentAlertFilterMode}'.
        </td></tr>`;
        return;
    }

    tbody.innerHTML = filtered.map(a => {
        const sev = (a.severity || "MEDIUM").toUpperCase();
        let sevColor = "var(--cyan)";
        let sevBg = "rgba(56,189,248,0.12)";
        if (sev === "CRITICAL") { sevColor = "var(--red)"; sevBg = "rgba(244,63,94,0.18)"; }
        else if (sev === "HIGH") { sevColor = "var(--amber)"; sevBg = "rgba(245,158,11,0.16)"; }
        else if (sev === "LOW") { sevColor = "var(--text-muted)"; sevBg = "rgba(100,116,139,0.15)"; }

        const isUnack = a.acknowledgement_state === "UNACKNOWLEDGED";
        const ackColor = isUnack ? "var(--amber)" : "var(--green)";
        const ackText = isUnack ? "UNACKNOWLEDGED" : `ACK (${escapeHtml(a.acknowledged_by || "user")})`;

        const timeFormatted = a.timestamp ? a.timestamp.substring(11, 19) : "--:--:--";
        const confPercent = (Number(a.confidence || 0.95) * 100).toFixed(1) + "%";

        const ackButton = isUnack ?
            `<button type="button" class="btn-sim-action btn-ack" data-alert-id="${escapeHtml(a.alert_id)}" onclick="acknowledgeAlert('${a.alert_id}')" style="padding: 3px 8px; font-size: 10px; background: rgba(245,158,11,0.15); border: 1px solid rgba(245,158,11,0.5); color: var(--amber); border-radius: 3px; cursor: pointer;">Acknowledge</button>` :
            `<span class="tag tag-ack-confirmed" style="font-size: 10px;">Acknowledged</span>`;

        return `<tr>
            <td><span class="tag" style="color:${sevColor}; background:${sevBg}; border-color:${sevColor}66; font-weight:700;">${sev}</span></td>
            <td style="font-family: var(--font-mono); font-weight:600; color:var(--text-primary);">${escapeHtml(a.alert_id)}</td>
            <td style="font-family: var(--font-mono); color:var(--text-muted);">${timeFormatted}</td>
            <td><strong style="color:var(--text-primary);">${escapeHtml(a.attack_type)}</strong></td>
            <td style="font-family: var(--font-mono); color:var(--text-secondary);">${escapeHtml(a.device_id || a.target)}</td>
            <td style="font-family: var(--font-mono);">${confPercent}</td>
            <td><span class="tag tag-lifecycle" style="font-size: 9px;">${escapeHtml(a.lifecycle_state)}</span></td>
            <td><span class="tag" style="font-size: 9px; color:var(--cyan); border-color:rgba(56,189,248,0.3);">${escapeHtml(a.current_action)}</span></td>
            <td><span class="tag" style="color:${ackColor}; border-color:${ackColor}44; font-size:9px;">${ackText}</span></td>
            <td style="white-space: nowrap;">
                <div style="display: flex; gap: 4px; align-items: center;">
                    ${ackButton}
                    <a href="#sec-incidents" onclick="highlightIncidentInJournal('${a.incident_id}')" style="padding: 3px 6px; font-size: 10px; background: var(--bg-card); border: 1px solid var(--border-subtle); color: var(--text-secondary); text-decoration: none; border-radius: 3px;">VIEW INCIDENT</a>
                </div>
            </td>
        </tr>`;
    }).join("");
}

async function acknowledgeAlert(alertId) {
    try {
        const res = await fetch(`/api/admin/alerts/${alertId}/acknowledge`, {
            method: "POST",
            headers: { "Content-Type": "application/json" }
        });
        if (res.ok) {
            await refreshAdminAlerts();
            await refreshAdminOverview();
            await refreshAdminAuditLogs();
        } else {
            const err = await res.json();
            alert(`Unable to acknowledge alert: ${err.error || "Permission denied"}`);
        }
    } catch (e) {
        console.error("Acknowledge alert error:", e);
    }
}

function highlightIncidentInJournal(incidentId) {
    const el = document.getElementById("sec-incidents");
    if (el) {
        el.scrollIntoView({ behavior: "smooth" });
        setTimeout(() => {
            const rows = document.querySelectorAll("#incidentsTableBody tr");
            rows.forEach(r => {
                if (r.textContent.includes(incidentId)) {
                    r.style.outline = "2px solid var(--cyan)";
                    r.style.background = "rgba(56, 189, 248, 0.15)";
                    setTimeout(() => {
                        r.style.outline = "";
                        r.style.background = "";
                    }, 3500);
                }
            });
        }, 400);
    }
}

async function refreshAdminUsers() {
    const tbody = document.getElementById("adminUsersTableBody");
    if (!tbody) return;

    if (!currentAuthSession) {
        await checkAuthStatus();
    }

    if (!currentAuthSession || currentAuthSession.role !== "ADMIN") {
        tbody.innerHTML = `<tr>
            <td>USR-OPERATOR-01</td>
            <td><strong>operator</strong></td>
            <td><span class="tag" style="color:var(--amber); border-color:rgba(245,158,11,0.4);">OPERATOR</span></td>
            <td><span class="tag" style="color:var(--green);">ACTIVE</span></td>
            <td><span class="tag" style="color:var(--amber);">SIMULATED MFA</span></td>
            <td style="font-family:var(--font-mono); color:var(--text-muted);">2026-09-15</td>
            <td style="font-family:var(--font-mono); color:var(--text-muted);">Recent</td>
            <td style="color:var(--text-muted); font-size:10px;">READ-ONLY VIEW</td>
        </tr>`;
        return;
    }

    try {
        const res = await fetch("/api/admin/users", { cache: "no-store" });
        if (!res.ok) return;
        const data = await res.json();
        const users = data.users || [];

        if (!users.length) {
            tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; color:var(--text-muted); padding:14px;">No users registered.</td></tr>';
            return;
        }

        tbody.innerHTML = users.map(u => {
            const isActive = u.status === "ACTIVE";
            const roleColor = u.role === "ADMIN" ? "var(--cyan)" : "var(--amber)";
            const toggleAction = isActive ? "DISABLED" : "ACTIVE";
            const toggleBtnText = isActive ? "Disable" : "Enable";
            const toggleBtnClass = isActive ? "btn-user-disable" : "btn-user-enable";
            const mustChange = Boolean(u.must_change_password);
            const mustChangeBadge = mustChange
                ? `<span class="tag" style="color:var(--amber); border-color:rgba(245,158,11,0.4); font-size:9px; margin-left:6px;" title="Mandatory password change required on next login">PW RESET REQ</span>`
                : "";

            return `<tr>
                <td style="font-family:var(--font-mono); font-size:10px; color:var(--text-muted);">${escapeHtml(u.user_id)}</td>
                <td style="font-weight:700; color:var(--text-primary);">
                    ${escapeHtml(u.username)}
                    ${mustChangeBadge}
                </td>
                <td><span class="tag" style="color:${roleColor}; border-color:${roleColor}55;">${escapeHtml(u.role)}</span></td>
                <td><span class="tag" style="color:${isActive ? 'var(--green)' : 'var(--red)'}; border-color:${isActive ? 'var(--green)' : 'var(--red)'}44;">${escapeHtml(u.status)}</span></td>
                <td><span class="tag" style="color:var(--amber); border-color:rgba(245,158,11,0.3); font-size:9px;">${escapeHtml(u.mfa_status || "SIMULATED")}</span></td>
                <td style="font-family:var(--font-mono); font-size:10px; color:var(--text-muted);">${u.created_at ? u.created_at.substring(0, 10) : "--"}</td>
                <td style="font-family:var(--font-mono); font-size:10px; color:var(--text-muted);">${u.last_login ? u.last_login.substring(11, 19) : "Never"}</td>
                <td>
                    <div class="user-action-group">
                        <button type="button" class="btn-user-action btn-user-edit" onclick="openEditUserModal('${escapeHtml(u.user_id)}', '${escapeHtml(u.username)}', '${escapeHtml(u.role)}')" title="Edit User Profile">
                            Edit
                        </button>
                        <button type="button" class="btn-user-action btn-user-reset" onclick="openResetPasswordModal('${escapeHtml(u.user_id)}', '${escapeHtml(u.username)}')" title="Reset User Password">
                            Reset PW
                        </button>
                        <button type="button" class="btn-user-action ${toggleBtnClass}" onclick="toggleUserStatus('${escapeHtml(u.user_id)}', '${toggleAction}')" title="${toggleBtnText} User Account">
                            ${toggleBtnText}
                        </button>
                        <button type="button" class="btn-user-action btn-user-delete" onclick="openDeleteUserModal('${escapeHtml(u.user_id)}', '${escapeHtml(u.username)}')" title="Permanently Delete User Account">
                            Delete
                        </button>
                    </div>
                </td>
            </tr>`;
        }).join("");
    } catch (e) {
        console.warn("Admin users error:", e);
    }
}

/* ==========================================================================
   USER MANAGEMENT ENHANCEMENT: NOTIFICATIONS, MODALS & MUTATION HANDLERS
   ========================================================================== */

function showAicgToast(message, type = "info", duration = 4000) {
    const container = document.getElementById("aicgToastContainer");
    if (!container) {
        console.log(`[AICG ${type.toUpperCase()}] ${message}`);
        return;
    }

    const toast = document.createElement("div");
    toast.className = `aicg-toast aicg-toast-${type}`;

    let iconSvg = "";
    if (type === "success") {
        iconSvg = `<svg class="aicg-toast-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>`;
    } else if (type === "error") {
        iconSvg = `<svg class="aicg-toast-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`;
    } else if (type === "warning") {
        iconSvg = `<svg class="aicg-toast-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
    } else {
        iconSvg = `<svg class="aicg-toast-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`;
    }

    toast.innerHTML = `
        ${iconSvg}
        <div class="aicg-toast-body">${escapeHtml(message)}</div>
        <button type="button" class="aicg-toast-close" aria-label="Dismiss">&times;</button>
    `;

    const closeBtn = toast.querySelector(".aicg-toast-close");
    const removeToast = () => {
        toast.style.opacity = "0";
        toast.style.transform = "translateY(8px) scale(0.96)";
        setTimeout(() => toast.remove(), 200);
    };

    closeBtn.addEventListener("click", removeToast);
    container.appendChild(toast);

    if (duration > 0) {
        setTimeout(removeToast, duration);
    }
}

function togglePasswordVisibility(inputId, btnEl) {
    const input = document.getElementById(inputId);
    if (!input) return;
    const isPassword = input.type === "password";
    input.type = isPassword ? "text" : "password";

    if (btnEl) {
        btnEl.setAttribute("aria-label", isPassword ? "Hide password" : "Show password");
        btnEl.innerHTML = isPassword
            ? `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`
            : `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
    }
}

/* Edit User Modal */
function openEditUserModal(userId, username, role) {
    const modal = document.getElementById("editUserModal");
    if (!modal) return;
    document.getElementById("editUserId").value = userId;
    document.getElementById("editUserIdentifier").value = userId;
    document.getElementById("editUsername").value = username;
    document.getElementById("editUserRole").value = role || "OPERATOR";
    const msg = document.getElementById("editUserMsg");
    if (msg) {
        msg.style.display = "none";
        msg.textContent = "";
        msg.className = "modal-alert-box";
    }
    modal.style.display = "flex";
    setTimeout(() => document.getElementById("editUsername").focus(), 50);
}

function closeEditUserModal() {
    const modal = document.getElementById("editUserModal");
    if (modal) modal.style.display = "none";
}

async function submitEditUser(event) {
    event.preventDefault();
    const userId = document.getElementById("editUserId").value;
    const username = document.getElementById("editUsername").value.trim();
    const role = document.getElementById("editUserRole").value;
    const msg = document.getElementById("editUserMsg");
    const saveBtn = document.getElementById("btnSaveEditUser");

    if (!username) {
        if (msg) {
            msg.className = "modal-alert-box error";
            msg.textContent = "Username cannot be empty.";
            msg.style.display = "block";
        }
        return;
    }

    if (saveBtn) saveBtn.disabled = true;

    try {
        const res = await fetch(`/api/admin/users/${encodeURIComponent(userId)}`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, role })
        });
        const data = await res.json();

        if (res.ok) {
            closeEditUserModal();
            showAicgToast(`User profile for '${username}' updated successfully.`, "success");
            await refreshAdminUsers();
            await refreshAdminOverview();
            await refreshAdminAuditLogs();
        } else {
            let errorText = data.error || "Failed to update user.";
            if (res.status === 409 || data.code === "USERNAME_CONFLICT") {
                errorText = `Username conflict: '${username}' is already in use.`;
            } else if (data.code === "LAST_ADMIN_PROTECTED") {
                errorText = "Action rejected: Cannot demote the last remaining active administrator account.";
            }
            if (msg) {
                msg.className = "modal-alert-box error";
                msg.textContent = errorText;
                msg.style.display = "block";
            }
            showAicgToast(errorText, "error");
        }
    } catch (err) {
        console.error("Edit user error:", err);
        if (msg) {
            msg.className = "modal-alert-box error";
            msg.textContent = "Network error while saving user profile.";
            msg.style.display = "block";
        }
        showAicgToast("Network communication error.", "error");
    } finally {
        if (saveBtn) saveBtn.disabled = false;
    }
}

/* Reset Password Modal */
function openResetPasswordModal(userId, username) {
    const modal = document.getElementById("resetPasswordModal");
    if (!modal) return;
    document.getElementById("resetPasswordUserId").value = userId;
    document.getElementById("resetPasswordTargetDisplay").textContent = username;
    document.getElementById("resetPasswordIdDisplay").textContent = userId;
    document.getElementById("adminNewPassword").value = "";
    document.getElementById("adminConfirmPassword").value = "";
    const msg = document.getElementById("resetPasswordMsg");
    if (msg) {
        msg.style.display = "none";
        msg.textContent = "";
        msg.className = "modal-alert-box";
    }
    modal.style.display = "flex";
    setTimeout(() => document.getElementById("adminNewPassword").focus(), 50);
}

function closeResetPasswordModal() {
    const modal = document.getElementById("resetPasswordModal");
    if (modal) modal.style.display = "none";
}

async function submitAdminPasswordReset(event) {
    event.preventDefault();
    const userId = document.getElementById("resetPasswordUserId").value;
    const targetUser = document.getElementById("resetPasswordTargetDisplay").textContent;
    const newPassword = document.getElementById("adminNewPassword").value;
    const confirmPassword = document.getElementById("adminConfirmPassword").value;
    const msg = document.getElementById("resetPasswordMsg");
    const submitBtn = document.getElementById("btnSubmitPasswordReset");

    if (!newPassword || newPassword.length < 8) {
        if (msg) {
            msg.className = "modal-alert-box error";
            msg.textContent = "New password must be at least 8 characters long.";
            msg.style.display = "block";
        }
        return;
    }

    if (newPassword !== confirmPassword) {
        if (msg) {
            msg.className = "modal-alert-box error";
            msg.textContent = "Password confirmation does not match.";
            msg.style.display = "block";
        }
        return;
    }

    if (submitBtn) submitBtn.disabled = true;

    try {
        const res = await fetch(`/api/admin/users/${encodeURIComponent(userId)}`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ password: newPassword })
        });
        const data = await res.json();

        if (res.ok) {
            closeResetPasswordModal();
            showAicgToast(`Password reset successfully for '${targetUser}'. Mandatory password change enforced on next login.`, "success", 5000);
            await refreshAdminUsers();
            await refreshAdminAuditLogs();
        } else {
            const errorText = data.error || "Password reset failed.";
            if (msg) {
                msg.className = "modal-alert-box error";
                msg.textContent = errorText;
                msg.style.display = "block";
            }
            showAicgToast(errorText, "error");
        }
    } catch (err) {
        console.error("Admin password reset error:", err);
        if (msg) {
            msg.className = "modal-alert-box error";
            msg.textContent = "Gateway communication error while resetting password.";
            msg.style.display = "block";
        }
        showAicgToast("Gateway communication error.", "error");
    } finally {
        if (submitBtn) submitBtn.disabled = false;
    }
}

/* Delete User Modal */
function openDeleteUserModal(userId, username) {
    const modal = document.getElementById("deleteUserModal");
    if (!modal) return;
    document.getElementById("deleteUserId").value = userId;
    document.getElementById("deleteTargetUsername").textContent = username;
    document.getElementById("deleteTargetUserId").textContent = userId;
    const msg = document.getElementById("deleteUserMsg");
    if (msg) {
        msg.style.display = "none";
        msg.textContent = "";
        msg.className = "modal-alert-box";
    }
    const confirmBtn = document.getElementById("btnConfirmDeleteUser");
    if (confirmBtn) confirmBtn.disabled = false;
    modal.style.display = "flex";
}

function closeDeleteUserModal() {
    const modal = document.getElementById("deleteUserModal");
    if (modal) modal.style.display = "none";
}

async function submitDeleteUser() {
    const userId = document.getElementById("deleteUserId").value;
    const username = document.getElementById("deleteTargetUsername").textContent;
    const msg = document.getElementById("deleteUserMsg");
    const confirmBtn = document.getElementById("btnConfirmDeleteUser");

    if (confirmBtn) confirmBtn.disabled = true;

    try {
        const res = await fetch(`/api/admin/users/${encodeURIComponent(userId)}`, {
            method: "DELETE"
        });
        const data = await res.json();

        if (res.ok) {
            closeDeleteUserModal();
            showAicgToast(`User account '${username}' (${userId}) deleted successfully.`, "success");
            await refreshAdminUsers();
            await refreshAdminOverview();
            await refreshAdminAuditLogs();
        } else {
            let errorText = data.error || "User deletion failed.";
            if (data.code === "SELF_DELETION_DENIED") {
                errorText = "Self-Deletion Denied: Administrators cannot delete their own active account.";
            } else if (data.code === "LAST_ADMIN_PROTECTED") {
                errorText = "Last-Admin Protected: Cannot delete the last remaining active administrator account.";
            } else if (res.status === 403) {
                errorText = "Forbidden: Administrator role required to delete user accounts.";
            } else if (res.status === 404) {
                errorText = "User not found or already deleted.";
            }
            if (msg) {
                msg.className = "modal-alert-box error";
                msg.textContent = errorText;
                msg.style.display = "block";
            }
            showAicgToast(errorText, "error");
        }
    } catch (err) {
        console.error("Delete user error:", err);
        if (msg) {
            msg.className = "modal-alert-box error";
            msg.textContent = "Gateway communication error while deleting user.";
            msg.style.display = "block";
        }
        showAicgToast("Gateway communication error.", "error");
    } finally {
        if (confirmBtn) confirmBtn.disabled = false;
    }
}

function toggleAddUserForm() {
    const el = document.getElementById("addUserFormContainer");
    if (el) el.style.display = (el.style.display === "none" || !el.style.display) ? "block" : "none";
}

async function submitCreateUser() {
    const user = document.getElementById("newLabUsername").value.trim();
    const pass = document.getElementById("newLabPassword").value;
    const role = document.getElementById("newLabRole").value;
    const msg = document.getElementById("addUserMsg");

    if (!user || !pass) {
        if (msg) {
            msg.style.display = "block";
            msg.style.color = "var(--red)";
            msg.textContent = "Username and password required.";
        }
        showAicgToast("Username and password are required.", "warning");
        return;
    }

    if (pass.length < 8) {
        if (msg) {
            msg.style.display = "block";
            msg.style.color = "var(--red)";
            msg.textContent = "Password must be at least 8 characters long.";
        }
        showAicgToast("Password must be at least 8 characters long.", "warning");
        return;
    }

    try {
        const res = await fetch("/api/admin/users", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username: user, password: pass, role: role })
        });
        const data = await res.json();
        if (res.ok) {
            document.getElementById("newLabUsername").value = "";
            document.getElementById("newLabPassword").value = "";
            toggleAddUserForm();
            showAicgToast(`User '${user}' created successfully with role ${role}.`, "success");
            await refreshAdminUsers();
            await refreshAdminOverview();
            await refreshAdminAuditLogs();
        } else {
            const errorText = data.error || "User creation failed.";
            if (msg) {
                msg.style.display = "block";
                msg.style.color = "var(--red)";
                msg.textContent = errorText;
            }
            showAicgToast(errorText, "error");
        }
    } catch (e) {
        console.error("Create user error:", e);
        showAicgToast("Network error while creating user.", "error");
    }
}

async function toggleUserStatus(userId, newStatus) {
    try {
        const res = await fetch(`/api/admin/users/${encodeURIComponent(userId)}`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ status: newStatus })
        });
        if (res.ok) {
            showAicgToast(`User account status updated to ${newStatus}.`, "success");
            await refreshAdminUsers();
            await refreshAdminOverview();
            await refreshAdminAuditLogs();
        } else {
            const err = await res.json();
            let errorText = err.error || "Status update failed.";
            if (err.code === "LAST_ADMIN_PROTECTED") {
                errorText = "Action rejected: Cannot disable the last remaining active administrator account.";
            }
            showAicgToast(errorText, "error");
        }
    } catch (e) {
        console.error("Toggle user status error:", e);
        showAicgToast("Network error while updating user status.", "error");
    }
}

let cachedAuditRecords = [];

async function checkAuditIntegrity() {
    const badge = document.getElementById("auditIntegrityBadge");
    if (!badge) return;
    try {
        const res = await fetch("/api/admin/audit/integrity", { cache: "no-store" });
        if (!res.ok) {
            if (res.status === 403) {
                badge.style.display = "none";
            } else {
                badge.textContent = "LEDGER INTEGRITY: ERROR";
                badge.className = "tag tag-tamper";
                badge.style.color = "var(--red)";
                badge.style.borderColor = "rgba(239,68,68,0.5)";
                badge.style.background = "rgba(239,68,68,0.15)";
            }
            return;
        }
        const data = await res.json();
        badge.style.display = "inline-flex";
        if (data.valid) {
            const countStr = typeof data.count === "number" ? ` (${data.count} records)` : "";
            badge.textContent = `LEDGER VERIFIED (SHA-256)${countStr}`;
            badge.className = "tag tag-verified";
            badge.style.color = "var(--green)";
            badge.style.borderColor = "rgba(16,185,129,0.4)";
            badge.style.background = "rgba(16,185,129,0.15)";
        } else {
            badge.textContent = "LEDGER TAMPER DETECTED (SHA-256)";
            badge.className = "tag tag-tamper";
            badge.style.color = "var(--red)";
            badge.style.borderColor = "rgba(239,68,68,0.5)";
            badge.style.background = "rgba(239,68,68,0.2)";
        }
    } catch (e) {
        console.warn("Audit integrity error:", e);
    }
}

async function refreshAdminAuditLogs() {
    const tbody = document.getElementById("adminAuditTableBody");
    if (!tbody) return;

    checkAuditIntegrity();

    try {
        const res = await fetch("/api/admin/audit?limit=100", { cache: "no-store" });
        if (!res.ok) {
            if (res.status === 403) {
                tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; color:var(--text-muted); padding:14px;">Audit log access is restricted to ADMIN role. Operator access is denied (HTTP 403).</td></tr>';
            }
            return;
        }
        const data = await res.json();
        cachedAuditRecords = data.audit_events || [];
        renderAuditTable(cachedAuditRecords);
    } catch (e) {
        console.warn("Audit logs error:", e);
    }
}

function renderAuditTable(records) {
    const tbody = document.getElementById("adminAuditTableBody");
    if (!tbody) return;

    if (!records.length) {
        const searchVal = document.getElementById("auditSearchInput")?.value?.trim();
        tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; color:var(--text-muted); padding:16px;">${searchVal ? "No administrative audit records match your filter criteria." : "No administrative audit records logged yet."}</td></tr>`;
        return;
    }

    tbody.innerHTML = records.map(a => {
        const isSuccess = a.result === "SUCCESS";
        const resultColor = isSuccess ? "var(--green)" : (a.result === "DENIED" ? "var(--amber)" : "var(--red)");
        const timeFormatted = a.timestamp ? a.timestamp.substring(0, 19).replace("T", " ") : "--";

        return `<tr>
            <td style="font-family: var(--font-mono); font-size:10px; color:var(--cyan);">${escapeHtml(a.event_id)}</td>
            <td style="font-family: var(--font-mono); font-size:10px; color:var(--text-muted);">${timeFormatted}</td>
            <td style="font-weight:700; color:var(--text-primary);">${escapeHtml(a.username)}</td>
            <td><span class="tag" style="font-size:9px;">${escapeHtml(a.role)}</span></td>
            <td style="font-family: var(--font-mono); font-weight:700; color:var(--cyan);">${escapeHtml(a.action)}</td>
            <td style="color:var(--text-muted);">${escapeHtml(a.resource || "system")}</td>
            <td><span class="tag" style="color:${resultColor}; border-color:${resultColor}44; font-size:9px;">${escapeHtml(a.result)}</span></td>
            <td style="color:var(--text-secondary); max-width:320px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${escapeHtml(a.details)}">${escapeHtml(a.details)}</td>
        </tr>`;
    }).join("");
}

function filterAuditTable() {
    const query = (document.getElementById("auditSearchInput")?.value || "").toLowerCase();
    if (!query) {
        renderAuditTable(cachedAuditRecords);
        return;
    }
    const filtered = cachedAuditRecords.filter(a => {
        return (a.action && a.action.toLowerCase().includes(query)) ||
               (a.username && a.username.toLowerCase().includes(query)) ||
               (a.details && a.details.toLowerCase().includes(query)) ||
               (a.resource && a.resource.toLowerCase().includes(query));
    });
    renderAuditTable(filtered);
}

// Expose Admin Security Layer functions to window
window.refreshAdminSection = refreshAdminSection;
window.refreshAdminOverview = refreshAdminOverview;
window.refreshAdminAlerts = refreshAdminAlerts;
window.refreshAdminUsers = refreshAdminUsers;
window.refreshAdminAuditLogs = refreshAdminAuditLogs;
window.filterAdminAlerts = filterAdminAlerts;
window.acknowledgeAlert = acknowledgeAlert;
window.toggleAddUserForm = toggleAddUserForm;
window.submitCreateUser = submitCreateUser;
window.toggleUserStatus = toggleUserStatus;
window.openEditUserModal = openEditUserModal;
window.closeEditUserModal = closeEditUserModal;
window.submitEditUser = submitEditUser;
window.openResetPasswordModal = openResetPasswordModal;
window.closeResetPasswordModal = closeResetPasswordModal;
window.submitAdminPasswordReset = submitAdminPasswordReset;
window.openDeleteUserModal = openDeleteUserModal;
window.closeDeleteUserModal = closeDeleteUserModal;
window.submitDeleteUser = submitDeleteUser;
window.togglePasswordVisibility = togglePasswordVisibility;
window.showAicgToast = showAicgToast;
window.filterAuditTable = filterAuditTable;
window.refreshAuditLogs = refreshAdminAuditLogs;
window.checkAuditIntegrity = checkAuditIntegrity;
window.scheduleCoalescedRefresh = scheduleCoalescedRefresh;
window.executeCoalescedRefresh = executeCoalescedRefresh;
window.__refreshCoalesce = {
    get timer() { return refreshTimer; },
    get inFlight() { return isRefreshInFlight; },
    get pending() { return refreshPending; },
    schedule: scheduleCoalescedRefresh,
    execute: executeCoalescedRefresh,
};

// Boot HMI
initSidebarNavigation();
checkAuthStatus();
refreshDashboard();
setInterval(refreshDashboard, 5000);
initSSE();

