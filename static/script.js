// ============================================================
// PHISHLENS — THREAT INTELLIGENCE ENGINE
// Premium Frontend Controller
// ============================================================

"use strict";

let qrScanner = null;
let scanCount = 0;
let threatCount = 0;
let scanHistory = [];

const HISTORY_KEY = "phishlens_history";
const MAX_HISTORY = 20;


// ============================================================
// INITIALIZATION
// ============================================================

document.addEventListener("DOMContentLoaded", () => {
    initializePhishLens();
});


function initializePhishLens() {

    generateSessionId();
    loadHistory();

    const result = document.getElementById("result");
    const loading = document.getElementById("loading");
    const urlSection = document.getElementById("urlSection");
    const qrSection = document.getElementById("qrSection");

    if (result) {
        result.classList.add("hidden");
    }

    if (loading) {
        loading.classList.add("hidden");
    }

    if (qrSection) {
        qrSection.classList.add("hidden");
    }

    if (urlSection) {
        urlSection.classList.remove("hidden");
    }

    updateStats();
    renderHistoryPreview();

    const input = document.getElementById("urlInput");

    if (input) {

        input.addEventListener("keydown", event => {

            if (
                event.key === "Enter" &&
                (event.ctrlKey || event.metaKey)
            ) {
                event.preventDefault();
                analyzeURL();
                return;
            }

            if (event.key === "Enter") {
                event.preventDefault();
                analyzeURL();
            }
        });

        input.addEventListener("input", () => {
            clearOldResult();
        });
    }
}


// ============================================================
// SESSION
// ============================================================

function generateSessionId() {

    const characters =
        "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

    let id = "";

    for (let i = 0; i < 4; i++) {

        id += characters.charAt(
            Math.floor(
                Math.random() * characters.length
            )
        );
    }

    const session =
        document.getElementById("sessionId");

    if (session) {
        session.textContent = id;
    }
}


// ============================================================
// NAVIGATION
// ============================================================

function scrollToScanner() {

    const scanner =
        document.getElementById("scanner");

    if (scanner) {

        scanner.scrollIntoView({
            behavior: "smooth",
            block: "start"
        });
    }
}


function showHowItWorks() {

    const section =
        document.getElementById("howItWorks") ||
        document.getElementById("how-it-works");

    if (section) {

        section.scrollIntoView({
            behavior: "smooth",
            block: "start"
        });
    }
}


// ============================================================
// TABS
// ============================================================

function showURL() {

    stopQRScanner();

    const urlSection =
        document.getElementById("urlSection");

    const qrSection =
        document.getElementById("qrSection");

    const result =
        document.getElementById("result");

    const loading =
        document.getElementById("loading");

    if (urlSection) {
        urlSection.classList.remove("hidden");
    }

    if (qrSection) {
        qrSection.classList.add("hidden");
    }

    if (result) {
        result.classList.add("hidden");
    }

    if (loading) {
        loading.classList.add("hidden");
    }

    setActiveTab(0);
}


function showQR() {

    const urlSection =
        document.getElementById("urlSection");

    const qrSection =
        document.getElementById("qrSection");

    const result =
        document.getElementById("result");

    const loading =
        document.getElementById("loading");

    if (urlSection) {
        urlSection.classList.add("hidden");
    }

    if (qrSection) {
        qrSection.classList.remove("hidden");
    }

    if (result) {
        result.classList.add("hidden");
    }

    if (loading) {
        loading.classList.add("hidden");
    }

    setActiveTab(1);
}


function setActiveTab(index) {

    const tabs =
        document.querySelectorAll(
            ".analysis-tab, .scanner-tab"
        );

    tabs.forEach((tab, i) => {

        tab.classList.toggle(
            "active",
            i === index
        );
    });
}


// ============================================================
// QUICK TESTS
// ============================================================

function useExample(type) {

    const input =
        document.getElementById("urlInput");

    if (!input) {
        return;
    }

    let url = "";

    switch (type) {

        case "safe":

            url =
                "https://google.com";

            break;

        case "suspicious":

            url =
                "http://192.168.1.1/login/verify/account";

            break;

        case "lookalike":

            url =
                "https://paypa1-secure-login.com/verify";

            break;

        case "shortener":

            url =
                "https://bit.ly/example";

            break;

        default:

            if (
                typeof type === "string" &&
                (
                    type.startsWith("http") ||
                    type.startsWith("upi://")
                )
            ) {
                url = type;
            } else {
                return;
            }
    }

    input.value = url;

    clearOldResult();

    input.focus();

    input.setSelectionRange(
        input.value.length,
        input.value.length
    );
}


// ============================================================
// CLEAR RESULT
// ============================================================

function clearOldResult() {

    const result =
        document.getElementById("result");

    const redirectCard =
        document.getElementById("redirectCard");

    if (result) {
        result.classList.add("hidden");
    }

    if (redirectCard) {
        redirectCard.classList.add("hidden");
    }
}


// ============================================================
// ANALYZE URL
// ============================================================

async function analyzeURL() {

    const input =
        document.getElementById("urlInput");

    if (!input) {
        return;
    }

    const url =
        input.value.trim();

    if (!url) {

        showToast(
            "Enter a URL before starting analysis."
        );

        input.focus();

        return;
    }

    const analyzeButton =
        document.getElementById("analyzeButton") ||
        document.querySelector(".analyze-button");

    if (analyzeButton) {
        analyzeButton.disabled = true;
    }

    clearOldResult();
    showLoading();

    try {

        const response =
            await fetch(
                "/analyze",
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        url: url
                    })
                }
            );

        if (!response.ok) {

            throw new Error(
                "Server returned HTTP " +
                response.status
            );
        }

        const data =
            await response.json();

        if (data.error) {
            throw new Error(data.error);
        }

        scanCount++;

        const verdict =
            String(
                data.verdict ||
                "UNKNOWN"
            ).toUpperCase();

        if (
            verdict === "DANGER" ||
            verdict === "CAUTION"
        ) {
            threatCount++;
        }

        saveToHistory(
            data,
            url
        );

        hideLoading();

        showResult(data);

        updateStats();

        renderHistoryPreview();

    } catch (error) {

        console.error(
            "PhishLens error:",
            error
        );

        hideLoading();

        showToast(
            error.message ||
            "Unable to analyze this destination."
        );

    } finally {

        if (analyzeButton) {
            analyzeButton.disabled = false;
        }
    }
}


// ============================================================
// LOADING
// ============================================================

function showLoading() {

    const urlSection =
        document.getElementById("urlSection");

    const qrSection =
        document.getElementById("qrSection");

    const result =
        document.getElementById("result");

    const loading =
        document.getElementById("loading");

    if (urlSection) {
        urlSection.classList.add("hidden");
    }

    if (qrSection) {
        qrSection.classList.add("hidden");
    }

    if (result) {
        result.classList.add("hidden");
    }

    if (loading) {
        loading.classList.remove("hidden");
    }

    animateAnalysisSteps();
}


function hideLoading() {

    const loading =
        document.getElementById("loading");

    if (loading) {
        loading.classList.add("hidden");
    }
}


function animateAnalysisSteps() {

    const steps =
        document.querySelectorAll(
            ".analysis-step"
        );

    steps.forEach(step => {
        step.classList.remove("active");
    });

    steps.forEach((step, index) => {

        setTimeout(() => {

            step.classList.add("active");

        }, index * 350);
    });
}


// ============================================================
// SHOW RESULT
// ============================================================

function showResult(data) {

    const result =
        document.getElementById("result");

    if (!result) {
        return;
    }

    result.classList.remove("hidden");

    renderVerdict(data);
    renderScore(data);
    renderSignals(data);
    renderReasons(data);
    renderDomainDNA(data);
    renderRedirectPath(data);
    renderUPIShield(data);
    renderConfidence(data);
    renderExplanation(data);
    renderPersistenceMeta(data);


    setTimeout(() => {

        result.scrollIntoView({
            behavior: "smooth",
            block: "start"
        });

    }, 150);
}


// ============================================================
// VERDICT
// ============================================================

function renderVerdict(data) {

    const verdict =
        String(
            data.verdict ||
            "UNKNOWN"
        ).toUpperCase();

    const badge =
        document.getElementById(
            "verdictBadge"
        );

    if (badge) {

        badge.textContent =
            verdict;

        badge.className =
            "verdict-badge";

        if (verdict === "SAFE") {

            badge.classList.add(
                "safe",
                "verdict-safe"
            );

        } else if (verdict === "CAUTION") {

            badge.classList.add(
                "caution",
                "verdict-caution"
            );

        } else {

            badge.classList.add(
                "danger",
                "verdict-danger"
            );
        }
    }

    const title =
        document.getElementById(
            "resultTitle"
        );

    if (!title) {
        return;
    }

    if (verdict === "SAFE") {

        title.textContent =
            "No major threat detected";

    } else if (verdict === "CAUTION") {

        title.textContent =
            "Suspicious indicators detected";

    } else {

        title.textContent =
            "Potential phishing threat detected";
    }
}


// ============================================================
// RISK SCORE
// ============================================================

function renderScore(data) {

    const rawScore =
        data.score ??
        data.risk_score ??
        0;

    const numericScore =
        Number(rawScore);

    const score =
        Number.isFinite(numericScore)
            ? Math.max(
                0,
                Math.min(
                    100,
                    numericScore
                )
            )
            : 0;

    const scoreElement =
        document.getElementById("scoreValue") ||
        document.getElementById("riskScore");

    const riskBar =
        document.getElementById("riskBar");

    if (scoreElement) {

        animateScore(
            scoreElement,
            score
        );
    }

    if (riskBar) {

        riskBar.style.width = "0%";

        requestAnimationFrame(() => {

            riskBar.style.width =
                score + "%";

        });

        applyRiskColor(
            riskBar,
            String(
                data.verdict ||
                ""
            ).toUpperCase()
        );
    }

    setText(
        "resultDomain",
        data.final_domain ||
        data.domain ||
        "Unknown destination"
    );
}


function animateScore(
    element,
    target
) {

    const finalScore =
        Math.round(target);

    const duration = 750;

    const start =
        performance.now();

    function update(timestamp) {

        const progress =
            Math.min(
                (
                    timestamp -
                    start
                ) / duration,
                1
            );

        const eased =
            1 -
            Math.pow(
                1 - progress,
                3
            );

        element.textContent =
            Math.round(
                eased *
                finalScore
            );

        if (progress < 1) {

            requestAnimationFrame(
                update
            );

        } else {

            element.textContent =
                finalScore;
        }
    }

    requestAnimationFrame(update);
}


// ============================================================
// THREAT SIGNALS
// ============================================================

function renderSignals(data) {

    const signals =
        data.signals || {};

    const reasons =
        Array.isArray(data.reasons)
            ? data.reasons
            : [];

    const reasonText =
        reasons
            .join(" ")
            .toLowerCase();

    const derivedURL =
        /url|http|ip address|long|encoded|@|subdomain|shortener|redirect/
            .test(reasonText)
            ? Math.min(
                100,
                25 +
                reasons.length * 10
            )
            : 0;

    const derivedDomain =
        /domain|lookalike|homoglyph|unicode|trusted|registr/
            .test(reasonText)
            ? Math.min(
                100,
                30 +
                reasons.length * 8
            )
            : 0;

    const derivedSecurity =
        /credential|login|verify|payment|collect|suspicious|phish|malicious|danger/
            .test(reasonText)
            ? Math.min(
                100,
                30 +
                reasons.length * 9
            )
            : 0;

    const urlRisk =
        Number(
            signals.url_structure ??
            signals.url ??
            derivedURL
        );

    const domainRisk =
        Number(
            signals.domain ??
            derivedDomain
        );

    const redirectRisk =
        Number(
            signals.redirect ??
            (
                Array.isArray(
                    data.redirect_chain
                ) &&
                data.redirect_chain.length > 1
                    ? Math.min(
                        100,
                        35 +
                        (
                            data.redirect_chain.length -
                            1
                        ) * 15
                    )
                    : 0
            )
        );

    const securityRisk =
        Number(
            signals.security ??
            derivedSecurity
        );

    setSignal(
        "urlSignal",
        urlRisk
    );

    setSignal(
        "domainSignal",
        domainRisk
    );

    setSignal(
        "securitySignal",
        Math.max(
            securityRisk,
            redirectRisk
        )
    );
}


function setSignal(
    id,
    value
) {

    const element =
        document.getElementById(id);

    if (!element) {
        return;
    }

    const numericValue =
        Number(value) || 0;

    const safeValue =
        Math.max(
            3,
            Math.min(
                100,
                numericValue
            )
        );

    element.style.width =
        "0%";

    requestAnimationFrame(() => {

        element.style.width =
            safeValue + "%";

    });
}


// ============================================================
// REASONS
// ============================================================

function renderReasons(data) {

    const container =
        document.getElementById("reasons") ||
        document.getElementById("reasonsList");

    if (!container) {
        return;
    }

    container.innerHTML = "";

    const list =
        Array.isArray(data.reasons)
            ? data.reasons
            : [];

    if (!list.length) {

        addReason(
            container,
            "No major suspicious indicators were detected."
        );

        return;
    }

    list.forEach(
        (reason, index) => {

            const item =
                document.createElement("div");

            item.className =
                "reason-item";

            item.style.animationDelay =
                index * 80 + "ms";

            item.innerHTML =
                "<span class='reason-dot'></span>" +
                "<span>" +
                escapeHTML(reason) +
                "</span>";

            container.appendChild(item);
        }
    );
}


function addReason(
    container,
    text
) {

    const item =
        document.createElement("div");

    item.className =
        "reason-item";

    item.innerHTML =
        "<span class='reason-dot'></span>" +
        "<span>" +
        escapeHTML(text) +
        "</span>";

    container.appendChild(item);
}


// ============================================================
// DOMAIN DNA
// ============================================================

function renderDomainDNA(data) {

    const info =
        data.domain_intelligence || {};

    const panel =
        document.getElementById("domainDNA") ||
        document.getElementById("domainIntelligence");

    if (!panel) {
        return;
    }

    const domain =
        info.domain ||
        data.domain ||
        "Unknown";

    const finalDomain =
        info.final_domain ||
        data.final_domain ||
        "";

    const type =
        info.type ||
        (
            info.is_ip
                ? "IP ADDRESS"
                : "DOMAIN"
        );

    const subdomains =
        info.subdomains ?? 0;

    const trusted =
        Boolean(info.trusted);

    const lookalike =
        Boolean(info.lookalike);

    const homoglyph =
        Boolean(info.homoglyph);

    const lookalikeTarget =
        info.lookalike_target ||
        "";

    panel.classList.remove("hidden");

    setText(
        "intelDomain",
        domain
    );

    setText(
        "intelType",
        type
    );

    setText(
        "intelSubdomains",
        subdomains
    );

    setText(
        "intelTrusted",
        trusted
            ? "YES"
            : "NO"
    );

    if (
        lookalike ||
        homoglyph
    ) {

        const displayTarget =
            lookalikeTarget
                ? String(
                    lookalikeTarget
                )
                    .replace(
                        /^https?:\/\//i,
                        ""
                    )
                    .replace(
                        /\/$/,
                        ""
                    )
                : "";

        setText(
            "intelLookalike",
            displayTarget
                ? `DETECTED → ${displayTarget}`
                : homoglyph
                    ? "UNICODE LOOKALIKE"
                    : "DETECTED"
        );

    } else {

        setText(
            "intelLookalike",
            "NONE"
        );
    }

    setText(
        "intelFinalDomain",
        finalDomain || "—"
    );

    const status =
        document.getElementById(
            "intelStatus"
        );

    if (status) {

        if (homoglyph) {

            status.textContent =
                "UNICODE LOOKALIKE";

        } else if (lookalike) {

            status.textContent =
                "LOOKALIKE DETECTED";

        } else if (trusted) {

            status.textContent =
                "TRUSTED DOMAIN";

        } else if (
            finalDomain &&
            finalDomain !== domain
        ) {

            status.textContent =
                "DESTINATION CHANGED";

        } else {

            status.textContent =
                "ANALYZED";
        }
    }

    panel.classList.remove(
        "domain-intelligence-reveal"
    );

    void panel.offsetWidth;

    panel.classList.add(
        "domain-intelligence-reveal"
    );
}


// ============================================================
// UPI SHIELD
// ============================================================

function renderUPIShield(data) {

    const panel =
        document.getElementById(
            "upiShield"
        );

    if (!panel) {
        return;
    }

    const upi =
        data.upi;

    if (!upi) {

        panel.classList.add(
            "hidden"
        );

        return;
    }

    panel.classList.remove(
        "hidden"
    );

    const risk =
        Number(
            upi.risk || 0
        );

    let statusText =
        "NO UPI SIGNAL";

    if (risk >= 60) {

        statusText =
            "HIGH RISK";

    } else if (risk >= 30) {

        statusText =
            "REVIEW";

    } else if (risk > 0) {

        statusText =
            "LOW RISK";
    }

    setText(
        "upiStatus",
        statusText
    );

    setText(
        "upiMessage",
        getUPIMessage(upi)
    );

    setText(
        "upiPayee",
        upi.payee ||
        "—"
    );

    setText(
        "upiPayeeName",
        upi.payee_name ||
        "—"
    );

    setText(
        "upiAmount",
        upi.amount ||
        "—"
    );

    setText(
        "upiCurrency",
        upi.currency ||
        "—"
    );

    setText(
        "upiRisk",
        risk + "/100"
    );
}


function getUPIMessage(upi) {

    if (
        Array.isArray(upi.reasons) &&
        upi.reasons.length
    ) {

        return upi.reasons[0];
    }

    if (upi.collect_detected) {

        return (
            "A payment-request or authorization " +
            "signal was detected. Verify the request " +
            "before approving it."
        );
    }

    return (
        "No major UPI-specific warning was detected."
    );
}


// ============================================================
// REDIRECT INTELLIGENCE
// ============================================================

function renderRedirectPath(data) {

    const card =
        document.getElementById(
            "redirectCard"
        );

    const chainElement =
        document.getElementById(
            "redirectChain"
        );

    const count =
        document.getElementById(
            "redirectCount"
        );

    if (!card || !chainElement) {
        return;
    }

    chainElement.innerHTML = "";

    const redirects =
        Array.isArray(
            data.redirect_chain
        )
            ? data.redirect_chain
            : [];

    if (
        redirects.length <= 1
    ) {

        card.classList.add(
            "hidden"
        );

        return;
    }

    card.classList.remove(
        "hidden"
    );

    const hops =
        Math.max(
            0,
            redirects.length - 1
        );

    if (count) {

        count.textContent =
            hops +
            " HOP" +
            (
                hops === 1
                    ? ""
                    : "S"
            );
    }

    redirects.forEach(
        (url, index) => {

            const node =
                document.createElement(
                    "div"
                );

            node.className =
                "redirect-node";

            const first =
                index === 0;

            const last =
                index ===
                redirects.length - 1;

            const label =
                first
                    ? "ORIGINAL DESTINATION"
                    : last
                        ? "FINAL DESTINATION"
                        : "REDIRECT " + index;

            const tag =
                first
                    ? "START"
                    : last
                        ? "FINAL"
                        : "HOP";

            node.innerHTML = `
                <div class="redirect-dot"></div>

                <div class="redirect-content">

                    <span class="redirect-label">
                        ${escapeHTML(label)}
                    </span>

                    <div class="redirect-url">
                        ${escapeHTML(url)}
                    </div>

                    <span class="redirect-tag">
                        ${escapeHTML(tag)}
                    </span>

                </div>
            `;

            chainElement.appendChild(node);
        }
    );
}


// ============================================================
// CONFIDENCE
// ============================================================

function renderConfidence(data) {

    let value =
        Number(
            data.confidence || 0
        );

    /*
     * Backend may omit confidence.
     * Build a frontend estimate from the
     * independent evidence returned.
     */
    if (
        !Number.isFinite(value) ||
        value <= 0
    ) {

        const reasons =
            Array.isArray(data.reasons)
                ? data.reasons.length
                : 0;

        const redirects =
            Array.isArray(data.redirect_chain)
                ? data.redirect_chain.length
                : 0;

        const hasDomainIntel =
            data.domain_intelligence &&
            Object.keys(
                data.domain_intelligence
            ).length > 0;

        const hasUPI =
            Boolean(data.upi);

        value = 48;

        value += Math.min(
            reasons * 7,
            28
        );

        value += Math.min(
            Math.max(
                redirects - 1,
                0
            ) * 5,
            10
        );

        value +=
            hasDomainIntel
                ? 7
                : 0;

        value +=
            hasUPI
                ? 4
                : 0;

        value = Math.max(
            35,
            Math.min(
                96,
                Math.round(value)
            )
        );
    }

    const valueElement =
        document.getElementById(
            "confidenceValue"
        );

    const bar =
        document.getElementById(
            "confidenceBar"
        );

    const description =
        document.getElementById(
            "confidenceText"
        ) ||
        document.getElementById(
            "confidenceDescription"
        );

    if (valueElement) {

        valueElement.textContent =
            value + "%";
    }

    if (bar) {

        bar.style.width =
            "0%";

        requestAnimationFrame(() => {

            bar.style.width =
                Math.min(
                    100,
                    value
                ) + "%";

        });
    }

    if (description) {

        if (value >= 80) {

            description.textContent =
                "High confidence: multiple independent security signals support this result.";

        } else if (value >= 60) {

            description.textContent =
                "Moderate confidence: several security signals were available for analysis.";

        } else {

            description.textContent =
                "Limited confidence: fewer independent signals were available.";
        }
    }
}


// ============================================================
// BACKEND PERSISTENCE STATUS
// ============================================================

function renderPersistenceMeta(data) {

    const result =
        document.getElementById("result");

    if (!result) {
        return;
    }

    let panel =
        document.getElementById(
            "persistenceMeta"
        );

    if (!panel) {

        panel =
            document.createElement("div");

        panel.id =
            "persistenceMeta";

        panel.className =
            "persistence-meta";

        result.prepend(panel);
    }

    const storage =
        data.storage || {};

    const scanId =
        data.scan_id ||
        storage.scan_id ||
        "Not generated";

    const stored =
        storage.stored === true;

    panel.innerHTML = `
        <div class="persistence-meta-header">
            <span>BACKEND RECORD</span>
            <span class="persistence-status ${stored ? "stored" : "not-stored"}">
                ${stored ? "PERSISTED" : "NOT STORED"}
            </span>
        </div>

        <div class="persistence-grid">

            <div class="persistence-item">
                <span class="persistence-label">
                    SCAN ID
                </span>

                <strong class="persistence-value">
                    ${escapeHTML(String(scanId))}
                </strong>
            </div>

            <div class="persistence-item">
                <span class="persistence-label">
                    STORAGE
                </span>

                <strong class="persistence-value">
                    ${stored
        ? "Database record created"
        : "Database record unavailable"}
                </strong>
            </div>

        </div>
    `;
}


// ============================================================
// EXPLANATION
// ============================================================

function renderExplanation(data) {

    const explanationText =
        document.getElementById(
            "explanationText"
        );

    if (!explanationText) {
        return;
    }

    const verdict =
        String(
            data.verdict || ""
        ).toUpperCase();

    const reasons =
        Array.isArray(data.reasons)
            ? data.reasons
            : [];

    if (verdict === "SAFE") {

        explanationText.textContent =
            "PhishLens did not find major suspicious indicators in this destination. Always verify the website before entering sensitive information.";

        return;
    }

    if (verdict === "CAUTION") {

        explanationText.textContent =
            "This destination contains signals that deserve additional review. Check the domain, redirects and requested information before continuing.";

        return;
    }

    const text =
        reasons
            .join(" ")
            .toLowerCase();

    if (
        text.includes("lookalike") ||
        text.includes("unicode") ||
        text.includes("altered")
    ) {

        explanationText.textContent =
            "The destination appears to imitate a trusted service using a misleading domain pattern. Verify the domain carefully before entering credentials.";

        return;
    }

    if (
        text.includes("ip address")
    ) {

        explanationText.textContent =
            "The destination uses an IP address instead of a normal domain and also shows other risk signals. Avoid entering sensitive information unless the destination is verified.";

        return;
    }

    if (
        text.includes("collect") ||
        text.includes("payment")
    ) {

        explanationText.textContent =
            "The payment data contains indicators that deserve verification before approving a transaction. Never approve an unexpected UPI collect request.";

        return;
    }

    explanationText.textContent =
        "Multiple security indicators suggest that this destination may be attempting to imitate a trusted service or collect sensitive information.";
}


// ============================================================
// HISTORY
// ============================================================

function saveToHistory(
    data,
    originalURL
) {

    const record = {

        id:
            Date.now() +
            "-" +
            Math.random()
                .toString(36)
                .slice(2, 8),

        url:
        originalURL,

        domain:
            data.final_domain ||
            data.domain ||
            "Unknown",

        verdict:
            String(
                data.verdict ||
                "UNKNOWN"
            ).toUpperCase(),

        score:
            Number(
                data.score ??
                data.risk_score ??
                0
            ),

        confidence:
            Number(
                data.confidence ||
                0
            ),

        reasons:
            Array.isArray(data.reasons)
                ? data.reasons.slice(0, 7)
                : [],

        data:
            sanitizeHistoryData(data),

        timestamp:
            Date.now(),

        time:
            new Date().toLocaleTimeString(
                [],
                {
                    hour: "2-digit",
                    minute: "2-digit"
                }
            ),

        date:
            new Date().toLocaleDateString(
                [],
                {
                    day: "2-digit",
                    month: "short"
                }
            )
    };

    scanHistory.unshift(record);

    scanHistory =
        scanHistory.slice(
            0,
            MAX_HISTORY
        );

    persistHistory();
    renderHistoryPreview();
}


function sanitizeHistoryData(data) {

    return {

        verdict:
        data.verdict,

        score:
            data.score ??
            data.risk_score ??
            0,

        domain:
        data.domain,

        final_domain:
        data.final_domain,

        reasons:
            Array.isArray(data.reasons)
                ? data.reasons.slice(0, 7)
                : [],

        redirect_chain:
            Array.isArray(data.redirect_chain)
                ? data.redirect_chain
                : [],

        domain_intelligence:
            data.domain_intelligence ||
            {},

        signals:
            data.signals ||
            {},

        confidence:
            data.confidence ||
            0,

        upi:
            data.upi ||
            null,

        scan_id:
            data.scan_id ||
            null,

        storage:
            data.storage ||
            null
    };
}


function persistHistory() {

    try {

        localStorage.setItem(
            HISTORY_KEY,
            JSON.stringify(
                scanHistory
            )
        );

    } catch (error) {

        console.warn(
            "Could not save history:",
            error
        );
    }
}


function loadHistory() {

    try {

        const stored =
            localStorage.getItem(
                HISTORY_KEY
            );

        if (!stored) {

            scanHistory = [];

            return;
        }

        const parsed =
            JSON.parse(stored);

        if (Array.isArray(parsed)) {

            scanHistory =
                parsed.slice(
                    0,
                    MAX_HISTORY
                );

        } else {

            scanHistory = [];
        }

    } catch (error) {

        console.warn(
            "Could not load history:",
            error
        );

        scanHistory = [];
    }
}


// ============================================================
// HISTORY UI
// ============================================================

function renderHistoryPreview() {

    const list =
        document.getElementById(
            "historyList"
        );

    if (!list) {
        return;
    }

    list.innerHTML = "";

    if (!scanHistory.length) {

        list.innerHTML = `
            <div class="history-empty">

                <div class="history-empty-icon">
                    ◌
                </div>

                <strong>
                    No scans yet
                </strong>

                <span>
                    Your analyzed destinations will appear here.
                </span>

            </div>
        `;

        updateHistorySummary();

        return;
    }

    scanHistory
        .slice(0, 8)
        .forEach(item => {

            list.appendChild(
                createHistoryCard(item)
            );
        });

    updateHistorySummary();
}


function createHistoryCard(item) {

    const card =
        document.createElement(
            "button"
        );

    card.type = "button";

    card.className =
        "history-row";

    const verdict =
        String(
            item.verdict ||
            "UNKNOWN"
        ).toUpperCase();

    const score =
        Number(
            item.score || 0
        );

    const domain =
        item.domain ||
        "Unknown destination";

    const date =
        item.date ||
        "";

    const time =
        item.time ||
        "";

    card.innerHTML = `

        <div class="history-status ${escapeHTML(
        verdict.toLowerCase()
    )}">
            ${escapeHTML(verdict)}
        </div>

        <div class="history-main">

            <strong>
                ${escapeHTML(domain)}
            </strong>

            <span>
                ${escapeHTML(
        shortenURL(
            item.url ||
            domain
        )
    )}
            </span>

        </div>

        <div class="history-score">

            <strong>
                ${score}
            </strong>

            <small>
                /100
            </small>

        </div>

        <div class="history-time">

            ${escapeHTML(date)}

            <br>

            ${escapeHTML(time)}

        </div>
    `;

    card.addEventListener(
        "click",
        () => {
            reopenHistoryItem(item);
        }
    );

    return card;
}


function updateHistorySummary() {

    const total =
        document.getElementById(
            "historyTotal"
        );

    const threats =
        document.getElementById(
            "historyThreats"
        );

    if (total) {

        total.textContent =
            scanHistory.length;
    }

    if (threats) {

        threats.textContent =
            scanHistory.filter(
                item =>
                    item.verdict === "DANGER" ||
                    item.verdict === "CAUTION"
            ).length;
    }
}


function reopenHistoryItem(item) {

    if (!item) {
        return;
    }

    const input =
        document.getElementById(
            "urlInput"
        );

    if (input) {

        input.value =
            item.url ||
            "";

        input.focus();
    }

    showURL();

    closeHistory();

    scrollToScanner();

    setTimeout(() => {

        if (
            item.data &&
            typeof item.data === "object"
        ) {

            showResult(
                item.data
            );

        } else {

            showToast(
                "Previous scan loaded. Analyze again to refresh its result."
            );
        }

    }, 500);
}


function showHistory() {

    renderHistoryPreview();

    const section =
        document.getElementById(
            "historySection"
        );

    if (section) {

        section.scrollIntoView({
            behavior: "smooth",
            block: "start"
        });

        return;
    }

    showToast(
        "No history section is available."
    );
}


function closeHistory() {
    // Compatibility function.
}


function clearHistory() {

    if (!scanHistory.length) {

        showToast(
            "Scan history is already empty."
        );

        return;
    }

    const confirmed =
        window.confirm(
            "Clear all PhishLens scan history from this browser?"
        );

    if (!confirmed) {
        return;
    }

    scanHistory = [];

    persistHistory();

    renderHistoryPreview();

    updateStats();

    showToast(
        "Local scan history cleared."
    );
}


// ============================================================
// STATS
// ============================================================

async function updateStats() {

    const analyses =
        document.getElementById(
            "analysisCount"
        );

    const threats =
        document.getElementById(
            "threatCount"
        );

    if (analyses) {

        analyses.textContent =
            scanCount;
    }

    if (threats) {

        threats.textContent =
            threatCount;
    }

    updateHistorySummary();
}


// ============================================================
// COPY SECURITY REPORT
// ============================================================

function copyResult() {

    const score =
        document.getElementById(
            "riskScore"
        ) ||
        document.getElementById(
            "scoreValue"
        );

    const verdict =
        document.getElementById(
            "verdictBadge"
        );

    const domain =
        document.getElementById(
            "resultDomain"
        );

    const reasons =
        document.getElementById(
            "reasons"
        ) ||
        document.getElementById(
            "reasonsList"
        );

    const scoreText =
        score
            ? score.textContent
            : "—";

    const verdictText =
        verdict
            ? verdict.textContent
            : "UNKNOWN";

    const domainText =
        domain
            ? domain.textContent
            : "Unknown";

    const reasonsText =
        reasons
            ? reasons.innerText
            : "No reasons available.";

    const persistence =
        document.getElementById(
            "persistenceMeta"
        );

    const backendRecordText =
        persistence
            ? persistence.innerText
            : "No backend record available.";

    const report =

        `PHISHLENS SECURITY REPORT
==========================

Destination:
${domainText}

Verdict:
${verdictText}

Risk Score:
${scoreText}/100

Threat Signals:
${reasonsText}

Backend Record:
${backendRecordText}

Generated by PhishLens.`;

    if (
        navigator.clipboard &&
        navigator.clipboard.writeText
    ) {

        navigator.clipboard
            .writeText(report)
            .then(() => {

                showToast(
                    "Security report copied."
                );

            })
            .catch(() => {

                fallbackCopy(report);

            });

    } else {

        fallbackCopy(report);
    }
}


function fallbackCopy(text) {

    const textarea =
        document.createElement(
            "textarea"
        );

    textarea.value =
        text;

    textarea.style.position =
        "fixed";

    textarea.style.opacity =
        "0";

    document.body.appendChild(
        textarea
    );

    textarea.select();

    try {

        document.execCommand(
            "copy"
        );

        showToast(
            "Security report copied."
        );

    } catch {

        showToast(
            "Unable to copy report."
        );
    }

    textarea.remove();
}


// ============================================================
// QR SCANNER
// ============================================================

async function startQRScanner() {

    if (
        typeof Html5Qrcode ===
        "undefined"
    ) {

        showToast(
            "QR scanner library is unavailable."
        );

        return;
    }

    const reader =
        document.getElementById(
            "qrReader"
        ) ||
        document.getElementById(
            "qr-reader"
        );

    if (!reader) {

        showToast(
            "QR scanner area was not found."
        );

        return;
    }

    try {

        if (qrScanner) {
            await stopQRScanner();
        }

        const readerId =
            reader.id;

        qrScanner =
            new Html5Qrcode(
                readerId
            );

        await qrScanner.start(

            {
                facingMode:
                    "environment"
            },

            {
                fps: 10,

                qrbox: {
                    width: 250,
                    height: 250
                }
            },

            decodedText => {

                const input =
                    document.getElementById(
                        "urlInput"
                    );

                if (input) {
                    input.value =
                        decodedText;
                }

                stopQRScanner();

                showURL();

                analyzeURL();
            },

            () => {
                // Normal QR frame failure.
            }
        );

        updateCameraStatus(
            "Camera active — position the QR code inside the frame."
        );

        showToast(
            "Camera ready."
        );

    } catch (error) {

        console.error(
            "QR scanner error:",
            error
        );

        updateCameraStatus(
            "Camera could not be started. Check browser permissions."
        );

        showToast(
            "Camera could not be started."
        );
    }
}


async function stopQRScanner() {

    if (!qrScanner) {
        return;
    }

    try {

        if (
            qrScanner.isScanning
        ) {

            await qrScanner.stop();
        }

        await qrScanner.clear();

    } catch (error) {

        console.warn(
            "QR cleanup:",
            error
        );
    }

    qrScanner = null;

    updateCameraStatus(
        "Camera scanner is inactive."
    );
}


function updateCameraStatus(message) {

    const cameraStatus =
        document.getElementById(
            "cameraStatus"
        );

    const qrStatus =
        document.getElementById(
            "qrStatus"
        );

    if (cameraStatus) {

        cameraStatus.textContent =
            message;
    }

    if (qrStatus) {

        qrStatus.textContent =
            message;
    }
}


// ============================================================
// RESET
// ============================================================

function resetScanner() {

    stopQRScanner();

    const input =
        document.getElementById(
            "urlInput"
        );

    const result =
        document.getElementById(
            "result"
        );

    const loading =
        document.getElementById(
            "loading"
        );

    const urlSection =
        document.getElementById(
            "urlSection"
        );

    const qrSection =
        document.getElementById(
            "qrSection"
        );

    const redirectCard =
        document.getElementById(
            "redirectCard"
        );

    if (input) {
        input.value = "";
    }

    if (result) {
        result.classList.add(
            "hidden"
        );
    }

    if (loading) {
        loading.classList.add(
            "hidden"
        );
    }

    if (redirectCard) {
        redirectCard.classList.add(
            "hidden"
        );
    }

    if (qrSection) {
        qrSection.classList.add(
            "hidden"
        );
    }

    if (urlSection) {
        urlSection.classList.remove(
            "hidden"
        );
    }

    setActiveTab(0);

    if (input) {
        input.focus();
    }

    scrollToScanner();
}


// ============================================================
// TOAST
// ============================================================

function showToast(message) {

    const oldToast =
        document.querySelector(
            ".phishlens-toast"
        );

    if (oldToast) {
        oldToast.remove();
    }

    const toast =
        document.createElement(
            "div"
        );

    toast.className =
        "phishlens-toast";

    toast.textContent =
        message;

    document.body.appendChild(
        toast
    );

    requestAnimationFrame(() => {

        toast.classList.add(
            "show"
        );
    });

    setTimeout(() => {

        toast.classList.remove(
            "show"
        );

        setTimeout(() => {

            toast.remove();

        }, 300);

    }, 2800);
}


// ============================================================
// HELPERS
// ============================================================

function setText(
    id,
    value
) {

    const element =
        document.getElementById(id);

    if (element) {

        element.textContent =
            value;
    }
}


function applyRiskColor(
    element,
    verdict
) {

    if (!element) {
        return;
    }

    element.classList.remove(
        "safe",
        "caution",
        "danger"
    );

    const normalized =
        String(
            verdict || ""
        ).toUpperCase();

    if (normalized === "SAFE") {

        element.classList.add(
            "safe"
        );

    } else if (
        normalized === "CAUTION"
    ) {

        element.classList.add(
            "caution"
        );

    } else {

        element.classList.add(
            "danger"
        );
    }
}


function shortenURL(url) {

    if (!url) {
        return "Unknown destination";
    }

    const maxLength = 58;

    if (
        url.length <=
        maxLength
    ) {
        return url;
    }

    return (
        url.substring(
            0,
            maxLength - 3
        ) +
        "..."
    );
}


function escapeHTML(value) {

    return String(value)

        .replace(
            /&/g,
            "&amp;"
        )

        .replace(
            /</g,
            "&lt;"
        )

        .replace(
            />/g,
            "&gt;"
        )

        .replace(
            /"/g,
            "&quot;"
        )

        .replace(
            /'/g,
            "&#039;"
        );
}


// ============================================================
// GLOBAL ERROR SAFETY
// ============================================================

window.addEventListener(
    "error",
    event => {

        console.error(
            "PhishLens frontend error:",
            event.error || event.message
        );
    }
);


window.addEventListener(
    "unhandledrejection",
    event => {

        console.error(
            "PhishLens promise error:",
            event.reason
        );
    }
);