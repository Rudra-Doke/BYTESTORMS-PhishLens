// ============================================================
// PHISHLENS — THREAT INTELLIGENCE ENGINE
// Premium Frontend Controller
// ============================================================

"use strict";

let qrScanner = null;
let qrDecodeHandled = false;
let lastQrFrameHint = 0;
let pendingQrPayload = "";
let deferredInstallPrompt = null;
let qrTorchEnabled = false;
let scanCount = 0;
let threatCount = 0;
let scanHistory = [];
let savedHistory = [];
let historySource = "saved";
let savedHistoryState = "loading";

const HISTORY_KEY = "phishlens_history";
const MAX_HISTORY = 20;
const DISPLAY_KEY = "phishlens_display_preferences";
let displayPreferences = {
    theme: "obsidian",
    reduceMotion: window.matchMedia("(prefers-reduced-motion: reduce)").matches
};


// ============================================================
// INITIALIZATION
// ============================================================

document.addEventListener("DOMContentLoaded", () => {
    initializePhishLens();
});


function initializePhishLens() {

    generateSessionId();
    setAppStatus("ready");
    loadDisplayPreferences();
    initializeMotion();
    loadHistory();
    initializeHistoryControls();

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

    initializeKeyboardTabs();
    initializeQRImageInput();
    initializeDisplayControls();
    initializeAppInstall();
    initializeConnectionStatus();
    initializeAppUpdates();
    initializeIncomingShare();
    initializePasteLink();
    initializeClearLink();

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

function initializeClearLink() {
    const button = document.getElementById("clearUrlButton");
    const input = document.getElementById("urlInput");
    button?.addEventListener("click", () => {
        if (!input) return;
        input.value = "";
        input.dispatchEvent(new Event("input", { bubbles: true }));
        input.focus();
    });
}

function initializePasteLink() {
    const button = document.getElementById("pasteLinkButton");
    const input = document.getElementById("urlInput");
    button?.addEventListener("click", async () => {
        if (!navigator.clipboard?.readText) {
            showToast("Clipboard paste is unavailable here. Tap the field and paste manually.");
            input?.focus();
            return;
        }
        try {
            const value = (await navigator.clipboard.readText()).trim();
            if (!value) {
                showToast("The clipboard is empty.");
                return;
            }
            if (input) {
                input.value = value;
                input.dispatchEvent(new Event("input", { bubbles: true }));
                input.focus();
            }
            showToast("Pasted. Review the content, then start analysis.");
        } catch (error) {
            showToast("Clipboard access was blocked. Tap the field and paste manually.");
            input?.focus();
        }
    });
}

function initializeIncomingShare() {
    const params = new URLSearchParams(window.location.search);
    const shared = (params.get("url") || params.get("text") || "").trim().slice(0, 4096);
    if (!shared) return;
    const input = document.getElementById("urlInput");
    if (!input) return;
    input.value = shared;
    input.dispatchEvent(new Event("input", { bubbles: true }));
    window.history.replaceState({}, document.title, window.location.pathname + window.location.hash);
    showToast("Shared content is ready for review. Start analysis when you’re ready.");
}

function initializeConnectionStatus() {
    const banner = document.getElementById("connectionBanner");
    if (!banner) return;
    const update = () => {
        banner.classList.toggle("hidden", navigator.onLine);
        if (!navigator.onLine) updateCameraStatus("You're offline. Reconnect to scan QR codes or analyze destinations.");
    };
    window.addEventListener("online", update);
    window.addEventListener("offline", update);
    update();
}

function initializeAppUpdates() {
    const banner = document.getElementById("appUpdateBanner");
    if (!banner || !("serviceWorker" in navigator)) return;
    const controlSeenKey = "phishlens_service_worker_control_seen";
    if (navigator.serviceWorker.controller) sessionStorage.setItem(controlSeenKey, "yes");
    navigator.serviceWorker.addEventListener("controllerchange", () => {
        if (sessionStorage.getItem(controlSeenKey) !== "yes") {
            sessionStorage.setItem(controlSeenKey, "yes");
            return;
        }
        banner.classList.remove("hidden");
    });
    document.getElementById("refreshAppButton")?.addEventListener("click", () => window.location.reload());
}

function initializeAppInstall() {
    const button = document.getElementById("installAppButton");
    if (!button) return;
    const isStandalone = window.matchMedia("(display-mode: standalone)").matches || window.navigator.standalone === true;
    if (isStandalone) return;

    window.addEventListener("beforeinstallprompt", event => {
        event.preventDefault();
        deferredInstallPrompt = event;
        button.classList.remove("hidden");
    });
    window.addEventListener("appinstalled", () => {
        deferredInstallPrompt = null;
        button.classList.add("hidden");
        showToast("PhishLens was added to your home screen.");
    });

    button.addEventListener("click", async () => {
        if (deferredInstallPrompt) {
            deferredInstallPrompt.prompt();
            await deferredInstallPrompt.userChoice;
            deferredInstallPrompt = null;
            button.classList.add("hidden");
            return;
        }
        const isIOS = /iphone|ipad|ipod/i.test(navigator.userAgent);
        showToast(isIOS
            ? "To install PhishLens: tap Share, then Add to Home Screen."
            : "Open your browser menu and choose Install app or Add to Home screen.");
    });

    if (/iphone|ipad|ipod/i.test(navigator.userAgent)) button.classList.remove("hidden");
}


function setAppStatus(state) {
    const pill = document.getElementById("appStatus");
    const label = document.getElementById("appStatusLabel");
    const labels = {
        ready: "Scanner Ready",
        scanning: "Analysis in Progress",
        result: "Result Ready",
        qr: "QR Reader Active"
    };
    const nextState = Object.prototype.hasOwnProperty.call(labels, state) ? state : "ready";
    if (pill) {
        pill.dataset.state = nextState;
        pill.setAttribute("aria-label", "PhishLens status: " + labels[nextState]);
    }
    if (label) label.textContent = labels[nextState];
}


function loadDisplayPreferences() {
    try {
        const stored = JSON.parse(localStorage.getItem(DISPLAY_KEY) || "{}");
        displayPreferences = {
            theme: stored.theme === "pearl" ? "pearl" : "obsidian",
            reduceMotion: typeof stored.reduceMotion === "boolean"
                ? stored.reduceMotion
                : window.matchMedia("(prefers-reduced-motion: reduce)").matches
        };
    } catch (error) {
        console.warn("Could not load display preferences:", error);
    }

    applyDisplayPreferences();
}


function applyDisplayPreferences() {
    document.body.dataset.theme = displayPreferences.theme;
    document.body.dataset.motion = displayPreferences.reduceMotion ? "reduce" : "full";

    document.querySelectorAll("[data-theme-choice]").forEach(button => {
        button.setAttribute(
            "aria-pressed",
            String(button.dataset.themeChoice === displayPreferences.theme)
        );
    });

    const motionToggle = document.getElementById("reduceMotionToggle");
    if (motionToggle) {
        motionToggle.checked = displayPreferences.reduceMotion;
    }
}


function saveDisplayPreferences() {
    applyDisplayPreferences();
    try {
        localStorage.setItem(DISPLAY_KEY, JSON.stringify(displayPreferences));
    } catch (error) {
        showToast("Display setting could not be saved in this browser.");
    }
}


function initializeDisplayControls() {
    document.querySelectorAll("[data-theme-choice]").forEach(button => {
        button.addEventListener("click", () => {
            displayPreferences.theme = button.dataset.themeChoice;
            saveDisplayPreferences();
        });
    });

    const motionToggle = document.getElementById("reduceMotionToggle");
    motionToggle?.addEventListener("change", () => {
        displayPreferences.reduceMotion = motionToggle.checked;
        saveDisplayPreferences();
        if (motionToggle.checked) {
            document.querySelectorAll(".reveal-unit").forEach(section => {
                section.classList.add("is-visible");
            });
        }
    });
}


function initializeKeyboardTabs() {
    const tablist = document.querySelector(".scanner-tabs");
    tablist?.addEventListener("keydown", event => {
        const tabs = Array.from(tablist.querySelectorAll('[role="tab"]'));
        const currentIndex = tabs.indexOf(document.activeElement);
        if (currentIndex < 0) return;

        let nextIndex = currentIndex;
        if (event.key === "ArrowRight" || event.key === "ArrowDown") {
            nextIndex = (currentIndex + 1) % tabs.length;
        } else if (event.key === "ArrowLeft" || event.key === "ArrowUp") {
            nextIndex = (currentIndex - 1 + tabs.length) % tabs.length;
        } else if (event.key === "Home") {
            nextIndex = 0;
        } else if (event.key === "End") {
            nextIndex = tabs.length - 1;
        } else {
            return;
        }

        event.preventDefault();
        tabs[nextIndex].focus();
        tabs[nextIndex].click();
    });
}


function initializeQRImageInput() {
    document.querySelectorAll("#qrImageInput, #qrCameraInput").forEach(input => input.addEventListener("change", async () => {
        const file = input.files?.[0];
        if (!file) return;

        if (typeof Html5Qrcode === "undefined") {
            updateCameraStatus("The QR reader is unavailable. Check your connection and reload the page.");
            input.value = "";
            return;
        }

        const reader = document.getElementById("qr-reader");
        if (!reader) {
            updateCameraStatus("QR image area is unavailable. Reload the page and try again.");
            input.value = "";
            return;
        }
        updateCameraStatus(`Reading ${file.name}…`);
        input.disabled = true;

        let decoder = null;
        let payload = "";
        try {
            decoder = new Html5Qrcode(reader.id);
            payload = await decoder.scanFile(file, true);
        } catch (error) {
            updateCameraStatus(error?.message || "No readable QR code was found in that image. Try a sharper, well-lit image.");
            showToast("Could not read a QR code from that image.");
            return;
        } finally {
            if (decoder) {
                try { await decoder.clear(); } catch (cleanupError) {
                    console.warn("QR image decoder cleanup:", cleanupError);
                }
            }
            input.disabled = false;
            input.value = "";
        }

        showURL();
        showQRPreview(payload, input.id === "qrCameraInput" ? "Camera photo" : "QR image");
    }));
    document.getElementById("qrAnalyzeButton")?.addEventListener("click", async () => {
        const payload = pendingQrPayload;
        if (!payload) return;
        document.getElementById("qrPreview")?.classList.add("hidden");
        const urlInput = document.getElementById("urlInput");
        if (urlInput) urlInput.value = payload;
        pendingQrPayload = "";
        await analyzeURL("/analyze", "payload");
    });
    document.getElementById("qrDismissButton")?.addEventListener("click", () => {
        pendingQrPayload = "";
        document.getElementById("qrPreview")?.classList.add("hidden");
        updateCameraStatus("QR preview dismissed. Scan or choose another image when ready.");
    });
    document.getElementById("qrCopyButton")?.addEventListener("click", async () => {
        if (!pendingQrPayload) return;
        try {
            await navigator.clipboard.writeText(pendingQrPayload);
            updateCameraStatus("Decoded QR text copied to the clipboard.");
            showToast("Decoded text copied.");
        } catch (error) {
            updateCameraStatus("Clipboard access is unavailable. Select the decoded text and copy it manually.");
            showToast("Could not access the clipboard.");
        }
    });
}

function showQRPreview(payload, source = "QR code") {
    pendingQrPayload = String(payload || "");
    const preview = document.getElementById("qrPreview");
    const content = document.getElementById("qrPreviewPayload");
    const kind = document.getElementById("qrPreviewKind");
    const guidance = document.getElementById("qrPreviewGuidance");
    if (!preview || !content) return;
    const classification = classifyQRPreview(pendingQrPayload);
    content.textContent = pendingQrPayload;
    if (kind) kind.textContent = `${source} · ${classification} · ${pendingQrPayload.length} characters`;
    if (guidance) {
        const unfamiliar = classification === "Plain text or unsupported format" || classification.startsWith("App or custom link");
        guidance.textContent = unfamiliar
            ? "This QR contains a format PhishLens may not fully interpret. You can inspect the decoded text here; analysis may provide limited results. Verify the source independently."
            : "PhishLens can inspect this decoded format. Review the details before continuing; scanning does not open the destination or carry out its requested action.";
    }
    preview.classList.remove("hidden");
    preview.scrollIntoView({ behavior: displayPreferences.reduceMotion ? "instant" : "smooth", block: "nearest" });
    updateCameraStatus("QR decoded. Review its contents, then choose Analyze content to continue.");
}

function classifyQRPreview(value) {
    const text = String(value || "").trim();
    if (/^upi:\/\/pay\b/i.test(text)) return "UPI payment request";
    if (/^WIFI:/i.test(text)) return "Wi-Fi network details";
    if (/^(?:BEGIN:VCARD|MECARD:)/i.test(text)) return "Contact card";
    if (/^geo:/i.test(text)) return "Location";
    if (/^BEGIN:VEVENT/i.test(text)) return "Calendar event";
    if (/^(?:mailto:|MATMSG:)/i.test(text)) return "Email message";
    if (/^(?:smsto?:|mmsto?:)/i.test(text)) return "Text message";
    if (/^(?:tel:)/i.test(text)) return "Phone number";
    if (/^(?:bitcoin:|ethereum:|litecoin:)/i.test(text)) return "Crypto payment address";
    if (/^(?:https?:\/\/|www\.)/i.test(text)) return "Web link";
    if (/^[a-z][a-z0-9+.-]*:/i.test(text)) return "App or custom link (not opened)";
    return "Plain text or unsupported format";
}


function initializeMotion() {

    const sections = document.querySelectorAll(
        ".hero, .analyzer-card, .history-section, .how-section, .signals-section, .stats-section"
    );

    if (!sections.length) {
        return;
    }

    const reduceMotion = displayPreferences.reduceMotion;

    sections.forEach(section => {
        section.classList.add("reveal-unit");
    });

    if (reduceMotion || !("IntersectionObserver" in window)) {
        sections.forEach(section => {
            section.classList.add("is-visible");
        });
        return;
    }

    const observer = new IntersectionObserver(entries => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add("is-visible");
                observer.unobserve(entry.target);
            }
        });
    }, {
        threshold: 0.12,
        rootMargin: "0px 0px -32px 0px"
    });

    sections.forEach(section => observer.observe(section));
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
    setAppStatus("ready");
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
    setAppStatus("ready");
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

        tab.setAttribute(
            "aria-selected",
            String(i === index)
        );

        tab.setAttribute(
            "tabindex",
            i === index ? "0" : "-1"
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

async function analyzeURL(endpoint = "/analyze", payloadField = "url") {

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
                endpoint,
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        [payloadField]: url
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

    const analyzer = document.querySelector(".analyzer-card");

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
        loading.setAttribute("aria-live", "polite");
        loading.setAttribute("aria-busy", "true");
    }

    if (analyzer) {
        analyzer.classList.add("is-scanning");
    }

    setAppStatus("scanning");

    animateAnalysisSteps();
}


function hideLoading() {

    const analyzer = document.querySelector(".analyzer-card");

    const loading =
        document.getElementById("loading");

    if (loading) {
        loading.classList.add("hidden");
        loading.setAttribute("aria-busy", "false");
    }

    if (analyzer) {
        analyzer.classList.remove("is-scanning");
    }

    setAppStatus("ready");
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
    setAppStatus("result");

    renderVerdict(data);
    renderScore(data);
    renderSignals(data);
    renderReasons(data);
    renderChecksPerformed(data);
    renderDomainDNA(data);
    renderRedirectPath(data);
    renderUPIShield(data);
    renderQRContent(data);
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

    const nextAction = document.getElementById("nextAction");
    const recommendations = {
        SAFE: "No major risk signals were found. Confirm the sender and destination are expected before proceeding.",
        CAUTION: "Pause and verify the domain through an official source. Avoid entering credentials or approving a payment while uncertain.",
        DANGER: "Do not open or share this destination. Report the message and visit the service through its official app or saved address."
    };

    if (nextAction) {
        nextAction.textContent = recommendations[verdict]
            || "Treat this result as inconclusive and verify the destination independently.";
        nextAction.closest(".next-step-card")?.classList.remove("safe", "caution", "danger");
        nextAction.closest(".next-step-card")?.classList.add(
            ["SAFE", "CAUTION", "DANGER"].includes(verdict)
                ? verdict.toLowerCase()
                : "unknown"
        );
    }

    if (verdict === "SAFE") {

        title.textContent =
            "No major threat signals found";

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

    const scoreBlock =
        document.querySelector(".score-block");

    const verdict = String(data.verdict || "DANGER").toUpperCase();
    const scoreColors = {
        SAFE: "#2f8764",
        CAUTION: "#b87333",
        DANGER: "#963448"
    };

    if (scoreBlock) {
        scoreBlock.classList.remove("safe", "caution", "danger");
        if (Object.prototype.hasOwnProperty.call(scoreColors, verdict)) {
            scoreBlock.classList.add(verdict.toLowerCase());
        }
        scoreBlock.style.setProperty("--score-value", score + "%");
        scoreBlock.style.setProperty(
            "--score-color",
            scoreColors[verdict] || "#d4af37"
        );
    }

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
    const signals = data.signals && typeof data.signals === "object" ? data.signals : {};
    const isUPI = Boolean(data.upi) || data.live_intelligence?.type === "UPI";
    const isPayment = isUPI || data.qr?.type === "QR PAYMENT";
    const breakdown = document.getElementById("threatBreakdown");
    document.getElementById("resultGrid")?.classList.toggle("is-payment-result", isPayment);
    const signalRows = breakdown?.querySelectorAll(".signal-row") || [];
    signalRows.forEach((row, index) => {
        row.classList.toggle("hidden", isPayment && index !== 2);
    });
    const paymentHeading = breakdown?.querySelector(".signal-row:nth-child(5) .signal-heading > span");
    const paymentCaption = breakdown?.querySelector(".signal-row:nth-child(5) .signal-heading > small");
    if (paymentHeading) paymentHeading.textContent = isPayment ? (isUPI ? "UPI PAYMENT SIGNAL" : "QR PAYMENT SIGNAL") : "SECURITY";
    if (paymentCaption) paymentCaption.textContent = isPayment ? "Payment payload indicators" : "Security indicators";
    setSignal("urlSignal", signals.url_structure ?? signals.url, "urlSignalValue");
    setSignal("domainSignal", signals.domain, "domainSignalValue");
    setSignal("securitySignal", signals.security, "securitySignalValue");
    setSignal("redirectSignal", signals.redirect, "redirectSignalValue");
}


function setSignal(
    id,
    value,
    valueId
) {

    const element =
        document.getElementById(id);

    if (!element) {
        return;
    }

    const numericValue = Number(value);
    const valueElement = valueId ? document.getElementById(valueId) : null;
    const available = value !== null && value !== undefined && Number.isFinite(numericValue);
    const safeValue = available ? Math.max(0, Math.min(100, numericValue)) : 0;

    element.closest(".signal-row")?.classList.toggle("is-unavailable", !available);
    if (valueElement) valueElement.textContent = available ? `${Math.round(safeValue)}/100` : "Not available";

    element.style.width =
        "0%";

    requestAnimationFrame(() => {

        element.style.width = safeValue + "%";

    });
}


function renderChecksPerformed(data) {
    const container = document.getElementById("checksPerformedList");
    const summary = document.getElementById("checksPerformedSummary");
    if (!container) return;

    const live = data.live_intelligence && typeof data.live_intelligence === "object"
        ? data.live_intelligence
        : null;
    const checks = [];
    const add = (name, state, detail) => checks.push({ name, state, detail });
    const stateFor = (record, options = {}) => {
        if (!record || typeof record !== "object") return { state: "not-returned", detail: "No status was returned." };
        if (record.available === true) return { state: "checked", detail: options.available || "Data was returned." };
        if (record.reason) return { state: options.inapplicableReasons?.includes(record.reason) ? "not-applicable" : "unavailable", detail: record.reason };
        if (record.error || record.status) return { state: "unavailable", detail: "The source did not return usable data." };
        return { state: "not-returned", detail: "No status was returned." };
    };

    if (live?.checked !== true) {
        if (data.upi || live?.type === "UPI") {
            add("UPI payment analysis", "checked", "Payment URI fields were inspected by the local analysis rules.");
        } else if (data.qr && String(data.qr.type || "").toUpperCase() !== "URL") {
            add("QR content classification", "checked", "QR payload classified as " + String(data.qr.type || "non-web content") + ".");
            add("Website intelligence", "not-run", "No website destination was available for live checks.");
        } else {
            add("Live intelligence", "not-returned", "The response did not include check statuses.");
        }
    } else {
        const dns = live.dns;
        const isIP = Boolean(data.domain_intelligence?.is_ip);
        if (isIP) add("DNS resolution", "not-applicable", "The destination is already an IP address.");
        else if (dns && typeof dns.resolved === "boolean") add("DNS resolution", "checked", dns.resolved ? "The domain resolved." : "No address was resolved.");
        else add("DNS resolution", "not-returned", "No DNS status was returned.");

        const http = live.http;
        if (http && Number.isFinite(Number(http.status)) && http.status !== null) add("HTTP response", "checked", "Response status " + Number(http.status) + ".");
        else if (http?.request_error) add("HTTP response", "unavailable", "The request could not be completed.");
        else add("HTTP response", "not-returned", "No HTTP response status was returned.");

        const pageState = stateFor(live.page, { available: "Page response details were sampled." });
        if (pageState.state === "not-returned" && http?.request_error) {
            pageState.state = "unavailable";
            pageState.detail = "No page response was available to inspect.";
        }
        add("Page response", pageState.state, pageState.detail);

        if (live.tls === null || live.tls === undefined) {
            const finalURL = String(http?.final_url || "");
            add("TLS certificate", finalURL && !/^https:/i.test(finalURL) ? "not-applicable" : "not-returned", finalURL && !/^https:/i.test(finalURL) ? "The final destination did not use HTTPS." : "No TLS status was returned.");
        } else if (live.tls.available === true) {
            add("TLS certificate", "checked", live.tls.valid === true ? "Certificate validation succeeded." : "Certificate validation failed.");
        } else {
            const tlsState = stateFor(live.tls, { inapplicableReasons: ["IP destination"] });
            add("TLS certificate", tlsState.state, tlsState.detail);
        }

        const rdapState = stateFor(live.rdap, {
            available: live.rdap?.age_days === null || live.rdap?.age_days === undefined
                ? "Registration record returned."
                : "Registration age data returned.",
            inapplicableReasons: ["IP destination", "No TLD"]
        });
        add("Domain registration (RDAP)", rdapState.state, rdapState.detail);

        const sourceState = (record, label) => {
            if (!record || typeof record !== "object") return { state: "not-returned", detail: "No status was returned." };
            if (record.checked === true) return { state: "checked", detail: record.matched ? "A reputation match was reported." : "No reputation match was reported." };
            if (record.configured === false) return { state: "not-configured", detail: label + " is not configured in this instance." };
            return { state: "unavailable", detail: "The source did not return a result." };
        };
        const googleState = sourceState(live.google_safe_browsing, "Google Safe Browsing");
        add("Google Safe Browsing", googleState.state, googleState.detail);
        const phishTankState = sourceState(live.phishtank, "PhishTank");
        add("PhishTank", phishTankState.state, phishTankState.detail);
    }

    const labels = {
        checked: "Checked",
        unavailable: "Unavailable",
        "not-configured": "Not configured",
        "not-applicable": "Not applicable",
        "not-run": "Not run",
        "not-returned": "Not returned"
    };
    container.replaceChildren();
    checks.forEach(check => {
        const item = document.createElement("li");
        item.className = "check-item is-" + check.state;
        const text = document.createElement("div");
        text.className = "check-item-copy";
        const name = document.createElement("strong");
        name.textContent = check.name;
        const detail = document.createElement("span");
        detail.textContent = check.detail;
        text.append(name, detail);
        const state = document.createElement("span");
        state.className = "check-state";
        state.textContent = labels[check.state] || "Status unknown";
        item.append(text, state);
        container.appendChild(item);
    });

    if (summary) {
        const checked = checks.filter(check => check.state === "checked").length;
        const pending = checks.length - checked;
        summary.textContent = pending
            ? `${checked} checked · ${pending} not run or unavailable`
            : `${checked} checked`;
    }
}


// ============================================================
// REASONS
// ============================================================

function renderReasons(data) {

    const container =
        document.getElementById("reasonsList") ||
        document.getElementById("reasons");

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
            "The analysis did not return reason details."
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

    const isUPI = Boolean(data.upi) || data.live_intelligence?.type === "UPI";
    const isPayment = isUPI || data.qr?.type === "QR PAYMENT";

    const info =
        data.domain_intelligence || {};

    const panel =
        document.getElementById("domainDNA") ||
        document.getElementById("domainIntelligence");

    if (!panel) {
        return;
    }

    panel.classList.toggle("hidden", isPayment);
    if (isPayment) return;

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

    const upi = data.upi;
    const isMerchantQR = data.qr?.type === "QR PAYMENT";
    const payment = upi || (isMerchantQR ? data.qr.data || {} : null);

    if (!payment) {

        panel.classList.add(
            "hidden"
        );

        return;
    }

    panel.classList.remove(
        "hidden"
    );

    const eyebrow = panel.querySelector(".upi-shield-header .section-label");
    const title = panel.querySelector(".upi-shield-header h3");
    const payeeLabel = panel.querySelector(".upi-payment-item:first-child > span");
    if (eyebrow) eyebrow.textContent = isMerchantQR ? "EMVCO PAYMENT QR" : "PAYMENT INTELLIGENCE";
    if (title) title.textContent = isMerchantQR ? "Merchant Payment QR" : "UPI Shield";
    if (payeeLabel) payeeLabel.textContent = isMerchantQR ? "MERCHANT" : "PAYEE";

    const risk =
        Number(
            upi?.risk ?? data.risk_score ?? data.score ?? 0
        );

    let statusText = isMerchantQR
        ? (risk >= 60 ? "HIGH PAYMENT RISK" : "VERIFY MERCHANT")
        : "NO UPI SIGNAL";

    if (isMerchantQR) {
        statusText = risk >= 60 ? "HIGH PAYMENT RISK" : "VERIFY MERCHANT";
    } else if (risk >= 60) {

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
    const statusElement = document.getElementById("upiStatus");
    if (statusElement) {
        statusElement.classList.toggle("is-review", (isMerchantQR && risk < 60) || (!isMerchantQR && risk >= 30 && risk < 60));
        statusElement.classList.toggle("is-danger", risk >= 60);
    }

    setText(
        "upiMessage",
        isMerchantQR
            ? [
                (data.reasons || []).find(reason => reason.includes("merchant payment QR")) || "Confirm the recipient in your payment app before approving.",
                payment.checksum_status === "valid"
                    ? "QR checksum is valid; this does not verify the merchant."
                    : payment.checksum_status === "invalid"
                        ? "QR checksum is invalid; the payload may be damaged or altered."
                        : "QR checksum could not be verified."
            ].join(" ")
            : getUPIMessage(upi)
    );

    setText(
        "upiPayee",
        (isMerchantQR ? payment.merchant_name : payment.payee) ||
        "—"
    );

    setText(
        "upiPayeeName",
        (isMerchantQR ? payment.merchant_city : payment.payee_name) ||
        "—"
    );

    setText(
        "upiAmount",
        formatUPIAmount(payment.amount, payment.currency)
    );

    setText(
        "upiCurrency",
        payment.currency || (isMerchantQR ? payment.currency_numeric : null) ||
        "—"
    );

    setText(
        "upiRisk",
        risk + "/100"
    );
}


function renderQRContent(data) {
    const card = document.getElementById("qrContentCard");
    const grid = document.getElementById("qrContentGrid");
    const title = document.getElementById("qrContentTitle");
    if (!card || !grid) return;

    const qr = data.qr;
    const type = String(qr?.type || "").toUpperCase();
    if (!qr || ["URL", "UPI PAYMENT", "QR PAYMENT"].includes(type)) {
        card.classList.add("hidden");
        grid.replaceChildren();
        return;
    }

    const info = qr.data && typeof qr.data === "object" ? qr.data : {};
    const fields = [];
    const add = (label, value) => {
        if (value === null || value === undefined || value === "") return;
        let display = typeof value === "string" ? value : JSON.stringify(value);
        if (display.length > 700) display = display.slice(0, 700) + "…";
        fields.push([label, display]);
    };
    const addParameters = parameters => {
        if (!parameters || typeof parameters !== "object") return;
        Object.entries(parameters).forEach(([key, value]) => add(key, Array.isArray(value) ? value.join(", ") : value));
    };

    if (type === "WI-FI") {
        add("Network name", info.ssid);
        add("Security", info.security);
        add("Hidden network", info.hidden ? "Yes" : "No");
        add("Network password", info.password_included ? "Included (not displayed)" : "Not included");
    } else if (type === "CONTACT") {
        add("Name", info.name);
        add("Phone", info.phone);
        add("Email", info.email);
        add("Organization", info.organization);
        add("Website", info.website);
    } else if (type === "LOCATION") {
        add("Latitude", info.latitude);
        add("Longitude", info.longitude);
        add("Coordinates valid", info.valid_coordinates === false ? "No" : "Yes");
        add("Place query", info.query);
    } else if (type === "CALENDAR EVENT") {
        add("Event", info.title);
        add("Starts", info.starts);
        add("Ends", info.ends);
        add("Location", info.location);
        add("Organizer", info.organizer);
        add("Event link included", info.event_link_present ? "Yes (not opened)" : "No");
    } else if (type === "EMAIL") {
        add("Address", info.email);
        add("Subject", info.subject);
        add("Message", info.body);
        addParameters(info.parameters);
    } else if (type === "TELEPHONE") {
        add("Phone number", info.telephone);
    } else if (type === "SMS") {
        add("Recipient", info.destination);
        if (typeof info.message === "object") addParameters(info.message);
        else add("Message", info.message);
    } else if (type === "CRYPTO PAYMENT") {
        add("Asset", info.currency);
        add("Wallet address", info.address);
        addParameters(info.parameters);
    } else if (type === "APP / DEEP LINK") {
        add("Link type", String(info.payload || "").split(":", 1)[0] || "Application link");
        add("Action", "Not opened");
    } else if (type === "TEXT") {
        add("Text", info.text);
    } else {
        Object.entries(info).forEach(([key, value]) => {
            if (!/password|secret|token|payload|raw_preview/i.test(key)) add(key.replace(/_/g, " "), value);
        });
    }

    if (!fields.length) add("Content", qr.display || type);
    if (title) title.textContent = qr.display || type;
    grid.replaceChildren();
    fields.forEach(([label, value]) => {
        const item = document.createElement("div");
        item.className = "intel-item";
        const labelElement = document.createElement("span");
        labelElement.textContent = label;
        const valueElement = document.createElement("strong");
        valueElement.textContent = value;
        item.append(labelElement, valueElement);
        grid.appendChild(item);
    });
    card.classList.remove("hidden");
}

function formatUPIAmount(amount, currency) {

    if (amount === null || amount === undefined || String(amount).trim() === "") {
        return "—";
    }

    const rawAmount = String(amount).trim();
    const numericAmount = Number(rawAmount);
    const currencyCode = String(currency || "INR").trim().toUpperCase();

    if (!Number.isFinite(numericAmount)) {
        return `${rawAmount} ${currencyCode}`;
    }

    try {
        return new Intl.NumberFormat("en-IN", {
            style: "currency",
            currency: currencyCode,
            maximumFractionDigits: 2
        }).format(numericAmount);
    } catch (error) {
        return `${rawAmount} ${currencyCode}`;
    }
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
    const rawValue = data.confidence;
    const numericValue = Number(rawValue);
    const available = typeof rawValue === "number" && Number.isFinite(numericValue)
        && numericValue >= 0 && numericValue <= 100;
    const value = available ? Math.round(numericValue) : null;

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
        valueElement.textContent = available ? value + "%" : "Not available";
        valueElement.setAttribute("aria-label", available
            ? "Engine confidence estimate " + value + " percent"
            : "Engine confidence estimate not available");
    }

    if (bar) {

        bar.style.width =
            "0%";

        bar.setAttribute("aria-valuenow", available ? String(value) : "0");
        bar.setAttribute("aria-valuetext", available ? value + "% engine estimate" : "Not available");
        bar.classList.toggle("is-unavailable", !available);

        requestAnimationFrame(() => {

            bar.style.width =
                (available ? value : 0) + "%";

        });
    }

    if (description) {
        description.textContent = available
            ? "This is the analysis engine’s confidence estimate, not a probability that the destination is safe or malicious."
            : "The analysis engine did not return a confidence estimate for this result.";
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

    const verdict = String(data.verdict || "UNKNOWN").toUpperCase();
    const reasons = Array.isArray(data.reasons)
        ? data.reasons.filter(reason => typeof reason === "string" && reason.trim())
        : [];
    const returnedEvidence = reasons.length
        ? reasons.join(" ")
        : "No explanatory reason details were returned by the analysis.";

    if (verdict === "SAFE") {
        explanationText.textContent = `No major suspicious indicators were found by the checks that ran. ${returnedEvidence} This is not proof that the destination is safe; verify the sender and context before sharing sensitive information.`;
    } else {
        explanationText.textContent = `The analysis returned: ${returnedEvidence} Use these observed reasons with the signal levels above to understand the result. The score is an estimate, not a probability.`;
    }
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
    loadSavedHistory();
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


function initializeHistoryControls() {
    const search = document.getElementById("historySearch");
    const filter = document.getElementById("historyVerdictFilter");
    search?.addEventListener("input", renderHistoryPreview);
    filter?.addEventListener("change", renderHistoryPreview);
    document.getElementById("historySourceSaved")?.addEventListener("click", () => setHistorySource("saved"));
    document.getElementById("historySourceBrowser")?.addEventListener("click", () => setHistorySource("browser"));
    document.getElementById("compareScansButton")?.addEventListener("click", compareSelectedScans);
    loadSavedHistory();
}


function setHistorySource(source) {
    historySource = source === "browser" ? "browser" : "saved";
    document.querySelectorAll("[data-history-source]").forEach(button => {
        const active = button.dataset.historySource === historySource;
        button.classList.toggle("is-active", active);
        button.setAttribute("aria-pressed", String(active));
    });
    const clearButton = document.getElementById("clearBrowserHistory");
    if (clearButton) clearButton.hidden = historySource !== "browser";
    const comparison = document.getElementById("historyComparison");
    if (comparison) comparison.hidden = true;
    renderHistoryPreview();
}


async function loadSavedHistory() {
    savedHistoryState = "loading";
    renderHistoryPreview();
    try {
        const response = await fetch("/api/history?limit=100", { headers: { Accept: "application/json" } });
        if (!response.ok) throw new Error(`History request failed (${response.status})`);
        const payload = await response.json();
        if (!Array.isArray(payload.scans)) throw new Error("Unexpected history response");
        savedHistory = payload.scans.map(scan => {
            const stamp = scan.created_at ? new Date(scan.created_at) : null;
            const result = scan.result && typeof scan.result === "object" ? { ...scan.result } : null;
            if (result && scan.scan_id && !result.scan_id) result.scan_id = scan.scan_id;
            return {
                ...scan,
                id: scan.scan_id,
                url: scan.submitted_preview || scan.domain || "",
                domain: scan.domain || scan.submitted_preview || "Unknown destination",
                verdict: String(scan.verdict || "UNKNOWN").toUpperCase(),
                score: Number(scan.score || 0),
                date: stamp && !Number.isNaN(stamp.getTime()) ? stamp.toLocaleDateString() : "",
                time: stamp && !Number.isNaN(stamp.getTime()) ? stamp.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "",
                data: result,
                source: "saved"
            };
        });
        savedHistoryState = "ready";
    } catch (error) {
        console.warn("Could not load saved scan history:", error);
        savedHistoryState = "error";
    }
    renderHistoryPreview();
    updateHistorySummary();
}


function getFilteredHistory(items = historySource === "browser" ? scanHistory : savedHistory) {
    const query = (document.getElementById("historySearch")?.value || "")
        .trim()
        .toLowerCase();
    const verdict = document.getElementById("historyVerdictFilter")?.value || "all";

    return items.filter(item => {
        const matchesQuery = !query || [item.domain, item.url, item.scan_id]
            .some(value => String(value || "").toLowerCase().includes(query));
        const matchesVerdict = verdict === "all"
            || String(item.verdict || "").toLowerCase() === verdict;
        return matchesQuery && matchesVerdict;
    });
}


function refreshHistoryComparisonOptions(items) {
    const earlier = document.getElementById("compareScanOlder");
    const later = document.getElementById("compareScanNewer");
    const button = document.getElementById("compareScansButton");
    if (!earlier || !later || !button) return;

    const priorEarlier = earlier.value;
    const priorLater = later.value;
    const identify = item => String(item.scan_id || item.id || "");
    const label = item => {
        const date = [item.date, item.time].filter(Boolean).join(" ")
            || (item.created_at ? new Date(item.created_at).toLocaleString() : "Date unavailable");
        return (item.domain || "Unknown destination") + " · " + (item.verdict || "UNKNOWN")
            + " · " + Number(item.score || 0) + "/100 · " + date;
    };

    [earlier, later].forEach(select => {
        select.replaceChildren();
        items.forEach(item => {
            const option = document.createElement("option");
            option.value = identify(item);
            option.textContent = label(item);
            select.appendChild(option);
        });
    });
    if (items.some(item => identify(item) === priorEarlier)) earlier.value = priorEarlier;
    if (items.some(item => identify(item) === priorLater)) later.value = priorLater;
    if (!priorEarlier && items.length > 1) earlier.value = identify(items[1]);
    if (!priorLater && items.length) later.value = identify(items[0]);
    earlier.disabled = later.disabled = items.length < 2;
    button.disabled = items.length < 2;
    button.title = items.length < 2 ? "At least two scans are needed to compare." : "Compare the selected scans.";
}


function compareSelectedScans() {
    const output = document.getElementById("historyComparison");
    const items = historySource === "browser" ? scanHistory : savedHistory;
    const olderId = document.getElementById("compareScanOlder")?.value;
    const newerId = document.getElementById("compareScanNewer")?.value;
    const identify = item => String(item.scan_id || item.id || "");
    const older = items.find(item => identify(item) === olderId);
    const newer = items.find(item => identify(item) === newerId);
    if (!output || !older || !newer || older === newer) {
        showToast("Choose two different scans to compare.");
        return;
    }

    const olderData = older.data && typeof older.data === "object" ? older.data : older.result || {};
    const newerData = newer.data && typeof newer.data === "object" ? newer.data : newer.result || {};
    const olderReasons = Array.isArray(olderData.reasons) ? olderData.reasons : Array.isArray(older.reasons) ? older.reasons : [];
    const newerReasons = Array.isArray(newerData.reasons) ? newerData.reasons : Array.isArray(newer.reasons) ? newer.reasons : [];
    const earlierReasons = new Set(olderReasons.map(reason => String(reason)));
    const laterReasons = new Set(newerReasons.map(reason => String(reason)));
    const added = newerReasons.filter(reason => !earlierReasons.has(String(reason)));
    const cleared = olderReasons.filter(reason => !laterReasons.has(String(reason)));
    const scoreChange = Number(newer.score || 0) - Number(older.score || 0);
    const scoreLabel = scoreChange === 0 ? "No score change" : (scoreChange > 0 ? "+" : "−") + Math.abs(scoreChange) + " points";
    const domain = item => item.domain || item.final_domain || item.url || "Unknown destination";
    const reasonList = (title, reasons) => "<div class=\"compare-reason-column\"><h4>" + title + "</h4>"
        + (reasons.length ? "<ul>" + reasons.map(reason => "<li>" + escapeHTML(String(reason)) + "</li>").join("") + "</ul>" : "<p>None reported</p>") + "</div>";

    output.innerHTML = "<div class=\"comparison-topline\"><strong>" + escapeHTML(domain(older)) + "</strong><span>" + escapeHTML(domain(newer)) + "</span></div>"
        + "<div class=\"comparison-metrics\"><div><small>EARLIER</small><strong>" + escapeHTML(String(older.verdict || "UNKNOWN")) + "</strong><span>" + escapeHTML(String(older.score ?? "—")) + "/100</span></div>"
        + "<div class=\"comparison-delta\"><small>SCORE DELTA</small><strong>" + escapeHTML(scoreLabel) + "</strong><span>"
        + (String(older.verdict || "UNKNOWN") === String(newer.verdict || "UNKNOWN") ? "Verdict unchanged" : escapeHTML(String(older.verdict || "UNKNOWN")) + " → " + escapeHTML(String(newer.verdict || "UNKNOWN"))) + "</span></div>"
        + "<div><small>LATER</small><strong>" + escapeHTML(String(newer.verdict || "UNKNOWN")) + "</strong><span>" + escapeHTML(String(newer.score ?? "—")) + "/100</span></div></div>"
        + "<div class=\"comparison-reasons\">" + reasonList("Newly reported reasons", added) + reasonList("No longer reported", cleared) + "</div>"
        + "<p class=\"comparison-caveat\">This compares the analysis records as saved. It does not confirm why a score changed; PhishLens does not provide per-signal score weights.</p>";
    output.hidden = false;
    output.scrollIntoView({ behavior: displayPreferences.reduceMotion ? "auto" : "smooth", block: "nearest" });
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

    const historyItems = historySource === "browser" ? scanHistory : savedHistory;
    refreshHistoryComparisonOptions(historyItems);
    if (historySource === "saved" && savedHistoryState === "loading") {
        list.setAttribute("aria-busy", "true");
        list.innerHTML = '<div class="history-empty"><div class="history-empty-icon" aria-hidden="true">◌</div><strong>Loading saved scans</strong><span>Retrieving your latest analyses.</span></div>';
        return;
    }
    list.setAttribute("aria-busy", "false");
    if (historySource === "saved" && savedHistoryState === "error") {
        const filterStatus = document.getElementById("historyFilterStatus");
        if (filterStatus) filterStatus.textContent = "Saved history is temporarily unavailable";
        list.innerHTML = '<div class="history-empty"><div class="history-empty-icon" aria-hidden="true">!</div><strong>Could not load saved scans</strong><span>Check your connection and try again.</span><button class="secondary-button history-retry" type="button">Retry</button></div>';
        list.querySelector(".history-retry")?.addEventListener("click", loadSavedHistory);
        updateHistorySummary();
        return;
    }

    if (!historyItems.length) {

        const filterStatus = document.getElementById("historyFilterStatus");
        if (filterStatus) {
            filterStatus.textContent = historySource === "browser" ? "Browser-local scan history" : "Saved scan history";
        }

        list.innerHTML = `
            <div class="history-empty">

                <div class="history-empty-icon">
                    ◌
                </div>

                <strong>
                    ${historySource === "browser" ? "No browser scans yet" : "No saved scans yet"}
                </strong>

                <span>
                    ${historySource === "browser" ? "Scans saved on this device will appear here." : "Completed analyses saved by PhishLens will appear here."}
                </span>

            </div>
        `;

        updateHistorySummary();

        return;
    }

    const filteredHistory = getFilteredHistory(historyItems);
    const filterStatus = document.getElementById("historyFilterStatus");
    if (filterStatus) {
        filterStatus.textContent = `Showing ${filteredHistory.length} of ${historyItems.length} ${historySource === "browser" ? "browser-local" : "saved"} scans`;
    }

    if (!filteredHistory.length) {
        list.innerHTML = `
            <div class="history-empty">
                <div class="history-empty-icon" aria-hidden="true">⌕</div>
                <strong>No matching scans</strong>
                <span>Try a different domain, link, or verdict filter.</span>
            </div>
        `;
        updateHistorySummary();
        return;
    }

    filteredHistory
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

    card.setAttribute(
        "aria-label",
        `${verdict} verdict, risk score ${score} out of 100, ${domain}, ${date} ${time}. Activate to reopen this result.`
    );

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
            if (item.source === "saved") reopenSavedHistoryItem(item);
            else reopenHistoryItem(item);
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

    const items = historySource === "browser" ? scanHistory : savedHistory;
    if (total) total.textContent = items.length;

    if (threats) {

        threats.textContent =
            items.filter(
                item =>
                    item.verdict === "DANGER" ||
                    item.verdict === "CAUTION"
            ).length;
    }
}


async function reopenSavedHistoryItem(item) {
    if (!item?.scan_id) return reopenHistoryItem(item);
    try {
        const response = await fetch(`/api/history/${encodeURIComponent(item.scan_id)}`, { headers: { Accept: "application/json" } });
        if (!response.ok) throw new Error(`Scan request failed (${response.status})`);
        const payload = await response.json();
        const scan = payload.scan;
        if (!scan || !scan.result || typeof scan.result !== "object") throw new Error("Saved result is unavailable");
        showURL();
        closeHistory();
        scrollToScanner();
        setTimeout(() => showResult(scan.result), 500);
    } catch (error) {
        console.warn("Could not reopen saved scan:", error);
        showToast("This saved result could not be opened. Try again shortly.");
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


function copyShareSafeSummary() {
    const result = document.getElementById("result");
    if (!result || result.classList.contains("hidden")) {
        showToast("Run an analysis before creating a share summary.");
        return;
    }

    const value = id => document.getElementById(id)?.innerText?.trim() || "Not available";
    const summary = [
        "PHISHLENS — SHARE-SAFE SCAN SUMMARY",
        "Destination details: Hidden",
        "",
        "Verdict: " + value("verdictBadge"),
        "Risk score: " + value("riskScore") + "/100",
        "Engine confidence: " + value("confidenceValue"),
        "",
        "Returned signal levels (not probabilities):",
        "URL structure: " + value("urlSignalValue"),
        "Domain: " + value("domainSignalValue"),
        "Security: " + value("securitySignalValue"),
        "Redirect path: " + value("redirectSignalValue"),
        "",
        "Recommended next step: " + value("nextAction"),
        "",
        "This summary omits the destination, scan ID, and raw reason text. A low score is not a guarantee of safety.",
        "Generated: " + new Date().toLocaleString()
    ].join("\n");

    if (navigator.clipboard?.writeText) {
        navigator.clipboard.writeText(summary)
            .then(() => showToast("Redacted summary copied. Destination details were omitted."))
            .catch(() => fallbackCopy(summary, "Redacted summary copied. Destination details were omitted."));
    } else {
        fallbackCopy(summary, "Redacted summary copied. Destination details were omitted.");
    }
}

async function shareSafeSummary() {
    const result = document.getElementById("result");
    if (!result || result.classList.contains("hidden")) {
        showToast("Run an analysis before sharing a summary.");
        return;
    }
    const value = id => document.getElementById(id)?.innerText?.trim() || "Not available";
    const text = [
        "PHISHLENS — SHARE-SAFE SCAN SUMMARY",
        "Destination details: Hidden",
        "Verdict: " + value("verdictBadge"),
        "Risk score: " + value("riskScore") + "/100",
        "Engine confidence: " + value("confidenceValue"),
        "Recommended next step: " + value("nextAction"),
        "This summary omits the destination, scan ID, and raw reason text. A low score is not a guarantee of safety."
    ].join("\n");
    if (navigator.share) {
        try {
            await navigator.share({ title: "PhishLens scan summary", text });
        } catch (error) {
            if (error?.name !== "AbortError") showToast("Could not open the share menu.");
        }
        return;
    }
    if (navigator.clipboard?.writeText) {
        try {
            await navigator.clipboard.writeText(text);
            showToast("Redacted summary copied. Destination details were omitted.");
        } catch (error) {
            fallbackCopy(text, "Redacted summary copied. Destination details were omitted.");
        }
    } else {
        fallbackCopy(text, "Redacted summary copied. Destination details were omitted.");
    }
}


function downloadReport() {
    const result = document.getElementById("result");
    if (!result || result.classList.contains("hidden")) {
        showToast("Run an analysis before exporting a report.");
        return;
    }

    const value = id => document.getElementById(id)?.innerText?.trim() || "—";
    const report = [
        "PHISHLENS SECURITY REPORT",
        "==========================",
        "",
        `Destination: ${value("resultDomain")}`,
        `Verdict: ${value("verdictBadge")}`,
        `Risk score: ${value("riskScore")}/100`,
        `Recommended next step: ${value("nextAction")}`,
        `Explanation: ${value("explanationText")}`,
        `Scan record: ${document.querySelector("#persistenceMeta .persistence-value")?.innerText?.trim() || "Not generated"}`,
        `Generated: ${new Date().toLocaleString()}`,
        "",
        "This report summarizes the PhishLens analysis shown in the app."
    ].join("\n");

    const blob = new Blob([report], { type: "text/plain;charset=utf-8" });
    const downloadUrl = URL.createObjectURL(blob);
    const link = document.createElement("a");
    const safeDomain = value("resultDomain")
        .toLowerCase()
        .replace(/[^a-z0-9.-]+/g, "-")
        .replace(/^-+|-+$/g, "") || "scan";

    link.href = downloadUrl;
    link.download = `phishlens-${safeDomain}-report.txt`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(downloadUrl), 1000);
    showToast("Text report downloaded.");
}


function downloadPDFReport() {
    const result = document.getElementById("result");
    if (!result || result.classList.contains("hidden")) {
        showToast("Run an analysis before exporting a report.");
        return;
    }

    const value = id => document.getElementById(id)?.innerText?.trim() || "—";
    const report = {
        destination: value("resultDomain"),
        verdict: value("verdictBadge"),
        score: value("riskScore"),
        recommendation: value("nextAction"),
        explanation: value("explanationText"),
        scanId: document.querySelector("#persistenceMeta .persistence-value")?.innerText?.trim() || "Not generated",
        generated: new Date().toLocaleString()
    };
    const popup = window.open("", "_blank", "width=900,height=720");
    if (!popup) {
        showToast("Allow pop-ups to create the print-ready report.");
        return;
    }
    popup.opener = null;
    const esc = text => escapeHTML(String(text));
    popup.document.open();
    popup.document.write(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>PhishLens Security Report</title><style>
        :root{color-scheme:light}*{box-sizing:border-box}body{margin:0;padding:48px;background:#f5f3ee;color:#1d2024;font:15px/1.6 Arial,sans-serif}.sheet{max-width:760px;margin:auto;padding:52px;background:#fff;border:1px solid #e7e2d7;box-shadow:0 18px 60px #18202a18}.brand{color:#93743a;font-size:12px;letter-spacing:.2em;font-weight:700}.rule{height:1px;background:#dfd7c4;margin:24px 0 32px}h1{font:500 34px/1.15 Georgia,serif;margin:0 0 8px}.muted{color:#6d717a}.summary{display:flex;gap:16px;align-items:center;margin:28px 0;padding:18px 20px;border:1px solid #e8e2d5;background:#fbfaf7}.verdict{font-weight:700;color:#795f2c;letter-spacing:.08em}.score{margin-left:auto;font:32px Georgia,serif}.item{padding:18px 0;border-bottom:1px solid #ece9e2}.item h2{font-size:11px;letter-spacing:.14em;color:#897444;text-transform:uppercase;margin:0 0 6px}.item p{margin:0;white-space:pre-wrap}.foot{margin-top:30px;color:#737782;font-size:12px}@media print{body{padding:0;background:#fff}.sheet{box-shadow:none;border:0;padding:24px;max-width:none}.summary,.item{break-inside:avoid}}@media(max-width:600px){body{padding:12px}.sheet{padding:24px}.score{font-size:26px}}
    </style></head><body><main class="sheet"><div class="brand">PHISHLENS · SECURITY INTELLIGENCE</div><div class="rule"></div><h1>Security analysis report</h1><div class="muted">Generated ${esc(report.generated)}</div><section class="summary"><div><div class="muted">VERDICT</div><div class="verdict">${esc(report.verdict)}</div></div><div class="score">${esc(report.score)}<span class="muted" style="font:14px Arial"> / 100</span></div></section><section class="item"><h2>Destination</h2><p>${esc(report.destination)}</p></section><section class="item"><h2>Recommended next step</h2><p>${esc(report.recommendation)}</p></section><section class="item"><h2>Analysis explanation</h2><p>${esc(report.explanation)}</p></section><section class="item"><h2>Scan record</h2><p>${esc(report.scanId)}</p></section><p class="foot">This report reflects the PhishLens result displayed at the time of export. Verify important decisions through official channels.</p></main><script>window.addEventListener('load',()=>setTimeout(()=>window.print(),250));<\/script></body></html>`);
    popup.document.close();
    showToast("Print-ready report opened. Choose Save as PDF in the print dialog.");
}


function downloadHistoryCSV() {
    const items = historySource === "browser" ? scanHistory : savedHistory;
    const rows = getFilteredHistory(items);
    if (!rows.length) {
        showToast("There are no matching scans to export.");
        return;
    }
    const fields = ["scan_id", "created_at", "domain", "url", "verdict", "score", "confidence", "input_type"];
    const cell = value => {
        let text = String(value ?? "");
        if (/^[=+@\-\t\r]/.test(text)) text = `'${text}`;
        return `"${text.replace(/"/g, '""')}"`;
    };
    const lines = [fields.map(cell).join(",")];
    rows.forEach(item => {
        const date = item.created_at || [item.date, item.time].filter(Boolean).join(" ");
        const values = [item.scan_id || item.id || "", date, item.domain || "", item.url || "", item.verdict || "", item.score ?? "", item.confidence ?? item.data?.confidence ?? "", item.input_type || ""];
        lines.push(values.map(cell).join(","));
    });
    const blob = new Blob(["\uFEFF", lines.join("\r\n")], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `phishlens-${historySource}-history-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    showToast(`${rows.length} scan${rows.length === 1 ? "" : "s"} exported as CSV.`);
}


function fallbackCopy(text, successMessage = "Security report copied.") {

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

        showToast(successMessage);

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

        qrDecodeHandled = false;

        await qrScanner.start(

            {
                facingMode:
                    "environment"
            },

            {
                fps: 10,
                qrbox: (viewfinderWidth, viewfinderHeight) => {
                    const side = Math.max(
                        1,
                        Math.floor(Math.min(viewfinderWidth, viewfinderHeight) * 0.88)
                    );
                    return { width: side, height: side };
                }
            },

            async decodedText => {

                if (qrDecodeHandled) return;
                qrDecodeHandled = true;

                updateCameraStatus("QR detected. Stopping the camera and preparing a content preview…");
                await stopQRScanner();
                showQRPreview(decodedText, "Camera scan");
            },

            () => {
                const now = Date.now();
                if (now - lastQrFrameHint > 3000) {
                    lastQrFrameHint = now;
                    updateCameraStatus("Looking for a QR code. Center it in the frame and hold steady.");
                }
            }
        );

        const torchButton = document.getElementById("qrTorchButton");
        const torchSupported = qrScanner.getRunningTrackCameraCapabilities?.().torchFeature?.().isSupported?.();
        if (torchButton) torchButton.classList.toggle("hidden", !torchSupported);

        document.querySelector(".analyzer-card")?.classList.add("is-qr-live");
        setAppStatus("qr");

        updateCameraStatus(
            "Camera active — position the QR code inside the frame."
        );

        showToast(
            "Camera ready."
        );

    } catch (error) {

        document.querySelector(".analyzer-card")?.classList.remove("is-qr-live");
        setAppStatus("ready");

        console.error(
            "QR scanner error:",
            error
        );

        const cameraMessage = error?.name === "NotAllowedError" || error?.name === "PermissionDeniedError"
            ? "Camera access was blocked. Allow camera access for this site in your browser, then try again."
            : error?.name === "NotFoundError" || error?.name === "DevicesNotFoundError"
                ? "No camera was found. Choose a QR image instead."
                : error?.name === "NotReadableError" || error?.name === "TrackStartError"
                    ? "The camera is busy in another app. Close that app or choose a QR image."
                    : "Camera could not start. Use localhost or HTTPS, check browser permissions, or choose a QR image.";

        updateCameraStatus(cameraMessage);

        showToast(
            "Camera could not be started."
        );
    }
}


async function stopQRScanner() {

    if (!qrScanner) {
        document.querySelector(".analyzer-card")?.classList.remove("is-qr-live");
        setAppStatus(document.getElementById("result")?.classList.contains("hidden") ? "ready" : "result");
        updateCameraStatus("Camera is off.");
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
    qrTorchEnabled = false;
    const torchButton = document.getElementById("qrTorchButton");
    torchButton?.classList.add("hidden");
    torchButton?.setAttribute("aria-pressed", "false");
    if (torchButton) torchButton.textContent = "Turn on flashlight";

    document.querySelector(".analyzer-card")?.classList.remove("is-qr-live");
    setAppStatus(document.getElementById("result")?.classList.contains("hidden") ? "ready" : "result");

    updateCameraStatus(
        "Camera scanner is inactive."
    );
}

async function toggleQRTorch() {
    if (!qrScanner?.isScanning) return;
    const button = document.getElementById("qrTorchButton");
    try {
        const capabilities = qrScanner.getRunningTrackCameraCapabilities?.();
        const supported = capabilities?.torchFeature?.().isSupported?.();
        if (!supported) {
            button?.classList.add("hidden");
            showToast("Flashlight control is not supported by this camera.");
            return;
        }
        const nextValue = !qrTorchEnabled;
        await qrScanner.applyVideoConstraints({ advanced: [{ torch: nextValue }] });
        qrTorchEnabled = nextValue;
        if (button) {
            button.textContent = nextValue ? "Turn off flashlight" : "Turn on flashlight";
            button.setAttribute("aria-pressed", String(nextValue));
        }
    } catch (error) {
        showToast("Could not change the flashlight. Your camera may not support it.");
    }
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
    setAppStatus("ready");

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

    toast.setAttribute("role", "alert");
    toast.setAttribute("aria-live", "assertive");

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
