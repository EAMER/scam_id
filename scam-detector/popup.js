// Scam Detector - Popup Script
// Auto-scans the active page and lets the user manually block or unblock domains.

let currentTabId = null;
let currentTabUrl = "";
let currentDomain = "";
let isCurrentDomainBlocked = false;

document.addEventListener("DOMContentLoaded", initializePopup);

async function initializePopup() {
    setupEventListeners();

    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

        currentTabId = tab?.id ?? null;
        currentTabUrl = tab?.url ?? "";
        currentDomain = formatDomain(currentTabUrl);

        updateContext(tab);

        if (!isScannableUrl(currentTabUrl)) {
            disableScanning("Open a regular website tab to use scanning or manual blocking.");
            return;
        }

        await refreshBlockState();
        await performScan();
    } catch (error) {
        console.error("Error initializing popup:", error);
        disableScanning("We could not read the active tab. Try opening the popup again.");
    }
}

function setupEventListeners() {
    document.getElementById("blockBtn").addEventListener("click", toggleBlockForCurrentSite);
    document.getElementById("freshScanBtn").addEventListener("click", () => performScan({ forceRefresh: true }));
    document.getElementById("reportBtn").addEventListener("click", reportWebsite);
}

function updateContext(tab) {
    const pageTitle = document.getElementById("pageTitle");
    const urlInput = document.getElementById("urlInput");
    const domainPill = document.getElementById("domainPill");
    const domainValue = document.getElementById("domainValue");

    const title = tab?.title || "Ready to scan this page";
    const url = tab?.url || "Switch to a website tab to begin.";
    const domain = formatDomain(tab?.url);

    pageTitle.textContent = title;
    urlInput.textContent = url;
    domainPill.textContent = domain;
    domainValue.textContent = domain;
}

function disableScanning(message) {
    document.getElementById("blockBtn").disabled = true;
    document.getElementById("freshScanBtn").disabled = true;
    document.getElementById("reportBtn").disabled = true;

    setScanSource("Unavailable");
    document.getElementById("freshnessPill").textContent = "Unsupported page";
    document.getElementById("helperText").textContent = message;
    displayError(message);
}

async function refreshBlockState() {
    if (!currentTabUrl || !isScannableUrl(currentTabUrl)) {
        return;
    }

    try {
        const response = await chrome.runtime.sendMessage({
            action: "getBlockState",
            url: currentTabUrl
        });

        isCurrentDomainBlocked = Boolean(response?.isBlocked);
        updateBlockButton();
    } catch (error) {
        console.error("Unable to load block state:", error);
    }
}

async function toggleBlockForCurrentSite() {
    const blockButton = document.getElementById("blockBtn");
    const blockButtonText = document.getElementById("blockBtnText");
    const originalText = blockButtonText.textContent;

    if (!currentTabUrl || !isScannableUrl(currentTabUrl)) {
        displayError("Open a regular website tab to block or unblock it.");
        return;
    }

    try {
        blockButton.disabled = true;
        blockButtonText.textContent = isCurrentDomainBlocked ? "Unblocking..." : "Blocking...";

        const response = await chrome.runtime.sendMessage({
            action: "toggleSiteBlock",
            url: currentTabUrl,
            tabId: currentTabId
        });

        if (!response?.success) {
            throw new Error(response?.error || "We could not update the block list.");
        }

        isCurrentDomainBlocked = Boolean(response.isBlocked);
        updateBlockButton();
        document.getElementById("helperText").textContent = response.message;

        if (!isCurrentDomainBlocked) {
            await refreshBlockState();
        }
    } catch (error) {
        console.error("Unable to toggle site block:", error);
        blockButtonText.textContent = originalText;
        document.getElementById("helperText").textContent = error.message || "We could not update the block list.";
    } finally {
        blockButton.disabled = false;
    }
}

function updateBlockButton() {
    const blockButton = document.getElementById("blockBtn");
    const blockButtonText = document.getElementById("blockBtnText");

    blockButton.classList.remove("button--danger", "button--success");

    if (isCurrentDomainBlocked) {
        blockButton.classList.add("button--success");
        blockButtonText.textContent = "Unblock site";
    } else {
        blockButton.classList.add("button--danger");
        blockButtonText.textContent = "Block site";
    }
}

async function performScan({ forceRefresh = false } = {}) {
    if (!currentTabId || !isScannableUrl(currentTabUrl)) {
        displayError("Open a regular website tab to run a scan.");
        return;
    }

    setLoadingState(true, forceRefresh ? "Running a fresh scan..." : "Running your automatic scan...");

    try {
        const response = await chrome.runtime.sendMessage({
            action: "analyzeWebsite",
            url: currentTabUrl,
            tabId: currentTabId,
            forceRefresh
        });

        if (response?.success) {
            displayResults(response.analysis, {
                fromCache: Boolean(response.fromCache),
                pageAnalysisAvailable: Boolean(response.pageAnalysisAvailable)
            });
        } else {
            displayError(response?.error || "We could not analyze this page.");
        }
    } catch (error) {
        console.error("Error during scan:", error);
        displayError("The extension could not complete the scan. Try reopening the popup.");
    } finally {
        setLoadingState(false);
    }
}

function setLoadingState(isLoading, message = "Analyzing live page signals...") {
    const blockBtn = document.getElementById("blockBtn");
    const freshScanBtn = document.getElementById("freshScanBtn");
    const scanBtnText = document.getElementById("scanBtnText");
    const scanLoader = document.getElementById("scanLoader");
    const resultsSection = document.getElementById("resultsSection");
    const loadingState = document.getElementById("loadingState");
    const loadingText = document.getElementById("loadingText");

    loadingText.textContent = message;
    resultsSection.classList.toggle("hidden", isLoading);
    loadingState.classList.toggle("hidden", !isLoading);
    blockBtn.disabled = isLoading;
    freshScanBtn.disabled = isLoading || !isScannableUrl(currentTabUrl);

    scanBtnText.textContent = isLoading ? "Rescanning" : "Rescan";
    scanLoader.classList.toggle("hidden", !isLoading);
}

function displayResults(analysis, meta = {}) {
    const score = clampScore(analysis.riskScore);
    const status = getRiskStatus(score);
    const details = analysis.details || {};
    const reputation = details.reputation || {};
    const ssl = details.ssl || {};
    const pageContent = details.pageContent || null;
    const community = details.community || null;

    const riskScore = document.getElementById("riskScore");
    const riskCircle = document.getElementById("riskCircle");
    const resultsSection = document.getElementById("resultsSection");
    const loadingState = document.getElementById("loadingState");
    const statusHeadline = document.getElementById("statusHeadline");
    const statusBody = document.getElementById("statusBody");
    const riskLevelLabel = document.getElementById("riskLevelLabel");
    const statusMessage = document.getElementById("statusMessage");
    const statusIcon = document.getElementById("statusIcon");
    const statusText = document.getElementById("statusText");
    const statusDescription = document.getElementById("statusDescription");
    const trustValue = document.getElementById("trustValue");
    const sslValue = document.getElementById("sslValue");
    const domainValue = document.getElementById("domainValue");
    const pageSignalsValue = document.getElementById("pageSignalsValue");
    const freshnessPill = document.getElementById("freshnessPill");
    const helperText = document.getElementById("helperText");

    riskScore.textContent = String(Math.round(score));

    const circumference = 2 * Math.PI * 54;
    riskCircle.style.strokeDashoffset = String(circumference - ((score / 100) * circumference));
    riskCircle.style.stroke = status.color;

    statusHeadline.textContent = status.headline;
    statusBody.textContent = buildStatusBody(analysis, status, meta);
    statusText.textContent = status.title;
    statusDescription.textContent = analysis.reasons?.[0] || status.description;
    statusIcon.textContent = status.icon;
    statusMessage.className = `card alert-card alert-card--${status.variant}`;

    setBadgeVariant(riskLevelLabel, status.variant, status.label);
    setScanSource(meta.fromCache ? "Cached URL check" : "Fresh scan");

    trustValue.textContent = typeof reputation.trustScore === "number" ? `${reputation.trustScore}%` : "--";
    sslValue.textContent = ssl.isSecure ? "Secure" : "Missing";
    domainValue.textContent = analysis.domain || formatDomain(analysis.url);
    pageSignalsValue.textContent = summarizePageSignals(pageContent);

    freshnessPill.textContent = meta.fromCache
        ? `Cached ${formatTimestamp(analysis.scanTimestamp)}`
        : `Updated ${formatTimestamp(analysis.scanTimestamp)}`;

    helperText.textContent = buildHelperText({
        isCurrentDomainBlocked,
        pageAnalysisAvailable: meta.pageAnalysisAvailable,
        community
    });

    renderDetails(analysis, document.getElementById("detailsList"));

    loadingState.classList.add("hidden");
    resultsSection.classList.remove("hidden");
}

function renderDetails(analysis, detailsList) {
    const threats = Array.isArray(analysis.threats) ? analysis.threats : [];
    const reasons = Array.isArray(analysis.reasons) ? analysis.reasons : [];
    const pageContent = analysis.details?.pageContent || null;
    const community = analysis.details?.community || null;

    detailsList.innerHTML = "";

    if (!threats.length && !reasons.length) {
        detailsList.appendChild(
            buildDetailCard({
                title: "No major warning signs",
                description: "This scan did not find strong phishing or scam indicators.",
                variant: "safe",
                tags: ["Low risk"]
            })
        );
        return;
    }

    threats.forEach((threat) => {
        detailsList.appendChild(
            buildDetailCard({
                title: threat.type || "Potential issue",
                description: threat.description || "This page needs a closer look.",
                variant: mapSeverityToVariant(threat.severity),
                tags: [formatSeverity(threat.severity)]
            })
        );
    });

    if (reasons.length) {
        detailsList.appendChild(
            buildDetailCard({
                title: "Why the score moved",
                description: reasons.join(" | "),
                variant: "muted",
                tags: ["Reason summary"]
            })
        );
    }

    if (community?.scannerCount && (community.blockedByUsers > 0 || community.reportCount > 0)) {
        detailsList.appendChild(
            buildDetailCard({
                title: "Community signal",
                description: `${community.blockedByUsers} of ${community.scannerCount} scanners blocked this domain, and ${community.reportCount} users reported it.`,
                variant: community.blockedByUsers > 0 || community.reportCount > 0 ? "warning" : "safe",
                tags: [`${community.blockRatePercent}% block rate`]
            })
        );
    }

    if (pageContent?.suspiciousKeywords?.length) {
        const topKeywords = pageContent.suspiciousKeywords
            .slice(0, 3)
            .map((entry) => entry.keyword)
            .join(", ");

        detailsList.appendChild(
            buildDetailCard({
                title: "Suspicious page language",
                description: `The live page includes: ${topKeywords}.`,
                variant: "warning",
                tags: [`Keyword score ${pageContent.keywordRiskScore}`]
            })
        );
    }
}

function buildDetailCard({ title, description, variant = "muted", tags = [] }) {
    const card = document.createElement("article");
    card.className = "detail-item";

    const titleElement = document.createElement("p");
    titleElement.className = "detail-item__title";
    titleElement.textContent = title;

    const badge = document.createElement("span");
    setBadgeVariant(badge, variant, tags[0] || "Detail");

    const topRow = document.createElement("div");
    topRow.className = "detail-item__top";
    topRow.appendChild(titleElement);
    topRow.appendChild(badge);

    const descriptionElement = document.createElement("p");
    descriptionElement.className = "detail-item__description";
    descriptionElement.textContent = description;

    card.appendChild(topRow);
    card.appendChild(descriptionElement);

    if (tags.length > 1) {
        const tagsWrap = document.createElement("div");
        tagsWrap.className = "detail-item__tags";

        tags.slice(1).forEach((tagText) => {
            const tag = document.createElement("span");
            tag.className = "pill pill--muted";
            tag.textContent = tagText;
            tagsWrap.appendChild(tag);
        });

        card.appendChild(tagsWrap);
    }

    return card;
}

function displayError(message) {
    const resultsSection = document.getElementById("resultsSection");
    const loadingState = document.getElementById("loadingState");
    const riskScore = document.getElementById("riskScore");
    const riskCircle = document.getElementById("riskCircle");
    const statusHeadline = document.getElementById("statusHeadline");
    const statusBody = document.getElementById("statusBody");
    const statusMessage = document.getElementById("statusMessage");
    const statusIcon = document.getElementById("statusIcon");
    const statusText = document.getElementById("statusText");
    const statusDescription = document.getElementById("statusDescription");
    const trustValue = document.getElementById("trustValue");
    const sslValue = document.getElementById("sslValue");
    const pageSignalsValue = document.getElementById("pageSignalsValue");
    const freshnessPill = document.getElementById("freshnessPill");
    const helperText = document.getElementById("helperText");

    riskScore.textContent = "0";
    riskCircle.style.strokeDashoffset = "339.29";
    riskCircle.style.stroke = "#61727d";
    statusHeadline.textContent = "Scan unavailable";
    statusBody.textContent = message;
    statusText.textContent = "We could not complete this scan.";
    statusDescription.textContent = "Check that the tab is a regular website and that the backend is reachable.";
    statusIcon.textContent = "Info";
    statusMessage.className = "card alert-card alert-card--neutral";

    setBadgeVariant(document.getElementById("riskLevelLabel"), "muted", "Error");
    setScanSource("Issue");
    trustValue.textContent = "--";
    sslValue.textContent = "--";
    pageSignalsValue.textContent = "--";
    freshnessPill.textContent = "No result";
    helperText.textContent = message;

    renderDetails(
        {
            threats: [],
            reasons: [message],
            details: {}
        },
        document.getElementById("detailsList")
    );

    loadingState.classList.add("hidden");
    resultsSection.classList.remove("hidden");
}

async function reportWebsite() {
    const reportBtn = document.getElementById("reportBtn");
    const originalText = reportBtn.textContent;

    if (!currentTabUrl || !isScannableUrl(currentTabUrl)) {
        displayError("Open a regular website tab to send a report.");
        return;
    }

    try {
        reportBtn.disabled = true;
        reportBtn.textContent = "Sending...";

        const response = await chrome.runtime.sendMessage({
            action: "reportScam",
            url: currentTabUrl,
            timestamp: new Date().toISOString()
        });

        if (!response?.success) {
            throw new Error(response?.error || "Report submission failed.");
        }

        document.getElementById("helperText").textContent = response.message || "Thanks. Your report was sent.";
        reportBtn.textContent = "Reported";
    } catch (error) {
        console.error("Error reporting website:", error);
        document.getElementById("helperText").textContent = error.message || "We could not submit the report.";
        reportBtn.textContent = "Try again";
    } finally {
        window.setTimeout(() => {
            reportBtn.textContent = originalText;
            reportBtn.disabled = false;
        }, 1600);
    }
}

function getRiskStatus(score) {
    if (score >= 60) {
        return {
            label: "High",
            variant: "danger",
            color: "#c44b42",
            icon: "High",
            title: "This page looks risky.",
            headline: "High-risk signals detected",
            description: "Multiple trust and content checks suggest this page may be unsafe."
        };
    }

    if (score >= 25) {
        return {
            label: "Caution",
            variant: "warning",
            color: "#c9871a",
            icon: "Care",
            title: "This page needs caution.",
            headline: "Some warning signs need a closer look",
            description: "A few signals suggest you should verify the site before interacting with it."
        };
    }

    return {
        label: "Low",
        variant: "safe",
        color: "#1d8d6b",
        icon: "Safe",
        title: "This page looks safe.",
        headline: "No strong scam indicators detected",
        description: "The scan did not uncover major warning signs on this page."
    };
}

function buildStatusBody(analysis, status, meta) {
    const sourceLabel = meta.fromCache ? "Cached URL reputation" : "Fresh URL reputation";
    const pageStatus = analysis.details?.pageContent ? "live page signals included" : "page signals unavailable";
    return `${sourceLabel} with ${pageStatus}. ${status.description}`;
}

function setScanSource(text) {
    const badge = document.getElementById("scanSourceBadge");
    badge.textContent = text;
    badge.className = "badge badge--hero";
}

function setBadgeVariant(element, variant, text) {
    element.textContent = text;
    element.className = `badge badge--${variant}`;
}

function summarizePageSignals(pageContent) {
    if (!pageContent) {
        return "Unavailable";
    }

    const totalSignals = (pageContent.suspiciousKeywords?.length || 0) + (pageContent.giveawayIndicators?.length || 0);

    if (!totalSignals) {
        return "Clean";
    }

    return `${totalSignals} found`;
}

function buildHelperText({ isCurrentDomainBlocked, pageAnalysisAvailable, community }) {
    if (isCurrentDomainBlocked) {
        return "This domain is on your manual block list. Any new visit will be intercepted.";
    }

    if (community?.scannerCount && (community.blockedByUsers > 0 || community.reportCount > 0)) {
        return `Community signal: ${community.blockedByUsers} of ${community.scannerCount} scanners blocked this domain.`;
    }

    return pageAnalysisAvailable
        ? "Automatic scan completed with live page signals."
        : "Automatic scan completed. Live page signals were not available on this tab.";
}

function formatSeverity(severity) {
    switch (severity) {
        case "critical":
            return "Critical";
        case "high":
            return "High";
        case "medium":
            return "Medium";
        case "low":
            return "Low";
        default:
            return "Detail";
    }
}

function mapSeverityToVariant(severity) {
    switch (severity) {
        case "critical":
        case "high":
            return "danger";
        case "medium":
            return "warning";
        case "low":
            return "safe";
        default:
            return "muted";
    }
}

function formatDomain(url) {
    try {
        return new URL(url).hostname;
    } catch (error) {
        return "No domain";
    }
}

function formatTimestamp(timestamp) {
    if (!timestamp) {
        return "just now";
    }

    try {
        return new Intl.DateTimeFormat([], {
            hour: "numeric",
            minute: "2-digit"
        }).format(new Date(timestamp));
    } catch (error) {
        return "just now";
    }
}

function clampScore(score) {
    const numericScore = Number.isFinite(score) ? score : 0;
    return Math.min(100, Math.max(0, numericScore));
}

function isScannableUrl(url) {
    if (!url) {
        return false;
    }

    try {
        const parsed = new URL(url);
        return parsed.protocol === "http:" || parsed.protocol === "https:";
    } catch (error) {
        return false;
    }
}
