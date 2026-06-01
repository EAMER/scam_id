// Scam Detector - Background Service Worker
// Coordinates backend analysis, live page analysis, caching, and manual site blocking.

const CACHE_DURATION = 24 * 60 * 60 * 1000;
const CACHE_KEY_PREFIX = "scam_detector_cache_";
const API_BASE_URL = "http://localhost:3000";
const API_SCAN_ENDPOINT = `${API_BASE_URL}/scan`;
const API_REPORT_ENDPOINT = `${API_BASE_URL}/scan/report`;
const API_COMMUNITY_BLOCK_ENDPOINT = `${API_BASE_URL}/community/block`;
const API_TIMEOUT = 10000;
const BLOCKLIST_STORAGE_KEY = "manualBlockedSites";
const BLOCKLIST_COUNTER_KEY = "nextManualBlockRuleId";
const BLOCKED_PAGE_PATH = "/blocked.html";
const BLOCK_RULE_ID_START = 5000;
const MANUAL_RULE_ID_MAX = 49999;
const CLIENT_ID_STORAGE_KEY = "scamDetectorClientId";

chrome.runtime.onInstalled.addListener(() => {
    syncManualBlockRules().catch((error) => {
        console.error("Failed to sync manual block rules on install:", error);
    });
});

chrome.runtime.onStartup.addListener(() => {
    syncManualBlockRules().catch((error) => {
        console.error("Failed to sync manual block rules on startup:", error);
    });
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    const candidateUrl = changeInfo.url || (changeInfo.status === "loading" ? tab.url : "");

    if (!candidateUrl) {
        return;
    }

    enforceManualBlockForTab(tabId, candidateUrl).catch((error) => {
        console.warn("Fallback block enforcement failed:", error.message);
    });
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "analyzeWebsite") {
        handleAnalyzeWebsite(request.url, request.tabId, request.forceRefresh)
            .then(sendResponse)
            .catch((error) => {
                console.error("Unhandled analyzeWebsite error:", error);
                sendResponse({
                    success: false,
                    error: error.message || "Unknown error occurred"
                });
            });

        return true;
    }

    if (request.action === "reportScam") {
        handleReportScam(request.url, request.timestamp)
            .then(sendResponse)
            .catch((error) => {
                console.error("Unhandled reportScam error:", error);
                sendResponse({
                    success: false,
                    error: error.message || "Unknown error occurred"
                });
            });

        return true;
    }

    if (request.action === "getBlockState") {
        getBlockStateForUrl(request.url)
            .then(sendResponse)
            .catch((error) => {
                sendResponse({
                    success: false,
                    error: error.message || "Unknown error occurred"
                });
            });

        return true;
    }

    if (request.action === "toggleSiteBlock") {
        toggleSiteBlock(request.url, request.tabId)
            .then(sendResponse)
            .catch((error) => {
                sendResponse({
                    success: false,
                    error: error.message || "Unknown error occurred"
                });
            });

        return true;
    }

    if (request.action === "unblockDomain") {
        unblockDomain(request.domain)
            .then(sendResponse)
            .catch((error) => {
                sendResponse({
                    success: false,
                    error: error.message || "Unknown error occurred"
                });
            });

        return true;
    }

    return false;
});

async function handleAnalyzeWebsite(url, tabId, forceRefresh = false) {
    validateUrl(url);

    const pageAnalysisPromise = getPageAnalysis(tabId);
    let baseAnalysis = null;
    let fromCache = false;

    if (!forceRefresh) {
        baseAnalysis = await getCachedResult(url);
        fromCache = Boolean(baseAnalysis);
    }

    if (!baseAnalysis) {
        baseAnalysis = await scanWebsite(url);
        await cacheResult(url, baseAnalysis);
    }

    const pageAnalysis = await pageAnalysisPromise;
    const mergedAnalysis = mergePageSignals(baseAnalysis, pageAnalysis);

    await syncWarningBadge(tabId, mergedAnalysis);

    return {
        success: true,
        analysis: mergedAnalysis,
        fromCache,
        pageAnalysisAvailable: Boolean(pageAnalysis && !pageAnalysis.error)
    };
}

async function scanWebsite(url) {
    validateUrl(url);
    const clientId = await getOrCreateClientId();

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), API_TIMEOUT);

    try {
        const response = await fetch(API_SCAN_ENDPOINT, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            body: JSON.stringify({
                url,
                timestamp: new Date().toISOString(),
                userAgent: navigator.userAgent,
                clientId
            }),
            signal: controller.signal
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(
                `API error: ${response.status} ${response.statusText}. ${errorData.error || ""}`.trim()
            );
        }

        const responseData = await response.json();

        if (!validateApiResponse(responseData)) {
            throw new Error("Invalid API response format");
        }

        return normalizeApiResponse(responseData.analysis || responseData, url);
    } catch (error) {
        if (error.name === "AbortError") {
            throw new Error(`API request timeout (${API_TIMEOUT}ms). Please try again.`);
        }

        if (error instanceof TypeError) {
            throw new Error("Network error: Unable to reach the backend API.");
        }

        throw error;
    } finally {
        clearTimeout(timeoutId);
    }
}

function validateApiResponse(data) {
    const analysis = data?.analysis || data;

    return (
        typeof analysis === "object" &&
        analysis !== null &&
        typeof analysis.riskScore === "number" &&
        Array.isArray(analysis.threats)
    );
}

function normalizeApiResponse(data, fallbackUrl) {
    const details = data.details || {};

    return {
        url: data.url || fallbackUrl,
        domain: data.domain || getHostname(data.url || fallbackUrl),
        scanTimestamp: data.scanTimestamp || new Date().toISOString(),
        riskScore: clampScore(data.riskScore),
        threats: Array.isArray(data.threats) ? data.threats : [],
        reasons: Array.isArray(data.reasons) ? data.reasons : [],
        details: {
            reputation: details.reputation || data.reputation || null,
            typosquatting: details.typosquatting || data.typosquatting || null,
            community: details.community || data.community || null,
            giveaway:
                details.giveaway ||
                (data.giveawayDetected !== undefined
                    ? {
                          detected: Boolean(data.giveawayDetected),
                          indicators: []
                      }
                    : null),
            ssl:
                details.ssl ||
                (data.sslSecure !== undefined
                    ? {
                          isSecure: Boolean(data.sslSecure)
                      }
                    : null)
        }
    };
}

function mergePageSignals(baseAnalysis, pageAnalysis) {
    const merged = deepClone(baseAnalysis);
    merged.details = merged.details || {};
    merged.details.pageContent = pageAnalysis || null;

    if (!pageAnalysis || pageAnalysis.error) {
        return merged;
    }

    const reasons = Array.isArray(merged.reasons) ? [...merged.reasons] : [];
    const threats = Array.isArray(merged.threats) ? [...merged.threats] : [];
    let riskScore = clampScore(merged.riskScore);

    if (pageAnalysis.suspiciousKeywords?.length) {
        const topKeywords = pageAnalysis.suspiciousKeywords
            .slice(0, 3)
            .map((entry) => entry.keyword)
            .join(", ");

        threats.push({
            type: "Suspicious page language",
            severity: pageAnalysis.keywordRiskScore >= 20 ? "high" : "medium",
            description: `The live page contains scam-related phrases such as ${topKeywords}.`
        });

        reasons.push(`Live page text includes suspicious phrases: ${topKeywords}`);
        riskScore += Math.min(15, Math.ceil(pageAnalysis.keywordRiskScore / 2));
    }

    if (pageAnalysis.giveawayIndicators?.length) {
        const topGiveaways = pageAnalysis.giveawayIndicators
            .slice(0, 3)
            .map((entry) => entry.keyword)
            .join(", ");

        threats.push({
            type: "Giveaway bait on page",
            severity: pageAnalysis.giveawayRiskScore >= 20 ? "high" : "medium",
            description: `The live page uses giveaway-style prompts such as ${topGiveaways}.`
        });

        reasons.push(`Live page content includes giveaway bait: ${topGiveaways}`);
        riskScore += Math.min(15, Math.ceil(pageAnalysis.giveawayRiskScore / 2));
    }

    merged.threats = dedupeThreats(threats);
    merged.reasons = dedupeText(reasons);
    merged.riskScore = clampScore(riskScore);

    return merged;
}

async function getPageAnalysis(tabId) {
    if (!tabId) {
        return null;
    }

    try {
        await ensureContentScript(tabId);
        return await chrome.tabs.sendMessage(tabId, { action: "analyzePageContent" });
    } catch (error) {
        console.warn("Live page analysis unavailable:", error.message);
        return null;
    }
}

async function ensureContentScript(tabId) {
    await chrome.scripting.executeScript({
        target: { tabId },
        files: ["content.js"]
    });
}

async function syncWarningBadge(tabId, analysis) {
    if (!tabId) {
        return;
    }

    try {
        await ensureContentScript(tabId);

        if (analysis.riskScore >= 25) {
            await chrome.tabs.sendMessage(tabId, {
                action: "showWarningBadge",
                riskLevel: getRiskLevel(analysis.riskScore),
                riskScore: analysis.riskScore
            });
        } else {
            await chrome.tabs.sendMessage(tabId, { action: "removeWarningBadge" });
        }
    } catch (error) {
        console.warn("Unable to update warning badge:", error.message);
    }
}

async function getBlockStateForUrl(url) {
    validateUrl(url);
    await syncManualBlockRules();

    const domain = getHostname(url);
    const blocklist = await getStoredBlocklist();
    const entry = blocklist[domain] || null;

    return {
        success: true,
        isBlocked: Boolean(entry),
        domain
    };
}

async function toggleSiteBlock(url, tabId) {
    validateUrl(url);
    await syncManualBlockRules();

    const domain = getHostname(url);
    const blocklist = await getStoredBlocklist();

    if (blocklist[domain]) {
        const response = await unblockDomain(domain);

        return {
            ...response,
            domain,
            message: `${domain} was removed from your manual block list.`
        };
    }

    const ruleId = await getNextBlockRuleId();
    const rule = buildManualBlockRule(domain, ruleId);

    await chrome.declarativeNetRequest.updateDynamicRules({
        addRules: [rule],
        removeRuleIds: []
    });

    blocklist[domain] = {
        domain,
        ruleId,
        createdAt: new Date().toISOString()
    };

    await saveStoredBlocklist(blocklist);

    let communityMessage = "";
    try {
        const community = await syncCommunityBlockPreference({ url, domain, isBlocked: true });
        communityMessage = formatCommunityMessage(community);
    } catch (error) {
        console.warn("Unable to sync block with backend:", error.message);
        communityMessage = " Local block applied, but community sync is unavailable right now.";
    }

    if (tabId) {
        await navigateTabToBlockedPage(tabId, domain);
    }

    return {
        success: true,
        isBlocked: true,
        domain,
        message: `${domain} is now blocked. Future visits will be redirected to Scam Detector.${communityMessage}`
    };
}

async function unblockDomain(domain) {
    const normalizedDomain = normalizeDomain(domain);
    const blocklist = await getStoredBlocklist();
    const entry = blocklist[normalizedDomain];

    if (!entry) {
        return {
            success: true,
            isBlocked: false,
            domain: normalizedDomain,
            message: `${normalizedDomain} is not on your manual block list.`
        };
    }

    await chrome.declarativeNetRequest.updateDynamicRules({
        addRules: [],
        removeRuleIds: [entry.ruleId]
    });

    delete blocklist[normalizedDomain];
    await saveStoredBlocklist(blocklist);

    let communityMessage = "";
    try {
        const community = await syncCommunityBlockPreference({ domain: normalizedDomain, isBlocked: false });
        communityMessage = formatCommunityMessage(community);
    } catch (error) {
        console.warn("Unable to sync unblock with backend:", error.message);
        communityMessage = " Local unblock worked, but community sync is unavailable right now.";
    }

    return {
        success: true,
        isBlocked: false,
        domain: normalizedDomain,
        message: `${normalizedDomain} was removed from your manual block list.${communityMessage}`
    };
}

function buildManualBlockRule(domain, ruleId) {
    return {
        id: ruleId,
        priority: 1,
        action: {
            type: "redirect",
            redirect: {
                extensionPath: `${BLOCKED_PAGE_PATH}?domain=${encodeURIComponent(domain)}`
            }
        },
        condition: {
            urlFilter: `||${domain}/`,
            resourceTypes: ["main_frame"]
        }
    };
}

async function navigateTabToBlockedPage(tabId, domain) {
    try {
        await chrome.tabs.update(tabId, {
            url: chrome.runtime.getURL(`blocked.html?domain=${encodeURIComponent(domain)}`)
        });
    } catch (error) {
        console.warn("Unable to redirect the current tab immediately:", error.message);
    }
}

async function getStoredBlocklist() {
    const stored = await chrome.storage.local.get(BLOCKLIST_STORAGE_KEY);
    return stored[BLOCKLIST_STORAGE_KEY] || {};
}

async function saveStoredBlocklist(blocklist) {
    await chrome.storage.local.set({
        [BLOCKLIST_STORAGE_KEY]: blocklist
    });
}

async function getNextBlockRuleId() {
    const stored = await chrome.storage.local.get(BLOCKLIST_COUNTER_KEY);
    const nextRuleId = Number.isInteger(stored[BLOCKLIST_COUNTER_KEY])
        ? stored[BLOCKLIST_COUNTER_KEY]
        : BLOCK_RULE_ID_START;

    await chrome.storage.local.set({
        [BLOCKLIST_COUNTER_KEY]: nextRuleId + 1
    });

    return nextRuleId;
}

async function syncManualBlockRules() {
    const blocklist = await getStoredBlocklist();
    const expectedRules = Object.values(blocklist).map((entry) => buildManualBlockRule(entry.domain, entry.ruleId));
    const dynamicRules = await chrome.declarativeNetRequest.getDynamicRules();

    const manualRuleIdsToRemove = dynamicRules
        .map((rule) => rule.id)
        .filter((ruleId) => ruleId >= BLOCK_RULE_ID_START && ruleId <= MANUAL_RULE_ID_MAX);

    await chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: manualRuleIdsToRemove,
        addRules: expectedRules
    });
}

async function enforceManualBlockForTab(tabId, url) {
    if (!url || url.startsWith(chrome.runtime.getURL("/"))) {
        return;
    }

    let domain = "";

    try {
        domain = getHostname(url);
    } catch (error) {
        return;
    }

    if (!domain) {
        return;
    }

    const blocklist = await getStoredBlocklist();

    if (blocklist[domain]) {
        await navigateTabToBlockedPage(tabId, domain);
    }
}

async function cacheResult(url, result) {
    try {
        const cacheKey = CACHE_KEY_PREFIX + hashUrl(url);
        const cacheableResult = deepClone(result);

        if (cacheableResult.details) {
            delete cacheableResult.details.pageContent;
        }

        await chrome.storage.local.set({
            [cacheKey]: {
                result: cacheableResult,
                timestamp: Date.now()
            }
        });
    } catch (error) {
        console.error("Error caching result:", error);
    }
}

async function getCachedResult(url) {
    try {
        const cacheKey = CACHE_KEY_PREFIX + hashUrl(url);
        const data = await chrome.storage.local.get(cacheKey);
        const cacheData = data[cacheKey];

        if (!cacheData) {
            return null;
        }

        if ((Date.now() - cacheData.timestamp) >= CACHE_DURATION) {
            await chrome.storage.local.remove(cacheKey);
            return null;
        }

        return cacheData.result;
    } catch (error) {
        console.error("Error retrieving cached result:", error);
        return null;
    }
}

function hashUrl(url) {
    let hash = 0;

    for (let index = 0; index < url.length; index += 1) {
        hash = ((hash << 5) - hash) + url.charCodeAt(index);
        hash &= hash;
    }

    return Math.abs(hash).toString(36);
}

async function handleReportScam(url, timestamp) {
    validateUrl(url);

    await sendReportToBackend(url, timestamp);

    const reports = await chrome.storage.local.get("scamReports");
    const reportsList = reports.scamReports || [];

    reportsList.push({
        url,
        timestamp
    });

    if (reportsList.length > 100) {
        reportsList.shift();
    }

    await chrome.storage.local.set({ scamReports: reportsList });

    return {
        success: true,
        message: "Thanks. The site was added to your report history."
    };
}

async function sendReportToBackend(url, timestamp) {
    const clientId = await getOrCreateClientId();
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    try {
        const response = await fetch(API_REPORT_ENDPOINT, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            body: JSON.stringify({
                url,
                timestamp,
                userAgent: navigator.userAgent,
                clientId
            }),
            signal: controller.signal
        });

        if (!response.ok) {
            throw new Error(`Failed to send report: ${response.status}`);
        }

        return await response.json();
    } catch (error) {
        if (error.name === "AbortError") {
            throw new Error("Report submission timed out. Please try again.");
        }

        throw error;
    } finally {
        clearTimeout(timeoutId);
    }
}

chrome.alarms.create("cleanupCache", { periodInMinutes: 60 });

chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === "cleanupCache") {
        cleanupExpiredCache();
    }
});

async function cleanupExpiredCache() {
    try {
        const allItems = await chrome.storage.local.get(null);
        const keysToRemove = [];
        const now = Date.now();

        for (const [key, value] of Object.entries(allItems)) {
            if (key.startsWith(CACHE_KEY_PREFIX) && value?.timestamp && (now - value.timestamp) > CACHE_DURATION) {
                keysToRemove.push(key);
            }
        }

        if (keysToRemove.length) {
            await chrome.storage.local.remove(keysToRemove);
        }
    } catch (error) {
        console.error("Error during cache cleanup:", error);
    }
}

async function syncCommunityBlockPreference({ url, domain, isBlocked }) {
    const clientId = await getOrCreateClientId();
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    try {
        const response = await fetch(API_COMMUNITY_BLOCK_ENDPOINT, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            body: JSON.stringify({
                url,
                domain,
                clientId,
                isBlocked
            }),
            signal: controller.signal
        });

        if (!response.ok) {
            throw new Error(`Community sync failed: ${response.status}`);
        }

        const data = await response.json();
        return data.community || null;
    } finally {
        clearTimeout(timeoutId);
    }
}

function formatCommunityMessage(community) {
    if (!community || !community.scannerCount) {
        return "";
    }

    return ` Community signal: ${community.blockedByUsers} of ${community.scannerCount} scanners blocked this domain.`;
}

async function getOrCreateClientId() {
    const stored = await chrome.storage.local.get(CLIENT_ID_STORAGE_KEY);

    if (stored[CLIENT_ID_STORAGE_KEY]) {
        return stored[CLIENT_ID_STORAGE_KEY];
    }

    const clientId = `client_${Date.now()}_${crypto.randomUUID()}`;
    await chrome.storage.local.set({
        [CLIENT_ID_STORAGE_KEY]: clientId
    });

    return clientId;
}

function getRiskLevel(score) {
    if (score >= 60) {
        return "high";
    }

    if (score >= 25) {
        return "medium";
    }

    return "low";
}

function validateUrl(url) {
    const parsedUrl = new URL(url);

    if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
        throw new Error("Only http and https pages can be scanned.");
    }
}

function clampScore(score) {
    const numericScore = Number.isFinite(score) ? score : 0;
    return Math.min(100, Math.max(0, numericScore));
}

function getHostname(url) {
    try {
        return normalizeDomain(new URL(url).hostname);
    } catch (error) {
        return "";
    }
}

function normalizeDomain(domain) {
    return String(domain || "").trim().toLowerCase();
}

function deepClone(value) {
    return JSON.parse(JSON.stringify(value));
}

function dedupeThreats(threats) {
    const seen = new Set();

    return threats.filter((threat) => {
        const key = `${threat.type}:${threat.description}`;

        if (seen.has(key)) {
            return false;
        }

        seen.add(key);
        return true;
    });
}

function dedupeText(entries) {
    return [...new Set(entries)];
}

console.log("Scam Detector service worker initialized with API endpoint:", API_SCAN_ENDPOINT);
