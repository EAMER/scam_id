// Scam Detector - Content Script
// Analyzes live page content and renders the floating warning badge.

if (globalThis.__scamDetectorMessageHandler) {
    chrome.runtime.onMessage.removeListener(globalThis.__scamDetectorMessageHandler);
}

const runtimeMessageHandler = (request, sender, sendResponse) => {
    if (request.action === "ping") {
        sendResponse({ success: true });
        return;
    }

    if (request.action === "analyzePageContent") {
        sendResponse(analyzePageContent());
        return;
    }

    if (request.action === "showWarningBadge") {
        showWarningBadge(request.riskLevel, request.riskScore);
        sendResponse({ success: true });
        return;
    }

    if (request.action === "removeWarningBadge") {
        removeWarningBadge();
        sendResponse({ success: true });
    }
};

chrome.runtime.onMessage.addListener(runtimeMessageHandler);
globalThis.__scamDetectorMessageHandler = runtimeMessageHandler;

function analyzePageContent() {
    try {
        const pageData = extractPageData();
        const keywordAnalysis = analyzeScamKeywords(pageData.content);
        const giveawayAnalysis = analyzeGiveawayPatterns(pageData.content);

        return {
            pageTitle: pageData.title,
            metaDescription: pageData.description,
            contentLength: pageData.content.length,
            suspiciousKeywords: keywordAnalysis.keywords,
            keywordRiskScore: keywordAnalysis.riskScore,
            giveawayIndicators: giveawayAnalysis.indicators,
            giveawayRiskScore: giveawayAnalysis.riskScore,
            totalRiskScore: Math.min(100, keywordAnalysis.riskScore + giveawayAnalysis.riskScore),
            timestamp: new Date().toISOString(),
            url: window.location.href
        };
    } catch (error) {
        console.error("Error analyzing page content:", error);
        return {
            error: error.message,
            url: window.location.href
        };
    }
}

function extractPageData() {
    try {
        let title = document.title;

        if (!title) {
            const heading = document.querySelector("h1");
            title = heading ? heading.textContent.trim() : "No title found";
        }

        const metaDescription = document.querySelector('meta[name="description"]');
        const description = metaDescription ? metaDescription.getAttribute("content") : "";

        return {
            title: title.substring(0, 200),
            description: description.substring(0, 300),
            content: extractMainContent()
        };
    } catch (error) {
        console.error("Error extracting page data:", error);
        return {
            title: "Error",
            description: "",
            content: ""
        };
    }
}

function extractMainContent() {
    try {
        const source = document.body || document.documentElement;

        if (!source) {
            return "";
        }

        const clone = source.cloneNode(true);
        const elementsToRemove = clone.querySelectorAll(
            "script, style, noscript, meta, link, iframe, nav, footer"
        );

        elementsToRemove.forEach((element) => element.remove());

        return (clone.innerText || clone.textContent || "")
            .replace(/\s+/g, " ")
            .trim()
            .substring(0, 5000)
            .toLowerCase();
    } catch (error) {
        console.error("Error extracting main content:", error);
        return "";
    }
}

function analyzeScamKeywords(content) {
    const scamKeywordCategories = {
        phishing: [
            "verify account", "confirm identity", "update payment", "validate credentials",
            "click here immediately", "act now", "verify email", "confirm password",
            "urgent action required", "security alert", "suspicious activity"
        ],
        fakeAuth: [
            "fake login", "phishing", "unauthorized access", "account compromised",
            "unusual activity detected", "for security purposes"
        ],
        malware: [
            "malware detected", "virus found", "system infected", "scan now",
            "fix your pc", "remove malware", "security threat"
        ],
        impersonation: [
            "amazon support", "apple support", "microsoft support", "google support",
            "paypal account", "bank alert", "irs notice"
        ]
    };

    const foundKeywords = [];
    let riskScore = 0;

    for (const [category, keywords] of Object.entries(scamKeywordCategories)) {
        for (const keyword of keywords) {
            const regex = new RegExp(`\\b${keyword}\\b`, "gi");
            const matches = content.match(regex);

            if (!matches) {
                continue;
            }

            foundKeywords.push({
                keyword,
                category,
                occurrences: matches.length
            });

            const riskPerOccurrence = category === "phishing" ? 5 : 3;
            riskScore += Math.min(matches.length * riskPerOccurrence, 20);
        }
    }

    return {
        keywords: foundKeywords.slice(0, 10),
        riskScore: Math.min(riskScore, 40)
    };
}

function analyzeGiveawayPatterns(content) {
    const giveawayPatterns = {
        prize: {
            keywords: ["win prize", "claim prize", "prize waiting", "prize claim", "free prize"],
            riskLevel: "high"
        },
        money: {
            keywords: ["free money", "easy money", "make money", "quick cash", "fast money"],
            riskLevel: "high"
        },
        iphone: {
            keywords: ["free iphone", "iphone giveaway", "win iphone", "claim iphone", "iphone prize"],
            riskLevel: "high"
        },
        limitedTime: {
            keywords: ["limited time", "act fast", "hurry", "don't miss", "expires today", "last chance"],
            riskLevel: "high"
        },
        congratulations: {
            keywords: ["congratulations", "you won", "you've won", "you are selected", "selected as winner"],
            riskLevel: "high"
        },
        clickHere: {
            keywords: ["click here now", "click to claim", "tap to confirm", "click to verify"],
            riskLevel: "medium"
        },
        giftCard: {
            keywords: ["free gift card", "gift card reward", "gift card giveaway", "free amazon gift"],
            riskLevel: "high"
        },
        survey: {
            keywords: ["free survey", "take survey", "survey reward", "survey bonus"],
            riskLevel: "medium"
        }
    };

    const foundIndicators = [];
    let riskScore = 0;

    for (const [type, data] of Object.entries(giveawayPatterns)) {
        for (const keyword of data.keywords) {
            const regex = new RegExp(`\\b${keyword}\\b`, "gi");
            const matches = content.match(regex);

            if (!matches) {
                continue;
            }

            foundIndicators.push({
                type,
                keyword,
                occurrences: matches.length,
                riskLevel: data.riskLevel
            });

            const baseRisk = data.riskLevel === "high" ? 8 : 4;
            riskScore += Math.min(matches.length * baseRisk, 25);
        }
    }

    return {
        indicators: foundIndicators.slice(0, 8),
        riskScore: Math.min(riskScore, 50)
    };
}

function showWarningBadge(riskLevel, riskScore) {
    try {
        removeWarningBadge();

        const container = ensurePageContainer();
        const palette = getRiskPalette(riskLevel, riskScore);

        const badge = document.createElement("div");
        badge.id = "scam-detector-badge";
        badge.style.cssText = [
            "position: fixed",
            "top: 18px",
            "right: 18px",
            "z-index: 2147483647",
            "min-width: 220px",
            "max-width: 280px",
            "padding: 14px 16px",
            "border-radius: 18px",
            `background: ${palette.background}`,
            `color: ${palette.textColor}`,
            `box-shadow: ${palette.shadow}`,
            "backdrop-filter: blur(14px)",
            "font-family: 'Segoe UI Variable', 'Aptos', 'Trebuchet MS', sans-serif",
            "cursor: pointer",
            "border: 1px solid rgba(255, 255, 255, 0.18)",
            "transition: transform 0.2s ease, box-shadow 0.2s ease"
        ].join(";");

        badge.innerHTML = `
            <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px;">
                <div>
                    <div style="font-size:11px;letter-spacing:0.08em;text-transform:uppercase;opacity:0.82;">Scam Detector</div>
                    <div style="margin-top:4px;font-size:16px;font-weight:700;line-height:1.2;">${palette.label}</div>
                    <div style="margin-top:6px;font-size:13px;line-height:1.45;opacity:0.92;">Risk score: ${Math.round(riskScore)}</div>
                </div>
                <button id="scam-detector-dismiss" type="button" style="
                    width:28px;
                    height:28px;
                    border:none;
                    border-radius:999px;
                    background:rgba(255,255,255,0.16);
                    color:inherit;
                    cursor:pointer;
                    font-size:14px;
                    line-height:1;
                ">x</button>
            </div>
        `;

        badge.addEventListener("mouseenter", () => {
            badge.style.transform = "translateY(-2px)";
            badge.style.boxShadow = palette.hoverShadow;
        });

        badge.addEventListener("mouseleave", () => {
            badge.style.transform = "translateY(0)";
            badge.style.boxShadow = palette.shadow;
        });

        badge.addEventListener("click", (event) => {
            const target = event.target;

            if (target && target.id === "scam-detector-dismiss") {
                event.stopPropagation();
                removeWarningBadge();
                return;
            }

            showBadgeDetails(riskScore, palette);
        });

        container.appendChild(badge);
    } catch (error) {
        console.error("Error showing warning badge:", error);
    }
}

function showBadgeDetails(riskScore, palette) {
    try {
        let detailsPanel = document.getElementById("scam-detector-details");

        if (detailsPanel) {
            detailsPanel.style.display = detailsPanel.style.display === "none" ? "block" : "none";
            return;
        }

        const container = ensurePageContainer();

        detailsPanel = document.createElement("div");
        detailsPanel.id = "scam-detector-details";
        detailsPanel.style.cssText = [
            "position: fixed",
            "top: 96px",
            "right: 18px",
            "z-index: 2147483646",
            "width: 280px",
            "padding: 16px",
            "border-radius: 18px",
            "background: rgba(255, 255, 255, 0.96)",
            "color: #13232c",
            "box-shadow: 0 18px 44px rgba(19, 35, 44, 0.2)",
            "border: 1px solid rgba(19, 35, 44, 0.08)",
            "font-family: 'Segoe UI Variable', 'Aptos', 'Trebuchet MS', sans-serif"
        ].join(";");

        detailsPanel.innerHTML = `
            <div style="font-size:11px;letter-spacing:0.08em;text-transform:uppercase;color:#61727d;">Scam Detector</div>
            <div style="margin-top:8px;font-size:18px;font-weight:700;line-height:1.2;color:${palette.accent};">
                ${palette.label}
            </div>
            <p style="margin:8px 0 0;font-size:13px;line-height:1.55;color:#4f5d66;">
                ${getRiskMessage(riskScore)}
            </p>
            <div style="margin-top:14px;padding-top:14px;border-top:1px solid rgba(19,35,44,0.08);">
                <div style="font-size:12px;font-weight:700;">Recommendation</div>
                <p style="margin:6px 0 0;font-size:13px;line-height:1.55;color:#4f5d66;">
                    ${getRecommendation(riskScore)}
                </p>
            </div>
            <button id="scam-detector-close-details" type="button" style="
                margin-top:14px;
                width:100%;
                min-height:38px;
                border:none;
                border-radius:12px;
                background:#edf3f5;
                color:#13232c;
                cursor:pointer;
                font-weight:600;
            ">Close</button>
        `;

        container.appendChild(detailsPanel);

        detailsPanel.querySelector("#scam-detector-close-details").addEventListener("click", () => {
            detailsPanel.style.display = "none";
        });
    } catch (error) {
        console.error("Error showing badge details:", error);
    }
}

function removeWarningBadge() {
    const badge = document.getElementById("scam-detector-badge");
    const details = document.getElementById("scam-detector-details");

    if (badge) {
        badge.remove();
    }

    if (details) {
        details.remove();
    }
}

function getRiskPalette(riskLevel, riskScore) {
    if (riskLevel === "high" || riskScore >= 60) {
        return {
            label: "High-risk page",
            background: "linear-gradient(135deg, rgba(196, 75, 66, 0.96), rgba(140, 43, 52, 0.96))",
            textColor: "#fff7f5",
            accent: "#c44b42",
            shadow: "0 16px 34px rgba(140, 43, 52, 0.28)",
            hoverShadow: "0 20px 38px rgba(140, 43, 52, 0.34)"
        };
    }

    if (riskLevel === "medium" || riskScore >= 25) {
        return {
            label: "Proceed with caution",
            background: "linear-gradient(135deg, rgba(201, 135, 26, 0.96), rgba(168, 97, 10, 0.96))",
            textColor: "#fffaf0",
            accent: "#c9871a",
            shadow: "0 16px 34px rgba(168, 97, 10, 0.25)",
            hoverShadow: "0 20px 38px rgba(168, 97, 10, 0.3)"
        };
    }

    return {
        label: "Low-risk page",
        background: "linear-gradient(135deg, rgba(29, 141, 107, 0.96), rgba(10, 92, 87, 0.96))",
        textColor: "#f6fffc",
        accent: "#1d8d6b",
        shadow: "0 16px 34px rgba(10, 92, 87, 0.22)",
        hoverShadow: "0 20px 38px rgba(10, 92, 87, 0.28)"
    };
}

function getRiskMessage(riskScore) {
    if (riskScore >= 60) {
        return "This page shows several signs of phishing, scam bait, or other trust issues.";
    }

    if (riskScore >= 25) {
        return "Some signals on this page deserve a closer look before you click, sign in, or pay.";
    }

    return "No strong scam indicators were detected, but you should still verify important pages yourself.";
}

function getRecommendation(riskScore) {
    if (riskScore >= 60) {
        return "Leave the page if it asks for passwords, payment details, or urgent action.";
    }

    if (riskScore >= 25) {
        return "Verify the URL, confirm the brand, and avoid sharing sensitive information until you trust the site.";
    }

    return "Stay cautious and confirm the address bar if this page requests any personal information.";
}

function ensurePageContainer() {
    return document.body || document.documentElement;
}
