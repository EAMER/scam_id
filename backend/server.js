// Scam Detector - Express.js Backend Server
// Handles website scanning, reputation checking, phishing detection, and community signals.

require('dotenv').config();
const fs = require('fs/promises');
const path = require('path');
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const NodeCache = require('node-cache');

const app = express();
const PORT = process.env.PORT || 3000;
const cache = new NodeCache({ stdTTL: 3600, checkperiod: 600 });
const COMMUNITY_DATA_PATH = path.join(__dirname, 'community-data.json');
const BASE_SCAN_CACHE_PREFIX = 'scan_base_';

let communityWriteQueue = Promise.resolve();

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
    next();
});

app.get('/health', async (req, res) => {
    const communityData = await loadCommunityData();

    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        trackedDomains: Object.keys(communityData.domains).length
    });
});

app.post('/scan', async (req, res) => {
    try {
        const { url, clientId } = req.body;
        const { domain } = parseRequestUrl(url);
        const normalizedClientId = normalizeClientId(clientId);

        if (normalizedClientId) {
            await trackCommunityScan(domain, normalizedClientId);
        }

        const cacheKey = `${BASE_SCAN_CACHE_PREFIX}${domain}`;
        let baseAnalysis = cache.get(cacheKey);
        const cached = Boolean(baseAnalysis);

        if (!baseAnalysis) {
            baseAnalysis = await analyzeWebsiteBase(url, domain);
            cache.set(cacheKey, baseAnalysis);
        }

        const analysis = await attachCommunitySignals(baseAnalysis, domain, normalizedClientId);

        res.json({
            success: true,
            analysis,
            cached
        });
    } catch (error) {
        console.error('Error in /scan endpoint:', error);
        const statusCode = error.message === 'URL is required' || error.message === 'Invalid URL format' ? 400 : 500;
        res.status(statusCode).json({
            success: false,
            error: error.message || 'Internal server error'
        });
    }
});

app.post('/scan/report', async (req, res) => {
    try {
        const { url, timestamp, userAgent, clientId } = req.body;
        const { domain } = parseRequestUrl(url);
        const normalizedClientId = normalizeClientId(clientId);

        console.log(`Scam report received for: ${url}`);

        if (normalizedClientId) {
            await trackCommunityReport(domain, normalizedClientId);
        }

        const report = {
            url,
            domain,
            timestamp,
            userAgent,
            clientId: normalizedClientId || undefined,
            reportedAt: new Date().toISOString()
        };

        console.log('Report stored:', JSON.stringify(report, null, 2));

        res.json({
            success: true,
            message: 'Report received and will be reviewed',
            reportId: generateReportId()
        });
    } catch (error) {
        console.error('Error in /scan/report endpoint:', error);
        const statusCode = error.message === 'URL is required' || error.message === 'Invalid URL format' ? 400 : 500;
        res.status(statusCode).json({
            success: false,
            error: error.message || 'Internal server error'
        });
    }
});

app.post('/community/block', async (req, res) => {
    try {
        const { url, domain, clientId, isBlocked } = req.body;
        const resolvedDomain = resolveDomain({ url, domain });
        const normalizedClientId = normalizeClientId(clientId);

        if (!normalizedClientId) {
            return res.status(400).json({
                success: false,
                error: 'clientId is required'
            });
        }

        const communityStats = await setCommunityBlockPreference(
            resolvedDomain,
            normalizedClientId,
            Boolean(isBlocked)
        );

        res.json({
            success: true,
            domain: resolvedDomain,
            isBlocked: Boolean(isBlocked),
            community: communityStats
        });
    } catch (error) {
        console.error('Error in /community/block endpoint:', error);
        const statusCode = error.message === 'URL is required' || error.message === 'Invalid URL format' ? 400 : 500;
        res.status(statusCode).json({
            success: false,
            error: error.message || 'Internal server error'
        });
    }
});

async function analyzeWebsiteBase(url, domain) {
    const analysisResults = {
        url,
        domain,
        scanTimestamp: new Date().toISOString(),
        riskScore: 0,
        threats: [],
        reasons: [],
        details: {}
    };

    const [
        reputationData,
        typosquattingData,
        giveawayData,
        sslData
    ] = await Promise.all([
        checkDomainReputation(domain),
        checkTyposquatting(domain),
        analyzeGiveawayIndicators(url),
        checkSSLCertificate(domain)
    ]);

    analysisResults.details.reputation = reputationData;
    analysisResults.details.typosquatting = typosquattingData;
    analysisResults.details.giveaway = giveawayData;
    analysisResults.details.ssl = sslData;

    let riskScore = 0;

    riskScore += Math.round((1 - reputationData.trustScore / 100) * 40);
    if (reputationData.blacklisted) {
        riskScore += 30;
        analysisResults.threats.push({
            type: 'Blacklisted Domain',
            severity: 'critical',
            description: 'Domain is listed on known malicious/phishing databases'
        });
        analysisResults.reasons.push('Domain appears on blacklist');
    }

    if (typosquattingData.detected) {
        riskScore += 30;
        analysisResults.threats.push({
            type: 'Typosquatting',
            severity: 'high',
            description: `Domain resembles legitimate brand: ${typosquattingData.suspectedBrand}`
        });
        analysisResults.reasons.push(`Suspicious domain mimicking: ${typosquattingData.suspectedBrand}`);
    }

    if (giveawayData.indicators.length > 0) {
        riskScore += giveawayData.riskContribution;
        analysisResults.threats.push({
            type: 'Giveaway Scam Patterns',
            severity: 'high',
            description: `Page contains ${giveawayData.indicators.length} giveaway/scam indicators`
        });
        analysisResults.reasons.push(`Found suspicious giveaway patterns: ${giveawayData.indicators.slice(0, 3).join(', ')}`);
    }

    if (!sslData.isSecure) {
        riskScore += 10;
        analysisResults.threats.push({
            type: 'No HTTPS',
            severity: 'medium',
            description: 'Website does not use HTTPS/TLS encryption'
        });
        analysisResults.reasons.push('Website is not using secure HTTPS connection');
    }

    analysisResults.riskScore = Math.min(100, Math.max(0, riskScore));

    return analysisResults;
}

async function attachCommunitySignals(baseAnalysis, domain, clientId) {
    const analysis = cloneData(baseAnalysis);
    const communityStats = await getCommunityStats(domain, clientId);

    analysis.details.community = communityStats;

    if (!communityStats.scannerCount) {
        return analysis;
    }

    const communityRiskContribution = Math.min(
        20,
        Math.round(communityStats.blockRatePercent / 6) + (communityStats.reportCount * 2)
    );

    if (communityRiskContribution <= 0) {
        return analysis;
    }

    analysis.riskScore = Math.min(100, analysis.riskScore + communityRiskContribution);

    const communitySeverity =
        communityStats.blockRatePercent >= 20 || communityStats.reportCount >= 3
            ? 'high'
            : 'medium';

    analysis.threats.push({
        type: 'Community Warning Signal',
        severity: communitySeverity,
        description: `Blocked by ${communityStats.blockedByUsers} of ${communityStats.scannerCount} scanners and reported by ${communityStats.reportCount} users`
    });

    analysis.reasons.push(
        `Community signal: ${communityStats.blockedByUsers}/${communityStats.scannerCount} scanners blocked this site`
    );

    if (communityStats.reportCount > 0) {
        analysis.reasons.push(`Community reports: ${communityStats.reportCount} user reports received`);
    }

    return analysis;
}

async function trackCommunityScan(domain, clientId) {
    await updateCommunityData((data) => {
        const record = ensureDomainRecord(data, domain);
        record.scanners[clientId] = new Date().toISOString();
    });
}

async function trackCommunityReport(domain, clientId) {
    await updateCommunityData((data) => {
        const record = ensureDomainRecord(data, domain);
        record.reports[clientId] = new Date().toISOString();
    });
}

async function setCommunityBlockPreference(domain, clientId, isBlocked) {
    await updateCommunityData((data) => {
        const record = ensureDomainRecord(data, domain);
        record.scanners[clientId] = new Date().toISOString();

        if (isBlocked) {
            record.blocked[clientId] = new Date().toISOString();
        } else {
            delete record.blocked[clientId];
        }
    });

    return getCommunityStats(domain, clientId);
}

async function getCommunityStats(domain, clientId) {
    const communityData = await loadCommunityData();
    const record = communityData.domains[normalizeDomain(domain)] || createEmptyDomainRecord();
    const scannerCount = Object.keys(record.scanners).length;
    const blockedByUsers = Object.keys(record.blocked).length;
    const reportCount = Object.keys(record.reports).length;

    return {
        scannerCount,
        blockedByUsers,
        reportCount,
        blockRatePercent: scannerCount > 0 ? Number(((blockedByUsers / scannerCount) * 100).toFixed(1)) : 0,
        currentUserHasBlocked: Boolean(clientId && record.blocked[clientId]),
        currentUserHasReported: Boolean(clientId && record.reports[clientId])
    };
}

async function loadCommunityData() {
    try {
        const fileContents = await fs.readFile(COMMUNITY_DATA_PATH, 'utf8');
        const parsed = JSON.parse(fileContents);

        return {
            version: 1,
            domains: parsed.domains || {}
        };
    } catch (error) {
        if (error.code === 'ENOENT') {
            return createCommunityData();
        }

        throw error;
    }
}

async function updateCommunityData(mutator) {
    communityWriteQueue = communityWriteQueue.catch(() => undefined).then(async () => {
        const data = await loadCommunityData();
        await mutator(data);
        await fs.writeFile(COMMUNITY_DATA_PATH, JSON.stringify(data, null, 2));
    });

    return communityWriteQueue;
}

function createCommunityData() {
    return {
        version: 1,
        domains: {}
    };
}

function ensureDomainRecord(data, domain) {
    const normalizedDomain = normalizeDomain(domain);

    if (!data.domains[normalizedDomain]) {
        data.domains[normalizedDomain] = createEmptyDomainRecord();
    }

    return data.domains[normalizedDomain];
}

function createEmptyDomainRecord() {
    return {
        scanners: {},
        blocked: {},
        reports: {}
    };
}

function resolveDomain({ url, domain }) {
    if (domain) {
        return normalizeDomain(domain);
    }

    return parseRequestUrl(url).domain;
}

function parseRequestUrl(url) {
    if (!url) {
        throw new Error('URL is required');
    }

    let parsedUrl;

    try {
        parsedUrl = new URL(url);
    } catch (error) {
        throw new Error('Invalid URL format');
    }

    return {
        url: parsedUrl.toString(),
        domain: normalizeDomain(parsedUrl.hostname)
    };
}

function normalizeDomain(domain) {
    return String(domain || '').trim().toLowerCase();
}

function normalizeClientId(clientId) {
    const normalized = String(clientId || '').trim();
    return normalized || '';
}

function cloneData(value) {
    return JSON.parse(JSON.stringify(value));
}

async function checkDomainReputation(domain) {
    try {
        const apiKey = process.env.VIRUSTOTAL_API_KEY;

        if (apiKey) {
            try {
                const response = await axios.get(
                    `https://www.virustotal.com/api/v3/domains/${domain}`,
                    {
                        headers: {
                            'x-apikey': apiKey
                        },
                        timeout: 5000
                    }
                );

                const stats = response.data.data.attributes.last_analysis_stats;
                const malicious = stats.malicious || 0;
                const suspicious = stats.suspicious || 0;
                const total = stats.malicious + stats.suspicious + stats.undetected + stats.harmless;

                const trustScore = Math.max(0, 100 - ((malicious * 10) + (suspicious * 5)));

                return {
                    source: 'VirusTotal',
                    trustScore,
                    blacklisted: malicious > 0,
                    maliciousVotes: malicious,
                    suspiciousVotes: suspicious,
                    totalVotes: total
                };
            } catch (error) {
                console.log('VirusTotal API error, using mock data:', error.message);
                return generateMockReputation(domain);
            }
        }

        return generateMockReputation(domain);
    } catch (error) {
        console.error('Error checking domain reputation:', error);
        return {
            source: 'local',
            trustScore: 50,
            blacklisted: false,
            error: error.message
        };
    }
}

function generateMockReputation(domain) {
    const knownSuspicious = ['paypa1', 'amaz0n', 'g00gle', 'phishing', 'scam'];
    const isSuspicious = knownSuspicious.some((word) => domain.toLowerCase().includes(word));

    if (isSuspicious) {
        return {
            source: 'mock',
            trustScore: 20,
            blacklisted: true,
            maliciousVotes: 45,
            suspiciousVotes: 10,
            totalVotes: 70
        };
    }

    const trustScore = Math.floor(Math.random() * 35) + 60;

    return {
        source: 'mock',
        trustScore,
        blacklisted: false,
        maliciousVotes: 0,
        suspiciousVotes: 0,
        totalVotes: Math.floor(Math.random() * 60) + 20
    };
}

function checkTyposquatting(domain) {
    const popularBrands = [
        {
            brand: 'PayPal',
            official: 'paypal.com',
            typos: ['paypa1', 'paypa-', 'paypa|', 'paypai', 'paypal-', 'paypal-secure']
        },
        {
            brand: 'Amazon',
            official: 'amazon.com',
            typos: ['amaz0n', 'amazom', 'amazon-', 'amazom.com', 'amz-on']
        },
        {
            brand: 'Google',
            official: 'google.com',
            typos: ['g00gle', 'gogle', 'goog1e', 'google-', 'goggle.com']
        },
        {
            brand: 'Apple',
            official: 'apple.com',
            typos: ['appl3', 'aple.com', 'appie', 'apple-', 'appple']
        },
        {
            brand: 'Microsoft',
            official: 'microsoft.com',
            typos: ['m1crosoft', 'microsoft-', 'msft-', 'microsoft.net', 'micr0soft']
        },
        {
            brand: 'Facebook',
            official: 'facebook.com',
            typos: ['faceb00k', 'facebook-', 'facebook.net', 'faceboo.com']
        }
    ];

    for (const brandData of popularBrands) {
        for (const typo of brandData.typos) {
            if (domain.toLowerCase().includes(typo)) {
                return {
                    detected: true,
                    suspectedBrand: brandData.brand,
                    officialDomain: brandData.official,
                    similarity: 'high',
                    riskLevel: 'critical',
                    message: `Domain may be impersonating ${brandData.brand}`
                };
            }
        }
    }

    const similarBrands = popularBrands.filter((brand) => {
        return levenshteinDistance(domain, brand.official) <= 2;
    });

    if (similarBrands.length > 0) {
        return {
            detected: true,
            suspectedBrand: similarBrands[0].brand,
            officialDomain: similarBrands[0].official,
            similarity: 'medium',
            riskLevel: 'high',
            message: `Domain is very similar to ${similarBrands[0].brand}`
        };
    }

    return {
        detected: false,
        similarity: 'none',
        message: 'No typosquatting detected'
    };
}

function levenshteinDistance(str1, str2) {
    const len1 = str1.length;
    const len2 = str2.length;
    const matrix = Array(len2 + 1).fill(null).map(() => Array(len1 + 1).fill(0));

    for (let index = 0; index <= len1; index += 1) {
        matrix[0][index] = index;
    }

    for (let index = 0; index <= len2; index += 1) {
        matrix[index][0] = index;
    }

    for (let row = 1; row <= len2; row += 1) {
        for (let column = 1; column <= len1; column += 1) {
            const indicator = str1[column - 1] === str2[row - 1] ? 0 : 1;
            matrix[row][column] = Math.min(
                matrix[row][column - 1] + 1,
                matrix[row - 1][column] + 1,
                matrix[row - 1][column - 1] + indicator
            );
        }
    }

    return matrix[len2][len1];
}

function analyzeGiveawayIndicators(url) {
    const giveawayPatterns = {
        prize: ['win prize', 'claim prize', 'prize waiting', 'prize claim'],
        money: ['free money', 'easy money', 'quick cash', 'earn money'],
        iphone: ['free iphone', 'iphone giveaway', 'win iphone', 'claim iphone'],
        limited_time: ['limited time', 'act fast', 'hurry', 'expires today', 'last chance'],
        congratulations: ['congratulations', 'you won', 'selected winner', 'you\'ve won'],
        gift_card: ['free gift card', 'amazon gift', 'gift card reward'],
        survey: ['free survey', 'survey reward', 'survey bonus']
    };

    const urlLower = url.toLowerCase();
    const foundIndicators = [];
    let riskContribution = 0;

    for (const keywords of Object.values(giveawayPatterns)) {
        for (const keyword of keywords) {
            if (urlLower.includes(keyword)) {
                foundIndicators.push(keyword);
                riskContribution += 3;
            }
        }
    }

    return {
        detected: foundIndicators.length > 0,
        indicators: foundIndicators,
        riskContribution: Math.min(riskContribution, 20),
        message: foundIndicators.length > 0
            ? `Found ${foundIndicators.length} giveaway indicators`
            : 'No giveaway patterns detected'
    };
}

async function checkSSLCertificate(domain) {
    try {
        const https = require('https');

        return new Promise((resolve) => {
            const request = https
                .get(`https://${domain}`, { timeout: 5000 }, (response) => {
                    const cert = response.socket.getPeerCertificate();
                    request.destroy();

                    resolve({
                        isSecure: true,
                        protocol: 'HTTPS',
                        certificateIssuer: cert.issuer?.O || 'Unknown',
                        certificateValid: Boolean(cert.valid_from && cert.valid_to)
                    });
                })
                .on('error', (error) => {
                    resolve({
                        isSecure: false,
                        protocol: 'HTTP',
                        error: error.message
                    });
                });

            request.setTimeout(5000);
        });
    } catch (error) {
        return {
            isSecure: false,
            protocol: 'HTTP',
            error: error.message
        };
    }
}

function generateReportId() {
    return `report_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
}

app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({
        success: false,
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

app.use((req, res) => {
    res.status(404).json({
        success: false,
        error: 'Endpoint not found'
    });
});

app.listen(PORT, async () => {
    try {
        const communityData = await loadCommunityData();
        console.log('\nScam Detector API Server running');
        console.log(`Port: ${PORT}`);
        console.log(`Tracked community domains: ${Object.keys(communityData.domains).length}`);
        console.log(`POST /scan - Scan a website`);
        console.log(`POST /scan/report - Report a scam`);
        console.log(`POST /community/block - Track block or unblock`);
        console.log(`GET /health - Health check\n`);
    } catch (error) {
        console.error('Server started, but community data could not be loaded:', error.message);
    }
});

module.exports = app;
