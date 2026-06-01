// Scam Detector API - Test Script
// Simple test suite for the API endpoints

const http = require('http');

const API_BASE = 'http://localhost:3000';

// Test URLs
const testUrls = [
    'https://paypa1.com/claim-prize',
    'https://amazon.com',
    'https://g00gle.com/free-iphone',
    'https://legitsite.com'
];

// Color output
const colors = {
    reset: '\x1b[0m',
    green: '\x1b[32m',
    red: '\x1b[31m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m'
};

async function makeRequest(method, path, data = null) {
    return new Promise((resolve, reject) => {
        const url = new URL(API_BASE + path);
        const options = {
            hostname: url.hostname,
            port: url.port,
            path: url.pathname,
            method: method,
            headers: {
                'Content-Type': 'application/json'
            }
        };

        const req = http.request(options, (res) => {
            let body = '';
            res.on('data', chunk => body += chunk);
            res.on('end', () => {
                try {
                    resolve({
                        status: res.statusCode,
                        data: JSON.parse(body)
                    });
                } catch (e) {
                    resolve({
                        status: res.statusCode,
                        data: body
                    });
                }
            });
        });

        req.on('error', reject);
        
        if (data) {
            req.write(JSON.stringify(data));
        }
        
        req.end();
    });
}

async function runTests() {
    console.log(`\n${colors.blue}🧪 Scam Detector API Test Suite${colors.reset}\n`);

    try {
        // Test 1: Health Check
        console.log(`${colors.yellow}Test 1: Health Check${colors.reset}`);
        const health = await makeRequest('GET', '/health');
        if (health.status === 200) {
            console.log(`${colors.green}✓ PASS${colors.reset} - API is running\n`);
        } else {
            throw new Error('Health check failed');
        }

        // Test 2: Scan legitimate website
        console.log(`${colors.yellow}Test 2: Scan Legitimate Website${colors.reset}`);
        const scanLegit = await makeRequest('POST', '/scan', {
            url: 'https://amazon.com',
            timestamp: new Date().toISOString(),
            userAgent: 'Scam Detector Test/1.0'
        });
        if (scanLegit.status === 200 && scanLegit.data.success) {
            console.log(`${colors.green}✓ PASS${colors.reset}`);
            console.log(`  Risk Score: ${scanLegit.data.analysis.riskScore}`);
            console.log(`  Threats: ${scanLegit.data.analysis.threats.length}\n`);
        } else {
            throw new Error('Legitimate scan failed');
        }

        // Test 3: Scan typosquatting domain
        console.log(`${colors.yellow}Test 3: Scan Typosquatting Domain${colors.reset}`);
        const scanTypo = await makeRequest('POST', '/scan', {
            url: 'https://paypa1.com',
            timestamp: new Date().toISOString(),
            userAgent: 'Scam Detector Test/1.0'
        });
        if (scanTypo.status === 200 && scanTypo.data.success) {
            console.log(`${colors.green}✓ PASS${colors.reset}`);
            console.log(`  Risk Score: ${scanTypo.data.analysis.riskScore}`);
            console.log(`  Detected: ${scanTypo.data.analysis.details.typosquatting.detected}\n`);
        } else {
            throw new Error('Typo scan failed');
        }

        // Test 4: Scan giveaway scam
        console.log(`${colors.yellow}Test 4: Scan Giveaway Scam Pattern${colors.reset}`);
        const scanGiveaway = await makeRequest('POST', '/scan', {
            url: 'https://example.com/free-iphone-prize-claim',
            timestamp: new Date().toISOString(),
            userAgent: 'Scam Detector Test/1.0'
        });
        if (scanGiveaway.status === 200 && scanGiveaway.data.success) {
            console.log(`${colors.green}✓ PASS${colors.reset}`);
            console.log(`  Risk Score: ${scanGiveaway.data.analysis.riskScore}`);
            console.log(`  Giveaway Detected: ${scanGiveaway.data.analysis.details.giveaway.detected}\n`);
        } else {
            throw new Error('Giveaway scan failed');
        }

        // Test 5: Report scam
        console.log(`${colors.yellow}Test 5: Report Scam${colors.reset}`);
        const report = await makeRequest('POST', '/scan/report', {
            url: 'https://malicious-site.com',
            timestamp: new Date().toISOString(),
            userAgent: 'Scam Detector Test/1.0'
        });
        if (report.status === 200 && report.data.success) {
            console.log(`${colors.green}✓ PASS${colors.reset}`);
            console.log(`  Report ID: ${report.data.reportId}\n`);
        } else {
            throw new Error('Report failed');
        }

        // Test 6: Invalid URL
        console.log(`${colors.yellow}Test 6: Invalid URL Handling${colors.reset}`);
        const invalid = await makeRequest('POST', '/scan', {
            url: 'not-a-valid-url',
            timestamp: new Date().toISOString()
        });
        if (invalid.status === 400) {
            console.log(`${colors.green}✓ PASS${colors.reset} - Properly rejected invalid URL\n`);
        } else {
            throw new Error('Invalid URL not rejected');
        }

        // Test 7: Caching
        console.log(`${colors.yellow}Test 7: Result Caching${colors.reset}`);
        const firstScan = await makeRequest('POST', '/scan', {
            url: 'https://test-cache.com',
            timestamp: new Date().toISOString()
        });
        const secondScan = await makeRequest('POST', '/scan', {
            url: 'https://test-cache.com',
            timestamp: new Date().toISOString()
        });
        if (secondScan.data.cached === true) {
            console.log(`${colors.green}✓ PASS${colors.reset} - Results cached successfully\n`);
        } else {
            throw new Error('Caching not working');
        }

        console.log(`${colors.green}✅ All tests passed!${colors.reset}\n`);

    } catch (error) {
        console.error(`\n${colors.red}❌ Test failed: ${error.message}${colors.reset}\n`);
        process.exit(1);
    }
}

// Run tests
runTests().catch(error => {
    console.error(`${colors.red}Error running tests: ${error.message}${colors.reset}`);
    console.error('\n⚠️  Make sure the API server is running:');
    console.error('   npm run dev');
    process.exit(1);
});
