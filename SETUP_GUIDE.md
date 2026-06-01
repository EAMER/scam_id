# Scam Detector - Complete Setup Guide

This guide walks you through setting up the entire Scam Detector system: Chrome extension + backend API.

## Project Structure

```
Scam_detector/
├── scam-detector/                 # Chrome Extension
│   ├── manifest.json             # Extension configuration
│   ├── popup.html               # UI popup
│   ├── popup.js                 # Popup logic
│   ├── background.js            # Service worker
│   ├── content.js               # Page content analyzer
│   ├── styles.css               # Styling
│   └── icons/                   # Extension icons
│
└── backend/                      # Express.js API Server
    ├── server.js                # Main server
    ├── package.json             # Dependencies
    ├── .env.example             # Environment template
    ├── test.js                  # Test suite
    ├── README.md                # API documentation
    └── thunder-collection.json  # API test collection
```

## 1. Backend Setup

### Install and Run

```bash
# Navigate to backend directory
cd backend

# Install dependencies
npm install

# Copy environment file
cp .env.example .env

# Start development server
npm run dev
```

The API will be running at `http://localhost:3000`

### Test the Backend

```bash
# Run automated tests
node test.js

# Or use curl
curl -X POST http://localhost:3000/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

### Using Thunder Client (VS Code)

1. Install Thunder Client extension
2. Open Thunder Client in VS Code
3. Import `backend/thunder-collection.json`
4. Run any request from the collection

## 2. Chrome Extension Setup

### Load Extension in Chrome

1. Open Chrome and go to `chrome://extensions/`
2. Enable "Developer mode" (toggle in top right)
3. Click "Load unpacked"
4. Select the `scam-detector` folder
5. The extension is now active!

### Configure API Endpoint

By default, the extension looks for the backend at `https://your-api.com/scan`

To use your local backend:

1. Open `scam-detector/background.js`
2. Find line with `const API_ENDPOINT = 'https://your-api.com/scan'`
3. Change to `const API_ENDPOINT = 'http://localhost:3000/scan'`
4. Save and the extension will reload

## 3. Using the Extension

### Basic Usage

1. Click the Scam Detector icon (shield) in your Chrome toolbar
2. The popup shows the current website URL
3. Click "🔍 Scan Website" to analyze
4. Results show:
   - Risk score (0-100) with color coding
   - Threat list with severity levels
   - Specific reasons for the score

### Warning Badge

When visiting a suspicious website:
- A floating badge appears in the top-right corner
- Shows risk level (High/Medium/Low)
- Click to see detailed analysis
- Shows recommendations for the user

### Report Scam

If you find a scam website:
1. Click the Scam Detector icon
2. Click the red "🚩 Report" button
3. Report is sent to backend and stored

## 4. Understanding Results

### Risk Score Breakdown

- **0-25**: Safe (Green) ✓
  - Legitimate websites
  - Proper HTTPS
  - Good reputation
  
- **25-60**: Caution (Yellow) ⚠️
  - Some suspicious indicators
  - Might be new domain
  - Investigate before entering data
  
- **60+**: Dangerous (Red) 🚨
  - Multiple red flags
  - Known phishing/malware
  - Leave immediately

### Threat Categories

**Blacklisted Domain** - Domain known for malicious activity
**Typosquatting** - Mimics popular brand (paypa1.com vs paypal.com)
**Giveaway Scam Patterns** - "Free iPhone", "Claim Prize", etc.
**No HTTPS** - Unencrypted connection
**Unknown Reputation** - Domain not verified

## 5. Development

### Modifying the Extension

1. Edit files in `scam-detector/` folder
2. Changes auto-reload in Chrome (usually)
3. If not reloading, go to `chrome://extensions/` and click reload button

### Key Files to Edit

- `popup.html` - UI layout
- `popup.js` - Popup interaction logic
- `background.js` - API communication, analysis logic
- `content.js` - Page content analysis
- `styles.css` - Visual styling

### Modifying the Backend

1. Edit `backend/server.js`
2. Changes require restart: `npm run dev`
3. Re-test with `node test.js` or Thunder Client

## 6. Deployment

### Deploy Backend to Production

#### Using Heroku (Free)

```bash
# Install Heroku CLI
# Login: heroku login
# Create app: heroku create scam-detector-api
# Deploy: git push heroku main
```

#### Using Render.com

```bash
# Push to GitHub
# Connect Render to your repo
# Deploy on commit
```

#### Using Docker

```bash
# Build: docker build -t scam-detector .
# Run: docker run -p 3000:3000 scam-detector
```

### Update Extension for Production

1. After deploying backend, get your URL (e.g., `https://scam-detector-api.herokuapp.com`)
2. Update `background.js`:
   ```javascript
   const API_ENDPOINT = 'https://scam-detector-api.herokuapp.com/scan';
   ```
3. Test thoroughly

### Deploy Extension to Chrome Web Store

1. Package extension as `.zip`
2. Go to [Chrome Developer Dashboard](https://chrome.google.com/webstore/devcenter)
3. Upload and publish

## 7. Advanced Configuration

### Enable VirusTotal Integration

1. Sign up at [VirusTotal](https://www.virustotal.com/)
2. Get API key from your profile
3. In `backend/.env`:
   ```
   VIRUSTOTAL_API_KEY=your_key_here
   ```
4. Restart backend

### Add Rate Limiting

In `backend/server.js`, add:
```javascript
const rateLimit = require('express-rate-limit');

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});

app.use('/scan', limiter);
```

### Enable HTTPS for Local Testing

Use mkcert to create local SSL certificate:
```bash
# Install mkcert
# Create cert: mkcert localhost
# Use in server
```

## 8. Troubleshooting

### Extension Not Working

- [ ] Check backend is running (`npm run dev`)
- [ ] Verify API endpoint in `background.js`
- [ ] Open Chrome DevTools (F12) and check Console tab for errors
- [ ] Reload extension in `chrome://extensions/`

### Backend Returning Errors

- [ ] Check server is running on port 3000
- [ ] Run `node test.js` to diagnose
- [ ] Check `.env` file exists
- [ ] View logs in terminal

### Extension Not Showing Badge

- [ ] Check `content.js` loaded on page
- [ ] Open browser Console (F12) to check for errors
- [ ] Verify page is not an extension/special page (gmail, chrome://, etc.)

### API Response is Slow

- [ ] First request slower (no cache)
- [ ] Subsequent requests faster (cached)
- [ ] If VirusTotal enabled, check API rate limits
- [ ] Check internet connection

## 9. Testing Scenarios

### Test URLs

```
Safe:
- https://google.com
- https://github.com
- https://amazon.com

Typosquatting:
- https://paypa1.com
- https://g00gle.com
- https://amaz0n.com

Giveaway Scams:
- https://example.com/free-iphone-prize
- https://test.com/claim-reward-now
- https://site.com/limited-time-offer

No HTTPS:
- http://example.com
```

## 10. Next Steps

1. **Customize branding** - Update logo, colors, messages
2. **Add database** - Store reports in MongoDB/PostgreSQL
3. **Real-time updates** - Push threat updates to extension
4. **User accounts** - Track scams reported by users
5. **Statistics dashboard** - Show detection trends
6. **Browser support** - Port to Firefox/Edge

## Support

For issues:
- Check error messages in Console (F12)
- Review API logs in terminal
- Test with provided URLs
- Check environment configuration

---

**Happy scam detecting! 🛡️**
