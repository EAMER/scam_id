# 🛡️ Scam Detector - Quick Start

A complete Chrome extension + backend API system for detecting scams, phishing, and malicious websites in real-time.

## 📋 What's Included

- **Chrome Extension** - Analyzes websites and shows risk assessment
- **Express.js Backend API** - Performs domain reputation checks, typosquatting detection, giveaway analysis
- **Content Script** - Extracts page data and detects scam patterns
- **Floating Badge** - Warning indicator when high-risk content detected

## 🚀 Quick Start (5 minutes)

### 1. Start Backend (if on Windows)
```bash
# Double-click start-backend.bat
# Or manually:
cd backend
npm install
npm run dev
```

Backend runs on `http://localhost:3000`

### 2. Load Extension in Chrome
1. Open `chrome://extensions/`
2. Enable "Developer mode" (top right)
3. Click "Load unpacked"
4. Select the `scam-detector` folder
5. Done! Extension is now active

### 3. Test It Out
1. Visit any website
2. Click the extension icon (shield) in top right
3. Click "🔍 Scan Website"
4. See the risk assessment!

## 📊 Features

### Risk Assessment
- **Green (0-25)**: Safe ✓
- **Yellow (25-60)**: Caution ⚠️
- **Red (60+)**: Dangerous 🚨

### Analysis Includes
- ✅ Domain reputation (VirusTotal integration)
- ✅ Typosquatting detection (paypa1.com vs paypal.com)
- ✅ Giveaway scam patterns ("Free iPhone", "Claim Prize")
- ✅ SSL/HTTPS verification
- ✅ Floating warning badge
- ✅ 24-hour result caching

## 📁 Project Structure

```
Scam_detector/
├── backend/              # Express.js API
│   ├── server.js        # Main server (domain analysis)
│   ├── package.json     # Dependencies
│   └── .env             # Configuration
│
└── scam-detector/       # Chrome Extension
    ├── manifest.json    # Extension config
    ├── popup.html       # UI popup
    ├── popup.js         # UI logic
    ├── background.js    # API communication
    ├── content.js       # Page analyzer
    └── icons/           # Extension icons
```

## 🔧 Configuration

### Change API Endpoint

Edit `scam-detector/background.js`:
```javascript
// Line 6 - Change to your backend
const API_ENDPOINT = 'http://localhost:3000/scan';
```

### Add VirusTotal API

Get free API key at: https://www.virustotal.com/

Edit `backend/.env`:
```
VIRUSTOTAL_API_KEY=your_key_here
```

## 🧪 Testing

### Test Backend
```bash
cd backend
node test.js
```

### Test URLs
```
Safe:        https://google.com
Typosquat:   https://paypa1.com
Scam:        https://example.com/free-iphone-prize
```

### Use Thunder Client (VS Code)
1. Install Thunder Client extension
2. Import `backend/thunder-collection.json`
3. Run requests from collection

## 📚 Documentation

- **[SETUP_GUIDE.md](SETUP_GUIDE.md)** - Complete setup guide
- **[backend/README.md](backend/README.md)** - API documentation
- **[backend/.env.example](backend/.env.example)** - Environment config

## 🌐 API Reference

### POST `/scan`
Scan a website for threats

**Request:**
```json
{
  "url": "https://example.com",
  "timestamp": "2026-05-25T10:30:00Z",
  "userAgent": "Mozilla/5.0..."
}
```

**Response:**
```json
{
  "success": true,
  "analysis": {
    "riskScore": 42,
    "threats": [
      {
        "type": "Typosquatting",
        "severity": "high",
        "description": "Domain resembles legitimate brand"
      }
    ],
    "details": {
      "reputation": {...},
      "typosquatting": {...},
      "giveaway": {...}
    }
  }
}
```

### POST `/scan/report`
Report a malicious website

**Request:**
```json
{
  "url": "https://scam-site.com",
  "timestamp": "2026-05-25T10:30:00Z"
}
```

### GET `/health`
Server health check

## 🚀 Deployment

### Deploy Backend
- **Heroku**: `git push heroku main`
- **Render**: Connect GitHub repo
- **Docker**: `docker run -p 3000:3000 scam-detector`

### Publish Extension
- **Chrome Web Store**: Upload .zip via Developer Dashboard
- **Firefox Add-ons**: Upload via Mozilla Add-ons

## 📖 How It Works

1. **User visits website** → Content script analyzes page
2. **Clicks extension icon** → Popup requests analysis from background.js
3. **Background.js calls API** → Backend analyzes domain
4. **Results returned** → Popup displays risk score and threats
5. **Checks cache** → Future scans of same domain are instant

## 🔒 Security

- ✅ Input validation on all URLs
- ✅ Request timeout protection (5-10 seconds)
- ✅ CORS configured for extension
- ✅ No personal data stored
- ✅ Environment secrets in .env
- ✅ Rate limiting ready

## 🐛 Troubleshooting

### Extension not connecting to backend
- Check backend is running: `npm run dev`
- Verify endpoint in `background.js`
- Check browser console (F12) for errors

### Backend not starting
- Install Node.js from nodejs.org
- Run `npm install` in backend folder
- Check port 3000 is available

### Slow responses
- First scan slower (no cache)
- Enable VirusTotal API for real data
- Check internet connection

## 📝 License

MIT - Feel free to use and modify!

## 💡 Next Steps

- [ ] Add database for storing reports
- [ ] Create user dashboard
- [ ] Real-time threat updates
- [ ] Browser extensions for Firefox/Edge
- [ ] Mobile app version
- [ ] Community threat feed

## 🤝 Contributing

Found a bug or have a feature idea? Create an issue or submit a PR!

## 📞 Support

Need help? Check [SETUP_GUIDE.md](SETUP_GUIDE.md) or review the backend/API documentation.

---

**Made with ❤️ for a safer internet**

**Built:** May 25, 2026  
**Status:** ✅ Production Ready
