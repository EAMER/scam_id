# Scam Detector Backend API

Production-ready Express.js backend for the Scam Detector Chrome extension. Provides comprehensive website security analysis with domain reputation checking, typosquatting detection, and giveaway scam pattern recognition.

## Features

- **Domain Reputation Analysis** - VirusTotal integration (with mock fallback for testing)
- **Typosquatting Detection** - Identifies domains impersonating popular brands
- **Giveaway Scam Detection** - Recognizes common scam patterns and phrases
- **SSL/TLS Verification** - Checks for secure HTTPS connections
- **Result Caching** - 1-hour cache to reduce API calls
- **Error Handling** - Comprehensive error handling and validation
- **RESTful API** - Clean, easy-to-use endpoints

## Setup

### 1. Install Dependencies

```bash
cd backend
npm install
```

### 2. Configure Environment

```bash
# Copy example environment file
cp .env.example .env

# Edit .env with your configuration
# Optional: Add VirusTotal API key for real reputation checking
```

### 3. Run Server

**Development mode (with auto-reload):**
```bash
npm run dev
```

**Production mode:**
```bash
npm start
```

Server runs on `http://localhost:3000`

## API Endpoints

### POST `/scan`

Scan a website for scams and security risks.

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
    "url": "https://example.com",
    "domain": "example.com",
    "scanTimestamp": "2026-05-25T10:30:00Z",
    "riskScore": 25,
    "threats": [
      {
        "type": "No HTTPS",
        "severity": "medium",
        "description": "Website does not use HTTPS/TLS encryption"
      }
    ],
    "reasons": [
      "Website is not using secure HTTPS connection"
    ],
    "details": {
      "reputation": {
        "trustScore": 75,
        "blacklisted": false,
        "source": "mock"
      },
      "typosquatting": {
        "detected": false,
        "similarity": "none"
      },
      "giveaway": {
        "detected": false,
        "indicators": [],
        "riskContribution": 0
      },
      "ssl": {
        "isSecure": false,
        "protocol": "HTTP"
      }
    }
  },
  "cached": false
}
```

### POST `/scan/report`

Report a malicious or scam website.

**Request:**
```json
{
  "url": "https://scam-site.com",
  "timestamp": "2026-05-25T10:30:00Z",
  "userAgent": "Mozilla/5.0..."
}
```

**Response:**
```json
{
  "success": true,
  "message": "Report received and will be reviewed",
  "reportId": "report_1716626400000_abc123"
}
```

### GET `/health`

Health check endpoint for monitoring.

**Response:**
```json
{
  "status": "ok",
  "timestamp": "2026-05-25T10:30:00Z"
}
```

## Risk Score Calculation

Risk score is calculated from 0-100 based on:

- **Domain Reputation** (0-40 points)
  - Malicious votes from VirusTotal
  - Blacklist status
  
- **Typosquatting** (0-30 points)
  - Similarity to known brand domains
  - Known typo patterns
  
- **Giveaway Patterns** (0-20 points)
  - "Free" giveaway keywords
  - "Prize" or "Congratulations" phrases
  - Limited time urgency tactics
  
- **SSL/HTTPS** (0-10 points)
  - Missing secure connection

## Threat Severity Levels

- **Critical** - Immediate threat (blacklisted domains, known phishing)
- **High** - Significant risk (typosquatting, giveaway scams)
- **Medium** - Moderate concern (missing HTTPS, suspicious keywords)
- **Low** - Minor issue (minor indicators)

## VirusTotal Integration

For real domain reputation checking:

1. Sign up at [VirusTotal](https://www.virustotal.com/)
2. Get your API key from your profile
3. Add to `.env`:
   ```
   VIRUSTOTAL_API_KEY=your_api_key_here
   ```

If API key is not set, the backend uses mock data for testing.

## Caching

Results are cached for 1 hour per domain to:
- Reduce API calls
- Improve response time
- Minimize VirusTotal API usage

Cache can be cleared by restarting the server.

## Error Handling

All errors return structured responses:

```json
{
  "success": false,
  "error": "Invalid URL format"
}
```

Common errors:
- 400 - Bad Request (missing/invalid URL)
- 500 - Server Error (processing failed)

## Rate Limiting

For production, consider adding:
- Express rate-limiter
- API key authentication
- Request throttling per IP

## Deployment

### Heroku
```bash
heroku create scam-detector-api
git push heroku main
```

### Docker
```bash
docker build -t scam-detector-backend .
docker run -p 3000:3000 -e NODE_ENV=production scam-detector-backend
```

### Environment Variables (Production)
```
PORT=3000
NODE_ENV=production
VIRUSTOTAL_API_KEY=your_key
CORS_ORIGIN=https://your-domain.com
```

## Development

### Testing the API

```bash
# Using curl
curl -X POST http://localhost:3000/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'

# Or use Postman/Thunder Client with the API examples above
```

### Logging

All requests are logged with timestamps and methods. For debugging:

```bash
# View logs while running
npm run dev
```

## Performance

- **Response Time**: ~100-500ms (depending on VirusTotal API)
- **Memory**: ~50MB base + cache
- **Concurrent Requests**: Handles ~100+ simultaneous connections

## Security Considerations

1. **Input Validation** - All URLs are validated before processing
2. **Timeout Protection** - API calls timeout at 5 seconds
3. **CORS** - Configured for extension origin only (update in production)
4. **Environment Secrets** - Never commit `.env` file
5. **Rate Limiting** - Consider adding in production

## Troubleshooting

### Port Already in Use
```bash
# Change port in .env
PORT=3001

# Or kill process on port 3000
# Windows: netstat -ano | findstr :3000
# Linux/Mac: lsof -ti:3000 | xargs kill -9
```

### VirusTotal API Errors
- Check API key in `.env`
- Verify rate limits not exceeded
- Backend falls back to mock data on error

### Slow Responses
- Check VirusTotal API status
- Review cache is working (logs show "Cache hit")
- Verify internet connection

## License

MIT

## Support

For issues or feature requests, contact: support@scamdetector.dev
