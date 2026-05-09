# PhishGuard — Real-Time Phishing Detection Extension

> **Privacy-first, client-side phishing detection for Chrome & Edge**
> Built with Manifest V3 · No backend required · < 5ms analysis

---

## 🚀 Quick Start

### Prerequisites
- Google Chrome (v88+) or Microsoft Edge (v88+)
- No build tools required — pure JavaScript (ES Modules)

### Installation

```bash
# 1. Clone or download the repository
cd "c:\Users\Akash Kumbar\Desktop\GIT hack\phishguard"

# 2. Open Chrome / Edge
# Navigate to: chrome://extensions
# (Edge: edge://extensions)

# 3. Enable "Developer Mode" (toggle top-right)

# 4. Click "Load unpacked"
# Select the 'phishguard' folder (this directory)

# 5. PhishGuard is now active! 🎉
```

---

## 📁 Project Structure

```
phishguard/
├── manifest.json                 ← MV3 manifest (minimal permissions)
├── assets/
│   └── icons/                    ← Extension icons (16/32/48/128px)
├── src/
│   ├── background/
│   │   └── service-worker.js     ← MV3 service worker (tab monitoring)
│   ├── analyzer/
│   │   ├── urlAnalyzer.js        ← Heuristic engine (18 rules)
│   │   ├── scorer.js             ← Score → category mapping
│   │   ├── brandList.js          ← Known brands for typosquatting detection
│   │   ├── suspiciousTlds.js     ← High-risk TLD list
│   │   ├── shortenerList.js      ← URL shortener detection
│   │   ├── localBlocklist.js     ← Bundled phishing blocklist
│   │   └── threatIntel.js        ← Google Safe Browsing + custom list
│   ├── popup/
│   │   ├── popup.html            ← Popup UI structure
│   │   ├── popup.js              ← Popup controller
│   │   └── popup.css             ← Premium dark UI styles
│   ├── options/
│   │   ├── options.html          ← Settings page
│   │   ├── options.js            ← Settings controller
│   │   └── options.css           ← Settings page styles
│   ├── content/
│   │   └── content.js            ← Minimal page signals (password field count)
│   └── shared/
│       ├── types.js              ← Shared constants, rule metadata
│       ├── utils.js              ← Levenshtein, entropy, domain helpers
│       └── cache.js              ← TTL cache (5 min, in-memory)
└── README.md
```

---

## 🎯 How It Works

### Analysis Pipeline

```
Tab loads / URL changes
        ↓
Service Worker triggered
        ↓
① Check cache (domain-keyed, 5min TTL)
        ↓ (cache miss)
② Run synchronous heuristics (~1-5ms)
        ↓
③ Update badge immediately (fast path)
        ↓
④ Run async threat intel checks
   (whitelist, custom blocklist, Google Safe Browsing)
        ↓
⑤ Merge results, update badge + popup
```

---

## 🔍 Heuristic Rules Engine

| # | Rule | Points | Reason |
|---|------|--------|--------|
| 1 | HTTP scheme | +15 | Unencrypted traffic; data can be intercepted |
| 2 | IP-based host | +25 | Legitimate sites use domain names |
| 3 | Punycode / IDN | +20 | International chars can impersonate Latin letters |
| 4 | @ in URL | +30 | Tricks browsers into ignoring real destination |
| 5 | Brand in subdomain | +20 | e.g., `paypal.evil.com` |
| 6 | Subdomain depth > 3 | +10 | Unusual for legitimate sites |
| 7 | Suspicious TLD | +15 | `.tk`, `.ml`, `.xyz` etc. frequently abused |
| 8 | Typosquatting | +30 | Levenshtein distance ≤2 from known brand |
| 9 | URL length > 150 | +10 | Long URLs hide real destinations |
| 10 | Excessive % encoding | +15 | > 3 encoded chars suggests obfuscation |
| 11 | High-entropy segment | +15 | Shannon entropy > 3.8 in path segment |
| 12 | Long query string > 200 | +10 | May hide redirect or payload |
| 13 | URL shortener | +20 | Real destination is hidden |
| 14 | Phishing keywords | +10 | ≥2 of: login, verify, secure, account... |
| 15 | Double slash in path | +10 | URL manipulation indicator |
| 16 | Non-standard port | +10 | Legitimate sites use 80/443 |
| 17 | Local blocklist hit | +100 | Known phishing domain |
| 18 | Google Safe Browsing | +100 | Confirmed malicious by Google |
| 19 | HTTPS (no other flags) | -5 | Minor positive signal |
| 20 | Password field (suspicious) | +8 | Password input on risky domain |
| 21 | User whitelisted | -200 | User explicitly trusts this domain |

### Score → Category Mapping

| Score | Category | Badge | Meaning |
|-------|----------|-------|---------|
| 0 – 19 | ✅ Safe | Green `OK` | No significant risk signals |
| 20 – 49 | ⚠️ Suspicious | Yellow `!` | Risk factors present; proceed with caution |
| 50+ | 🚨 Phishing | Red `PH` | Strong phishing indicators; do not enter credentials |

### Tuning False Positives

- **Too many false positives?** Use "Relaxed" sensitivity in Settings. This raises thresholds internally.
- **Whitelist trusted domains** via popup "Trust Domain" button or Options → Whitelist.
- **Typosquatting false positives**: The Levenshtein check only fires when distance ≤ 2 and domain length difference ≤ 3. This prevents flagging `google.com` for being similar to `google` alone.
- **Keyword false positives**: Keywords require ≥ 2 hits, not 1.

---

## 🛡️ Threat Intelligence

### Option 1: Google Safe Browsing API (Recommended)

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a project → Enable "Safe Browsing API"
3. Create an API key (restrict to Safe Browsing API)
4. Paste key in PhishGuard → Settings → Threat Intel

**Privacy note**: URLs are sent to Google's servers. Only enable if acceptable.

### Option 2: Local Blocklist (Default — Privacy Preserving)

- Bundled demo list in `src/analyzer/localBlocklist.js`
- Import custom blocklist: Settings → Blocklist → Import (`.txt` or `.json`)
- Format: one domain per line, or JSON array of strings

### Option 3: No API Key

The extension works **fully offline** using heuristics + local blocklist.

---

## 🔒 Privacy

| Data | Status |
|------|--------|
| Browsing history | ❌ Never collected or stored |
| URLs | ❌ Not sent anywhere (unless Safe Browsing enabled) |
| Form/input values | ❌ Never read (content script only counts fields) |
| Analysis results | ⏱️ Cached in memory only (5min, lost on browser close) |
| Settings | ✅ Stored locally via `chrome.storage.sync` |
| Custom blocklist | ✅ Stored locally via `chrome.storage.local` |

---

## ⚡ Performance

- **Heuristic analysis**: < 5ms (synchronous, no I/O)
- **Threat intel checks**: Async, badge updates in ~100-500ms
- **Cache hit**: < 1ms (Map lookup)
- **Memory**: < 2MB total extension footprint
- **No DOM scanning**: Content script only runs `querySelectorAll` once after idle

---

## 🧪 Test URLs

### Safe
```
https://www.google.com
https://github.com
https://stackoverflow.com
```

### Suspicious
```
http://bit.ly/someshortlink
https://paypal-customer-service.com
http://192.168.1.1/admin
```

### Phishing (Simulated — do NOT visit)
```
https://paypa1.com/login
https://secure-paypal-account-verify.xyz
https://appleid.apple.com.account-locked.xyz
http://chase-bank-secure.tk/verify
```

### Test Typosquatting
```
https://gooogle.com     (typo of google)
https://amazzon.com     (typo of amazon)
https://paypa1.com      (1 instead of l)
```

---

## 🏗️ MV3 Permissions Justification

| Permission | Why Needed |
|-----------|------------|
| `tabs` | Monitor tab URL changes and get active tab |
| `activeTab` | Access current tab info when popup opens |
| `storage` | Save settings + whitelist |
| `scripting` | Inject content script for page signals |
| `webNavigation` | Detect SPA navigation (history state changes) |
| `alarms` | Periodic cache cleanup every 10 minutes |
| `https://safebrowsing.googleapis.com/*` | Optional Safe Browsing API calls |

---

## 🤝 Contributing

This is a hackathon project. Contributions welcome:

1. Add more brands to `brandList.js`
2. Update `suspiciousTlds.js` from Spamhaus data
3. Add unit tests for `urlAnalyzer.js`
4. Implement hash-based Safe Browsing (v4 Update API) for better privacy

---

## 📄 License

MIT License — Build freely, stay safe.

---

*PhishGuard — Because your credentials are worth protecting.*
