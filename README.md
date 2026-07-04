# PhishGuard

**Real-time phishing detection, on your browser and in your pocket.**

Built at **HTF3** (KLS Gogte Institute of Technology, Belagavi) — a national-level hackathon — where this project placed in the **Top 10**.

PhishGuard is a two-part security system: a browser extension that flags dangerous websites as you browse, and an Android app that extends the same protection to SMS, notifications, and clipboard content on your phone.

---

## Why this exists

Most phishing protection either lives in a paid enterprise product or only checks a database of known-bad sites after the damage is already spreading. PhishGuard runs its own detection logic locally, in real time, for free — and works fully offline if you don't want any data leaving your device.

---

## What's in this repo

### 🧩 [`/phishguard`](./phishguard) — Browser Extension
A Manifest V3 Chrome/Edge extension that scores every site you visit against 18+ heuristic rules (typosquatting, homograph attacks, suspicious TLDs, URL shorteners, entropy analysis, and more) in under 5ms, with optional Google Safe Browsing integration.

- Pure JavaScript, no build step required
- Fully tested — `npm test` runs the analyzer test suite
- **[Full documentation →](./phishguard/README.md)**

### 📱 [`/phishguard-mobile`](./phishguard-mobile) — Android App
A Kotlin Android app that brings the same threat-detection logic to SMS messages, notifications, and clipboard content — catching phishing links before you even open a browser.

- Built with Room database for local scan history
- SMS and notification listener services for real-time monitoring
- Includes its own unit tests (`SmsThreatScannerTest.kt`)

---

## Team

Built collaboratively as part of a national hackathon team effort.

---

## License

MIT License — Build freely, stay safe.
