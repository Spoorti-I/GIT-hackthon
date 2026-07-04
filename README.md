# PhishGuard

**Every day, someone loses their savings, their identity, or their peace of mind to a link that looked just real enough to trust.**

PhishGuard was our answer to that problem — built in the pressure and adrenaline of a national-level hackathon, running on caffeine, whiteboards full of scratched-out ideas, and the belief that security tools shouldn't be locked behind an enterprise price tag.

Built at **HTF3**, a national-level hackathon hosted by **KLS Gogte Institute of Technology, Belagavi**, and **sponsored by TCS**, PhishGuard went on to place in the **Top 10** out of hundreds of teams.

---

## The problem we set out to solve

Phishing doesn't announce itself. It hides in a misspelled domain, a cloned login page, a text message that looks like it's from your bank. Most protection against it either costs money, needs a data connection, or reacts only after thousands of people have already been fooled.

We wanted something different: detection that happens **instantly, locally, and for free** — whether you're clicking a link in your browser or opening a text on your phone.

---

## What we built

Two systems, one mission.

### 🧩 [`/phishguard`](./phishguard) — Browser Extension
A Manifest V3 Chrome/Edge extension that silently analyzes every site you visit against 18+ heuristic signals — typosquatting, homograph attacks, suspicious TLDs, disguised shorteners, entropy anomalies — and flags danger in under 5 milliseconds. No servers required. No browsing history stored.

- Pure JavaScript, zero build step
- Backed by a real, passing test suite (`npm test`)
- **[Full technical documentation →](./phishguard/README.md)**

### 📱 [`/phishguard-mobile`](./phishguard-mobile) — Android App
Because phishing doesn't stop at your browser. This Kotlin Android app watches SMS messages, notifications, and clipboard activity, catching malicious links the moment they arrive — before you even think to open them.

- Local-first architecture with a Room database for scan history
- Real-time SMS and notification listener services
- Its own dedicated test coverage (`SmsThreatScannerTest.kt`)

---

## Why it matters

This wasn't built for a grade or a demo reel. It was built because the people who most need protection from phishing — students, first-time smartphone users, people who've never heard the word "typosquatting" — are usually the ones
