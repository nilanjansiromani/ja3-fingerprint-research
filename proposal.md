# Separating Bots from Browsers: A TLS Fingerprinting Proposal

> **Author:** Nilanjan Siromani
> **Date:** 2026-07-06
> **Status:** Draft

---

## The Problem

Every HTTP request that hits our servers carries a `User-Agent` header — a string that says "I'm Chrome 149 on Windows" or "I'm Safari 18 on macOS." The problem is, **anyone can lie about this.** A Python script, a curl command, or a Go scraper can trivially set its User-Agent to look exactly like Chrome:

```bash
curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/149.0.0.0 Safari/537.36" \
     https://our-site.com/api/login
```

To our application, this looks identical to a real Chrome browser. We can't tell the difference. And that's what attackers exploit.

Today, we see significant automated traffic hitting our sensitive endpoints — login pages, APIs, checkout flows — that **claims to be a browser but isn't.** This traffic includes:

- **Credential-stuffing bots** trying thousands of username/password combinations
- **Scraping bots** harvesting content and pricing data
- **Inventory-hoarding bots** holding items in checkout to deny them to real customers

Our current defenses — rate limiting, IP blocking, User-Agent filtering — are not enough. Rate limits catch volume but miss slow-and-steady attacks. IP blocking is a whack-a-mole game against rotating proxies. User-Agent filtering is trivially bypassed, as shown above.

We need a signal that **cannot be faked by simply changing a header.**

---

## The Insight: Every Client Has a TLS "Accent"

When a browser connects to our site over HTTPS, the very first thing it does — before sending any HTTP request — is perform a **TLS handshake.** During this handshake, the client sends a message called the **ClientHello**, which contains:

- Which encryption algorithms it supports (cipher suites)
- Which TLS extensions it uses
- Which protocol versions it prefers
- Which signature algorithms it trusts

Here's the key insight: **every TLS library constructs this ClientHello differently.** Chrome uses Google's BoringSSL library. Firefox uses Mozilla's NSS. Safari uses Apple's SecureTransport. Python's `requests` library uses OpenSSL. Go's `net/http` uses its own crypto/tls. And curl uses whatever TLS library it was compiled with.

Each of these produces a **distinct fingerprint** — like an accent that reveals where you're really from, even if you're speaking the same language.

This is what **JA4 fingerprinting** captures. It's a standardized way to hash the ClientHello into a short, readable string that uniquely identifies the TLS library (and therefore the client) making the request.

---

## How It Actually Works

A JA4 fingerprint looks like this:

```
t13d1516h2_8daaf6152771_d8a2da3f94cd
```

Reading left to right:

| Part | Value | Meaning |
|------|-------|---------|
| `t` | Transport | TCP (would be `q` for QUIC/HTTP3) |
| `13` | TLS version | TLS 1.3 |
| `d` | SNI | Domain name present in the handshake |
| `15` | Cipher count | Client offered 15 cipher suites |
| `16` | Extension count | Client sent 16 TLS extensions |
| `h2` | ALPN | Client requested HTTP/2 |
| `8daaf6152771` | Cipher hash | SHA-256 of the sorted cipher list |
| `d8a2da3f94cd` | Extension hash | SHA-256 of the sorted extensions + signature algorithms |

The beauty of JA4 is that it's **stable and predictable.** Chrome 149 on Windows, macOS, and Linux all produce the same JA4 fingerprint. Firefox produces a different one. Safari produces yet another. And crucially, **curl, Python, and Go each produce their own distinct fingerprints** that look nothing like any browser.

---

## What This Looks Like in Practice

Here's the core of why this works — real browsers and common bot tools produce completely different JA4 fingerprints:

### Real Browsers (Allow)

| Client | JA4 Fingerprint | Why It Looks Like This |
|--------|-----------------|----------------------|
| Chrome 148/149 | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | 15 ciphers, 16 extensions, HTTP/2 — BoringSSL stack |
| Firefox 148 | `t13d1717h2_5b57614c22b0_3cbfd9057e0d` | 17 ciphers, 17 extensions — NSS stack, different cipher set |
| Safari 18 | `t13d2013h2_a09f3c656075_7f0f34a4126d` | 20 ciphers, 13 extensions — Apple's stack, fewest extensions |

### Automated Tools (Block or Challenge)

| Client | JA4 Fingerprint | What Gives It Away |
|--------|-----------------|-------------------|
| **curl** (default) | `t13d3112h2_e8f1e7e78f70_375ca2c5e164` | **31 ciphers** — way more than any browser offers |
| **Python requests** | `t13d1712h1_ab0a1bf427ad_882d495ac381` | ALPN is **h1** (HTTP/1.1) — no real browser defaults to h1 |
| **Python httpx** | `t13d1712h1_ab0a1bf427ad_8e6e362c5eac` | Also h1 — same giveaway |
| **Go net/http** | `t13d1411h2_cbb2034c60b8_e7c285222651` | Only **14 ciphers, 11 extensions** — too few for a browser |
| **OpenSSL s_client** | `t13d410_16476d049b0b_78f1d400d464` | Only **4 ciphers, no ALPN at all** — dead giveaway |

Notice the patterns:

> [!IMPORTANT]
> **A request claiming to be Chrome but carrying the JA4 fingerprint of Python requests is definitively a bot.** The User-Agent header says Chrome, but the TLS handshake says Python. The handshake doesn't lie — it happens before the HTTP layer, and changing it requires replacing the entire TLS library.

### Quick Detection Rules

These simple rules catch the vast majority of default-library bot traffic:

- **ALPN = `h1`** → Almost certainly a bot. Real browsers negotiate HTTP/2 or HTTP/3.
- **Cipher count > 25** → Likely curl (offers 31 ciphers by default).
- **Cipher count < 10** → Likely a minimal TLS stack (OpenSSL s_client, custom tools).
- **Extension count < 10** → Too few for any modern browser (Chrome has 16, Firefox has 17, Safari has 13).
- **No ALPN at all** → Definitely not a browser.

---

## What About Sophisticated Bots?

We should be honest about the limitations. Some bot operators use **impersonation libraries** — tools specifically designed to mimic browser TLS fingerprints:

| Tool | What It Does | Can We Detect It? |
|------|-------------|-------------------|
| **curl-impersonate** | Replaces curl's TLS library with a browser-like one | Partially — older versions produce outdated Chrome fingerprints (e.g., Chrome 131 when real Chrome is at 149). The version mismatch is the signal. |
| **uTLS** (Go library) | Lets Go programs send a pixel-perfect Chrome/Firefox ClientHello | Hard with JA4 alone — the fingerprint matches a real browser exactly. |

This is where **layered detection** comes in. JA4 is one signal, not the only signal. We can combine it with:

- **HTTP/2 fingerprints** — The way a client configures HTTP/2 settings (window size, priority frames, header order) differs between browsers. A bot with a perfect Chrome JA4 but wrong HTTP/2 settings is still detectable.
- **Behavioral signals** — Real users move mice, scroll, click. Bots often don't.
- **Rate and pattern analysis** — A "Chrome browser" making 1,000 login attempts per hour isn't a real user.

JA4 alone catches the **easy 90%** — the bots using default Python, Go, curl, and Java stacks. Combined with HTTP/2 fingerprints, we catch a significant chunk of the remaining impersonation bots. The truly sophisticated 1% requires behavioral analysis, which is a future investment.

---

## How We Would Implement This

We've evaluated six different approaches. Here's the short version — full details are in the [Strategy Options document](file:///Users/nilanjansiromani/.gemini/antigravity/brain/89f8d7c1-a1c8-4362-ae38-0ff22b02c0e9/strategy_options.md):

| Strategy | How It Works | Monthly Cost | Real-Time? | Best For |
|----------|-------------|-------------|-----------|----------|
| **A** — EdgeWorker | Compute JA4 at Akamai edge, block before traffic reaches us | $50–500 | ✅ | Full edge protection |
| **B** — Origin Compute | Forward raw TLS data to our servers, compute JA4 ourselves | $20–100 | ✅ | Zero Akamai cost |
| **C** — Offline Analysis | Log TLS data, analyze later | $65–270 | ❌ | Baselining first |
| **D** — Bot Manager | Akamai's managed bot detection | $2,500–8,000+ | ✅ | Hands-off, big budget |
| **E** — Cloudflare | Migrate CDN, use native JA4 | $4,000–16,000+ | ✅ | Already planning migration |
| **F** — Hybrid | EdgeWorker on login/checkout only, origin compute for the rest | $20–175 | ✅ | Best cost/protection balance |

### Our Recommendation

**Start with Strategy C (Offline Analysis) for 2 weeks**, then move to **Strategy B (Origin Compute)** or **Strategy F (Hybrid)** depending on what we learn.

Here's why:

1. **Week 1–2: Listen first.** Deploy logging only. Capture JA4 fingerprints for all traffic via Akamai DataStream. No blocking, no impact on users. This tells us exactly what's hitting our site — which fingerprints, how much bot traffic, which endpoints are targeted.

2. **Week 3–6: Start scoring.** Forward the raw TLS ClientHello to our origin servers. Compute JA4 there (zero Akamai cost). Build a scoring engine that combines JA4 + User-Agent consistency + rate signals. Start with soft enforcement — challenge suspicious traffic, log everything, measure false positives.

3. **Week 7+: Harden.** If the data justifies it, upgrade critical paths (login, checkout, API) to use an EdgeWorker for edge-level blocking. Keep origin-side computation for everything else. This is the Hybrid strategy — edge protection where it matters most, at minimal cost.

---

## What We Need to Proceed

1. **Confirm with our Akamai TAM** that `AK_CLIENT_HELLO` (the raw TLS handshake data) is available on our contract. This is a prerequisite for every strategy. If it's not available, we need to discuss a contract amendment or consider alternatives.

2. **Engineering allocation** — approximately 2 engineer-weeks for Phase 1 (logging + baseline) and 2 engineer-weeks for Phase 2 (origin-side scoring engine).

3. **Agree on scope** — which endpoints are "critical" and should get the strongest protection? Our recommendation: `/login`, `/api/auth/*`, `/checkout`, `/payment/*`.

---

## What Success Looks Like

After 8 weeks, we should be able to:

- **Identify ≥90%** of automated traffic using default library fingerprints (the Python/curl/Go bots that don't even try to impersonate browsers)
- **Maintain <0.1% false-positive rate** on legitimate browser traffic (measured by how often real users fail challenges)
- **Detect version-mismatch impersonation** — bots claiming to be Chrome 149 but presenting a Chrome 131 TLS fingerprint
- **Have a living baseline** of all JA4 fingerprints hitting our site, updated automatically as browser versions change

The total incremental cost should be **under $200/month** for the recommended approach.

---

## Appendix: The Technical Detail

For those who want to go deeper, the full technical references are:

- [Strategy Options & Implementation Guide](file:///Users/nilanjansiromani/.gemini/antigravity/brain/89f8d7c1-a1c8-4362-ae38-0ff22b02c0e9/strategy_options.md) — detailed architecture diagrams, code samples, and cost breakdowns for all 6 strategies
- [Browser Fingerprints & Platforms Reference](file:///Users/nilanjansiromani/codebase/ja3-fingerprint/browser_fingerprints_platforms.md) — complete JA4 fingerprint database for all major browsers and platforms
- [JA3/JA4 Knowledge Base](file:///Users/nilanjansiromani/codebase/ja3-fingerprint/JA3_JA4_KNOWLEDGE_BASE.md) — comprehensive 1,486-line reference covering the full JA4+ suite, evasion techniques, malware C2 fingerprints, and academic research
