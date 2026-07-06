# JA4 Bot Detection — Bypass Strategies & Weakness Analysis

> **Purpose:** Systematic catalog of every technique that could defeat JA4-based bot detection, ranked by feasibility, impact, and detection difficulty.
> **Last Updated:** 2026-07-06

---

## Bypass Strategy Table

| # | Strategy | Layer | Feasibility | Detection Impact | Detection Difficulty | Akamai Mitigation | Notes |
|---|----------|-------|-------------|-----------------|---------------------|-------------------|-------|
| 1 | **uTLS impersonation** — Go library that crafts arbitrary ClientHellos to parrot Chrome/Firefox/Safari | JA4 (TLS) | ★★★★★ Trivial | ★★★★★ JA4 match identical | ★★★★★ Very hard | H2 fingerprint, header analysis, behavioral | uTLS 1.8.1+ fixes CVE-2026-27017; JA4 is identical to real browser |
| 2 | **curl-impersonate / curl_cffi** — Patched curl with BoringSSL + Chrome cipher/ext lists + GREASE | JA4 (TLS) | ★★★★★ Trivial | ★★★★★ JA4 match identical | ★★★★★ Very hard | curl_cffi also matches H2; check HTTP headers (sec-ch-ua, Accept-Language) | Python `curl_cffi` wraps this; widely used by scrapers |
| 3 | **Cipher stunting** — Reorder/append/remove cipher suites to change JA3 hash | JA3 only | ★★★★★ Trivial | ★★★★☆ JA3 broken | ★☆☆☆☆ Trivial to detect | JA4 is order-independent (sorted), immune to reordering | Only affects JA3, not JA4. JA4 sorts ciphers before hashing. |
| 4 | **GREASE injection** — Add GREASE cipher/extension values to match browser behavior | JA4 (cipher/ext) | ★★★★☆ Easy | ★★★★☆ JA4 ext hash changes | ★★☆☆☆ Moderate | Check GREASE values match known browser patterns | Bots can add GREASE but must match browser-specific GREASE ranges |
| 5 | **ALPN manipulation** — Advertise h2 or http/1.1 ALPN to match browsers | JA4 (ALPN) | ★★★★★ Trivial | ★★☆☆☆ Low | ★☆☆☆☆ Trivial to detect | ALPN alone is weak; combine with H2 SETTINGS check | All modern HTTP clients already send ALPN |
| 6 | **SNI injection** — Send SNI to appear browser-like | JA4 (SNI) | ★★★★★ Trivial | ★☆☆☆☆ Low | ★☆☆☆☆ Trivial to detect | SNI is expected; lack of SNI is stronger signal | Most HTTP libraries send SNI by default |
| 7 | **Extension list inflation** — Add browser-like extensions (0x002b, 0x0033, 0x000d, etc.) | JA4 (ext count) | ★★★★☆ Easy | ★★★☆☆ ext hash changes | ★★★☆☆ Hard | Must match browser extension VALUES + ORDER in hash | JA4_c hashes sorted extensions; values matter, not order |
| 8 | **H2 SETTINGS forgery** — Match Chrome's SETTINGS frame (HEADER_TABLE_SIZE=65536, etc.) | H2 (Akamai) | ★★★☆☆ Moderate | ★★★★★ H2 hash identical | ★★★★★ Very hard | curl_cffi matches Chrome H2; check WINDOW_UPDATE timing | nghttp2-based libraries can match Chrome SETTINGS |
| 9 | **H2 pseudo-header order** — Send `:method :path :scheme :authority` like browsers | H2 (Akamai) | ★★★☆☆ Moderate | ★★★★☆ Order detected | ★★★★☆ Hard | Akamai hashes pseudo-header order separately | Browsers use consistent order; Go/net/http uses different order |
| 10 | **TLS 1.3 downgrade to 1.2** — Use TLS 1.2 to match older bot stdlib | JA4 (version) | ★★★★★ Trivial | ★☆☆☆☆ Low | ★☆☆☆☆ Trivial to detect | Using TLS 1.2 in 2026 is itself suspicious | Python urllib uses TLS 1.2 by default |
| 11 | **QUIC → TCP fallback** — Switch from QUIC/h3 to TCP/h2 to change q→t prefix | Protocol | ★★★★★ Trivial | ★★☆☆☆ JA4 prefix changes | ★☆☆☆☆ Trivial to detect | TCP vs QUIC is observable; both have distinct fingerprints | Browsers prefer QUIC; TCP-only traffic is slightly suspicious |
| 12 | **Proxy / CDN TLS termination** — Akamai/Cloudflare terminates TLS, origin sees proxy's ClientHello | Infrastructure | ★★★★★ N/A | ★★★★★ JA4 is proxy's, not client's | ★★★★★ Impossible at origin | Use Akamai `AK_CLIENT_HELLO` or Bot Manager signals | **Critical**: EdgeWorker reads client's original ClientHello, not proxy's |
| 13 | **Headless browser (Puppeteer/Playwright)** — Real browser TLS but detectable via JS/behavior | Multi-layer | ★★★☆☆ Moderate | ★★★★☆ JA4 matches but headless leaks | ★★★★☆ Hard | Check `navigator.webdriver`, screen size, font list | JA4 is identical to real browser; detection requires non-TLS signals |
| 14 | **JA4T TCP spoofing** — Craft TCP SYN params (window size, MSS, options) to mimic browser | TCP | ★★☆☆☆ Hard | ★★☆☆☆ Few systems check JA4T | ★★★☆☆ Moderate | Akamai doesn't expose TCP params via standard variables | Requires raw socket access; Go/Node stdlibs can't control TCP params |
| 15 | **PSK / 0-RTT manipulation** — Send pre-shared key extension to change JA4 hash | JA4 (ext list) | ★★★☆☆ Moderate | ★★☆☆☆ ext hash changes | ★★☆☆☆ Moderate | Few bots use PSK; its presence is suspicious | Browsers may send PSK for session resumption |
| 16 | **ECH (Encrypted ClientHello)** — Encrypts SNI and other extensions | JA4 (SNI) | ★★★☆☆ Moderate | ★★☆☆☆ SNI field changes to "e" | ★★☆☆☆ Moderate | JA4 prefix changes `d`→`e`; detectable | Increasingly common in Chrome; breaks SNI-based analysis |
| 17 | **Certificate pinning / spoofing** — Present custom certs to change JA4X fingerprint | JA4X (cert) | ★★☆☆☆ Hard | ★☆☆☆☆ Low | ★☆☆☆☆ Trivial to detect | JA4X is rarely checked in production | Akamai does not expose JA4X via standard variables |
| 18 | **ClientHello fragmentation** — Split ClientHello across multiple TCP packets | Parsing | ★★☆☆☆ Hard | ★★★★★ Breaks naive parsers | ★★☆☆☆ Moderate | Robust parsers reassemble TLS records | Our parser uses `once('data')` — would fail on fragmentation |
| 19 | **IPv6 → IPv4 switching** — Change IP protocol version | Network | ★★★★★ Trivial | ★☆☆☆☆ No effect on JA4 | ★☆☆☆☆ Trivial | JA4 is same over IPv4 and IPv6 | No bypass value |
| 20 | **Timing-based evasion** — Add artificial delays to match human timing | Behavioral | ★★☆☆☆ Hard | ★☆☆☆☆ No effect on JA4 | ★★☆☆☆ Moderate | JA4 captures TLS only; timing is separate signal | Not applicable to TLS fingerprinting |
| 21 | **ML-generated ClientHello** — Use ML to generate ClientHello matching browser distribution | JA4 (TLS) | ★☆☆☆☆ Theoretical | ★★★★★ Exact match | ★★★★★ Very hard | No known production implementation | Research only; extremely high development cost |
| 22 | **Fingerprint rotation** — Rotate through many JA4 profiles to avoid blacklisting | Operational | ★★★★☆ Easy | ★★★☆☆ Each profile still detectable | ★★★☆☆ Hard | Requires per-connection profile; detectable via entropy | C2 malware often uses this with uTLS profile rotation |
| 23 | **Akamai Bot Manager bypass** — Abuse Bot Manager whitelist/blacklist logic | Policy | ★☆☆☆☆ Difficult | ★★★★★ Completely invisible | ★★★★★ Very hard | Requires internal Akamai config knowledge | Not a technical bypass; requires leaked credentials/config |
| 24 | **HTTP/1.0 downgrade** — Use HTTP/1.0 instead of HTTP/1.1 or h2 | Application | ★★★★★ Trivial | ★★★☆☆ HTTP/1.0 is rare in 2026 | ★★☆☆☆ Moderate | HTTP/1.0 is itself a strong bot signal | Very few legitimate clients use HTTP/1.0 |
| 25 | **Custom TLS library** — Write a TLS stack from scratch with browser-like parameters | JA4 (TLS) | ★☆☆☆☆ Extremely Hard | ★★★★★ Any profile possible | ★★★★★ Very hard | Requires deep TLS expertise; months of development | Not practical for most attackers |

---

## Key Findings

### Tier 1: Immediately Dangerous (exploitable today)
| # | Strategy | Why It Works Today |
|---|----------|-------------------|
| 1 | uTLS impersonation | Go scraper libraries widely available; JA4 is byte-for-byte identical to Chrome/Firefox |
| 2 | curl-impersonate / curl_cffi | Python/CLI tools that produce identical JA4 + H2 SETTINGS to Chrome |
| 13 | Headless browsers | Real browser binaries — TLS is 100% identical; leak only via non-TLS signals |

### Tier 2: Moderate Threat (requires effort but feasible)
| # | Strategy | Why It Works Today |
|---|----------|-------------------|
| 8 | H2 SETTINGS forgery | curl_cffi matches Chrome H2; Akamai H2 hash is identical |
| 9 | H2 pseudo-header order | Forged by advanced tools; detectable only via deep H2 inspection |
| 18 | ClientHello fragmentation | Many TLS parsers assume single-packet ClientHello |

### Tier 3: Low Risk (impractical or easily detected)
| # | Strategy | Why Low Risk |
|---|----------|-------------|
| 3-7 | Cipher/ALPN/SNI/extension manipulation | JA4 is order-independent; single signals are weak compared to combined scoring |
| 10 | TLS version change | TLS 1.2 in 2026 is itself a strong bot signal |
| 22 | Fingerprint rotation | Each rotation still produces a detectable JA4; behavioral analysis catches rotation |

---

## Layered Defense Strategy

The only reliable defense against JA4 bypass is **multi-layer fingerprinting**:

```
Clients → [TLS Handshake] → JA4 (TLS fingerprint)
       → [H2 Preface]     → H2 SETTINGS / WINDOW_UPDATE / pseudo-header order
       → [HTTP Headers]    → JA4H (header order, sec-ch-ua, Accept-*)
       → [HTTP Body]       → Payload analysis (JS challenges, CAPTCHA)
       → [Behavioral]      → Request timing, mouse movements (JS)
       → [IP/Network]      → IP reputation, ASN, proxy/VPN detection
```

Each layer independently contributes to a **bot confidence score**. Bypassing any single layer is insufficient — an attacker must match ALL layers simultaneously.

### Layer Effectiveness Matrix

| Layer | Impersonation Difficulty | Current Bypass Rate | Notes |
|-------|------------------------|-------------------|-------|
| JA4 (TLS) | Moderate (uTLS exists) | ~80% of advanced scrapers | curl_cffi matches Chrome |
| H2 SETTINGS | Moderate (nghttp2) | ~60% | curl_cffi matches; Go/net/http does not |
| H2 pseudo-headers | Hard | ~20% | Rarely spoofed correctly |
| HTTP headers (JA4H) | Very Hard | ~5% | Not supported by any impersonation library |
| JS challenges | Extremely Hard | ~0.1% | Requires full browser engine |
| Behavioral | Extremely Hard | ~0.01% | Requires human-like interaction |

---

## Recommendations for Akamai Deployment

1. **Always use AK_CLIENT_HELLO** — without it, you see the edge's ClientHello, not the client's
2. **Combine JA4 + H2 fingerprints** — both are available at Akamai edge via EdgeWorkers
3. **Set conservative thresholds** — JA4 alone should never trigger blocking; use it as a scoring input
4. **Monitor for `exts_lt8` + `no_grease`** — the strongest bot signals in our test (100% accuracy)
5. **Beware of macOS clients** — macOS curl/Node.js send browser-normal sigalg/group counts
6. **Log bot_signals array** — analyze which signals trigger most for your traffic
7. **Watch for ClientHello fragmentation** — add a reassembly buffer in production parsers

---

## Test Results (macOS, 2026-07-06)

| Bot Client | JA4 | Signals Passed | Confidence |
|-----------|-----|---------------|-----------|
| curl (macOS LibreSSL) | `t13i4906h2_0d8feac7bc37_7395dae3b2f3` | 6/10 | High |
| openssl s_client (macOS LibreSSL) | `t13d490700_0d8feac7bc37_460f73f9cefb` | 7/10 | High |
| Node.js https GET (LibreSSL) | `t13i521000_b262b3658495_8e6e362c5eac` | 9/10 | High |
| Python urllib | `t12i380400_10ed599f3404_67a080e8974e` | 8/10 | High |
