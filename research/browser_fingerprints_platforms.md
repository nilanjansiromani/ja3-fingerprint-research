# Browser JA4+ Fingerprint Database & Akamai Implementation Guide

> **Purpose:** Production-ready reference for bot detection using JA4 TLS fingerprinting at the Akamai edge.
> **Last Updated:** 2026-07-06
> **Sources:** httpcloak presets (verified tls.peet.ws captures 2026-05-10), krowdev live captures 2026-06-13, JA4DB, FoxIO specification, Akamai EdgeWorker examples

---

## Table of Contents

1. [Browser JA4 Fingerprints by Platform](#1-browser-ja4-fingerprints-by-platform)
2. [QUIC (qJA4) Fingerprints](#2-quic-qja4-fingerprints)
3. [JA4T TCP Fingerprints](#3-ja4t-tcp-fingerprints)
4. [JA4S Server Response Fingerprints](#4-ja4s-server-response-fingerprints)
5. [Non-Browser / Bot / Library Fingerprints](#5-non-browser--bot--library-fingerprints)
6. [Akamai Implementation Guide](#6-akamai-implementation-guide)
7. [Cost Analysis](#7-cost-analysis)
8. [Testing & Development](#8-testing--development)
9. [References](#9-references)

---

## 1. Browser JA4 Fingerprints by Platform

### Format Quick Reference

```
JA4 = {ptype}{tls_ver}{sni}{ciph_ct}{ext_ct}{alpn}_{cipher_hash}_{ext_hash}
Example: t13d1516h2_8daaf6152771_d8a2da3f94cd
  t    = TLS over TCP (q = QUIC)
  13   = TLS 1.3
  d    = SNI present (i = absent)
  15   = 15 cipher suites (after GREASE removal)
  16   = 16 extensions (after GREASE removal)
  h2   = ALPN = HTTP/2
  8daaf6152771 = SHA-256 truncated (12 hex) of sorted cipher list
  d8a2da3f94cd = SHA-256 truncated (12 hex) of sorted ext list + sigalgs
```

### 1.1 Chrome / Chromium Desktop

All share `ja4_b = 8daaf6152771` (same cipher set). `ja4_c` distinguishes sub-versions.

| Profile | JA4 (TCP) | JA3 Hash | OS |
|---------|-----------|----------|----|
| Chrome 149 Linux | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | `51c8a5ff78d815668581664c5789d09c` | Linux |
| Chrome 149 Windows | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | `f592f2dfba4cdfc1b18ed1f29df8c8b7` | Windows |
| Chrome 149 macOS | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | Not yet captured — use tls.peet.ws to obtain | macOS |
| Chrome 148 Windows | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | `f592f2dfba4cdfc1b18ed1f29df8c8b7` | Windows |
| Chrome 148 Linux | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | `51c8a5ff78d815668581664c5789d09c` | Linux |
| Chrome 131 (curl_cffi) | `t13d1516h2_8daaf6152771_02713d6af862` | — | cross-platform |
| Chrome 136 (curl_cffi) | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | — | cross-platform |
| Chrome 142 (curl_cffi) | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | — | cross-platform |
| FoxIO canonical example | `t13d1516h2_8daaf6152771_e5627efa2ab1` | — | — |
| bunny.net / GTI example | `t13d1516h2_8daaf6152771_02713d6af862` | — | — |

**Key insight:** Chrome on different OSes produces **different JA3 hashes** (due to extension ordering) but the **same JA4**. JA4's hash parts (B and C) are order-independent for ciphers and extensions — ciphers are sorted before hashing, extensions are sorted before hashing (sigalgs retain their observed order). `ja3_hash` is unstable across Chrome restarts (extension shuffle). JA4 is stable.

**JA4_c evolution across Chrome versions:**
- Chrome 131: `02713d6af862`
- Chrome 136+: `d8a2da3f94cd`
- These change when Chrome bumps sigalg lists on major versions

### 1.2 Chrome Android

Android Chrome runs its own TLS stack (not WebKit). Fingerprint matches desktop Chrome Linux.

| Profile | JA4 (TCP) | Notes |
|---------|-----------|-------|
| Chrome 148 Android | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | Same as desktop Linux; uses uTLS `HelloChrome_148_Linux` preset |
| Chrome 131 Android | `t13d1516h2_8daaf6152771_02713d6af862` | curl_cffi target |

`sec-ch-ua-mobile: ?1`, `sec-ch-ua-platform: "Android"`. Akamai H2 matches Chrome desktop (identical H2 stack).

### 1.3 Chrome iOS

iOS Chrome is a WebKit wrapper (Apple policy). Fingerprint **matches Safari iOS**, not desktop Chrome.

| Profile | JA4 (TCP) | Notes |
|---------|-----------|-------|
| Chrome 148 iOS | same as Safari 18 iOS | WebKit; uses uTLS `HelloIOS_18` |

Akamai H2: `2:0;4:2097152;3:100;5:16384;9:1|10485760|0|m,s,p,a`

> WINDOW_UPDATE value: `10485760` (Safari 18 confirmed). Safari 17 and earlier use `10420275`.

### 1.4 Firefox Desktop

Firefox uses different TLS extension ordering from Chrome. No `sec-ch-ua` headers.

| Profile | JA4 (TCP) | JA3 Hash | Notes |
|---------|-----------|----------|-------|
| Firefox 148 | `t13d1717h2_5b57614c22b0_3cbfd9057e0d` | `6f7889b9fb1a62a9577e685c1fcfa919` | Latest shipped |
| Firefox 135 | `t13d1717h2_5b57614c22b0_3cbfd9057e0d` | — | Same as 148 |
| Firefox 133 (curl_cffi) | `t13d1716h2_5b57614c22b0_eeeea6562960` | — | Older shape; extension count 16→17 between v133 and v134 |

**Characteristics:**
- 17 ciphers, 17 extensions (vs Chrome's 15/16)
- `ja4_b = 5b57614c22b0` (different cipher set from Chrome)
- Sends `TE: trailers` header (Chrome does not)
- ALPN = h2
- No QUIC fingerprint in uTLS (uTLS lacks Firefox QUIC presets; Firefox itself has had HTTP/3 since v88 via its neqo Rust stack)
- Akamai H2: `1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s`

### 1.5 Safari macOS

Safari uses Apple's TLS stack. Shortest extension list among major browsers.

| Profile | JA4 (TCP) | JA3 Hash | Notes |
|---------|-----------|----------|-------|
| Safari 18 macOS | `t13d2013h2_a09f3c656075_7f0f34a4126d` | `c8af4d593e65bd6ba927ef9a0bdef541` | Latest |
| Safari 18.4 (curl_cffi) | `t13d2014h2_a09f3c656075_7f0f34a4126d` | — | 14 extensions |
| Safari 26.0 (curl_cffi) | `t13d2014h2_a09f3c656075_d0a99439f9b1` | — | Newer version |
| Safari 26.0.1 (curl_cffi) | `t13d2013h2_a09f3c656075_7f0f34a4126d` | — | Back to 13 ext |

**Characteristics:**
- 20 ciphers, 13-14 extensions (fewer than Chrome/Firefox)
- `ja4_b = a09f3c656075` (distinct cipher set)
- No `sec-ch-ua` (Safari doesn't do Client Hints)
- Pseudo-header order: `m,s,p,a` (different from Chrome's `m,a,s,p`)
- `NO_RFC7540_PRIORITIES=1` (opts out of stream priorities)
- Akamai H2: `2:0;4:2097152;3:100;5:16384;9:1|10485760|0|m,s,p,a`
- H3 via uTLS `HelloIOS_18_QUIC` (shared with iOS Safari)

### 1.6 Safari iOS

Same H2 stack as macOS Safari, slightly different TLS extension order.

| Profile | JA4 (TCP) | JA3 Hash | Notes |
|---------|-----------|----------|-------|
| Safari 18 iOS | `t13d2013h2_a09f3c656075_7f0f34a4126d` | `e7c59d91e34d9d83e510732edf732b83` | JA3 differs from macOS, JA4 is same |
| Safari 17 iOS | (older) | — | H1/H2 only |

JA4 and Akamai H2 hash are **identical** to Safari macOS. JA3 differs due to platform-specific extensions. This means JA4 alone **cannot** distinguish Safari macOS from Safari iOS.

### 1.7 Edge

Edge is Chromium-based. On desktop, JA4 matches Chrome for the same Chromium version. On iOS, Edge is a WebKit wrapper (same as Chrome iOS = Safari iOS).

| Profile | JA4 (TCP) | Notes |
|---------|-----------|-------|
| Edge (any Chromium version) | Chrome-equivalent JA4 | Same Blink TLS stack |
| Edge iOS | Safari iOS-equivalent JA4 | WebKit wrapper |

### 1.8 Brave / Opera / Vivaldi

All Chromium-based. JA4 matches Chrome for the same underlying Chromium version. The `sec-ch-ua` brand list differs (Brave adds "Brave", Opera adds "OPR"), but this does **not** affect JA4 (which is purely TLS-level).

### HTTP/2 Akamai Fingerprint Comparison

| Client | SETTINGS | WINDOW_UPDATE | PRIORITY | Pseudo-Header Order |
|--------|----------|---------------|----------|---------------------|
| Chrome | `1:65536;2:0;4:6291456;6:262144` | `15663105` | `0` | `m,a,s,p` |
| Firefox | `1:65536;2:0;4:131072;5:16384` | `12517377` | `0` | `m,p,a,s` |
| Safari | `2:0;3:100;4:2097152;5:16384;9:1` | `10485760` | `0` | `m,s,p,a` |

H2 fingerprints complement JA4: a bot with a perfect Chrome JA4 but wrong SETTINGS is still detectable.

---

## 2. QUIC (qJA4) Fingerprints

QUIC fingerprints start with `q` instead of `t`. These become increasingly important as HTTP/3 adoption grows.

| Profile | qJA4 (QUIC) | Notes |
|---------|-------------|-------|
| Chrome 149 (any OS) | `q13d1516h2_8daaf6152771_d8a2da3f94cd` | Uses uTLS `HelloChrome_149_QUIC`; JA4_c may differ from TCP variant |
| Chrome 148 (any OS) | `q13d1516h2_8daaf6152771_d8a2da3f94cd` | Uses uTLS `HelloChrome_148_QUIC` |
| Chrome 148 iOS | `q13d1516h2_...` | Uses uTLS `HelloIOS_18_QUIC` |
| Safari 18 (macOS+iOS) | `q13d1516h2_...` | Uses uTLS `HelloIOS_18_QUIC` |
| Firefox | Not available | uTLS lacks Firefox QUIC presets (Firefox H3 itself is mature via neqo) |

**Detection value:** If a request uses HTTP/3 (QUIC), the qJA4 provides the same identification signal as JA4 does for TCP. Akamai exposes the QUIC version via `PMUSER_QUIC_VERSION` / `AK_QUIC_VERSION`.

---

## 3. JA4T TCP Fingerprints

JA4T captures the **TCP handshake parameters** from the SYN packet (Layer 4, before TLS exists). Useful as a secondary OS-identification signal alongside JA4.

### JA4T Format (FoxIO Spec)

```
JA4T = {window_size}_{tcp_options}_{mss}_{window_scale}
```

| Field | Example | Meaning |
|-------|---------|---------|
| window_size | `64240` | Raw TCP receive window from SYN (before window-scale multiplication) |
| tcp_options | `2-4-8-1-3` | TCP option kind numbers in **original packet order** (never sorted) |
| mss | `1460` | Maximum Segment Size |
| window_scale | `8` | TCP Window Scale value; `00` if absent |

### Common OS Signatures (options sequences)

| Options | OS |
|---------|----|
| `2-4-8-1-3` | Linux kernel 4.x+ |
| `2-1-3-1-1-4` | Windows 10/11 (no timestamps, SACK last) |
| `2-1-3-1-1-8-4-0-0` | macOS / iOS (timestamp after window scale, EOL padding) |
| `2-1-3` | **HIGHLY SUSPICIOUS** — minimal stack, custom tooling (nmap, masscan) |

### TCP Option Codes

| Code | Option |
|------|--------|
| 0 | EOL (End of Options List) |
| 1 | NOP (No-Operation / padding) |
| 2 | MSS (Maximum Segment Size) |
| 3 | Window Scale |
| 4 | SACK Permitted |
| 5 | SACK (Selective ACK) |
| 8 | Timestamps |
| 14 | Fast Open (TFO) |

**Note:** JA4T is best used as a secondary signal (tiebreaker when JA4 alone is ambiguous). TCP parameters can vary by network path (NAT, VPN, proxies alter MSS and window). JA4T is primarily useful offline (Arkime/Zeek) — Akamai edge cannot inspect raw SYN packets.

---

## 4. JA4S Server Response Fingerprints

JA4S identifies the **server** side of the TLS handshake. Crucial insight: **JA4S cannot be spoofed by the client**, making it a strong detection signal — particularly when paired with JA4. However, note that against the same server (e.g., both a browser and a bot connecting to your Akamai edge), JA4S will be identical — so the pairing value is greatest when the bot hits its own C2 server.

JA4S format: `{proto}{version}{ext_count}{alpn}_{cipher}_{ext_hash}`

The `alpn` field is 4 characters: first two chars of first ALPN value + first two chars of second ALPN value, zero-padded if fewer than 2 ALPN values. Example: `h2h1` for h2 + http/1.1, `0000` if no ALPN.

### Known JA4S Fingerprints

| Server Fingerprint | Context | Source |
|-------------------|---------|--------|
| `t120300_c030_5e2616a54c73` | IcedID malware C2 (paired with JA4 `t13d201100_2b729b4bf6f3_9e7b989ebec8`) | FoxIO DB |
| `t130200_1301_a56c5b993250` | Sliver C2 (Go TLS) | FoxIO DB |
| Akamai edge (modern) | Varies by config | Capture from your own Akamai property |

### How to Use JA4S

When bot-detecting, the JA4+JA4S pair is far more reliable than JA4 alone:
- Browser → Legitimate server: JA4 = Chrome/Firefox/Safari, JA4S = Akamai/Cloudflare/AWS
- Bot → Legitimate server: JA4 = Python/Go/curl, JA4S = Akamai
- Bot → C2 server: JA4 = malware TLS, JA4S = attacker server

**Akamai limitation:** The EdgeWorker `onClientRequest` only sees the client's ClientHello. To capture JA4S, you need either:
- Arkime (already in your stack) — Zeek plugin logs JA4S
- A separate edge-side capture mechanism (EdgeWorker `onOriginResponse` can't access ServerHello TLS data)

---

## 5. Non-Browser / Bot / Library Fingerprints

Critical for detection: default library fingerprints are **distinct** from browsers even when User-Agent claims otherwise.

### Known Non-Browser JA4 Fingerprints

| Client | JA4 (TCP) | ALPN | Notes |
|--------|-----------|------|-------|
| curl 8.10+ (modern distro) | `t13d3112h2_e8f1e7e78f70_375ca2c5e164` | h2 | 31 ciphers, 12 extensions |
| Python `requests` (urllib3) | `t13d1712h1_ab0a1bf427ad_882d495ac381` | h1 | HTTP/1.1! 17 ciphers |
| Python `httpx` (httpcore) | `t13d1712h1_ab0a1bf427ad_8e6e362c5eac` | h1 | HTTP/1.1! |
| Go `net/http` 1.22.2 | `t13d1411h2_cbb2034c60b8_e7c285222651` | h2 | 14 ciphers, 11 extensions |
| OpenSSL `s_client -tls1_3` | `t13d410_16476d049b0b_78f1d400d464` | none | No ALPN! 4 ciphers |
| OpenSSL `s_client -alpn h2` | `t13d411h2_16476d049b0b_78f1d400d464` | h2 | 4 ciphers |
| Java 11+ HttpClient | `t13d1517h2_...` | h2 | Differs from native browsers |
| Node.js 20 `fetch` | `t13d1517h2_...` | h2 | Depends on TLS lib |
| curl-impersonate Chrome | `t13d1516h2_8daaf6152771_02713d6af862` | h2 | Matches Chrome 131 |
| curl-impersonate Firefox | `t13d1716h2_5b57614c22b0_eeeea6562960` | h2 | Matches Firefox 133 |

### Detection-Value Indicators

**Strong bot signals (any of these = very likely bot):**
- ALPN = `h1` (strong bot signal — browsers default to h2/h3; exceptions: enterprise proxy downgrade, captive portal, Safari initial connection, `--http1.1` flags)
- ALPN = `00` (no ALPN at all)
- Cipher count < 10 (browsers offer 15-20)
- Extension count < 10 (browsers offer 13-17)
- Cipher count > 25 (browsers cap at ~20)
- JA4 prefix `t13d4...` (only 4 ciphers = OpenSSL s_client)

**Weak bot signals (check alongside other factors):**
- JA4 starts with `t13d17` (Firefox range — could be real Firefox)
- JA4 starts with `t13d15` (Chrome range)
- JA4 starts with `t13d20` (Safari range)

### Known Bot JA4 Fingerprints (from JA4DB)

| Application | JA4 Fingerprint | Verified |
|-------------|----------------|----------|
| SemrushBot | `t13d301000_01455d0db58d_5ac7197df9d2` | No |
| Googlebot (varies) | Varies by generation | pre-2020: custom Google TLS; ~2021-2023: Chrome-like BoringSSL; 2024+: often mirrors Chrome. Requires separate allowlist entry — do not assume Chrome-JA4 match |
| Bingbot | Chrome-family JA4 | Uses Chromium TLS |
| AhrefsBot | Varies | Often custom stack |
| Bytespider | Varies | Often custom stack |

---

## 6. Akamai Implementation Guide

### 6.1 Architecture Overview

```
Client TLS Handshake
       │
       ▼
┌──────────────────────────────────────────┐
│  Akamai Edge (Enhanced TLS / CPS)        │
│  ┌────────────────────────────────────┐   │
│  │ AK_CLIENT_HELLO (raw base64)       │   │
│  │ AK_QUIC_VERSION (if QUIC)          │   │
│  └────────────────────────────────────┘   │
│                  │                        │
│                  ▼                        │
│  ┌────────────────────────────────────┐   │
│  │  PMUSER variable assignment         │   │
│  │  (Property Manager Advanced)        │   │
│  └────────────────────────────────────┘   │
│                  │                        │
│                  ▼                        │
│  ┌────────────────────────────────────┐   │
│  │  EdgeWorker JA4 Calculation         │   │
│  │  → Parses ClientHello             │   │
│  │  → Computes JA4 fingerprint       │   │
│  │  → Sets PMUSER_JA4_FINGERPRINT    │   │
│  └────────────────────────────────────┘   │
│                  │                        │
│                  ▼                        │
│  ┌────────────────────────────────────┐   │
│  │  Property Manager Rules             │   │
│  │  → Read PMUSER_JA4_FINGERPRINT    │   │
│  │  → Set origin header              │   │
│  │  → Rate-limit / block by JA4      │   │
│  │  → Log via DataStream             │   │
│  └────────────────────────────────────┘   │
│                  │                        │
└──────────────────┼────────────────────────┘
                   │
                   ▼
         Origin Server (your app)
         Receives X-JA4-Fingerprint header
```

### 6.2 Prerequisites (Akamai CPS Configuration)

**Step 1: Enable ClientHello capture in Enhanced TLS**

Add to ESSLINDEX Metadata Extensions, at the Deployment Settings:

```xml
<save-client-hello>on</save-client-hello>
```

This enables `AK_CLIENT_HELLO` which contains the raw ClientHello data in Base64 encoding. Required for both JA3 and JA4.

> **Caveat:** `AK_CLIENT_HELLO` is accessible via `request.getVariable('AK_CLIENT_HELLO')` inside EdgeWorkers. Whether `%(AK_CLIENT_HELLO)` can be dereferenced directly in Property Manager PAPI rules depends on your Akamai contract and configuration version. If PM-only access fails, the EdgeWorker can read `AK_CLIENT_HELLO` directly and compute JA4 without the PMUSER forwarding step.

**Step 2: Define Property Variables**

Create these PMUSER variables in Property Manager:
- `PMUSER_TLS_CLIENT_HELLO` — receives raw ClientHello from AK_CLIENT_HELLO
- `PMUSER_QUIC_VERSION` — receives QUIC version from AK_QUIC_VERSION (for qJA4)
- `PMUSER_JA4_FINGERPRINT` — stores the computed JA4 fingerprint

Set visibility should be `visible` for debugging, then `hidden` in production.

### 6.3 Property Manager Configuration (Illustrative)

> **Note:** The XML below is **illustrative pseudo-code** showing the intended data flow, not deployable PAPI XML. Actual Akamai Property Manager uses JSON/PAPI with behavior-specific schemas. Use these as a guide when configuring via the Akamai Control Center UI or PAPI.

**Key configuration steps:**
1. Create PMUSER variables: `PMUSER_TLS_CLIENT_HELLO`, `PMUSER_QUIC_VERSION`, `PMUSER_JA4_FINGERPRINT`
2. Use the `setVariable` behavior to assign `%(AK_CLIENT_HELLO)` → `PMUSER_TLS_CLIENT_HELLO` and `%(AK_QUIC_VERSION)` → `PMUSER_QUIC_VERSION`
3. Add the EdgeWorker behavior (runs after variable assignment)
4. After the EdgeWorker, read `PMUSER_JA4_FINGERPRINT` and inject it as an origin header

**Inject JA4 header to origin:**

In the Origin Server behavior, add an outgoing header:

```
Header Name:  X-JA4-Fingerprint
Header Value: %(PMUSER_JA4_HEADER_VALUE)
```

### 6.4 EdgeWorker: JA4 Calculation Code

**`main.js`:**

```javascript
import * as util from './util.js';
import { logger } from 'log';

export async function onClientRequest(request) {
  const client_hello = request.getVariable('PMUSER_TLS_CLIENT_HELLO');
  if (!client_hello) {
    logger.info("No ClientHello available");
    return;
  }

  const buffer = util.base64toUint8Array(client_hello);
  const quic_version = request.getVariable('PMUSER_QUIC_VERSION');
  const proto = quic_version ? "q" : "t";

  try {
    const JA4_fingerprint = await util.getJA4Fingerprint(buffer, proto);
    request.setVariable('PMUSER_JA4_FINGERPRINT', JA4_fingerprint);
  } catch (error) {
    logger.error(`JA4 calculation error: ${error.message}`);
  }
}
```

**`util.js`:** (see the full source at [nmckay77/ja4-edgeworker](https://github.com/nmckay77/ja4-edgeworker) or use the complete implementation below)

The `util.js` file implements:
- `base64toUint8Array(base64)` — decodes base64 ClientHello
- `truncatedHash(data)` — SHA-256 → first 12 hex chars
- `getJA4Fingerprint(buffer, proto)` — full JA4 calculation

Key implementation details:
- GREASE values are filtered out (`0x0a0a, 0x1a1a, 0x2a2a, ... 0xfafa`)
- Cipher suites are sorted hex-order before hashing (JA4 is order-independent)
- Extensions 0x0000 (SNI) and 0x0010 (ALPN) are excluded from extension hash (already in prefix)
- Signature algorithms are appended to extension hash input with `_` separator
- Supported versions extension overrides the record-layer TLS version
- ALPN first/last char extraction handles printable ASCII vs hex fallback

**Bundle and deploy:**
```bash
# Create EdgeWorker bundle
mkdir -p ja4-edgeworker && cd ja4-edgeworker
# Place main.js and util.js here
# Create bundle.json
cat > bundle.json << 'EOF'
{
  "edgeworker-version": "1.0",
  "name": "ja4-fingerprint",
  "description": "JA4 TLS fingerprint computation EdgeWorker"
}
EOF
tar -czf ja4-edgeworker.tgz main.js util.js bundle.json
# Upload via Akamai Control Center or CLI
```

### 6.5 Without EdgeWorkers (Fallback Methods)

If EdgeWorker per-request pricing is a concern, you have alternatives:

**Option A: Bot Manager (subscription)**

Akamai Bot Manager can identify bots using TLS fingerprinting internally and set `Akamai-Bot-Id` headers or trigger actions (challenge, deny, alert). You don't get the raw JA4 value, but you get the classification.

Configure in Bot Manager:
1. Enable "TLS Fingerprint" detection category
2. Set action: `monitor` / `deny` / `challenge` per bot score
3. If using headers: outbound `Akamai-Bot-Id` header for origin processing

**Limitation:** You get a bot/non-bot verdict, not the raw JA4 string. Akamai's detection logic may not expose JA4 externally without EdgeWorkers.

**Option B: Property Manager Only (limited)**

Akamai's Property Manager has `AK_CLIENT_HELLO` available but cannot parse TLS structures natively (no regex or binary parsing in PAPI). You cannot compute JA4 without EdgeWorkers.

**Option C: DataStream + Offline Analysis**

Ship ClientHello data via DataStream to a SIEM, compute JA4 offline. Not real-time but useful for:
- Building a baseline of legitimate JA4s hitting your site
- Identifying bot clusters retrospectively
- Tuning EdgeWorker rules before deploying

**Option D: EdgeWorker with Selective Execution**

To reduce costs, run the EdgeWorker only on a subset of traffic:
- Use Property Manager criteria to invoke EdgeWorker only for suspicious paths
- Sample traffic (e.g., every Nth request)
- Only activate during attack windows via Property Manager activation

### 6.6 Edge Diagnostics / Testing

Use Akamai Edge Diagnostics to verify JA4 is flowing correctly:

1. Go to Akamai Control Center → Property Manager → Edge Diagnostics
2. Send a test request from your browser
3. Check `X-Akamai-Session-Info` response header for PMUSER values
4. Verify origin receives `X-JA4-Fingerprint` header

**Note:** `request.setVariable()` in EdgeWorker changes security settings to hidden. You may not see the value in `X-Akamai-Session-Info` after the EdgeWorker runs. Set a separate debug variable visible before the EdgeWorker invocation.

### 6.7 DataStream Logging

Add PMUSER_JA4_FINGERPRINT to your DataStream configuration:

1. In DataStream, edit your stream
2. Add custom variable `PMUSER_JA4_FINGERPRINT` to the log fields
3. Ship to your SIEM / Arkime for correlation

This lets you:
- Analyze JA4 distribution across traffic
- Identify new fingerprints appearing during attacks
- Correlate JA4 with other signals (IP, User-Agent, path, rate)

---

## 7. Cost Analysis

| Solution | Pricing Model | Estimated Cost | Notes |
|----------|--------------|----------------|-------|
| **EdgeWorkers** | Per invocation | ~$0.15-0.50/million invocations | Tiered; first ~2M free/month |
| **DataStream** | Per GB ingested | ~$0.50-2.00/GB | First ~1GB free/month |
| **Bot Manager** | Subscription (annual) | $X0,000+/year | Negotiated; varies by traffic volume |
| **Property Manager** | Included with CDN | $0 | No extra for basic config |
| **Enhanced TLS (CPS)** | Included with CDN | $0 | Requires Enhanced TLS cert |

> **Cost interplay note:** If logging every `PMUSER_JA4_FINGERPRINT` via DataStream, DataStream per-GB costs can match or exceed EdgeWorker per-invocation costs at high traffic volumes. Consider sampled logging (e.g., 1:1000) for cost control during the gather phase.

### Recommendation for Your Use Case

**Tier 1 (Testing / Low traffic):** EdgeWorkers only (~$0-50/month for moderate traffic)
- Compute JA4, inject header, log via DataStream
- Analyze at origin / Arkime

**Tier 2 (Production):** EdgeWorkers + Bot Manager
- EdgeWorkers for JA4 header
- Bot Manager for automated blocking of known bots
- DataStream for SIEM alerting

**Tier 3 (High volume):** EdgeWorkers selective + Bot Manager
- EdgeWorkers only on suspicious paths (login, checkout, API)
- Bot Manager for broad protection
- Property Manager rules for challenge/block based on header values

---

## 8. Testing & Development

### 8.1 Akamai Developer Account

**Current status:** No standalone free tier for non-Akamai-customers.
- EdgeWorkers 30-day trial available but requires existing Akamai account
- Evaluation tier requires an existing contract
- Linode ($100 credit) is IaaS only — cannot test Akamai edge features

**Workaround options:**

1. **Cloudflare** — JA4 signals available in Bot Management (Enterprise add-on; not available on free/Pro/Business plans)
2. **Local testing** — Use `nmckay77/ja4-edgeworker` locally with Node.js to verify JA4 calculation
3. **tls.peet.ws** — Reflect your own fingerprint for testing
4. **Arkime** — Already in your stack; can compute JA4 from captured PCAPs for baseline analysis

### 8.2 Testing Your Own Browser Fingerprint

```bash
# Get your current JA4
curl -s https://tls.peet.ws/api/all | python3 -c "import sys,json; d=json.load(sys.stdin); print('JA4:', d['tls']['ja4']); print('JA3:', d['tls']['ja3_hash'])"
```

Or visit https://tls.peet.ws/api/all in a browser.

### 8.3 Testing with curl-impersonate

```bash
# Test Chrome impersonation
# Requires Rust toolchain: install via rustup.rs or brew install rust
pip install curl_cffi
python3 -c "
from curl_cffi import requests
r = requests.get('https://tls.peet.ws/api/all', impersonate='chrome131')
data = r.json()
print('JA4:', data['tls']['ja4'])
print('Matched browser JA4')
"
```

### 8.4 JA4DB Query

```bash
# Note: JA4DB API is paginated. For full DB, use ja4LookR (see References).
# Fetch first page (limited results):
curl -s 'https://ja4db.com/api/read/?limit=500' -o ja4db_page1.json
# Inspect schema to find correct field names:
cat ja4db_page1.json | jq '.[0] | keys'
# Query by application:
cat ja4db_page1.json | jq '.[] | select(.application? | test("Chrome|Firefox|Safari"; "i")) | {fingerprint: .ja4_fingerprint, app: .application, os: .os}'
```

### 8.5 Bot Detection Test Matrix

When deploying, test these scenarios:

| Test Case | Expected JA4 | Expected Verdict |
|-----------|-------------|------------------|
| Real Chrome 148 Windows | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | Allow |
| Real Firefox 148 | `t13d1717h2_5b57614c22b0_3cbfd9057e0d` | Allow |
| Real Safari 18 macOS | `t13d2013h2_a09f3c656075_7f0f34a4126d` | Allow |
| curl default | `t13d3112h2_e8f1e7e78f70_375ca2c5e164` | Block/Challenge |
| Python requests | `t13d1712h1_ab0a1bf427ad_882d495ac381` | Block/Challenge |
| Go net/http | `t13d1411h2_cbb2034c60b8_e7c285222651` | Block/Challenge |
| curl-impersonate Chrome | `t13d1516h2_8daaf6152771_02713d6af862` | Depends on version match |
| SemrushBot (unverified) | `t13d301000_01455d0db58d_5ac7197df9d2` | Block (if unwanted) — unverified fingerprint |

### 8.6 Building Your Allowlist Workflow

1. **Gather phase (1-2 weeks):** Deploy EdgeWorker to inject JA4 header. Log all JA4s via DataStream. Do NOT block anything yet.
2. **Analysis phase:** Query Arkime/DataStream for JA4 distribution. Identify top-N fingerprints hitting your site.
3. **Classification phase:** Map each JA4 to its client using JA4DB + your own knowledge. Tag as browser/bot/unknown.
4. **Action phase:** Start with monitor-only rules for known-bot JA4s. Gradually escalate to challenge, then block.
5. **Maintenance phase:** Monitor for new JA4s (browser updates create new fingerprints). Refresh allowlist on major browser version releases.

---

## 9. References

### Specifications
- [JA4+ Technical Details (FoxIO)](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md)
- [JA4+ Suite Overview](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/README.md)
- [JA4 Blog Post (John Althouse)](https://blog.foxio.io/ja4%2B-network-fingerprinting)

### Databases & Tools
- [JA4DB](https://ja4db.com/) — Official JA4+ fingerprint database
- [JA4DB API Docs](https://docs.ja4db.com/ja4%2B-database/usage/read-the-database)
- [tls.peet.ws](https://tls.peet.ws/api/all) — Live TLS/JA3/JA4/HTTP2 reflection API
- [httpcloak Presets](https://httpcloak.dev/reference/presets/) — Verified browser fingerprint database

### Akamai Resources
- [Akamai JA3 EdgeWorker Example](https://github.com/akamai/edgeworkers-examples/tree/master/edgecompute/examples/authentication/ja3-fingerprinting)
- [Akamai JA4 EdgeWorker (nmckay77)](https://github.com/nmckay77/ja4-edgeworker) — Production-ready JA4 calculation
- [EdgeWorkers Documentation](https://techdocs.akamai.com/edgeworkers/docs)
- [Enhanced TLS / CPS Documentation](https://techdocs.akamai.com/cps/docs)

### Detection Context
- [Cloudflare JA4 Signals Blog](https://blog.cloudflare.com/ja4-signals)
- [bunny.net JA4 Fingerprinting Docs](https://docs.bunny.net/cdn/security/ja4-fingerprinting)
- [Scrapfly JA4 Test Tool](https://scrapfly.io/web-scraping-tools/ja3-fingerprint?algo=ja4)
- [Common JA4 Fingerprints Decoded (krowdev)](https://krowdev.com/article/common-ja4-fingerprints-decoded/)

### Implementation Libraries
- [curl_cffi](https://github.com/lexiforest/curl_cffi) — Python TLS impersonation
- [curl-impersonate](https://github.com/lexiforest/curl-impersonate) — Maintained fork of lwthiker/curl-impersonate
- [tlsprint](https://github.com/NotChaosuu/tlsprint) — CLI TLS fingerprint analyzer
- [JA4LookR](https://github.com/MikeVriesema/ja4LookR) — JA4DB lookup tool
