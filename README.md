# JA3 & JA4+ TLS Fingerprinting — Knowledge Base + Bot Detection Server

A comprehensive TLS fingerprinting reference with a production-grade bot detection server using **JA4** fingerprinting.

## Project Overview

Two tightly coupled parts:

1. **Knowledge Base** — Deeply researched JA3/JA4+ reference (~62KB, 33 sections, 1,486 lines)
2. **Bot Detection Server** — Raw TCP TLS ClientHello parser with weighted-scoring classifier

## Bot Detection Server

Single-file Node.js server (`server.js`) that classifies TLS clients from raw TCP connections.

### Architecture

```
Client → TCP :9443 → parse ClientHello → compute JA4 → score signals → verdict
```

### Detection Signals (10 total)

| Signal | Weight | Accuracy |
|--------|--------|----------|
| JA4 exact match (KNOWN list) | 100% | 100% |
| Cipher count | +12/-3 | 100% |
| TLS version | +5 | 100% |
| Prefix heuristic | +15/-3 | 100% |
| GREASE presence | +8 | 100% |
| SNI presence | +5 | 86% |
| Extension count | +10 | 71% |
| ALPN check | +10 | 57% |
| Sigalg count | +5 | 29% |
| Group count | +4 | 29% |

### Scoring

- **>= 25**: High confidence bot
- **>= 15**: Medium confidence bot
- **default**: Low confidence bot
- **<= -10 + browser prefix**: Browser

### Quick Start

```bash
node server.js          # Start server on :9443
node test_fingerprints.mjs  # Run 7 real TLS clients
node break_test.mjs         # Run bypass tests
```

Curl example:
```bash
curl -k https://127.0.0.1:9443/check  # From this machine
# Or:
openssl s_client -connect 127.0.0.1:9443  # Raw TLS (paste GET /check HTTP/1.1\r\n\r\n)
```

### Test Results

**7/7 real bots correctly classified** (curl, openssl, Node.js, Python urllib):

```
┌────────────────────┬──────────┬──────┬─────┬─────────┬─────┬──────┐
│ Client             │ Verdict  │ Ciph │ Ext │ Grease  │ SNI │ ALPN │
├────────────────────┼──────────┼──────┼─────┼─────────┼─────┼──────┤
│ curl (Linux)       │ ⚠ BOT   │ 10   │ 3   │ 0       │ ✗   │ h2   │
│ curl (macOS)       │ ⚠ BOT   │ 10   │ 7   │ 0       │ ✓   │ h2   │
│ Node.js https      │ ⚠ BOT   │ 4    │ 5   │ 0       │ ✓   │ -    │
│ openssl s_client   │ ⚠ BOT   │ 20   │ 4   │ 0       │ ✓   │ -    │
│ Python urllib      │ ⚠ BOT   │ 4    │ 4   │ 0       │ ✓   │ -    │
│ Python requests    │ ⚠ BOT   │ 4    │ 4   │ 0       │ ✓   │ -    │
│ curl macOS (noSNI) │ ⚠ BOT   │ 10   │ 4   │ 0       │ ✗   │ -    │
└────────────────────┴──────────┴──────┴─────┴─────────┴─────┴──────┘
```

Per‑signal pass rate: **77.1%** (10 signals × 7 clients = 70 checks, 54 pass)

### Bypass Vectors & Countermeasures

| Vector | Threat | Status |
|--------|--------|--------|
| Bot injects GREASE | Tier 3 (low) | **Blocked** — caught by `exts_lt8` / low ext count |
| Bot mimics Chrome counts | Tier 2 (moderate) | **Blocked** — falls to low confidence bot (not browser) |
| uTLS/curl-impersonate | **Tier 1 (critical)** | **Bypasses TLS-only** — requires H2 SETTINGS or HTTP header analysis |

uTLS / curl-impersonate / curl_cffi produce byte‑for‑byte identical JA4 to real Chrome. Detection at the TLS layer is impossible — must use **Layer 2 (H2 Akamai fingerprint)** or **Layer 3 (HTTP headers/JA4H)**.

## Bypass Strategies

`BYPASS_STRATEGIES.md` catalogs 25 bypass techniques with feasibility, impact, detection difficulty, and Akamai mitigations:

- **Tier 1** (immediately dangerous): uTLS, curl-impersonate, curl_cffi
- **Tier 2** (moderate threat): GP assaults, GREASE injection, ECH/ESNI, padding manipulation
- **Tier 3** (low risk): OS adaptation, proxy/VPN, HTTP/1.1 downgrade

## File Structure

```
.
├── README.md                          # This file
├── JA3_JA4_KNOWLEDGE_BASE.md          # Full knowledge base (1,486 lines)
├── browser_fingerprints_platforms.md  # Production deliverable (638 lines)
├── server.js                          # TLS fingerprint + bot detection server
├── test_fingerprints.mjs              # Real TLS client test suite
├── break_test.mjs                     # Crafted ClientHello bypass tests
├── BYPASS_STRATEGIES.md               # 25 bypass strategies & mitigations
├── opencode.json                      # opencode MCP config (Craft Docs)
└── .git/
```

## Knowledge Base

### What's Inside (33 sections)

- TLS Client Hello anatomy & extension reference
- GREASE (RFC 8701) — how it broke JA3 and how JA4 fixes it
- HTTP/2 (Akamai) fingerprinting — SETTINGS, WINDOW_UPDATE, PRIORITY, pseudo-header order
- ML/AI-based detection — CatBoost AUC 0.998, Cloudflare Signals Intelligence
- Post-quantum TLS — X25519MLKEM768, 1,216-byte key shares, fingerprint impact
- QUIC & HTTP/3 — transport parameters, dual-hash requirement
- Evasion techniques — uTLS, curl-impersonate, cipher stunting, ECH, CVE-2026-27017
- JA4DB — FoxIO fingerprint database (~73K records, lookup tools)
- Legal & privacy — GDPR, CCPA, unblockability vs browser fingerprinting
- The detection layer cake — 9 layers from TCP to behavioral
- Complete comparison table — JA3 vs JA4 vs JARM vs Akamai H2
- Common TLS library fingerprints — Chrome/Firefox/Safari/Python/Go/curl/Node/Java/.NET
- Known malware C2 fingerprints — Cobalt Strike, Sliver, IcedID, DarkGate, Lumma
- Full reference list — academic papers, CDN docs, tools, testing sites

### Source Attribution

All information gathered through web research (July 2026) from primary sources including:
- [salesforce/ja3](https://github.com/salesforce/ja3)
- [FoxIO-LLC/ja4](https://github.com/FoxIO-LLC/ja4)
- [RFC 8701 (GREASE)](https://datatracker.ietf.org/doc/html/rfc8701)
- [Cloudflare JA4 Signals](https://developers.cloudflare.com/bots/additional-configurations/ja3-ja4-fingerprint/)
- Academic papers (Springer, arXiv), industry blogs (Fastly, Akamai, FoxIO)

## License

The knowledge base content is provided for reference. Individual fingerprint methods
have their own licenses (see section 22 in the knowledge base for details).
