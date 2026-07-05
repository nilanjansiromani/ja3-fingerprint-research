# JA3 & JA4+ TLS Fingerprinting — Knowledge Base

A comprehensive, deeply researched reference on TLS fingerprinting spanning **JA3 (2017)** through **JA4+ (2026)** and everything in between.

## What's Inside

The single-file knowledge base (`JA3_JA4_KNOWLEDGE_BASE.md`, ~62KB, 1,486 lines) covers:

### Core Methods
| Method | What it fingerprints |
|---|---|
| **JA3 / JA3S** | TLS client & server (Salesforce 2017, MD5, passive) |
| **JARM** | TLS server (Salesforce 2020, active, 10-probe) |
| **JA4** | TLS/QUIC/DTLS client (FoxIO 2023, SHA-256, sorted) |
| **JA4S** | TLS server response |
| **JA4H** | HTTP client headers & cookies |
| **JA4T / JA4TS** | TCP SYN / SYN-ACK OS fingerprinting |
| **JA4X** | X.509 certificate structure |
| **JA4L / JA4LS** | Latency / light distance |
| **JA4SSH** | SSH traffic patterns |
| **JA4D / JA4D6** | DHCPv4 / DHCPv6 |

### Deep Dives (33 sections total)
- TLS Client Hello anatomy & extension reference
- GREASE (RFC 8701) — how it broke JA3 and how JA4 fixes it
- HTTP/2 (Akamai) fingerprinting — SETTINGS, WINDOW_UPDATE, PRIORITY, pseudo-header order
- ML/AI-based detection — CatBoost AUC 0.998, Cloudflare Signals Intelligence
- Post-quantum TLS — X25519MLKEM768, 1,216-byte key shares, fingerprint impact
- QUIC & HTTP/3 — transport parameters, dual-hash requirement
- Evasion techniques — uTLS, curl-impersonate, cipher stunting, ECH, CVE-2026-27017
- JA4DB — the FoxIO fingerprint database (~73K records, lookup tools)
- Legal & privacy — GDPR, CCPA, unblockability vs browser fingerprinting
- The detection layer cake — 9 layers from TCP to behavioral
- Complete comparison table — JA3 vs JA4 vs JARM vs Akamai H2
- Common TLS library fingerprints — Chrome/Firefox/Safari/Python/Go/curl/Node/Java/.NET
- Known malware C2 fingerprints — Cobalt Strike, Sliver, IcedID, DarkGate, Lumma
- Full reference list — academic papers, CDN docs, tools, testing sites

## Usage

```bash
# Browse the knowledge base
less JA3_JA4_KNOWLEDGE_BASE.md

# Search for specific topics
grep -i "post-quantum" JA3_JA4_KNOWLEDGE_BASE.md
grep -i "cobalt" JA3_JA4_KNOWLEDGE_BASE.md
grep -i "tcp options" JA3_JA4_KNOWLEDGE_BASE.md
```

## Quick Reference

### JA4 Format
```
t13d1516h2_8daaf6152771_e5627efa2ab1
││││││││  │           │
││││││││  │           └─ Extension hash (12 hex)
││││││││  └─ Cipher hash (12 hex)
││││││└└── ALPN "h2"
││││└└──── Extension count (16)
││└└────── Cipher count (15)
│└──────── SNI present (d=domain, i=IP)
└───────── Transport (t=TCP, q=QUIC, d=DTLS)
```

### Key CLI Tools
| Tool | What it does |
|---|---|
| `ja4plus` (Python) | Compute all JA4+ fingerprints from pcap |
| `ja4` (Rust binary) | PCAP analysis with JA4+ output |
| `ja4x` (Rust binary) | Compute JA4X from cert files |
| `ja4LookR` | JA4DB lookup with CLI + web |
| `tls.peet.ws` | Online TLS/H2 fingerprint tester |

## File Structure

```
.
├── README.md                   # This file
├── JA3_JA4_KNOWLEDGE_BASE.md   # The full knowledge base (1,486 lines)
├── opencode.json                # opencode MCP config (Craft Docs integration)
└── .git/
```

## Source Attribution

All information was gathered through web research (July 2026) from primary sources including:
- [salesforce/ja3](https://github.com/salesforce/ja3)
- [FoxIO-LLC/ja4](https://github.com/FoxIO-LLC/ja4)
- [RFC 8701 (GREASE)](https://datatracker.ietf.org/doc/html/rfc8701)
- [Cloudflare JA4 Signals](https://developers.cloudflare.com/bots/additional-configurations/ja3-ja4-fingerprint/)
- Academic papers (Springer, arXiv)
- Industry blogs (Fastly, Akamai, FoxIO)

## License

The knowledge base content is provided for reference. Individual fingerprint methods
have their own licenses (see section 22 in the knowledge base for details).
