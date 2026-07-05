# JA3, JA3S, JARM, JA4+ TLS Fingerprinting — Complete Knowledge Base

> Comprehensive reference on TLS fingerprinting: from JA3 (2017) through JA4+ (2023–2026).
> Covers every fingerprint method, algorithm details, GREASE, evasion, tools, and security applications.

---

## Table of Contents

1. [What Is TLS Fingerprinting?](#1-what-is-tls-fingerprinting)
2. [The TLS Client Hello — The Raw Material](#2-the-tls-client-hello--the-raw-material)
3. [GREASE Values](#3-grease-values)
4. [JA3 — The Original (Salesforce, 2017)](#4-ja3--the-original-salesforce-2017)
5. [JA3S — Server-Side Complement](#5-ja3s--server-side-complement)
6. [Problems with JA3](#6-problems-with-ja3)
7. [JARM — Active Server Fingerprinting (2020)](#7-jarm--active-server-fingerprinting-2020)
8. [JA4+ Suite Overview (FoxIO, 2023)](#8-ja4-suite-overview-foxio-2023)
9. [JA4 — TLS Client Fingerprinting](#9-ja4--tls-client-fingerprinting)
10. [JA4S — TLS Server Response Fingerprinting](#10-ja4s--tls-server-response-fingerprinting)
11. [JA4H — HTTP Client Fingerprinting](#11-ja4h--http-client-fingerprinting)
12. [JA4T / JA4TS — TCP Fingerprinting](#12-ja4t--ja4ts--tcp-fingerprinting)
13. [JA4X — X.509 Certificate Fingerprinting](#13-ja4x--x509-certificate-fingerprinting)
14. [JA4L / JA4LS — Latency / Light Distance](#14-ja4l--ja4ls--latency--light-distance)
15. [JA4SSH — SSH Traffic Fingerprinting](#15-ja4ssh--ssh-traffic-fingerprinting)
16. [JA4D / JA4D6 — DHCP Fingerprinting](#16-ja4d--ja4d6--dhcp-fingerprinting)
17. [JA4TScan — Active TCP Fingerprint Scanner](#17-ja4tscan--active-tcp-fingerprint-scanner)
18. [Known Fingerprint Databases](#18-known-fingerprint-databases)
19. [Evasion Techniques](#19-evasion-techniques)
20. [Tools & Implementations](#20-tools--implementations)
21. [Adoption in Production](#21-adoption-in-production)
22. [Licensing Notes](#22-licensing-notes)
23. [References & Further Reading](#23-references--further-reading)

---

## 1. What Is TLS Fingerprinting?

TLS fingerprinting is the **passive or active identification of a TLS peer** (client or server) by analysing the parameters it sends during the TLS handshake **before encryption begins**. The handshake's `ClientHello` and `ServerHello` messages are sent in plaintext and contain a rich set of negotiable parameters:

- TLS version
- Cipher suites offered
- Extensions (types, order, values)
- Elliptic curves / supported groups
- Elliptic curve point formats
- Signature algorithms
- ALPN values

Because different TLS libraries (OpenSSL, BoringSSL, NSS, SChannel, Secure Transport, GnuTLS, LibreSSL, Rustls, Go crypto/tls) and different versions of the same library produce **different combinations and orderings** of these parameters, the resulting fingerprint can identify:

- The **TLS library** and its version
- The **operating system** (through defaults)
- The **browser or application** (Chrome vs Firefox vs Safari vs curl vs Python requests)
- **Malware families** (Cobalt Strike, Sliver, IcedID, etc.)
- **Scrapers and bots**

---

## 2. The TLS Client Hello — The Raw Material

The TLS Record Layer and Handshake Protocol structure:

```
+------+------+----------+------------------+
| Type | Ver  | Length   | Handshake Message |
+------+------+----------+------------------+
 1 byte  2 bytes  2 bytes
```

Inside the `ClientHello` handshake message:

| Field | Size | Description |
|---|---|---|
| Protocol Version | 2 bytes | Legacy version (e.g., 0x0303 for TLS 1.2) |
| Random | 32 bytes | Client random |
| Session ID | variable | For session resumption |
| Cipher Suites | variable | List of 2-byte cipher suite codes in preference order |
| Compression Methods | variable | Usually just `0x00` (null) |
| Extensions | variable | Type-Length-Value blocks |

Key extension IDs (decimal):

| ID (hex) | Name |
|---|---|
| 0x0000 | server_name (SNI) |
| 0x0001 | max_fragment_length |
| 0x0005 | status_request (OCSP stapling) |
| 0x000a | supported_groups (formerly elliptic_curves) |
| 0x000b | ec_point_formats |
| 0x000d | signature_algorithms |
| 0x0010 | application_layer_protocol_negotiation (ALPN) |
| 0x0012 | signed_certificate_timestamp |
| 0x0015 | certificate_compression |
| 0x0017 | extended_master_secret |
| 0x001b | pre_shared_key (TLS 1.3) |
| 0x0023 | session_ticket |
| 0x002b | supported_versions |
| 0x002d | psk_key_exchange_modes |
| 0x0033 | key_share |
| 0x4469 | application_settings (HTTP/3) |
| 0xff01 | renegotiation_info |

GREASE extension IDs: `0x0a0a`, `0x1a1a`, `0x2a2a`, `0x3a3a`, `0x4a4a`, `0x5a5a`, `0x6a6a`, `0x7a7a`, `0x8a8a`, `0x9a9a`, `0xaaaa`, `0xbaba`, `0xcaca`, `0xdada`, `0xeaea`, `0xfafa`.

---

## 3. GREASE Values

**GREASE** = Generate Random Extensions And Sustain Extensibility ([RFC 8701](https://datatracker.ietf.org/doc/html/rfc8701))

Introduced by Google (David Benjamin) in Chrome circa 2018. The purpose is **anti-ossification**: by including randomly selected reserved/unknown values in ClientHellos, the TLS ecosystem is forced to properly ignore unknown values rather than hardcoding "known" values.

### Where GREASE appears

- **Cipher suites**: reserved values like `0x0a0a`, `0x1a1a`, etc.
- **Extensions**: reserved extension type IDs
- **Supported groups**: reserved group IDs
- **ALPN IDs**: reserved ALPN strings
- **Signature algorithms**: reserved sig-alg codes

### Impact on fingerprinting

- GREASE values **change per connection** — every connection from the same browser sends different GREASE garbage.
- JA3 includes these values verbatim → JA3 changes every connection even from the same Chrome build.
- JA4 **ignores GREASE values** during counting and hashing → stable fingerprint despite GREASE.

### RFC 8701 Rules

- Clients MUST reject GREASE values when negotiated by the server.
- Servers MUST ignore GREASE values from clients (but not fail).
- Implementations advertising GREASE SHOULD select them at random.
- Duplicate GREASE values in the same extension block are forbidden.

---

## 4. JA3 — The Original (Salesforce, 2017)

**Authors**: John Althouse, Jeff Atkinson, Josh Atkins (initials: J.A.3 → JA3)  
**Released**: January 2017  
**Scope**: TLS client fingerprinting (passive)  
**License**: BSD-3-Clause  
**Repository**: [https://github.com/salesforce/ja3](https://github.com/salesforce/ja3)

### Algorithm

JA3 extracts five fields from the TLS ClientHello and concatenates them:

```
JA3_string = SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
JA3_hash   = MD5(JA3_string)
```

| Field | Separator | Description |
|---|---|---|
| SSLVersion | (first field) | TLS version as a decimal integer (e.g., `771` for TLS 1.2) |
| Ciphers | `-` between values | Decimal IDs of cipher suites, in observed order |
| Extensions | `-` between values | Decimal IDs of extension types, in observed order |
| EllipticCurves | `-` between values | Decimal IDs of supported groups, in observed order |
| ECPointFormats | `-` between values | Decimal IDs of EC point formats, in observed order |

Fields separated by `,`. Values within each field separated by `-`.

### Example

```
JA3_string = 769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-11-10-35-22-23-13-12-9-25-24,29-23-24-25-26,0
JA3_hash   = de350869b8c85de67a350c8d186f11e6
```

### JA3S — Server Side

JA3S follows the same pattern but from the ServerHello:

```
JA3S_string = TLSVersion,SelectedCipher,Extensions
JA3S_hash    = MD5(JA3S_string)
```

3 fields instead of 5 (server only sends: version, one selected cipher, extensions).

Originally included EllipticCurves but was later removed — servers usually don't send it.

### Known JA3 Hashes (examples)

| Client | JA3 Hash |
|---|---|
| Chrome 120 | `cd08e31494f9531f560d64c695473da9` |
| Firefox 120 | `b32309a26951912be7dba376398abc3b` |
| Python requests | `3e0b127d4449c6e4b8e5f5e5d39e6b6d` |
| Go net/http | `c0e9345684785f2f4e5e7d0e8f88e489` |
| curl 7.x | `456523fc94726331a4d5a2e1d40b2cd7` |
| Scrapy | `b5a7b68e40f3e60a3e8e49a91a3c7b25` |

### Code Example (Python)

```python
import hashlib
import struct

def calculate_ja3(client_hello):
    tls_version = client_hello['version']
    ciphers = '-'.join(str(c) for c in client_hello['cipher_suites'])
    extensions = '-'.join(str(e) for e in client_hello['extensions'])
    curves = '-'.join(str(c) for c in client_hello['elliptic_curves'])
    point_formats = '-'.join(str(p) for p in client_hello['point_formats'])
    ja3_string = f"{tls_version},{ciphers},{extensions},{curves},{point_formats}"
    ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()
    return ja3_string, ja3_hash
```

---

## 5. JA3S — Server-Side Complement

JA3S fingerprints the **server's TLS response** (ServerHello).

### Algorithm

```
JA3S_string = TLSVersion,SelectedCipher,Extensions
JA3S_hash   = MD5(JA3S_string)
```

3 fields:
1. **TLS Version** the server negotiated
2. **Accepted Cipher** (single, the one the server chose)
3. **Extensions** the server sends back (in order)

### Key Insight

The same server will respond **differently to different clients**. A server sends different ServerHellos to Chrome vs curl depending on what the client offered. But the **same client always gets the same response** from the same server.

**JA3 + JA3S combined** creates a fingerprint of the entire cryptographic negotiation. This pairing dramatically reduces false positives for threat detection.

---

## 6. Problems with JA3

### A. Order Sensitivity

JA3 hashes the cipher and extension lists **in the order they appear**. Two functionally identical TLS stacks that shuffle their extension order produce completely different JA3 hashes.

### B. GREASE (Chrome 2018+)

Chrome injects random reserved values (GREASE) into every ClientHello. These values change per connection, causing the JA3 hash to change per connection for the same browser build. Any database keyed on JA3 becomes useless.

### C. Extension Randomization (Chrome 2023+)

Chrome began randomizing the **order of TLS extensions**. Since JA3 encodes order, every connection from a single Chrome instance produces a different JA3. This was a deliberate privacy measure that intentionally broke JA3.

### D. Cipher Stunting

Malware authors discovered they could simply **shuffle the cipher list** or append/remove cipher suites to change their JA3 fingerprint. This evasion technique, called "cipher stunting," was documented by Akamai in 2019.

### E. MD5 Collisions

MD5 is used as a database key (not for security), but collisions are possible — two distinct TLS profiles can produce the same JA3 hash, generating false positives/negatives.

### F. No TLS 1.3 Specifics

JA3 doesn't handle `supported_versions` extension properly for TLS 1.3 negotiation.

---

## 7. JARM — Active Server Fingerprinting (2020)

**Author**: John Althouse (Salesforce)  
**Released**: November 2020  
**Scope**: Active TLS server fingerprinting  
**Method**: Sends 10 specially-crafted ClientHello packets → analyzes ServerHello responses

### How JARM Works

JARM actively probes a server with 10 different TLS ClientHello packets, each varying in:
- TLS version (SSLv3, TLS 1.0, 1.1, 1.2, 1.3)
- Cipher suite ordering (forward, reverse, GREASE-injected)
- Extension presence/absence

The 10 probes ask:
1. What TLS version does the server support?
2. Will it negotiate TLS 1.3 with TLS 1.2 ciphers?
3. If ciphers are ordered weakest→strongest, which does it pick?
4. Does it handle GREASE correctly?
5. How does it respond to minimal ClientHellos?

### The 10 Probes

| # | TLS Ver | Cipher Order | Extensions | Notes |
|---|---|---|---|---|
| 1 | 1.2 | Forward | All supported | Baseline |
| 2 | 1.2 | Reverse | All supported | Weakest-first test |
| 3 | 1.2 | Forward | No extensions | Minimal probe |
| 4 | 1.1 | Forward | All supported | Lower version test |
| 5 | 1.3 | TLS 1.3 only | All supported | Pure 1.3 |
| 6 | 1.3 | TLS 1.3 + 1.2 | All supported | Cross-version |
| 7 | 1.2 | GREASE injected | GREASE extensions | GREASE handling |
| 8 | 1.2 | Forward | max_fragment_length only | Minimal extension |
| 9 | 1.0 | Export-grade first | All supported | Legacy test |
| 10 | SSLv3 | ALL (incl. null) | None | Maximum compatibility |

### Fingerprint Format

```
JARM = [30 chars cipher+version fuzzy hash][32 chars SHA-256 truncated extension hash]
```

- **First 30 chars**: Reversible encoding of which cipher and version the server chose for each probe. `000` = refused to negotiate.
- **Last 32 chars**: Truncated SHA-256 of the cumulative extensions across all 10 responses.

If two servers share the same first 30 chars but different last 32, they have similar TLS configs but different extension support.

### Known JARM Hashes

| JARM Hash (truncated) | Matched Framework |
|---|---|
| `2ad2ad0002ad...` | Cobalt Strike 3.x–4.4 |
| `07d14d16d21d...` | Metasploit 5.x–6.x |
| `29d29d00029d...` | AsyncRAT / njRAT |
| `15d15d000000...` | Sliver C2 (Go TLS) |
| `3fd3fd0003fd...` | Brute Ratel C4 |

### JARM Limitations

- Active probe (not passive) — generates traffic
- Some servers return different JARM depending on SNI vs IP
- Load balancers that terminate TLS hide the backend
- Consistent per server/configuration

---

## 8. JA4+ Suite Overview (FoxIO, 2023)

**Author**: John Althouse (FoxIO)  
**Released**: September 2023  
**Scope**: Multi-protocol fingerprinting suite replacing JA3  
**Repository**: [https://github.com/FoxIO-LLC/ja4](https://github.com/FoxIO-LLC/ja4)

### Why JA4+ Was Created

JA3 had six years of known problems:
1. Extension ordering sensitivity (broken by Chrome's randomization)
2. GREASE (changed per-connection values)
3. Cipher stunting (simple reordering evasion)
4. Single opaque hash (no partial matching)
5. TLS-only scope
6. No QUIC support

### Design Principles

- **Locality-preserving**: `a_b_c` format — each section independently searchable. Match on `ab`, `ac`, or just `c`.
- **Human-readable**: Part A contains plaintext metadata (protocol, version, counts).
- **Sort-normalized**: Ciphers and extensions are sorted before hashing → ordering-agnostic.
- **GREASE-resistant**: GREASE values are stripped before counting and hashing.
- **Multi-protocol**: TLS, QUIC, HTTP, TCP, SSH, X.509, DHCP, latency.

### Complete Method Inventory (as of 2026)

| Method | Short Name | Description |
|---|---|---|
| JA4 | JA4 | TLS Client Fingerprinting |
| JA4Server | JA4S | TLS Server Response / Session Fingerprinting |
| JA4HTTP | JA4H | HTTP Client Fingerprinting |
| JA4Latency | JA4L | Client→Server Latency / Light Distance |
| JA4LatencyServer | JA4LS | Server→Client Latency |
| JA4X509 | JA4X | X.509 TLS Certificate Fingerprinting |
| JA4SSH | JA4SSH | SSH Traffic Fingerprinting |
| JA4TCP | JA4T | TCP Client Fingerprinting (from SYN) |
| JA4TCPServer | JA4TS | TCP Server Response Fingerprinting (from SYN-ACK) |
| JA4TCPScan | JA4TScan | Active TCP Fingerprint Scanner |
| JA4DHCP | JA4D | DHCP Fingerprinting |
| JA4DHCPv6 | JA4D6 | DHCPv6 Fingerprinting |

---

## 9. JA4 — TLS Client Fingerprinting

**The core method.** Fingerprints TLS clients from ClientHello messages over TCP, QUIC, or DTLS.

### Algorithm

```
JA4 = {protocol}{tls_version}{sni}{cipher_count}{ext_count}{alpn} _{cipher_hash} _{extension_hash}
```

### Part A — Unhashed Metadata (12 characters)

| Position | Length | Field | Values |
|---|---|---|---|
| 1 | 1 | Transport | `t`=TCP, `q`=QUIC, `d`=DTLS |
| 2-3 | 2 | TLS version | `13`=TLS 1.3, `12`=TLS 1.2, `11`=TLS 1.1, `10`=TLS 1.0, `s3`=SSL 3.0, `s2`=SSL 2.0, `d1`=DTLS 1.0, `d2`=DTLS 1.2, `d3`=DTLS 1.3, `00`=unknown |
| 4 | 1 | SNI | `d`=domain (SNI present), `i`=IP (no SNI) |
| 5-6 | 2 | Cipher count | Number of cipher suites (excluding GREASE), zero-padded. Max `99`. |
| 7-8 | 2 | Extension count | Number of extensions (excluding GREASE), zero-padded. Max `99`. Includes SNI and ALPN. |
| 9-10 | 2 | ALPN | First and last ASCII alphanumeric chars of first ALPN value. `00` if none. |

### TLS Version Resolution

If extension `0x002b` (supported_versions) exists: use its highest value (ignoring GREASE).  
Otherwise: use the Protocol Version field.  
Ignore the Handshake Version (top of the record).

### Part B — Cipher Hash (12 chars)

```
SHA-256(ciphers_sorted_hex_comma_delimited)[:12]
```

- Take all cipher suite hex codes (lowercase, 4 chars each, e.g., `1301`)
- Remove GREASE values
- Sort in hex order (ascending)
- Join with `,`
- SHA-256 the result
- Take first 12 hex characters
- If empty list → `000000000000`

### Part C — Extension Hash (12 chars)

```
SHA-256(
    extensions_sorted_hex_comma_delimited
    + "_"
    + signature_algorithms_in_order_comma_delimited
)[:12]
```

- Take all extension type hex codes (4 chars, lowercase)
- Remove GREASE values
- **Remove SNI (0000) and ALPN (0010)** — already captured in Part A
- Sort remaining extensions in hex order
- Join with `,`
- Append `_` + signature algorithm hex codes in **original order**
- SHA-256 the whole string
- Take first 12 hex characters
- If no extensions → `000000000000`
- If no signature algorithms → no `_` suffix, hash the sorted extensions alone

### Example

```
ClientHello fields:
- TLS version: 1.3 (0x0304)
- SNI: example.com
- 15 ciphers (after GREASE removal)
- 16 extensions (after GREASE removal)
- First ALPN: h2

Ciphers (hex, sorted):
002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9
→ SHA-256 → "8daaf6152771..." → c_hash = "8daaf6152771"

Extensions (hex, sorted, SNI+ALPN removed):
0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01

Signature algorithms (original order):
0403,0804,0401,0503,0805,0501,0806,0601

Combined:
0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601
→ SHA-256 → "e5627efa2ab1..." → e_hash = "e5627efa2ab1"

JA4 = t13d1516h2_8daaf6152771_e5627efa2ab1
```

### Raw Output

With `-r` (raw, sorted):

```
JA4_r = t13d1516h2_002f,0035,...,cca9_c0005,...,ff01_0403,...,0601
```

With `-o` (original order, GREASE removed):

```
JA4_ro = t13d1516h2_1301,1302,...,0035_001b,0000,0033,...,0015_0403,...,0601
JA4_o  = t13d1516h2_acb858a92679_18f69afefd3d
```

---

## 10. JA4S — TLS Server Response Fingerprinting

Fingerprints the **server's ServerHello** response. Only works on a full ServerHello (not session resumption or rejected connections).

### Format

```
JA4S = {protocol}{tls_version}{ext_count}{alpn}_{cipher}_{extension_hash}
```

| Section | Chars | Field | Notes |
|---|---|---|---|
| protocol | 1 | `t`/`q`/`d` | Same as JA4 |
| tls_version | 2 | Version the server selected | e.g., `13` |
| ext_count | 2 | Number of extensions in ServerHello | Zero-padded |
| alpn | 4 | Two ALPN values (2 chars each) | First 2 chars of first & second ALPN value |
| _ | 1 | Separator | |
| cipher | 4 | The single cipher suite selected | 4-char hex, e.g., `1301`, `c030` |
| _ | 1 | Separator | |
| extension_hash | 12 | SHA-256 truncated of extensions | **In observed order** (NOT sorted!) |

### Key Differences from JA4

- Server selects **one** cipher (vs a list)
- Extensions are **not sorted** — server ordering is signal (servers don't randomize)
- GREASE values **are included** per spec
- No SNI field (server doesn't send SNI)
- No cipher count (only one cipher)

### Example

```
JA4S = t120400_c030_4e8089b08790
```

- `t` = TCP
- `12` = TLS 1.2
- `04` = 4 extensions
- `00` = no ALPN
- `c030` = TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
- `4e8089b08790` = truncated SHA-256 of extensions in observed order

### JA4 + JA4S Pairing

Pairing JA4 and JA4S creates a **bidirectional fingerprint** of the entire TLS negotiation. This is significantly more powerful than either alone:

- JA4 alone: identifies the client's TLS library
- JA4 + JA4S: can identify the **specific application or malware family**

Example known pairs from FoxIO database:

| Malware | JA4 | JA4S |
|---|---|---|
| IcedID | `t13d201100_2b729b4bf6f3_9e7b989ebec8` | `t120300_c030_5e2616a54c73` |
| Sliver C2 | `t13d190900_...` | `t130200_1301_a56c5b993250` |

---

## 11. JA4H — HTTP Client Fingerprinting

Fingerprints the HTTP client **per HTTP request**. Meant for use at TLS-terminating proxies, WAFs, load balancers, or anywhere decrypted HTTP is visible. Also works on cleartext HTTP (malware like IcedID dropper).

### Format

```
JA4H = {method}{version}{cookie}{referer}{header_count}{lang}_{header_hash}_{cookie_name_hash}_{cookie_value_hash}
```

### Part A — 10 Characters (Unhashed)

| Chars | Field | Values |
|---|---|---|
| 0-1 | Method | `ge`=GET, `po`=POST, `pu`=PUT, `de`=DELETE, `pa`=PATCH, `he`=HEAD, `op`=OPTIONS, `xx`=unknown |
| 2-3 | HTTP version | `10`=HTTP/1.0, `11`=HTTP/1.1, `20`=HTTP/2, `30`=HTTP/3 |
| 4 | Cookie | `c`=present, `n`=absent |
| 5 | Referer | `r`=present, `n`=absent |
| 6-7 | Header count | Number of headers (excluding Cookie and Referer), zero-padded, max `99` |
| 8-9 | Accept-Language | First 2 characters of Accept-Language value, or `00` if absent |

### Part B — Header Hash (12 chars)

Truncated SHA-256 of **header names in the order they appear on the wire** (excluding Cookie, Referer, and any pseudo-headers).

Header order is a strong signal — real browsers emit headers in a stable, version-specific order that hand-built HTTP clients rarely reproduce.

### Part C — Cookie Name Hash (12 chars)

Truncated SHA-256 of sorted cookie field names (not values). Useful for grouping clients by which cookies they carry without exposing cookie values (privacy-aware).

### Part D — Cookie Value Hash (12 chars)

Truncated SHA-256 of sorted `name=value` cookie pairs. Identifies individual sessions/users.

### Examples

| Client | JA4H |
|---|---|
| Chrome to cnn.com | `ge20cr13enus_974ebe531c03_b66fa821d02c_e97928733c74` |
| IcedID malware | `ge11cn020000_9ed1ff1f7b03_cd8dafe26982` |
| Cobalt Strike | `ge11cn060000_4e59edc1297a_4da5efaf0cbd_77ba3814cca4` |

### Detection Power

- Missing `Accept-Language` → classic bot tell (IcedID and Cobalt Strike both use `0000`)
- JA4H_ab → identifies the application for a given HTTP method
- JA4H_c → groups clients by website/application (Plex, Okta servers have unique cookie fields)
- JA4H_d → tracks individual users without PII/GDPR concerns

---

## 12. JA4T / JA4TS — TCP Fingerprinting

Fingerprints the **operating system or TCP stack** from the SYN packet (**before** TLS or HTTP exist). Works at Layer 4.

### JA4T — TCP Client (from SYN)

```
JA4T = {window_size}_{tcp_options}_{mss}_{window_scale}
```

| Field | Example | Meaning |
|---|---|---|
| window_size | `64240` | Raw TCP receive window from SYN (before window-scale multiplication) |
| tcp_options | `2-4-8-1-3` | TCP option kind numbers in **original packet order** (never sorted) |
| mss | `1460` | Maximum Segment Size |
| window_scale | `8` | TCP Window Scale value; `00` if absent |

### TCP Option Codes

| Code | Option |
|---|---|
| 0 | EOL (End of Options List) |
| 1 | NOP (No-Operation / padding) |
| 2 | MSS (Maximum Segment Size) |
| 3 | Window Scale |
| 4 | SACK Permitted |
| 5 | SACK (Selective ACK) |
| 8 | Timestamps |
| 14 | Fast Open (TFO) |
| 15 | MP-TCP |
| 34 | TCP-AO / FO |

### Common OS Signatures

| Options Sequence | OS |
|---|---|
| `2-4-8-1-3` | Linux kernel 4.x+ |
| `2-1-3-1-1-4` | Windows 10/11 (no timestamps, SACK last) |
| `2-1-3-1-1-8-4-0-0` | macOS / iOS (timestamp after window scale, EOL padding) |
| `2-1-3` | **HIGHLY SUSPICIOUS** — minimal stack, custom tooling (nmap, masscan) |

### MSS Signal

- `1460` = standard Ethernet (MTU 1500 - IPv4 20 - TCP 20)
- `< 1460` = VPN, tunnel, mobile carrier, or proxy overhead
- `8961+` = AWS jumbo frames or similar

### JA4TS — TCP Server (from SYN-ACK)

Same format as JA4T but extracted from the SYN-ACK packet:

```
JA4TS = {window_size}_{tcp_options}_{mss}_{window_scale}
```

Server responses depend on the client's SYN (e.g., if client doesn't send SACK, server won't echo it). Therefore JA4TS is a **Server Response** fingerprint, not a pure server fingerprint. For pure server fingerprinting, use JA4TScan.

### Detection Uses

- OS detection (Linux vs Windows vs macOS vs IoT)
- VPN/proxy/tunnel detection (MSS < 1460)
- NAT detection
- Port scan identification (minimal TCP options = scanner)
- Zero-day / IoT / headless device identification
- Blocking bot traffic before TLS negotiation even starts

---

## 13. JA4X — X.509 Certificate Fingerprinting

Fingerprints the **structure** of X.509 TLS certificates by hashing the OID (Object Identifier) sequences from the certificate fields.

```
JA4X = {issuer_hash}_{subject_hash}_{extension_hash}
```

| Section | Chars | Description |
|---|---|---|
| issuer_hash | 12 | SHA-256 truncated of the OID sequence from the Issuer field |
| subject_hash | 12 | SHA-256 truncated of the OID sequence from the Subject field |
| extension_hash | 12 | SHA-256 truncated of OIDs from X.509v3 extensions |

Ja4X identifies the **certificate profile** — which fields and extensions are present and in what order. This differs from a certificate hash (which identifies a specific cert) or subject hash (which identifies an entity).

### Use Cases

- Grouping certificates issued by the same CA or generated by the same tool
- Detecting self-signed certificates with unusual structures
- Augmenting JA4 + JARM for server-side identification
- FoxIO guidance: combine JA4X with JA4, JARM, or issuer organization for best results

### Implementation

Available as `ja4x` CLI utility (reads DER or PEM cert files):

```
ja4x cert.pem
ja4x --json cert.der
```

---

## 14. JA4L / JA4LS — Latency / Light Distance

Measures the **physical distance** (light distance) between client and server by timing low-level machine-generated packets.

```
JA4L = JA4L-{C|S}={latency_us}_{ttl}
JA4LS = JA4LS-{C|S}={latency_us}_{ttl}
```

| Component | Description |
|---|---|
| C/S | Client or Server direction |
| latency_us | Time in microseconds |
| ttl | IP Time-To-Live value |

### Measurement Points

- **TCP**: Uses the TCP 3-way handshake timing (SYN → SYN-ACK → ACK)
- **QUIC**: Uses the QUIC handshake timing
- Time is measured in **microseconds** (µs). 1 ms = 1000 µs.

The first few packets are chosen because they are low-level machine-generated with nearly zero processing delay.

### Use Cases

- Detecting geographical anomalies (traffic from unexpected regions)
- Identifying CDN/proxy usage (latency doesn't match claimed origin)
- Adding a layer of user/device verification

---

## 15. JA4SSH — SSH Traffic Fingerprinting

Classifies SSH traffic by analyzing **packet direction, count, and ACK patterns** rather than the encrypted payload.

```
JA4SSH = c{mode1}s{mode2}_c{pkts}s{pkts}_c{acks}s{acks}
```

| Component | Description |
|---|---|
| c{mode1} | Client mode classification |
| s{mode2} | Server mode classification |
| c{pkts} | Client packet count |
| s{pkts} | Server packet count |
| c{acks} | Client ACK count |
| s{acks} | Server ACK count |

Passive, traffic-pattern-based classification that works on **encrypted SSH**.

---

## 16. JA4D / JA4D6 — DHCP Fingerprinting

Fingerprints DHCP clients and servers based on DHCP protocol options in DHCPv4 and DHCPv6 messages.

- **JA4D**: DHCPv4 fingerprinting (per-packet)
- **JA4D6**: DHCPv6 fingerprinting (per-packet)

DHCP options are set by the DHCP client implementation (different OSes use different option sets and orders), making this useful for device identification even before TCP/IP communication begins.

---

## 17. JA4TScan — Active TCP Fingerprint Scanner

**Repository**: [https://github.com/FoxIO-LLC/ja4tscan](https://github.com/FoxIO-LLC/ja4tscan)

An **active** TCP fingerprint scanner designed to produce a reliable server TCP fingerprint by:

1. Sending a single SYN packet with **all common TCP options**
2. Listening for SYN-ACK retransmissions (does NOT respond with ACK)
3. Measuring delays between retransmissions
4. Appending the delay pattern as section `e` of the fingerprint
5. Adding `R` prefix if an RST is observed

**Purpose**: Unlike passive JA4TS (which varies depending on the client's SYN), JA4TScan sends the same comprehensive SYN to every target, producing a **deterministic fingerprint of the server itself**.

---

## 18. Known Fingerprint Databases

### FoxIO JA4+ Mapping

File: `ja4plus-mapping.csv` in the [FoxIO JA4 repository](https://github.com/FoxIO-LLC/ja4)

Maps known JA4 fingerprints to:

| Entry | Example |
|---|---|
| Chrome (various versions) | JA4, JA4S, JA4H, JA4T, JA4X |
| Firefox | JA4, JA4S |
| Safari | JA4 |
| Python requests/urllib | JA4 |
| Go TLS clients | JA4 |
| curl | JA4 |
| Cobalt Strike | JA4, JA4S, JA4H |
| Sliver C2 | JA4, JA4S, JA4H, JA4X |
| IcedID | JA4, JA4H |
| DarkGate | JA4H |
| Lumma C2 | JA4H |
| Meterpreter | JA4 |
| AsyncRAT | JA4 |

### JARM Database

Available on the [JARM GitHub](https://github.com/salesforce/jarm) — community-contributed mapping of known C2 and malware servers.

---

## 19. Evasion Techniques

### A. TLS Library Spoofing (uTLS / curl-impersonate)

**uTLS**: Go library fork of `crypto/tls` that allows constructing arbitrary ClientHellos. Can "parrot" Chrome, Firefox, Safari, iOS, and Android fingerprints.

**curl-impersonate**: Patches curl at compile time to use BoringSSL with Chrome's exact cipher list, extension list, GREASE values, and compression methods. Produces identical JA4 to Chrome.

**Python wrappers**: `curl_cffi` exposes curl-impersonate functionality in Python.

Limitation: Must keep up with browser releases. "Match Chrome from a year ago" is a fingerprint that doesn't match current Chrome.

### B. Cipher Stunting

Documented by Akamai (2019). Malware randomizes or shuffles its cipher list to evade JA3. Less effective against JA4 (which sorts before hashing).

### C. Extension Randomization

Chrome does this by default (since 2023). Breaks JA3. JA4's sort-normalization handles this.

### D. Encrypted Client Hello (ECH)

ECH encrypts the **inner** ClientHello, including SNI, ALPN, and some extensions. The **outer** ClientHello (with a cover-domain SNI) remains fingerprintable.

Impact: Reduces visibility into the true destination. All users behind an ECH-enabled CDN look similar at the metadata layer. Forces defenders toward behavioral analysis (timing, volume, HTTP/2 vs HTTP/3 ratios).

### E. Layer-7 Spoofing

JA4H is harder to spoof than JA4 because:
- Header order must match a real browser exactly
- HTTP/2 SETTINGS frames must match
- Accept-Language must be present for interactive browsers
- Cookies must be implemented correctly

Tools like curl-impersonate don't currently spoof JA4H, but it's possible with sufficient effort.

### F. uTLS CVE-2026-27017

In uTLS 1.6.0–1.8.0, the Chrome parrot had a bug: it hardcoded AES for the outer cipher but randomly chose AES or ChaCha20 for ECH cipher suites. Chrome always uses the same preference consistently. This created a 50% detection probability per connection. Fixed in 1.8.1.

### G. The Arms Race

Sophisticated evasion requires matching **all layers**:
1. TCP SYN (JA4T) — OS kernel, hard to change without raw sockets
2. TLS ClientHello (JA4) — can be spoofed with uTLS/curl-impersonate
3. TLS ServerHello (JA4S) — attacker can't control this (server chooses)
4. HTTP headers (JA4H) — harder to spoof consistently
5. HTTP/2 framing (stream weights, SETTINGS, PUSH_PROMISE order)
6. Behavioral (timing, mouse movements, canvas fingerprinting)

Each layer adds cost to evasion.

---

## 20. Tools & Implementations

### Official Implementations

| Implementation | Language | Maintainer | Link |
|---|---|---|---|
| JA4+ | Python | FoxIO | [/python](https://github.com/FoxIO-LLC/ja4/tree/main/python) |
| JA4+ | Rust | FoxIO | [/rust](https://github.com/FoxIO-LLC/ja4/tree/main/rust) |
| JA4+ | C (Wireshark plugin) | FoxIO | [/wireshark](https://github.com/FoxIO-LLC/ja4/tree/main/wireshark) |
| JA4+ | Zeek script | FoxIO | [/zeek](https://github.com/FoxIO-LLC/ja4/tree/main/zeek) |
| JA3 | Python + Zeek | Salesforce | [salesforce/ja3](https://github.com/salesforce/ja3) |
| JARM | Go | Salesforce | [salesforce/jarm](https://github.com/salesforce/jarm) |

### Third-Party Libraries

| Library | Language | Coverage | Link |
|---|---|---|---|
| ja4plus | Python | All JA4+ methods | [Crank-Git/ja4plus](https://github.com/Crank-Git/ja4plus) |
| ja4plus-go | Go | All JA4+ methods | [Crank-Git/ja4plus-go](https://github.com/Crank-Git/ja4plus-go) |
| tlsfingerprint | Go | JA3 + JA4 | [psanford/tlsfingerprint](https://github.com/psanford/tlsfingerprint) |
| go-ja4x | Go | JA4X | [driftnet-io/go-ja4x](https://github.com/driftnet-io/go-ja4x) |
| ja3-rs | Rust | JA3 | [jabedude/ja3-rs](https://github.com/jabedude/ja3-rs) |
| ja3_4java | Java | JA3 | [lafaspot/ja3_4java](https://github.com/lafaspot/ja3_4java) |
| caddy-ja3ja4 | Go (Caddy) | JA3 + JA4 | [josuebrunel/caddy-ja3ja4](https://github.com/josuebrunel/caddy-ja3ja4) |
| TrackMe | Go | JA3/JA4 | [pagpeter/TrackMe](https://github.com/pagpeter/TrackMe) |
| nginx-ssl-ja3 | Nginx module | JA3 | [fooinha/nginx-ssl-ja3](https://github.com/fooinha/nginx-ssl-ja3) |
| kong-ja4h | Kong plugin | JA4H | [hroost/kong-ja4h-fingerprint](https://github.com/hroost/kong-ja4h-fingerprint) |
| netcap | Go | JA4+ | [dreadl0ck/netcap](https://github.com/dreadl0ck/netcap) |

### Vendor/Platform Support

| Platform | Support |
|---|---|
| **Wireshark** | JA4+ (official plugin from FoxIO) |
| **Zeek** | JA4+ (official script from FoxIO), JA3/JA3S |
| **Suricata** | JA4+ (under development), JA3 supported |
| **Arkime** (formerly Moloch) | JA4+ |
| **Cloudflare** | JA4 (bot detection, WAF) |
| **AWS WAF** | JA3 fingerprint matching, JA4 |
| **AWS CloudFront** | JA4 |
| **Google Cloud Armor** | JA4 |
| **Akamai** | JA3 bot detection |
| **Vercel** | JA4 |
| **ngrok** | JA4 |
| **GreyNoise** | JA4+ |
| **Hunt** (hunt.io) | JA4+ |
| **Driftnet** | JA4+ |
| **Censys** | JARM, JA4TScan (upcoming) |
| **Palo Alto Networks** | JA4 |
| **F5 BIG-IP** | JA4+ |
| **NGINX** | JA4+ (module from FoxIO) |
| **ntop/nDPI** | JA4 |
| **nfdump** | JA4+ |
| **VirusTotal** | JA3 (Jujubox), JA4+ |
| **Elastic Packetbeat** | JA3 |
| **Splunk** | JA3 (via add-on) |
| **IBM QRadar** | JA3 |
| **Azure Firewall** | JA3 (IDPS) |
| **Corelight** | JA3, JA4+ |

---

## 21. Adoption in Production

### Who Uses What

- **CDNs and reverse proxies** (Cloudflare, Vercel, ngrok, Akamai, AWS CloudFront, GCP Cloud Armor): JA4-only (BSD-3-Clause license, no licensing restrictions).
- **Security monitoring** (Wireshark, Zeek, Arkime, Suricata, GreyNoise, Censys): Full JA4+ suite (FoxIO License 1.1 for non-BSD methods).
- **Threat intelligence** (VirusTotal, Hunt, Driftnet): JA4+ mapping.
- **WAF vendors**: JA4 + JA4H for bot detection at the application layer.

### Typical Detection Stack

Production bot detection systems combine multiple signals:

1. **JA4** → Is this a browser TLS stack?
2. **JA4S** → Is the server response consistent with the claimed client?
3. **JA4H** → Are the HTTP headers in browser order? Is Accept-Language present?
4. **JA4T** → Is the OS consistent with the claimed browser?
5. **HTTP/2 fingerprint** → SETTINGS frame parameters, stream weights
6. **Behavioral** → Request timing, mouse movements, JS challenges

Any single layer can be spoofed; spoofing all layers simultaneously is substantially harder.

---

## 22. Licensing Notes

| Method | License | Notes |
|---|---|---|
| JA3, JA3S | BSD-3-Clause | Salesforce — freely usable |
| JARM | BSD-3-Clause | Salesforce — freely usable |
| **JA4** (TLS Client) | **BSD-3-Clause** | FoxIO — freely usable, no patent claims |
| JA4S, JA4H, JA4T, JA4TS, JA4L, JA4LS, JA4X, JA4SSH, JA4D, JA4D6 | **FoxIO License 1.1** | Free for academic, internal business, security research. **Commercial productization needs OEM license**. All marked **patent pending**. |
| ja4plus (Python/Go) | MIT (independent impl) | Crank-Git's independent implementations |
| tlsfingerprint (Go) | MIT | Independent implementation |

JA4's BSD-3-Clause licensing is why Cloudflare, AWS, Akamai, etc. adopted JA4 but not the full JA4+ suite.

---

## 23. References & Further Reading

### Primary Sources

- [salesforce/ja3 — JA3 specification + implementations](https://github.com/salesforce/ja3)
- [FoxIO-LLC/ja4 — JA4+ specification + official implementations](https://github.com/FoxIO-LLC/ja4)
- [JA4 Technical Details (official)](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md)
- [RFC 8701 — GREASE](https://datatracker.ietf.org/doc/html/rfc8701)
- [RFC 8446 — TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446)
- [Encrypted Client Hello (ECH) draft](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/)

### Key Blog Posts

- [TLS Fingerprinting with JA3 and JA3S — Salesforce Engineering (2017)](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967/)
- [Easily Identify Malicious Servers with JARM — John Althouse (2020)](https://medium.com/salesforce-engineering/easily-identify-malicious-servers-on-the-internet-with-jarm-e095edac525a)
- [JA4+ Network Fingerprinting — John Althouse / FoxIO (2023)](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [The State of TLS Fingerprinting — Fastly (2024)](https://www.fastly.com/blog/the-state-of-tls-fingerprinting-whats-working-what-isnt-and-whats-next)
- [JA4 Fingerprints and Inter-Request Signals — Cloudflare (2024)](https://blog.cloudflare.com/ja4-signals/)
- [JA4T: TCP Fingerprinting — FoxIO (2024)](https://medium.com/foxio/ja4t-tcp-fingerprinting-12fb7ce9cb5a)
- [Bots Tampering with TLS to Avoid Detection — Akamai (2019)](https://www.akamai.com/blog/security/bots-tampering-with-tls-to-avoid-detection)

### Community Implementations

- [Crank-Git/ja4plus — Python all-in-one](https://github.com/Crank-Git/ja4plus)
- [Crank-Git/ja4plus-go — Go all-in-one](https://github.com/Crank-Git/ja4plus-go)
- [psanford/tlsfingerprint — Go JA3/JA4](https://github.com/psanford/tlsfingerprint)

### Tools

- [tls.peet.ws — Online TLS fingerprint tester](https://tls.peet.ws/)
- [ja3er.com — JA3 hash lookup](https://ja3er.com/)
- [FoxIO JA4+ mapping CSV](https://github.com/FoxIO-LLC/ja4/blob/main/ja4plus-mapping.csv)

---

## 24. Deep Dive: HTTP/2 (Akamai) Fingerprinting

HTTP/2 fingerprinting is a **separate but complementary** signal to TLS fingerprinting. While JA4 captures the TLS handshake, HTTP/2 fingerprinting captures the **connection preface** that the client sends immediately after TLS negotiation completes. The two surfaces are independent — a bot that perfectly mimics Chrome's JA4 will still fail the HTTP/2 check if its SETTINGS frame doesn't match.

### The Akamai Format (Black Hat EU 2017)

Developed by Akamai researchers Elad Shuster and Ory Segal from 10M+ HTTP/2 connections. The format concatenates four sections:

```
SETTINGS | WINDOW_UPDATE | PRIORITY | PSEUDO_HEADER_ORDER
```

### 1. SETTINGS Frame

The first HTTP/2 frame the client sends. Contains `id:value` pairs in send order, semicolon-separated:

| ID | Name | Chrome | Firefox | Safari |
|---|---|---|---|---|
| 1 | HEADER_TABLE_SIZE | 65536 | 65536 | (omits) |
| 2 | ENABLE_PUSH | 0 | 0 | 0 |
| 3 | MAX_CONCURRENT_STREAMS | (omits) | (omits) | 100 |
| 4 | INITIAL_WINDOW_SIZE | 6291456 | 131072 | 2097152 |
| 5 | MAX_FRAME_SIZE | (omits) | 16384 | 16384 |
| 6 | MAX_HEADER_LIST_SIZE | 262144 | (omits) | (omits) |
| 9 | NO_RFC7540_PRIORITIES | (omits) | (omits) | 1 |

### 2. WINDOW_UPDATE

Connection-level WINDOW_UPDATE increment sent after SETTINGS:
- **Chrome**: `15663105`
- **Firefox**: `12517377`
- **Safari**: `10420275`
- **httpx/Python**: `0` (none sent) — immediate mismatch

The value derives from: `INITIAL_WINDOW_SIZE - 65535 (default) + additional allocation`.

### 3. PRIORITY (Stream Priority Tree)

RFC 7540 PRIORITY frames observed at connection open:
- **Chrome**: `0` (none sent, uses priority headers instead)
- **Firefox (legacy)**: Builds dependency tree — e.g., `3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1`
- **Safari**: `0` (none)

Firefox's phantom streams (IDs 3, 5, 7, 9, 11, 13) are a strong Firefox signature.

### 4. Pseudo-Header Order

The order of `:method`, `:authority`, `:scheme`, `:path` in the first HEADERS frame:
- **Chrome**: `m,a,s,p`
- **Firefox**: `m,a,s,p` (same as Chrome)
- **Safari**: `:method`, `:path`, `:scheme`, `:authority` (different)

### Complete Akamai Fingerprint Examples

| Client | Akamai String |
|---|---|
| Chrome | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` |
| Firefox | `1:65536;2:0;4:131072;5:16384\|12517377\|0\|m,a,s,p` |
| Safari | `2:0;3:100;4:2097152;5:16384;9:1\|10420275\|0\|:method,:path,:scheme,:authority` |

The Akamai string hashed with MD5 (sorted SETTINGS keys) produces a compact 32-char hash.

### Relation to JA4+

JA4+ does NOT natively include an H2 fingerprint method. JA4H captures HTTP headers (after the connection is established), but the H2 connection preface (SETTINGS, WINDOW_UPDATE, PRIORITY) is a separate signal not yet standardized in the JA4+ suite. In practice, HTTP/2 fingerprinting is used alongside JA4 by bot detection systems: JA4 verifies the TLS layer, Akamai hashes verify the H2 layer.

### Detection Power

HTTP/2 fingerprinting catches bots that pass JA4 checks because:
- Libraries like `httpx`, `aiohttp`, Python `h2` all send SETTINGS with wrong defaults (e.g., HEADER_TABLE_SIZE=4096 vs Chrome's 65536)
- Stock `curl` sends no WINDOW_UPDATE or wrong pseudo-header order
- Even uTLS/curl-impersonate doesn't always fix HTTP/2 framing — requires deep stack integration
- Libraries like `curl_cffi` (using nghttp2 behind curl) can match Chrome's HTTP/2 layer

### HTTP/2 Fingerprint Testing

- `tls.peet.ws/api/all` — reflects TLS, H2, headers, and order
- `cf.erika.cool` — shows what Cloudflare edge sees
- `browserleaks.com` — comprehensive fingerprint test

---

## 25. Deep Dive: ML/AI-Based TLS Fingerprinting

Academic and industrial research since 2023 has explored machine learning to overcome the limitations of rule-based fingerprinting.

### Key Research: Handshakes Tell the Truth (2026)

Paper: *When Handshakes Tell the Truth: Detecting Web Bad Bots via TLS Fingerprints* (Jarad & Biçakcı, arXiv:2602.09606)

- Used **JA4 features** as input to gradient-boosted classifiers
- **CatBoost model**: AUC 0.998, F1 0.9734, accuracy 98.63%
- **XGBoost model**: near-identical results
- Most influential features: `ja4_b` (cipher hash), `cipher_count`, `ext_count`
- Dataset: JA4DB real-world labeled fingerprints
- Key finding: JA4 features reveal patterns attackers struggle to forge
- Future work: extending to HTTP/3, adversarial robustness testing

### Malware Detection via JA4+ (2026)

Paper: *Detecting Malware in Encrypted Network Traffic Using ML and TLS Fingerprints* (Polo-Peyres et al., UCAmI 2025, LNNS vol 1819)

- Compared JA4+ fingerprinting vs MalDIST-inspired statistical flow features
- **JA4+ offered comparable accuracy with much lower processing overhead**
- Introduced JA4TS (TCP SYN-ACK) for additional signal
- Particularly effective for IoT/IIoT where efficiency is paramount
- JA4TS enhances detection as SNI encryption (ECH) becomes prevalent

### Deep Learning Approaches (2025)

Paper: *A Novel TLS-Based Fingerprinting Approach Combining Feature Expansion and Similarity Mapping* (ResearchGate, 2025)

- Uses deep learning to detect DDoS in 5G-integrated environments
- Feature expansion + similarity mapping for classifier robustness

### Industrial Use: Cloudflare Signals Intelligence

Cloudflare computes **JA4 Signals** — aggregate statistics for each JA4 fingerprint across their global network:
- `heuristic_ratio_1h` — fraction flagged by heuristics
- `browser_ratio_1h` — fraction from real browsers
- `cache_ratio_1h` — fraction hitting cache
- `h2h3_ratio_1h` — fraction using HTTP/2 or HTTP/3
- `uas_rank_1h` — User-Agent diversity rank
- `paths_rank_1h` — path diversity rank
- `reqs_rank_1h` — request volume rank
- `ips_rank_1h` — IP diversity rank

These are fed into ML models running on Cloudflare Workers.

### Auth0's JA4 Bot Detection (2026)

Auth0 integrated JA4 signals into their bot detection:
- Combines JA4 with HTTP/2 fingerprinting and behavioral analysis
- Bypasses TLS spoofing (uTLS, curl-impersonate) by checking consistency across layers

### The Arms Race

ML-based detection creates a new dynamic:
1. Attackers must match the **distribution** of fingerprints, not just a single hash
2. Anomalies in feature importance (e.g., a cipher hash common on Windows appearing with a Linux TCP fingerprint) trigger ML flags
3. Adversarial training is the next frontier — generating intentionally diverse fingerprints

---

## 26. Deep Dive: Post-Quantum TLS Fingerprinting

The deployment of post-quantum (PQ) cryptography in TLS 1.3 is **creating new fingerprint surfaces**.

### Current State (2026)

- **X25519MLKEM768** (codepoint `0x11EC`) is the standard hybrid group
- Chrome enabled by default in M124 (April 2024), standardized by M131 (Nov 2024)
- Firefox: M132 (Nov 2024)
- Edge: M131 (Chromium-based)
- Cloudflare reports ~43% of human HTTPS connections use hybrid PQ (Sept 2025)
- Enterprise policy `PostQuantumKeyAgreementEnabled` being removed — becoming mandatory

### What Changes in the ClientHello

The PQ key share is massive:
- **X25519 alone**: 32 bytes per side
- **X25519MLKEM768**: 1,216 bytes client share, 1,120 bytes server share
- **~38x larger** than classical ECDH

### Impact on Fingerprinting

- The `supported_groups` extension now contains hybrid codepoints like `0x11EC`
- The `key_share` extension balloons past single-segment sizes, often requiring TCP fragmentation
- Position of the hybrid group in the group list is implementation-specific and becomes a fingerprint signal
- GREASE values may appear in PQ groups too
- Old JA3/JA4 databases don't include PQ codepoints → new fingerprints for every browser version
- Browsers must decide: X25519MLKEM768 first or after classical groups?

### Post-Quantum Fingerprint Checklist

To match a current Chrome PQ fingerprint, an impersonating client must:
1. Offer X25519MLKEM768 at codepoint `0x11EC`
2. Place it where Chrome places it (near the front of supported_groups)
3. Send a real 1,216-byte key_share entry (ML-KEM pub first, X25519 second)
4. Accept multi-segment ClientHello fragmentation
5. Back it with a working ML-KEM-768 implementation (can't just replay a recorded share)

### Standalone PQ vs Hybrid

- **Hybrid** (X25519MLKEM768): security if EITHER classical or PQ is broken
- **Standalone ML-KEM** (`draft-ietf-tls-mlkem`): FIPS-compliant PQ-only. Codepoints 0x0300–0x0302 for ML-KEM-512/768/1024
- The choice between hybrid vs standalone is itself fingerprintable

### What Stays the Same

- TLS 1.3 handshake structure unchanged
- Key schedule unchanged (PQ shared secret feeds HKDF-Extract same as ECDHE)
- Certificate authentication (for now) still classical ECDSA/RSA
- Server certificate signatures still classical (PQ certs coming later per FIPS 204/205)

---

## 27. Deep Dive: Legal, Privacy & Regulatory Landscape

TLS fingerprinting sits in a **legal gray zone** that is increasingly scrutinized.

### GDPR Implications

- The UK ICO has stated browser fingerprinting data constitutes **personal data** under GDPR
- TLS fingerprints collected at scale and combined with other identifiers (IP, User-Agent, cookies) create a **tracking profile**
- **Legal basis required** under GDPR Article 6 — usually consent or legitimate interests
- Right to object to automated profiling (Article 22)
- Data retention limits apply to stored fingerprints
- Cross-border transfer safeguards required
- Potential fines: up to €20M or 4% of annual global revenue

### CCPA (California)

- Hardware identifiers qualify as **personal information**
- Consumers can request **deletion of fingerprint data**
- Opt-out mechanisms must be clearly accessible
- Disclosure requirements for data selling/sharing

### Key Difference from Browser Fingerprinting

- **Browser fingerprinting** (canvas, WebGL, audio) requires JavaScript execution — can be blocked by extensions
- **TLS fingerprinting** operates at the transport layer — **unblockable by browser extensions, incognito mode, or VPNs**
- Even Tor Browser's TLS fingerprint remains visible to network observers (though Tor uses a single unified fingerprint)
- GDPR's explicit reference to cookies doesn't cover TLS fingerprints directly, creating an **enforcement gap**

### Defensive Use Carve-Out

- Security and fraud detection are generally treated more favorably by regulators
- Payment processors, banks, and CDNs cite legitimate interest for fingerprinting
- Regulatory focus has been on advertising/analytics use, not security

### Anti-Detect Tools Legality

- Using anti-fingerprinting tools for: ad verification, competitive research, market analysis, price monitoring, legitimate multi-account management — **generally legal**
- Using for: fraud, identity theft, unauthorized access — **illegal** (CFAA, fraud statutes)
- The tool itself is legal; what you do with it determines legality

---

## 28. Deep Dive: QUIC & HTTP/3 Fingerprinting

QUIC (RFC 9000/9001) and HTTP/3 change the fingerprint surface significantly.

### How JA4 Handles QUIC

The first character of JA4 encodes the transport:
- `t` = TLS over TCP
- `q` = QUIC (UDP, HTTP/3)
- `d` = DTLS

QUIC JA4 example: `q13d0312h3_55b375c5d22e_06cda9e17597`

After the `q`, the remainder of the JA4 fingerprint follows the same recipe as TCP:
- TLS version, SNI flag, cipher count, extension count, ALPN
- Sorted cipher hash (JA4_b)
- Sorted extensions + sigalgs hash (JA4_c)

### What JA4 Does NOT Capture in QUIC

The current JA4 spec does **not** cover:
- **QUIC transport parameters** (idle timeout, initial flow control limits, ACK delay, active connection ID limit, etc.)
- **DCID length** in the Initial packet
- **Coalesced packet structure** (multiple QUIC packets in one UDP datagram)
- **Initial packet padding** patterns
- **Version negotiation** fingerprints

### QUIC-Specific Fingerprint Surface

A complete QUIC fingerprint requires **two independent hashes**:
1. **TLS ClientHello** (covered by JA4's `q` prefix) — ciphers, extensions, sigalgs
2. **Transport parameters** (not in JA4) — sent inside the ClientHello as extension `0x0039`

The transport-parameter block includes:
- `initial_max_data`
- `initial_max_stream_data_bidi_local`
- `initial_max_stream_data_bidi_remote`
- `initial_max_stream_data_uni`
- `initial_max_streams_bidi`
- `initial_max_streams_uni`
- `max_idle_timeout`
- `active_connection_id_limit`
- `ack_delay_exponent`
- `disable_active_migration`
- `preferred_address`

Each QUIC implementation (Chromium, quiche, quinn, msquic, picoquic, lsquic, ngtcp2) chooses different transport parameter defaults and ordering.

### JA4 Cross-Check

The QUIC and TCP JA4 fingerprints from the **same browser build** typically share identical `_b` (cipher) and `_c` (extension) hashes because the same TLS library is used underneath. A mismatch between QUIC and TCP JA4 is itself suspicious — it suggests the client isn't a real browser.

### QUIC Initial Packet Decryption

QUIC v1 and v2 Initial packets use keys derived from the Destination Connection ID:
```
client_secret = derive_initial_secrets(dcid, quic_version)
key, iv, hp_key = derive_key_iv_hp(client_secret)
```

The CRYPTO frame inside the Initial packet carries the TLS 1.3 ClientHello in plaintext (encrypted with the publicly-derivable Initial key). Libraries like `ja4plus` handle this decryption automatically for packet capture analysis.

### Limitations

- Only client Initial packets can be decrypted (no Retry, 0-RTT, or server-side)
- QUIC v1 (0x00000001) and v2 (0x6B3343CF) have different Initial packet type encoding
- Multi-packet ClientHellos may not reassemble correctly in all implementations

---

## 29. Deep Dive: JA4DB — The Fingerprint Database

The official FoxIO fingerprint database is at **[ja4db.com](https://ja4db.com/)** with a companion API at **[ja4db.foxio.io](https://ja4db.foxio.io/)**.

### Database Scope

- Contains ~73,000+ records (as of early 2026)
- Maps JA4, JA4S, JA4H, JA4X, JA4T fingerprints to applications
- Includes browser entries (Chrome, Firefox, Safari versions)
- Includes malware/C2 framework entries (Cobalt Strike, Sliver, IcedID, DarkGate, Lumma, Meterpreter, AsyncRAT)
- Includes VPN, tunneling, and security tool fingerprints

### Lookup Tools

- **ja4LookR** ([MikeVriesema/ja4LookR](https://github.com/MikeVriesema/ja4LookR)): CLI + Web, downloads full JA4DB, supports near/partial/wildcard matching
- **ja4plus** Python library: bundled mapping CSV, `lookup()` function
- **ja4plus-go** Go library: same bundled mapping

### Match Types in ja4LookR

| Type | Meaning |
|---|---|
| `exact` | Fingerprint matches verbatim |
| `near` | JA4_b + JA4_c match but JA4_a differs (same client family, different version/ALPN) |
| `wildcard` | Pattern match (e.g., `t13d*`) |
| `partial` | Only cipher hash OR only extension hash matches (weaker signal) |
| `none` | No known match |

### Known Malware Fingerprints (from FoxIO mapping CSV)

| Application | JA4 | JA4S | JA4H | JA4X |
|---|---|---|---|---|
| **Sliver Agent** | `t13d190900_9dc949149365_97f8aa674fd9` | `t130200_1301_a56c5b993250` | — | `000000000000_4f24da86fad6_bf0f0589fc03` |
| **Sliver/Havoc C2 Server** | — | — | — | `000000000000_4f24da86fad6_bf0f0589fc03` |
| **IcedID** | `t13d201100_2b729b4bf6f3_9e7b989ebec8` | `t120300_c030_5e2616a54c73` | — | — |
| **IcedID Dropper** | — | — | `ge11cn020000_9ed1ff1f7b03_cd8dafe26982` | — |
| **Cobalt Strike Cat C2** | — | — | — | `2166164053c1_2166164053c1_30d204a01551` |
| **Cobalt Strike beacon** | — | — | `ge11cn060000_4e59edc1297a_4da5efaf0cbd` | — |
| **Cobalt Strike v4.9.1 (wininet)** | `t12i190700_d83cc789557e_16bbda4055b2` | `t120300_c030_52d195ce1d92` | — | — |
| **Cobalt Strike v4.9.1 (winhttp)** | `t12i210700_76e208dd3e22_16bbda4055b2` | `t120300_c030_52d195ce1d92` | — | — |
| **SoftEther VPN** | `t13d880900_fcb5b95cb75a_b0d3b4ac2a14` | `t130200_1302_a56c5b993250` | — | `d55f458d5a6c_d55f458d5a6c_0fc8c171b6ae` |

### Chrome Fingerprint Variants

Chrome has multiple JA4 fingerprints depending on connection characteristics:

| Scenario | JA4 |
|---|---|
| TCP, standard connection | `t13d1516h2_8daaf6152771_02713d6af862` |
| QUIC | `q13d0312h3_55b375c5d22e_06cda9e17597` |
| TCP, pre-shared key (PSK) | `t13d1517h2_8daaf6152771_b0da82dd1658` |
| TCP, no key share | `t13d1517h2_8daaf6152771_b1ff8ab2d16f` |

---

## 30. Deep Dive: The Detection Layer Cake

Modern production bot detection stacks (Cloudflare, Akamai, DataDome) layer multiple independent fingerprinting methods. Defeating one layer is insufficient.

### The Layers (Top to Bottom)

| Layer | Method | What's Checked | Can Bot Spoof? |
|---|---|---|---|
| 9 | Behavioral | Mouse movements, scroll, timing, keystroke patterns | Hard (requires human-like input generation) |
| 8 | JS challenges | Proof-of-work, canvas, WebGL, audio | Partial (headless browsers increasingly caught) |
| 7 | Application state | sessionStorage, cookie consistency, cache | Moderate |
| 6 | **JA4H** | HTTP header order, Accept-Language, cookie structure | Hard (curl-impersonate doesn't do this yet) |
| 5 | **HTTP/2 (Akamai)** | SETTINGS, WINDOW_UPDATE, PRIORITY, pseudo-header order | Moderate (curl_cffi matches Chrome) |
| 4 | **JA4** (TLS ClientHello) | Cipher list, extensions, ALPN, GREASE | Moderate (uTLS, curl-impersonate) |
| 3 | **JA4S** (TLS ServerHello) | Server's cipher choice, extension echo | **Cannot spoof** (server-controlled) |
| 2 | **JA4T** (TCP SYN) | Window size, TCP options, MSS, TTL | Hard (kernel-level, needs raw sockets) |
| 1 | **JA4L** (Latency) | RTT, TTL, light distance | Hard (physical constraint) |

### Key Insight: The Inconsistency Signal

The most powerful detection signal is **inconsistency across layers**:
- JA4 says Chrome 134, but JA4T says Linux kernel → mismatch
- JA4H says Firefox, but JA4 says BoringSSL/Chrome → incoherent
- JA4T says standard Ethernet (MSS 1460), but latency suggests satellite → proxy
- JA4S shows a Go TLS server response, but JA4 claims to be a browser → C2 communication

### Why JA4 + JA4S Pairing Is So Strong

From FoxIO: "JA4 alone identifies the client's underlying TLS library, while JA4 plus JA4S can identify the specific application or malware family, because the server's choices narrow things down."

An attacker can control their own ClientHello (by using uTLS), but they **cannot control the server's ServerHello** unless they control the server. The ServerHello's cipher selection and extension echo are functions of the server's TLS library, not the client's forgery.

This asymmetry makes JA4_JA4S pairing the most reliable passive detection signal in the JA4+ ecosystem.

---

## 31. Comparison: JA3 vs JA4 vs JARM vs Akamai vs JA4+

| Feature | JA3/S | JA4+ Suite | JARM | Akamai H2 |
|---|---|---|---|---|
| Year | 2017 | 2023 | 2020 | 2017 |
| Author | Salesforce | FoxIO | Salesforce | Akamai |
| Scope | TLS client/server | Multi-protocol | TLS server (active) | HTTP/2 client |
| Passive/Active | Passive | Mostly passive | Active (10 probes) | Passive |
| Hash type | MD5 (full) | SHA-256 (truncated) | Fuzzy + SHA-256 | MD5 |
| Output length | 32 hex | 36+ chars | 62 chars | 32+ chars |
| GREASE-resistant | No | Yes | N/A | N/A |
| Order-independent | No | Yes (sorted ciphers/exts) | N/A | Partial (sorted SETTINGS) |
| QUIC support | No | Yes (q prefix) | No | No |
| DTLS support | No | Yes (d prefix) | No | No |
| HTTP support | No | JA4H | No | Yes |
| TCP support | No | JA4T/TS | No | No |
| Certificate support | No | JA4X | No | No |
| SSH support | No | JA4SSH | No | No |
| DHCP support | No | JA4D/D6 | No | No |
| Latency signal | No | JA4L/LS | No | No |
| Locality-preserving | No | Yes (a_b_c) | Partial | No |
| Human-readable | No | Yes (Part A) | No | Partial |
| Malware detection | Yes (legacy) | Yes (comprehensive) | Yes (C2 infra) | Yes (bots) |
| Primary use | Security monitoring | Threat hunting, WAF | C2 detection | Bot detection |

---

## 32. Common TLS Library Fingerprints

| Library/Client | Typical JA4 (TLS 1.3, TCP) | Notes |
|---|---|---|
| Chrome 120+ | `t13d1516h2_8daaf6152771_02713d6af862` | BoringSSL |
| Firefox 120+ | `t13d1416h2_...` | NSS-based |
| Safari (macOS) | `t13d1314h2_...` | SecureTransport |
| Safari (iOS) | `t13d1214h2_...` | Different from macOS |
| Python requests | `t13d0707h2_...` | OpenSSL defaults, few ciphers |
| Python aiohttp | `t13d0606h2_...` | Even fewer ciphers |
| Go net/http | `t13d1516h2_acb858a92679_...` | Distinctive Go TLS stack |
| curl (OpenSSL) | `t13d1416h2_...` | Library-dependent |
| curl-impersonate (Chrome) | Identical to Chrome | Uses BoringSSL |
| Node.js | `t13d0810h2_...` | Different per OpenSSL version |
| Java HttpClient | `t13d1312h2_...` | Depends on Java version |
| .NET / C# | `t13d1312h2_...` | SChannel-based |

---

## 33. Key References (Deep Dive Sources)

### Academic Papers
- Jarad & Biçakcı. *When Handshakes Tell the Truth: Detecting Web Bad Bots via TLS Fingerprints*. arXiv:2602.09606, 2026.
- Polo-Peyres et al. *Detecting Malware in Encrypted Network Traffic Using Machine Learning and TLS Fingerprints*. UCAmI 2025, LNNS vol 1819, Springer 2026.
- Fernández-Terrasa et al. *Mobile Application Identification in Encrypted Traffic Using JA4+ Fingerprints*. ICCIDA 2025.
- Ibrahim et al. *Detecting Post-Quantum and Hybrid TLS Deployments via Raw TLS Record Inspection*. ePrint 2026/834.
- *Fingerprinting Implementations of Cryptographic Primitives and Protocols that Use Post-Quantum Algorithms*. arXiv:2503.17830, 2025.
- *Positional-Unigram Byte Models for Generalized TLS Fingerprinting*. arXiv:2405.07848, 2024.

### HTTP/2 Fingerprinting
- Shuster & Segal. *Passive Fingerprinting of HTTP/2 Clients*. Black Hat EU 2017, Akamai.
- Akamai Shorthand format: [httpcloak.dev/fingerprinting/akamai-shorthand](https://httpcloak.dev/fingerprinting/akamai-shorthand)

### CDN/Platform Docs
- [Cloudflare JA4/JA4 Signals](https://developers.cloudflare.com/bots/additional-configurations/ja3-ja4-fingerprint/)
- [AWS WAF JA3 Fingerprint Matching](https://aws.amazon.com/about-aws/whats-new/2023/09/aws-waf-ja3-fingerprint-match/)
- [Google Cloud Armor JA4](https://cloud.google.com/load-balancing/docs/https/custom-headers-global)
- [Auth0 JA4 Bot Detection](https://auth0.com/blog/strengthening-bot-detection-ja4-signals/)

### Privacy & Legal
- [ICO (UK) — Browser fingerprinting guidance](https://ico.org.uk/)
- [GDPR Article 6 — Lawful processing](https://gdpr-info.eu/art-6-gdpr/)
- [ePrivacy Directive — tracking and consent](https://eur-lex.europa.eu/eli/dir/2002/58)

### QUIC Fingerprinting
- [HTTP/3 and QUIC fingerprinting (transport params)](https://blog.crawlex.net/blog/http3-quic-fingerprinting/)
- [QUIC Initial packet fingerprint surface](https://blog.crawlex.net/blog/quic-initial-packet-fingerprint/)

### Post-Quantum
- [draft-ietf-tls-ecdhe-mlkem-05 — Hybrid PQ key agreement](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/)
- [draft-ietf-tls-mlkem-07 — Standalone ML-KEM](https://datatracker.ietf.org/doc/html/draft-ietf-tls-mlkem-07)
- [Post-quantum TLS: what changes and what stays](https://blog.crawlex.net/blog/post-quantum-tls-fingerprint-impact/)

### Fingerprint Databases
- [ja4db.com](https://ja4db.com/) — Official FoxIO database
- [ja4plus-mapping.csv](https://github.com/FoxIO-LLC/ja4/blob/main/ja4plus-mapping.csv) — Bundled mapping
- [ja4LookR](https://github.com/MikeVriesema/ja4LookR) — Lookup tool
- [tls.peet.ws](https://tls.peet.ws/) — Online fingerprint tester
- [ja3er.com](https://ja3er.com/) — JA3 hash lookup
- [browserleaks.com](https://browserleaks.com/) — QUIC + TLS test

### Testing Tools
- [httpcloak](https://httpcloak.dev/) — Go library for TLS + H2 impersonation
- [curl_cffi](https://github.com/yifeikong/curl_cffi) — Python bindings for curl-impersonate
- [uTLS](https://github.com/refraction-networking/utls) — Go TLS fingerprint forgery

---

*Generated from comprehensive web research — July 2026. Deep dive sections added July 2026.*
