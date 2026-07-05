const net = require('net');
const crypto = require('crypto');
const fs = require('fs');
const { execSync } = require('child_process');
const tls = require('tls');

const PORT = parseInt(process.argv[2], 10) || 8443;
const HTTPS_PORT = parseInt(process.argv[3], 10) || 8444;

const GREASE = new Set([
  0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
  0x7a7a, 0x8a7a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca,
  0xdada, 0xeaea, 0xfafa
]);

const TLS_VER_MAP = {
  '0x0002': 's2', '0x0300': 's3', '0x0301': '10',
  '0x0302': '11', '0x0303': '12', '0x0304': '13'
};

function hex(v, n) { return '0x' + v.toString(16).padStart(n || 4, '0'); }

function readU8(buf, off) { return [buf.readUInt8(off), off + 1]; }
function readU16(buf, off) { return [buf.readUInt16BE(off), off + 2]; }
function readU24(buf, off) { return [buf.readUIntBE(off, 3), off + 3]; }

function sha256Trunc(data) { return crypto.createHash('sha256').update(data).digest('hex').substring(0, 12); }
function md5Hex(data) { return crypto.createHash('md5').update(data).digest('hex'); }
function isPrintableAscii(c) { return c >= 0x20 && c <= 0x7e; }

const fingerprints = [];

function parseClientHello(buf) {
  try {
    const TLS_REC_HEADER = 5;
    let off = 0;
    const [contentType] = readU8(buf, off);
    if (contentType !== 0x16) return null;

    const [recLen] = readU16(buf, 3);
    const recEnd = TLS_REC_HEADER + recLen;
    if (recEnd > buf.length) return null;

    const [handshakeType, off2] = readU8(buf, TLS_REC_HEADER);
    if (handshakeType !== 0x01) return null;

    const [handshakeLen, off3] = readU24(buf, off2);
    const chEnd = off3 + handshakeLen;
    if (chEnd > recEnd) return null;

    let pos = off3;
    const [clientVer] = readU16(buf, pos);
    pos += 2 + 32;

    const [sessIdLen] = readU8(buf, pos);
    pos += 1 + sessIdLen;

    const [ciphLen] = readU16(buf, pos);
    pos += 2;
    const rawCiphers = [];
    const ciphEnd = pos + ciphLen;
    while (pos < ciphEnd) { const [c] = readU16(buf, pos); rawCiphers.push(c); pos += 2; }

    const [compLen] = readU8(buf, pos);
    pos += 1 + compLen;

    const rawExtTypes = [];
    const extensions = [];
    let sni = 'i', alpn = '00';
    const sigalgs = [], supportedGroups = [], ecPointFormats = [], supportedVersions = [];

    if (pos < chEnd) {
      const [extLen] = readU16(buf, pos);
      pos += 2;
      const extEnd = pos + extLen;
      while (pos < extEnd) {
        const [extType] = readU16(buf, pos);
        const [extDataLen] = readU16(buf, pos + 2);
        const extDataStart = pos + 4;
        const extDataEnd = extDataStart + extDataLen;
        pos = extDataEnd;

        if (!GREASE.has(extType)) {
          rawExtTypes.push(extType);
          extensions.push(hex(extType));

          if (extType === 0x0000) sni = 'd';
          else if (extType === 0x0010) {
            if (extDataEnd > extDataStart + 2) {
              const [alpnListLen] = readU16(buf, extDataStart);
              let ap = extDataStart + 2;
              const apEnd = ap + alpnListLen;
              while (ap < apEnd) {
                const [plen] = readU8(buf, ap); ap += 1;
                if (ap + plen <= apEnd) {
                  const val = buf.toString('utf8', ap, ap + plen);
                  if (!alpn || alpn === '00') {
                    const fc = val.charCodeAt(0), lc = val.charCodeAt(val.length - 1);
                    alpn = (isPrintableAscii(fc) && isPrintableAscii(lc))
                      ? val[0] + val[val.length - 1]
                      : ((fc >> 4) & 0x0f).toString(16) + (lc & 0x0f).toString(16);
                  }
                  ap += plen;
                }
              }
            }
          } else if (extType === 0x000a && extDataEnd > extDataStart + 2) {
            const [glen] = readU16(buf, extDataStart);
            let gp = extDataStart + 2;
            const gEnd = gp + glen;
            while (gp < gEnd) { const [g] = readU16(buf, gp); if (!GREASE.has(g)) supportedGroups.push(g); gp += 2; }
          } else if (extType === 0x000b && extDataEnd > extDataStart + 1) {
            const [flen] = readU8(buf, extDataStart);
            let fp = extDataStart + 1, fEnd = fp + flen;
            while (fp < fEnd) { const [f] = readU8(buf, fp); ecPointFormats.push(f); fp += 1; }
          } else if (extType === 0x000d && extDataEnd > extDataStart + 2) {
            const [slen] = readU16(buf, extDataStart);
            let sp = extDataStart + 2, sEnd = sp + slen;
            while (sp < sEnd) { const [s] = readU16(buf, sp); if (!GREASE.has(s)) sigalgs.push(s); sp += 2; }
          } else if (extType === 0x002b && extDataEnd > extDataStart + 1) {
            const [vlen] = readU8(buf, extDataStart);
            let vp = extDataStart + 1, vEnd = vp + vlen;
            while (vp < vEnd) { const [v] = readU16(buf, vp); if (!GREASE.has(v)) supportedVersions.push(v); vp += 2; }
          }
        }
      }
    }

    return { rawCiphers, rawExtTypes, extensions, sni, alpn, sigalgs, supportedGroups, ecPointFormats, supportedVersions, clientVer, chEnd };
  } catch (e) { return null; }
}

function computeJA3(p) {
  const ver = hex(p.clientVer);
  const ciphers = p.rawCiphers.filter(c => !GREASE.has(c)).join('-');
  const exts = p.rawExtTypes.join('-');
  const curves = p.supportedGroups.join('-');
  const formats = p.ecPointFormats.join('-');
  const raw = `${ver},${ciphers},${exts},${curves},${formats}`;
  return { ja3: md5Hex(raw), rawJA3: raw };
}

function computeJA4(p) {
  const ciphers = p.rawCiphers.filter(c => !GREASE.has(c));
  const exts = p.rawExtTypes.filter(e => !GREASE.has(e));
  const maxVer = p.supportedVersions.length > 0 ? Math.max(...p.supportedVersions) : null;
  const tlsVer = maxVer ? (TLS_VER_MAP[hex(maxVer)] || '00') : (TLS_VER_MAP[hex(p.clientVer)] || '00');
  const ct = String(ciphers.length).padStart(2, '0');
  const et = String(exts.length).padStart(2, '0');
  const prefix = `t${tlsVer}${p.sni}${ct}${et}${p.alpn}`;
  const sortedCiphers = ciphers.map(c => c.toString(16).padStart(4, '0')).sort();
  const b = sha256Trunc(sortedCiphers.join(','));
  const extsForHash = exts.filter(e => e !== 0x0000 && e !== 0x0010).map(e => e.toString(16).padStart(4, '0')).sort();
  let extInput = extsForHash.join(',');
  if (p.sigalgs.length > 0) extInput += '_' + p.sigalgs.map(s => s.toString(16).padStart(4, '0')).join(',');
  const c = sha256Trunc(extInput);
  return { ja4: `${prefix}_${b}_${c}`, ja4_a: prefix, ja4_b: b, ja4_c: c };
}

const KNOWN = [
  { prefix: 't13d1516h2', b: '8daaf6152771', c: 'd8a2da3f94cd', name: 'Chrome 136+',         type: 'browser' },
  { prefix: 't13d1516h2', b: '8daaf6152771', c: '02713d6af862', name: 'Chrome 131',          type: 'browser' },
  { prefix: 't13d1516h2', b: '8daaf6152771', c: 'e5627efa2ab1', name: 'Chrome (FoxIO)',      type: 'browser' },
  { prefix: 't13d1717h2', b: '5b57614c22b0', c: '3cbfd9057e0d', name: 'Firefox 135+',       type: 'browser' },
  { prefix: 't13d1716h2', b: '5b57614c22b0', c: 'eeeea6562960', name: 'Firefox 133',        type: 'browser' },
  { prefix: 't13d2013h2', b: 'a09f3c656075', c: '7f0f34a4126d', name: 'Safari 18',          type: 'browser' },
  { prefix: 't13d2014h2', b: 'a09f3c656075', c: '7f0f34a4126d', name: 'Safari 18.4',        type: 'browser' },
  { prefix: 't13d2014h2', b: 'a09f3c656075', c: 'd0a99439f9b1', name: 'Safari 26.0',        type: 'browser' },
  { prefix: 't13d3112h2', b: 'e8f1e7e78f70', c: '375ca2c5e164', name: 'curl (Linux OpenSSL)',type: 'bot' },
  { prefix: 't13d4907h2', b: '0d8feac7bc37', c: '7395dae3b2f3', name: 'curl (macOS)',        type: 'bot' },
  { prefix: 't13d4906h1', b: '0d8feac7bc37', c: '7395dae3b2f3', name: 'curl (macOS H1)',     type: 'bot' },
  { prefix: 't13i4906h2', b: '0d8feac7bc37', c: '7395dae3b2f3', name: 'Node.js/curl (no SNI)',type: 'bot' },
  { prefix: 't13d4906h2', b: '0d8feac7bc37', c: '7395dae3b2f3', name: 'Node.js (macOS)',     type: 'bot' },
  { prefix: 't13d490700', b: '0d8feac7bc37', c: '460f73f9cefb', name: 'curl (macOS no ALPN)',type: 'bot' },
  { prefix: 't13i521000', b: 'b262b3658495', c: '8e6e362c5eac', name: 'LibreSSL s_client',   type: 'bot' },
  { prefix: 't12i380400', b: '10ed599f3404', c: '67a080e8974e', name: 'Python urllib',       type: 'bot' },
  { prefix: 't13d1712h1', b: 'ab0a1bf427ad', c: '882d495ac381', name: 'Python requests',     type: 'bot' },
  { prefix: 't13d1712h1', b: 'ab0a1bf427ad', c: '8e6e362c5eac', name: 'Python httpx',       type: 'bot' },
  { prefix: 't13d1411h2', b: 'cbb2034c60b8', c: 'e7c285222651', name: 'Go net/http',        type: 'bot' },
  { prefix: 't13d410',    b: '16476d049b0b', c: '78f1d400d464', name: 'OpenSSL s_client',    type: 'bot' },
  { prefix: 't13d411h2',  b: '16476d049b0b', c: '78f1d400d464', name: 'OpenSSL s_client h2',type: 'bot' },
  { prefix: 't13d301000', b: '01455d0db58d', c: '5ac7197df9d2', name: 'SemrushBot',         type: 'bot' },
];

function classify(prefix, b, c, cipherCount, extCount, alpn, hadSNI, sigalgCount, groupCount, hadGrease) {
  // 1. Exact JA4 match (highest priority)
  const exact = KNOWN.find(e => prefix === e.prefix && b === e.b && c === e.c);
  if (exact) return { fromBrowser: exact.type === 'browser', possibleBot: exact.type === 'bot', match: exact.name, confidence: 'high' };

  // 2. Prefix+b match (c variant — different sigalg set, same client)
  const prefixB = KNOWN.find(e => prefix === e.prefix && b === e.b);
  if (prefixB) return { fromBrowser: prefixB.type === 'browser', possibleBot: prefixB.type === 'bot', match: prefixB.name + ' (c variant)', confidence: 'high' };

  // 3. Weighted score — each signal contributes points toward bot classification
  let score = 0;
  const reasons = [];

  // ALPN
  if (!alpn || alpn === '00') { score += 15; reasons.push('no_alpn'); }
  else if (alpn === 'h1') { score += 8; reasons.push('alpn_h1'); }

  // Cipher count (browsers: 14-24)
  if (cipherCount < 8) { score += 20; reasons.push('ciphers_lt8'); }
  else if (cipherCount > 24) { score += 12; reasons.push('ciphers_gt24'); }

  // Extension count (browsers: 15-25)
  if (extCount < 8) { score += 15; reasons.push('exts_lt8'); }
  else if (extCount < 11) { score += 10; reasons.push('exts_lt11'); }

  // SNI
  if (!hadSNI) { score += 12; reasons.push('no_sni'); }

  // Sigalg count (browsers: 8-16)
  if (sigalgCount > 0 && (sigalgCount < 8 || sigalgCount > 16)) { score += 6; reasons.push('sigalgs_anomalous'); }

  // Group count (browsers: 3-6)
  if (groupCount > 0 && (groupCount < 3 || groupCount > 6)) { score += 6; reasons.push('groups_anomalous'); }

  // GREASE presence (browsers always send GREASE; bots rarely do)
  if (!hadGrease) { score += 8; reasons.push('no_grease'); }

  // JA4_a prefix heuristic (soft signal only — does NOT override other signals)
  const isBrowserPrefix = prefix.startsWith('t13d15') || prefix.startsWith('t13d17') || prefix.startsWith('t13d20');
  const isTLS13Prefix = prefix.startsWith('t13d') || prefix.startsWith('t13i');
  if (isBrowserPrefix) { score -= 3; }
  else if (isTLS13Prefix) { score += 3; reasons.push('non_browser_prefix'); }
  if (prefix.startsWith('t12')) { score += 10; reasons.push('tls12_prefix'); }

  // Decision: conservative — unless KNOWN says browser, default to bot
  if (score >= 25) return { fromBrowser: false, possibleBot: true, match: reasons.join(';'), confidence: 'high' };
  if (score >= 15) return { fromBrowser: false, possibleBot: true, match: reasons.join(';'), confidence: 'medium' };
  if (score <= -10 && isBrowserPrefix) return { fromBrowser: true, possibleBot: false, match: 'weighted_low_score', confidence: 'medium' };
  return { fromBrowser: false, possibleBot: true, match: reasons.join(';') || 'unrecognized', confidence: 'low' };
}

function sendResponse(socket, statusCode, body) {
  const b = JSON.stringify(body, null, 2);
  const resp = `HTTP/1.1 ${statusCode} OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: ${Buffer.byteLength(b)}\r\nAccess-Control-Allow-Origin: *\r\n\r\n${b}`;
  socket.end(resp);
}

function sendTLSAlert(socket) {
  const alert = Buffer.alloc(7);
  alert[0] = 0x15;
  alert[1] = 0x03; alert[2] = 0x03;
  alert[3] = 0x00; alert[4] = 0x02;
  alert[5] = 0x01; alert[6] = 0x5A;
  socket.end(alert);
}

function processFingerprint(addr, rawData) {
  const parsed = parseClientHello(rawData);
  if (!parsed) return null;

  const ciphers = parsed.rawCiphers.filter(c => !GREASE.has(c));
  const exts = parsed.rawExtTypes.filter(e => !GREASE.has(e));
  const hadGrease = (parsed.rawCiphers.length !== ciphers.length) || (parsed.rawExtTypes.length !== exts.length);
  const greaseCount = (parsed.rawCiphers.length - ciphers.length) + (parsed.rawExtTypes.length - exts.length);
  const j3 = computeJA3(parsed);
  const j4 = computeJA4(parsed);
  const verdict = classify(j4.ja4_a, j4.ja4_b, j4.ja4_c, ciphers.length, exts.length, parsed.alpn, parsed.sni === 'd', parsed.sigalgs.length, parsed.supportedGroups.length, hadGrease);

  const result = {
    ts: new Date().toISOString(),
    client: addr,
    ja3: j3.ja3,
    ja4: j4.ja4,
    ja4_a: j4.ja4_a,
    ja4_b: j4.ja4_b,
    ja4_c: j4.ja4_c,
    tls_version: TLS_VER_MAP[hex(parsed.clientVer)] || '?',
    cipher_count: ciphers.length,
    extension_count: exts.length,
    alpn: parsed.alpn === '00' ? null : (parsed.alpn === 'h2' ? 'h2' : parsed.alpn === 'h1' ? 'http/1.1' : parsed.alpn),
    sni_present: parsed.sni === 'd',
    from_a_browser: verdict.fromBrowser,
    possible_bot: verdict.possibleBot,
    match: verdict.match,
    confidence: verdict.confidence,
    bot_signals: verdict.confidence === 'medium' || verdict.confidence === 'low' ? (verdict.match.split(';')) : [],
    grease_present: hadGrease,
    grease_count: greaseCount,
    extensions: parsed.extensions,
    extension_types: parsed.rawExtTypes.filter(e => !GREASE.has(e)),
    cipher_ids: ciphers.slice(0, 10).map(c => hex(c)),
    sigalgs: parsed.sigalgs.map(s => hex(s)),
    supported_groups: parsed.supportedGroups.map(g => hex(g)),
  };

  fingerprints.unshift(result);
  if (fingerprints.length > 100) fingerprints.length = 100;

  const line = `[${result.ts}] ${addr} | JA4: ${result.ja4} | JA3: ${result.ja3} | browser=${result.from_a_browser} bot=${result.possible_bot} match="${result.match}" confidence=${result.confidence}`;
  console.log(line);

  return result;
}

// ── Raw TCP capture server ──
const rawServer = net.createServer((socket) => {
  const addr = socket.remoteAddress + ':' + socket.remotePort;

  socket.once('data', (data) => {
    if (data.length > 0 && data[0] === 0x16) {
      const result = processFingerprint(addr, data);
      if (result) {
        sendResponse(socket, 200, result);
      } else {
        sendResponse(socket, 400, { error: 'could_not_parse_client_hello' });
      }
    } else if (data[0] === 0x47 || data[0] === 0x50 || data[0] === 0x44) {
      const firstLine = data.toString('utf8').split('\r\n')[0] || 'unknown';
      const method = firstLine.split(' ')[0] || 'GET';
      const path = (firstLine.split(' ')[1] || '/').split('?')[0];

      if (path === '/' || path === '/results') {
        const limit = Math.min(parseInt(firstLine.match(/limit=(\d+)/)?.[1]) || 20, 100);
        sendResponse(socket, 200, { count: fingerprints.length, results: fingerprints.slice(0, limit) });
      } else if (path === '/stats') {
        const browsers = fingerprints.filter(r => r.from_a_browser).length;
        const bots = fingerprints.filter(r => r.possible_bot).length;
        sendResponse(socket, 200, { total: fingerprints.length, browsers, bots, note: 'since server start' });
      } else {
        sendResponse(socket, 200, {
          service: 'tls-fingerprint-server',
          version: '1.0',
          endpoints: {
            '/results': 'show last N fingerprints (?limit=N)',
            '/stats': 'summary stats',
          },
          test: 'connect with any TLS client (curl, browser, openssl) to capture fingerprint',
        });
      }
    } else {
      sendResponse(socket, 400, { error: 'unrecognized_protocol', hint: 'send a TLS ClientHello or HTTP request' });
    }
  });

  socket.on('error', () => {});
});

// ── TLS/HTTPS server ──
try {
  if (!fs.existsSync('server.key') || !fs.existsSync('server.crt')) {
    console.log('Generating self-signed certificate...');
    execSync('openssl req -x509 -newkey rsa:2048 -nodes -keyout server.key -out server.crt -days 365 -subj "/CN=localhost" 2>/dev/null');
  }
  const opts = { key: fs.readFileSync('server.key'), cert: fs.readFileSync('server.crt') };

  const httpsServer = tls.createServer(opts, (socket) => {
    const addr = socket.remoteAddress + ':' + socket.remotePort;
    let data = '';
    socket.on('data', (chunk) => {
      data += chunk.toString();
      if (data.includes('\r\n\r\n')) {
        const method = data.split(' ')[0];
        const path = (data.split(' ')[1] || '/').split('?')[0];
        const limit = Math.min(parseInt(data.match(/limit=(\d+)/)?.[1]) || 20, 100);

        const body = path === '/results'
          ? JSON.stringify({ count: fingerprints.length, results: fingerprints.slice(0, limit) }, null, 2)
          : path === '/stats'
          ? JSON.stringify({ total: fingerprints.length, browsers: fingerprints.filter(r => r.from_a_browser).length, bots: fingerprints.filter(r => r.possible_bot).length }, null, 2)
          : JSON.stringify({
              service: 'tls-fingerprint-server',
              message: 'your TLS fingerprint was captured and logged by the raw TCP server on port ' + PORT,
              endpoints: { '/results': 'show fingerprints', '/stats': 'summary stats' },
              test: 'connect via HTTP to port ' + PORT + ' for JSON, or via any TLS client for capture',
            }, null, 2);

        const resp = 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: ' + Buffer.byteLength(body) + '\r\nAccess-Control-Allow-Origin: *\r\n\r\n' + body;
        socket.end(resp);
      }
    });
    socket.on('error', () => {});
  });

  httpsServer.listen(HTTPS_PORT, '0.0.0.0', () => {
    const c = fingerprints.length;
  });
} catch (e) {
  console.log('HTTPS server not available (need openssl for cert generation)');
}

rawServer.listen(PORT, '0.0.0.0', () => {
  console.log('╔══════════════════════════════════════════════════════╗');
  console.log('║         TLS Fingerprint Detection Server            ║');
  console.log('╠══════════════════════════════════════════════════════╣');
  console.log('║  Raw TCP capture port: ' + String(PORT).padEnd(38) + '║');
  console.log('║  HTTPS results port:   ' + String(HTTPS_PORT).padEnd(38) + '║');
  console.log('╠══════════════════════════════════════════════════════╣');
  console.log('║  TEST:                                                ║');
  console.log('║  curl -k https://localhost:' + String(PORT).padEnd(35) + '║');
  console.log('║  openssl s_client -connect localhost:' + String(PORT).padEnd(28) + '║');
  console.log('║  curl http://localhost:' + String(PORT) + '/results        ║');
  console.log('╚══════════════════════════════════════════════════════╝');
});
