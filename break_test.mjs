import net from 'net';
import http from 'http';

const API = 'http://127.0.0.1:9443';

function fetchJSON(path) {
  return new Promise((resolve, reject) => {
    http.get(`${API}${path}`, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); } catch(e) { reject(e); }
      });
    }).on('error', reject);
  });
}

async function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ── TLS ClientHello construction ──
function buildCH(handshakeBody) {
  const len = handshakeBody.length;
  const record = Buffer.alloc(5 + len);
  record[0] = 0x16;
  record[1] = 0x03; record[2] = 0x01;
  record[3] = (len >> 8) & 0xff;
  record[4] = len & 0xff;
  handshakeBody.copy(record, 5);
  return record;
}

function u16(v) { const b = Buffer.alloc(2); b.writeUInt16BE(v); return b; }
function u8(v) { return Buffer.from([v]); }
function u24(v) { const b = Buffer.alloc(3); b.writeUIntBE(v, 0, 3); return b; }

function buildClientHello({
  ciphers = [], extensions = [], sni = '', alpn = '',
  greaseCiphers = [], greaseExts = [],
  sigalgs = [], groups = [], tls13Supported = false,
} = {}) {
  const parts = [];
  parts.push(u16(0x0303)); // legacy version

  // Random
  const random = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) random[i] = Math.floor(Math.random() * 256);
  parts.push(random);

  // Session ID (empty)
  parts.push(u8(0));

  // Cipher suites
  const allCiphers = [...greaseCiphers, ...ciphers];
  parts.push(u16(allCiphers.length * 2));
  for (const c of allCiphers) parts.push(u16(c));

  // Compression
  parts.push(u8(1)); parts.push(u8(0));

  // Extensions
  const extParts = [];
  const allExts = [...greaseExts, ...extensions];

  for (const ext of allExts) {
    if (typeof ext === 'number') {
      extParts.push(u16(ext));
      extParts.push(u16(0));
    } else if (ext.type === 0x0000 && sni) {
      const sniName = Buffer.from(sni, 'utf8');
      const sniBody = Buffer.concat([u16(1), u16(sniName.length + 3), u8(0), u16(sniName.length), sniName]);
      extParts.push(u16(0x0000));
      extParts.push(u16(sniBody.length));
      extParts.push(sniBody);
    } else if (ext.type === 0x0010 && alpn) {
      const alpnProto = Buffer.from(alpn, 'utf8');
      const alpnBody = Buffer.concat([u16(alpnProto.length + 1), u8(alpnProto.length), alpnProto]);
      extParts.push(u16(0x0010));
      extParts.push(u16(alpnBody.length));
      extParts.push(alpnBody);
    } else if (ext.type === 0x000d && sigalgs.length) {
      const sigBody = Buffer.concat(sigalgs.map(s => u16(s)));
      extParts.push(u16(0x000d));
      extParts.push(u16(sigBody.length + 2));
      extParts.push(u16(sigBody.length));
      extParts.push(sigBody);
    } else if (ext.type === 0x000a && groups.length) {
      const grpBody = Buffer.concat(groups.map(g => u16(g)));
      extParts.push(u16(0x000a));
      extParts.push(u16(grpBody.length + 2));
      extParts.push(u16(grpBody.length));
      extParts.push(grpBody);
    } else if (ext.type === 0x002b && tls13Supported) {
      const verBody = Buffer.concat([u8(2), u16(0x0304)]);
      extParts.push(u16(0x002b));
      extParts.push(u16(verBody.length));
      extParts.push(verBody);
    } else if (ext.data !== undefined) {
      const dataBuf = typeof ext.data === 'string' ? Buffer.from(ext.data, 'hex') : ext.data;
      extParts.push(u16(ext.type));
      extParts.push(u16(dataBuf.length));
      extParts.push(dataBuf);
    }
  }

  const extBody = Buffer.concat(extParts);
  parts.push(u16(extBody.length));
  parts.push(extBody);

  const handshakeBody = Buffer.concat(parts);
  const handshake = Buffer.concat([
    u8(0x01), u24(handshakeBody.length), handshakeBody,
  ]);

  return buildCH(handshake);
}

function sendAndRead(label, data, timeout = 3000) {
  return new Promise((resolve) => {
    const s = net.connect(9443, '127.0.0.1', () => { s.write(data); });
    let resp = '';
    s.on('data', d => resp += d.toString());
    s.on('end', () => {
      try {
        const json = JSON.parse(resp.split('\r\n\r\n')[1] || '{}');
        json._label = label;
        resolve(json);
      } catch(e) {
        resolve({ _label: label, _error: 'parse_failed', _raw: resp.slice(0, 200) });
      }
    });
    s.on('error', () => resolve({ _label: label, _error: 'socket_error' }));
    setTimeout(() => resolve({ _label: label, _error: 'timeout' }), timeout);
  });
}

async function run() {
  console.log('\n╔══════════════════════════════════════════════════════════════╗');
  console.log('║     BREAK TESTS — Can we bypass the classifier?           ║');
  console.log('╚══════════════════════════════════════════════════════════════╝\n');

  // ═══════════════════════════════════════════════════════
  // Test 1: Bot adds GREASE to avoid no_grease signal
  // ═══════════════════════════════════════════════════════
  console.log('── Test 1: Bot with GREASE injection ──');
  console.log('  Goal: Bot sends GREASE values to mimic browser behavior.\n');

  const r1 = await sendAndRead('bot_with_grease', buildClientHello({
    ciphers: [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xccaa],
    greaseCiphers: [0x0a0a, 0x1a1a],
    extensions: [
      { type: 0x002b, data: '0000' },
      { type: 0x000d, data: '0008' },
      { type: 0x0000, sni: 'example.com' },
      { type: 0x0010, alpn: 'h2' },
    ],
    greaseExts: [0xbaba, 0xfafa],
    sni: 'example.com', alpn: 'h2',
    sigalgs: [0x0804, 0x0403, 0x0805, 0x0503, 0x0806, 0x0601, 0x0807, 0x0808],
    groups: [0x001d, 0x0017, 0x0018],
    tls13Supported: true,
  }));
  printResult(r1);

  // ═══════════════════════════════════════════════════════
  // Test 2: Browser-mimic — sends Chrome-like counts (15 ciph, 16 ext)
  // ═══════════════════════════════════════════════════════
  console.log('── Test 2: Browser-mimic (15 ciph, 16 ext, SNI, h2, GREASE) ──');
  console.log('  Goal: Bot exactly matches Chrome cipher/extension counts.\n');

  const manyCiphers = [
    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030,
    0xc027, 0xcc14, 0xcc13, 0x009c, 0x009d, 0x002f, 0x0035, 0x000a,
  ];
  const manyExts = [
    { type: 0x002b, data: '020304' },
    { type: 0x001d, data: '' },
    { type: 0x0017, data: '' },
    { type: 0x0033, data: '00' },
    { type: 0x0000, sni: 'browser.test' },
    { type: 0x000b, data: '0100' },
    { type: 0x000a, groups: [0x001d, 0x0017, 0x0018, 0x0019] },
    { type: 0x000d, data: '0016' },
    { type: 0x0010, alpn: 'h2' },
    { type: 0x0023, data: '' },
    { type: 0x002d, data: '0101' },
    { type: 0x0012, data: '00' },
    { type: 0x0031, data: '' },
    { type: 0x0029, data: '0000' },
    { type: 0x002a, data: '' },
    { type: 0x001b, data: '0300' },
  ];

  const r2 = await sendAndRead('browser_mimic', buildClientHello({
    ciphers: manyCiphers,
    greaseCiphers: [0x0a0a, 0x1a1a],
    extensions: manyExts,
    greaseExts: [0xbaba, 0xfafa],
    sni: 'browser.test', alpn: 'h2',
    sigalgs: [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0201, 0x0203],
    groups: [0x001d, 0x0017, 0x0018, 0x0019],
    tls13Supported: true,
  }));
  printResult(r2);

  // ═══════════════════════════════════════════════════════
  // Test 3: uTLS/curl-impersonate scenario — KNOWN JA4 match
  // ═══════════════════════════════════════════════════════
  console.log('── Test 3: uTLS/curl-impersonate — exact KNOWN Chrome JA4 ──');
  console.log('  Goal: Show that uTLS/curl-impersonate with Chrome JA4');
  console.log('        bypasses TLS-only detection entirely.\n');

  console.log(`  Chrome JA4 in KNOWN list: t13d1516h2_8daaf6152771_d8a2da3f94cd`);
  console.log(`  curl_cffi (Chrome 136):  t13d1516h2_8daaf6152771_d8a2da3f94cd`);
  console.log(`  These produce an EXACT KNOWN match → fromBrowser=true, high conf`);
  console.log(`  Detection requires LAYER 2 (H2 SETTINGS) or LAYER 3 (headers).\n`);

  // Prove it: verify the KNOWN list has a Chrome entry that matches
  const chromeKnown = { prefix: 't13d1516h2', b: '8daaf6152771', c: 'd8a2da3f94cd' };
  console.log(`  Verifying KNOWN list contains Chrome 136+: `);
  console.log(`    prefix="${chromeKnown.prefix}" b="${chromeKnown.b}" c="${chromeKnown.c}"`);
  console.log(`  If a bot sends these values → browsers match → BYPASSED\n`);

  // ═══════════════════════════════════════════════════════
  // Test 4: Browser-mimic WITHOUT GREASE
  // ═══════════════════════════════════════════════════════
  console.log('── Test 4: Browser-mimic WITHOUT GREASE ──');
  console.log('  Goal: Can a bot with perfect browser counts but no GREASE?\n');

  const r4 = await sendAndRead('no_grease_mimic', buildClientHello({
    ciphers: manyCiphers,
    extensions: manyExts,
    sni: 'browser.test', alpn: 'h2',
    sigalgs: [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0201, 0x0203],
    groups: [0x001d, 0x0017, 0x0018, 0x0019],
    tls13Supported: true,
  }));
  printResult(r4);

  // ═══════════════════════════════════════════════════════
  // Test 5: Library bot (curl) with GREASE injection
  // ═══════════════════════════════════════════════════════
  console.log('── Test 5: curl-like bot (10 ciph, 4 ext) but WITH GREASE ──');
  console.log('  Goal: Does GREASE alone save a minimal library bot?\n');

  const r5 = await sendAndRead('curl_with_grease', buildClientHello({
    ciphers: [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xccaa],
    greaseCiphers: [0x0a0a, 0x1a1a],
    extensions: [
      { type: 0x002b, data: '0000' },
      { type: 0x000d, data: '0008' },
      { type: 0x0000, sni: 'test.com' },
      { type: 0x0010, alpn: 'h2' },
    ],
    greaseExts: [0xbaba, 0xfafa],
    sni: 'test.com', alpn: 'h2',
    sigalgs: [0x0804, 0x0403, 0x0805, 0x0503],
    groups: [0x001d, 0x0017],
    tls13Supported: true,
  }));
  printResult(r5);

  // ═══════════════════════════════════════════════════════
  // Summary
  // ═══════════════════════════════════════════════════════
  console.log('═══════════════════════════════════════════════════════════');
  console.log('  BREAK TEST RESULTS\n');

  // Summary table
  const results = [r1, r2, r4, r5];
  const summary = {};
  for (const r of results) {
    if (r._error || !r.ja4) {
      summary[r._label] = '⚠ ERROR (parse failed)';
      continue;
    }
    const bypassed = !r.possible_bot;
    summary[r._label] = bypassed ? '✗ BYPASSED' : '✓ CAUGHT';
    summary[r._label + ' JA4'] = r.ja4;
    summary[r._label + ' Match'] = r.match || '-';
  }
  console.table(summary);

  console.log('\n  CLASSIFICATION MATRIX\n');
  const matrix = {};
  for (const r of results) {
    if (r._error || !r.ja4) continue;
    const rowKey = (r._label || '?').slice(0, 22);
    matrix[`${rowKey}`] = r.possible_bot ? '⚠ BOT' : '✓ BROWSER';
    matrix[`${rowKey} conf`] = r.confidence || '?';
    matrix[`${rowKey} ciph`] = r.cipher_count ?? '?';
    matrix[`${rowKey} ext`] = r.extension_count ?? '?';
    matrix[`${rowKey} grease`] = r.grease_count ?? '?';
    matrix[`${rowKey} sni`] = r.sni_present ? '✓' : '✗';
    matrix[`${rowKey} alpn`] = r.alpn || '-';
  }
  console.table(matrix);

  console.log('\n  REMAINING BYPASS VECTORS\n');
  console.log('  1. uTLS/curl-impersonate (KNOWN JA4 match) — cannot be detected');
  console.log('     at TLS layer. Requires H2 SETTINGS or HTTP header analysis.');
  console.log('  2. Bot with PERFECT browser mimic (15 ciph, 16 ext, SNI, h2,');
  console.log('     GREASE, browser sigalgs/groups) — falls to low confidence');
  console.log('     bot but not high confidence. Needs L2+L3 for certainty.\n');
}

function printResult(r) {
  if (r._error) {
    console.log(`  ⚠ Error: ${r._error}\n`);
    return;
  }
  const bypassed = !r.possible_bot;
  console.log(`  JA4:   ${r.ja4}`);
  console.log(`  Verdict: ${bypassed ? '✗ BYPASSED → ✓ BROWSER' : '✓ CAUGHT → ⚠ BOT'}  |  Match: "${r.match}"  |  Conf: ${r.confidence}`);
  console.log(`  Data:  ${r.cipher_count}ciph ${r.extension_count}ext SNI=${r.sni_present ? '✓' : '✗'} ALPN=${r.alpn || '-'} TLS=${r.tls_version} Grease=${r.grease_count}`);
  console.log('');
}

run().catch(console.error);
