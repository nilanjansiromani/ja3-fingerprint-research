import { execSync } from 'child_process';
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

function trigger(label, cmd, timeout = 5000) {
  try { execSync(cmd, { timeout, stdio: 'pipe', killSignal: 'SIGTERM' }); }
  catch(e) {}
}

async function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ── Detection Signals ──
// Each signal returns { fires: bool|null, data: string, reason: string }
//   fires=true  → "yes, this looks like a bot"
//   fires=false → "no, this looks like a browser"
//   fires=null  → inconclusive (data not available)
//   data        → the actual captured value
//   reason      → human-readable explanation of why fires=true/false
//
// botExpected / browserExpected: what fires value do we expect for each?

const SIGNALS = [
  {
    id: 'exact_ja4',
    name: '1. Exact JA4 match',
    desc: 'JA4(a+b+c) matches a known bot fingerprint in database',
    test: (r) => {
      const matched = r.match && r.confidence === 'high' && r.possible_bot;
      return {
        fires: matched,
        data: r.match || '(no match)',
        reason: matched
          ? `"${r.match}" exact match in fingerprint DB`
          : `no known bot fingerprint matched "${r.match}"`,
      };
    },
    botExpected: true,
    browserExpected: false,
  },
  {
    id: 'alpn_check',
    name: '2. ALPN protocol',
    desc: 'Browsers: h2. Bots: omit ALPN or send h1 only.',
    test: (r) => {
      const alpn = r.alpn || '(none)';
      const fires = !r.alpn || r.alpn === 'http/1.1';
      return {
        fires,
        data: `ALPN=${alpn}`,
        reason: fires
          ? `ALPN is "${alpn}" — bots often omit ALPN or use h1`
          : `ALPN is "${alpn}" — browsers use h2 but bots can too`,
      };
    },
    botExpected: true,
    browserExpected: false,
  },
  {
    id: 'cipher_count',
    name: '3. Cipher suite count',
    desc: 'Browsers: 14-24. Bots: <8 or >24.',
    test: (r) => {
      const c = r.cipher_count;
      const fires = c < 8 || c > 24;
      return {
        fires,
        data: `count=${c}`,
        reason: fires
          ? `${c} ciphers is outside browser range (14-24)`
          : `${c} ciphers is within browser range (14-24)`,
      };
    },
    botExpected: true,
    browserExpected: false,
  },
  {
    id: 'extension_count',
    name: '4. Extension count',
    desc: 'Browsers: 15-25. Minimal bots: <8.',
    test: (r) => {
      const e = r.extension_count;
      const fires = e < 8;
      return {
        fires,
        data: `count=${e}`,
        reason: fires
          ? `${e} extensions is far below browser minimum (~15)`
          : `${e} extensions is in browser range (15-25)`,
      };
    },
    botExpected: true,
    browserExpected: false,
  },
  {
    id: 'sni_check',
    name: '5. SNI presence',
    desc: 'Browsers always send SNI. Many bots omit it.',
    test: (r) => {
      const fires = r.sni_present === false;
      return {
        fires,
        data: `SNI=${r.sni_present ? 'present' : 'absent'}`,
        reason: fires
          ? 'SNI is absent — legitimate browsers always send SNI'
          : 'SNI is present — expected for browsers, less common in bots',
      };
    },
    botExpected: true,
    browserExpected: false,
  },
  {
    id: 'tls_version',
    name: '6. TLS version',
    desc: 'Browsers: TLS 1.3. Stdlib bots: often TLS 1.2.',
    test: (r) => {
      const ver = r.tls_version;
      const fires = ver !== '13';
      return {
        fires,
        data: `TLS=${ver}`,
        reason: fires
          ? `TLS ${ver} — bots (especially stdlib) often use TLS 1.2`
          : `TLS ${ver} — browsers use TLS 1.3 (but bots can too)`,
      };
    },
    botExpected: true,
    browserExpected: false,
  },
  {
    id: 'sigalg_count',
    name: '7. Sigalg count',
    desc: 'Browsers: 8-16 sigalgs. Bots: <8 or >16.',
    test: (r) => {
      const sc = (r.sigalgs || []).length;
      if (sc === 0) return { fires: null, data: `count=${sc}`, reason: 'sigalg list not captured by parser' };
      const fires = sc < 8 || sc > 16;
      return {
        fires,
        data: `count=${sc}`,
        reason: fires
          ? `${sc} sigalgs is outside browser range (8-16)`
          : `${sc} sigalgs is within browser range (8-16)`,
      };
    },
    botExpected: true,
    browserExpected: false,
  },
  {
    id: 'group_count',
    name: '8. Group count',
    desc: 'Browsers: 3-6 supported groups. Bots: <3 or >6.',
    test: (r) => {
      const gc = (r.supported_groups || []).length;
      if (gc === 0) return { fires: null, data: `count=${gc}`, reason: 'group list not captured by parser' };
      const fires = gc < 3 || gc > 6;
      return {
        fires,
        data: `count=${gc}`,
        reason: fires
          ? `${gc} groups is outside browser range (3-6)`
          : `${gc} groups is within browser range (3-6)`,
      };
    },
    botExpected: true,
    browserExpected: false,
  },
  {
    id: 'prefix_heuristic',
    name: '9. JA4_a prefix heuristic',
    desc: 'Prefix t13d15/17/20 → browser. Other → bot.',
    test: (r) => {
      const p = r.ja4_a || '';
      const isBrowserPrefix = p.startsWith('t13d15') || p.startsWith('t13d17') || p.startsWith('t13d20');
      const fires = !isBrowserPrefix;
      return {
        fires,
        data: `prefix="${p}"`,
        reason: fires
          ? `"${p}" does NOT match any known browser prefix (t13d15/17/20)`
          : `"${p}" matches a known browser prefix`,
      };
    },
    botExpected: true,
    browserExpected: false,
  },
  {
    id: 'grease_check',
    name: '10. GREASE presence',
    desc: 'Browsers always inject GREASE values. Bots almost never do.',
    test: (r) => {
      const fires = r.grease_present === false || r.grease_count === 0;
      return {
        fires,
        data: `grease_count=${r.grease_count ?? '?'}`,
        reason: fires
          ? `no GREASE values found (count=${r.grease_count ?? 0}) — all browsers send GREASE`
          : `GREASE values present (count=${r.grease_count}) — browser-like behavior`,
      };
    },
    botExpected: true,
    browserExpected: false,
  },
];

async function runAll() {
  console.log('\n╔══════════════════════════════════════════════════════════════╗');
  console.log('║   TLS Fingerprint — Bot Detection Signal-by-Signal Test   ║');
  console.log('╚══════════════════════════════════════════════════════════════╝\n');

  // ── Trigger TLS clients ──
  const testDefs = [
    { label: 'curl (macOS LibreSSL)' },
    { label: 'openssl s_client (macOS LibreSSL)' },
    { label: 'Node.js https GET' },
    { label: 'curl H2' },
    { label: 'curl H1' },
    { label: 'Node.js no-SNI' },
    { label: 'Python urllib' },
  ];

  for (const t of testDefs) {
    process.stdout.write(`  ${t.label.padEnd(34)} ... `);
    if (t.label.includes('curl')) {
      trigger(t.label, `curl -sk --connect-timeout 3 https://127.0.0.1:9443 2>/dev/null || true`);
    } else if (t.label.includes('openssl')) {
      trigger(t.label, `echo | openssl s_client -connect 127.0.0.1:9443 -servername localhost 2>&1 || true`);
    } else if (t.label.includes('Node.js no-SNI')) {
      trigger(t.label, `node -e "require('https').get('https://127.0.0.1:9443',{rejectUnauthorized:false,servername:''}).on('error',()=>{})" 2>/dev/null`);
    } else if (t.label.includes('Node.js')) {
      trigger(t.label, `node -e "require('https').get('https://127.0.0.1:9443',{rejectUnauthorized:false}).on('error',()=>{})" 2>/dev/null`);
    } else if (t.label.includes('Python')) {
      trigger(t.label, `python3 -c "import urllib.request; urllib.request.urlopen('https://127.0.0.1:9443',timeout=3)" 2>/dev/null || true`);
    }
    await sleep(500);
    console.log('✓');
  }
  await sleep(500);

  const all = await fetchJSON('/results?limit=50');
  const results = all.results || [];
  const chronological = [...results].reverse().slice(0, testDefs.length);

  console.log(`\nCaptured ${results.length} total. Testing ${chronological.length}...\n`);

  if (chronological.length === 0) {
    console.log('❌ No fingerprints captured. Is the server running?');
    process.exit(1);
  }

  // ── Per-test analysis with reason table ──
  for (let i = 0; i < chronological.length; i++) {
    const r = chronological[i];
    const label = testDefs[i]?.label || `Test #${i + 1}`;
    const isBot = r.possible_bot;
    const verdict = isBot ? '⚠ BOT' : '✓ BROWSER';

    console.log(`═══════════════════════════════════════════════════════════`);
    console.log(`  Test #${i + 1}: ${label}`);
    console.log(`  JA4:   ${r.ja4}`);
    console.log(`  JA4_a: ${r.ja4_a}  |  JA4_b: ${r.ja4_b}  |  JA4_c: ${r.ja4_c}`);
    console.log(`  → Server verdict: ${verdict}  |  Matched: "${r.match}"  |  Confidence: ${r.confidence}`);
    console.log(`  Raw:   TLS ${r.tls_version}  |  ${r.cipher_count} ciphers  |  ${r.extension_count} exts`);
    console.log(`         ALPN: ${r.alpn || 'none'}  |  SNI: ${r.sni_present ? '✓' : '✗'}`);
    console.log(`         SigAlgs: ${(r.sigalgs || []).length}  |  Groups: ${(r.supported_groups || []).length}`);
    if (r.bot_signals && r.bot_signals.length) console.log(`         Signals triggered: ${r.bot_signals.join(', ')}`);

    // Build per-signal table with reason
    const sigRows = [];
    let sigTotal = 0, sigPassed = 0, sigFailed = 0;

    for (const s of SIGNALS) {
      let result;
      try { result = s.test(r); } catch(e) { result = { fires: null, data: '?', reason: `error: ${e.message}` }; }

      if (result.fires === null) { continue; }
      sigTotal++;

      const expected = isBot ? s.botExpected : s.browserExpected;
      const isPass = (result.fires === true && expected === true) ||
                     (result.fires === false && expected === false);

      if (isPass) sigPassed++; else sigFailed++;

      sigRows.push({
        Signal: s.name,
        Data: result.data,
        Fires: result.fires ? '⚠ yes' : 'no',
        Expect: isBot ? 'bot→yes' : 'browser→no',
        Result: isPass ? '✓ PASS' : '✗ FAIL',
        Reason: result.reason,
      });
    }

    console.log(`\n  Signal Analysis (${sigPassed}/${sigTotal} passed, ${sigFailed} failed):\n`);
    // Print as aligned text table for readability
    for (const row of sigRows) {
      const passFail = row.Result === '✓ PASS' ? '✓' : '✗';
      console.log(`  ${passFail} ${row.Signal}`);
      console.log(`     Data:   ${row.Data}   |   Fired: ${row.Fires}   |   Expected: ${row.Expect}`);
      console.log(`     Why:    ${row.Reason}`);
      console.log('');
    }
    console.log('');
  }

  // ── Aggregate ──
  console.log('═══════════════════════════════════════════════════════════');
  console.log('  AGGREGATE SIGNAL PERFORMANCE\n');

  const agg = {};
  for (const s of SIGNALS) agg[s.id] = { name: s.name, total: 0, passed: 0, failed: 0, na: 0 };

  for (const r of chronological) {
    const isBot = r.possible_bot;
    for (const s of SIGNALS) {
      let result;
      try { result = s.test(r); } catch(e) { result = { fires: null }; }
      if (result.fires === null) { agg[s.id].na++; continue; }
      agg[s.id].total++;
      const expected = isBot ? s.botExpected : s.browserExpected;
      const isPass = (result.fires === true && expected === true) ||
                     (result.fires === false && expected === false);
      if (isPass) agg[s.id].passed++; else agg[s.id].failed++;
    }
  }

  const aggTable = {};
  for (const [id, a] of Object.entries(agg)) {
    if (a.total === 0) continue;
    const rate = a.total > 0 ? ((a.passed / a.total) * 100).toFixed(0) : '-';
    const fails = a.failed > 0 ? ` (${a.failed} failed)` : '';
    aggTable[id.slice(0, 20)] = `${a.passed}/${a.total} ${rate}%${fails}`;
  }
  console.table(aggTable);

  const allRates = Object.values(agg).filter(a => a.total > 0);
  const totalPassed = allRates.reduce((s, a) => s + a.passed, 0);
  const totalTests = allRates.reduce((s, a) => s + a.total, 0);
  const overallRate = totalTests > 0 ? ((totalPassed / totalTests) * 100).toFixed(1) : '0';

  console.log(`\n  OVERALL: ${totalPassed}/${totalTests} tests passed (${overallRate}%)`);
  console.log(`  Server:  ${results.length} total  |  ${results.filter(r => r.from_a_browser).length} browsers  |  ${results.filter(r => r.possible_bot).length} bots`);
  console.log('');
}

runAll().catch(console.error);
