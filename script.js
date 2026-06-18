/**
 * PassCheck — script.js
 * Clean modular password strength analyzer
 */

'use strict';

/* ─── Data ────────────────────────────────────────────── */

const COMMON = new Set([
  'password','password1','password123','123456','12345678','1234567890',
  'qwerty','qwerty123','letmein','iloveyou','admin','admin123','welcome',
  'monkey','dragon','master','sunshine','princess','shadow','superman',
  'batman','football','baseball','abc123','111111','000000','123123',
  '654321','trustno1','hello','hello123','pass','test','login','solo',
  'changeme','starwars','1234','12345','123456789','passw0rd','pass1',
  'qwertyuiop','1q2w3e4r','zaq12wsx','password!','welcome1','welcome123',
  'letmein123','dragon123','freedom','whatever','qazwsx','michael',
  'jennifer','jordan23','harley','ranger','buster','soccer','hockey',
  'killer','george','andrew','charlie','tigger','robert','thomas',
  'access','flower','hunter','fuckyou','2000','test123','admin1',
  'root','toor','guest','default','temp1234','asdf1234','iloveyou1',
  'monkey123','letme123','passwordpassword','1111111111','00000000',
  'newpassword','correcthorsebatterystaple',
]);

const SEQ = [
  'abcdefghijklmnopqrstuvwxyz',
  'zyxwvutsrqponmlkjihgfedcba',
  '0123456789', '9876543210',
  'qwertyuiop', 'asdfghjkl', 'zxcvbnm',
];

/* ─── Engine ──────────────────────────────────────────────────
   Scoring model follows NIST SP 800-63B Revision 4 (2025):
   - Length is the primary strength signal, not character variety.
   - Composition rules (must-have upper/lower/number/symbol) are NOT
     required or enforced — shown only as informational signals.
   - Known-breached / commonly-used passwords are blocklisted and
     fail regardless of length (NIST mandates blocklist screening).
   - Predictable patterns (repeats, sequences) reduce effective
     entropy and are still flagged.
   ──────────────────────────────────────────────────────────── */

const MIN_LEN  = 8;  // absolute floor (NIST: with MFA, 8 is acceptable)
const GOOD_LEN = 15; // NIST recommendation for single-factor passwords

/**
 * Full password strength check.
 * @param {string} pw
 * @returns {object|null}
 */
function checkStrength(pw) {
  if (!pw) return null;

  // Informational signals — never block a "strong" rating on their own.
  const signals = {
    upper: /[A-Z]/.test(pw),
    lower: /[a-z]/.test(pw),
    num:   /[0-9]/.test(pw),
    sym:   /[^a-zA-Z0-9]/.test(pw),
  };

  // Hard-fail conditions per NIST blocklist + pattern guidance.
  const blocked  = COMMON.has(pw.toLowerCase());
  const repeats  = hasRepeats(pw);
  const sequence = hasSequence(pw);

  const has = {
    len:    pw.length >= MIN_LEN,
    goodLen: pw.length >= GOOD_LEN,
    ...signals,
    common: !blocked,
    rep:    !repeats,
    seq:    !sequence,
  };

  const { level, pct } = scorePassword(pw, { blocked, repeats, sequence });

  return { has, level, pct, entropy: entropy(pw) };
}

/**
 * Length-led scoring. Character variety nudges the score but
 * never gates it — a long passphrase of lowercase words can
 * still reach "strong", matching NIST's length-over-complexity stance.
 */
function scorePassword(pw, { blocked, repeats, sequence }) {
  // Blocklisted credentials are weak no matter how long they are.
  if (blocked) return { level: 'weak', pct: 8 };

  const len = pw.length;

  // Base score climbs steeply with length up to the 15-char target,
  // then continues more gradually (diminishing but real returns).
  let pct;
  if (len <= 0)       pct = 0;
  else if (len < MIN_LEN)  pct = (len / MIN_LEN) * 25;                 // 0–8 chars   -> 0–25%
  else if (len < GOOD_LEN) pct = 25 + ((len - MIN_LEN) / (GOOD_LEN - MIN_LEN)) * 50; // 8–15 -> 25–75%
  else                 pct = 75 + Math.min((len - GOOD_LEN) * 2.5, 25); // 15+ chars  -> 75–100%

  // Small bonus for character variety (informational, not required).
  const varietyCount = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/].filter(r => r.test(pw)).length;
  pct += Math.max(varietyCount - 1, 0) * 1.5;

  // Predictable patterns meaningfully reduce real-world strength.
  if (repeats)  pct -= 15;
  if (sequence) pct -= 15;

  pct = Math.max(0, Math.min(100, Math.round(pct)));

  let level;
  if (pct < 40)      level = 'weak';
  else if (pct < 75) level = 'medium';
  else               level = 'strong';

  return { level, pct };
}

/**
 * Password entropy: length × log2(pool)
 * @param {string} pw
 * @returns {number} bits
 */
function calculateEntropy(pw) {
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 32;
  return pool ? Math.round(pw.length * Math.log2(pool)) : 0;
}
const entropy = calculateEntropy; // alias

/**
 * Detect 3+ consecutive repeated chars (aaa, 111…)
 */
function hasRepeats(pw) {
  return /(.)\1{2,}/.test(pw);
}

/**
 * Detect 3+ sequential characters (abc, 123, qwe…)
 */
function hasSequence(pw) {
  const lc = pw.toLowerCase();
  for (const s of SEQ) {
    for (let i = 0; i <= s.length - 3; i++) {
      if (lc.includes(s.slice(i, i + 3))) return true;
    }
  }
  return false;
}

/**
 * Estimate crack time from entropy bits.
 * Assumes 10 billion guesses/sec (GPU cluster), average case.
 */
function crackTime(bits) {
  const secs = Math.pow(2, bits) / 1e10 / 2;
  if (secs < 1)            return 'less than a second';
  if (secs < 60)           return `${Math.round(secs)} seconds`;
  if (secs < 3600)         return `${Math.round(secs / 60)} minutes`;
  if (secs < 86400)        return `${Math.round(secs / 3600)} hours`;
  if (secs < 2592000)      return `${Math.round(secs / 86400)} days`;
  if (secs < 31536000)     return `${Math.round(secs / 2592000)} months`;
  if (secs < 3.15e9)       return `${Math.round(secs / 31536000)} years`;
  return 'centuries';
}

/**
 * Generate a cryptographically secure strong password.
 * @param {number} len
 * @returns {string}
 */
function generatePassword(len = 18) {
  const sets = [
    'ABCDEFGHJKLMNPQRSTUVWXYZ',
    'abcdefghjkmnpqrstuvwxyz',
    '23456789',
    '!@#$%^&*-_=+?',
  ];
  const all = sets.join('');
  // Guarantee at least one from each set
  let chars = sets.map(s => s[rnd(s.length)]);
  while (chars.length < len) chars.push(all[rnd(all.length)]);
  // Shuffle
  for (let i = chars.length - 1; i > 0; i--) {
    const j = rnd(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join('');
}

/** Secure random integer in [0, max) */
function rnd(max) {
  const a = new Uint32Array(1);
  crypto.getRandomValues(a);
  return a[0] % max;
}

/* ─── DOM ─────────────────────────────────────────────── */

const $  = id => document.getElementById(id);
const el = {
  input:    $('passwordInput'),
  toggle:   $('toggleBtn'),
  eyeShow:  $('eyeShow'),
  eyeHide:  $('eyeHide'),
  copy:     $('copyBtn'),
  gen:      $('genBtn'),
  copyMsg:  $('copyMsg'),
  barFill:  $('barFill'),
  label:    $('meterLabel'),
  stats:    $('meterStats'),
  crack:    $('crackTime'),
  checks:   $('checks'),
  divider:  $('divider'),
  tips:     $('tipsWrap'),
  tipsList: $('tipsList'),
  history:  $('historyWrap'),
  histList: $('historyList'),
  clearBtn: $('clearBtn'),
  themeBtn: $('themeBtn'),
  iconMoon: $('iconMoon'),
  iconSun:  $('iconSun'),
};

const LABELS = {
  'ck-len':    h => h.goodLen,   // headline: 15+ chars (NIST recommendation)
  'ck-floor':  h => h.len,       // 8-char minimum floor
  'ck-upper':  h => h.upper,
  'ck-lower':  h => h.lower,
  'ck-num':    h => h.num,
  'ck-sym':    h => h.sym,
  'ck-common': h => h.common,
  'ck-rep':    h => h.rep,
  'ck-seq':    h => h.seq,
};

const TIPS = {
  goodLen: 'Aim for 15+ characters — length matters far more than mixing symbols (NIST SP 800-63B)',
  len:     'Use at least 8 characters as an absolute floor',
  upper:   'Optional: uppercase letters add a little variety, but are not required',
  lower:   'Optional: lowercase letters add a little variety, but are not required',
  num:     'Optional: numbers add a little variety, but are not required',
  sym:     'Optional: symbols add a little variety, but are not required',
  common:  'This password (or a close variant) appears in known breach lists — avoid it entirely',
  rep:     'Remove repeated characters (e.g. "aaa") — they reduce real-world strength',
  seq:     'Avoid sequences like "1234" or "abcd" — they\'re easy to guess',
};

/* ─── State ───────────────────────────────────────────── */

let history  = [];
let copyTimer = null;
let dark     = false;

/* ─── Render ──────────────────────────────────────────── */

function render(pw) {
  const result = checkStrength(pw);

  if (!result) {
    el.barFill.style.width = '0';
    el.barFill.className   = 'bar-fill';
    el.label.textContent   = '—';
    el.label.className     = 'meter-label';
    el.stats.textContent   = '';
    el.crack.textContent   = '';
    el.checks.style.display  = 'none';
    el.divider.style.display = 'none';
    el.tips.style.display    = 'none';
    resetDots();
    return;
  }

  // Bar
  el.barFill.style.width = result.pct + '%';
  el.barFill.className   = `bar-fill ${result.level}`;

  // Label
  const names = { weak: 'Weak', medium: 'Medium', strong: 'Strong' };
  el.label.textContent = names[result.level];
  el.label.className   = `meter-label ${result.level}`;

  // Stats & crack
  el.stats.textContent = `${result.entropy} bits`;
  el.crack.textContent = `Estimated crack time: ${crackTime(result.entropy)}`;

  // Checks
  el.checks.style.display  = 'grid';
  el.divider.style.display = 'block';

  Object.entries(LABELS).forEach(([id, test]) => {
    const li  = $(id);
    const ok  = test(result.has);
    li.className = `check ${ok ? 'pass' : 'fail'}`;
  });

  // Tips — ordered by what actually matters under NIST guidance:
  // length & blocklist & patterns first (these are the real risks),
  // composition last (purely optional, never a requirement).
  const PRIORITY = ['goodLen', 'len', 'common', 'rep', 'seq', 'upper', 'lower', 'num', 'sym'];
  const missing = PRIORITY
    .filter(k => result.has[k] === false)
    .map(k => TIPS[k])
    .filter(Boolean);

  if (missing.length) {
    el.tipsList.innerHTML = missing.map((t, i) =>
      `<li style="animation-delay:${i * .04}s">${t}</li>`
    ).join('');
    el.tips.style.display = 'block';
  } else {
    el.tips.style.display = 'none';
  }
}

function resetDots() {
  document.querySelectorAll('.check').forEach(li => {
    li.className = 'check';
  });
}

/* ─── History ─────────────────────────────────────────── */

let historyTimer = null;

function addHistory(pw, level) {
  if (history[0]?.raw === pw) return;
  const masked =
    pw.length <= 3 ? '*'.repeat(pw.length) :
    pw[0] + '*'.repeat(Math.max(pw.length - 2, 2)) + pw.slice(-1);
  history.unshift({ raw: pw, masked, level });
  if (history.length > 5) history.pop();
  renderHistory();
}

function renderHistory() {
  if (!history.length) { el.history.style.display = 'none'; return; }
  el.history.style.display = 'block';
  el.histList.innerHTML = history.map((h, i) => `
    <li style="animation-delay:${i * .04}s">
      <span class="h-pw">${h.masked}</span>
      <span class="h-badge ${h.level}">${h.level}</span>
    </li>
  `).join('');
}

/* ─── Events ──────────────────────────────────────────── */

// Real-time analysis
el.input.addEventListener('input', () => {
  const pw = el.input.value;
  const result = checkStrength(pw);
  render(pw);
  clearTimeout(historyTimer);
  if (pw.length >= 4 && result) {
    historyTimer = setTimeout(() => addHistory(pw, result.level), 900);
  }
});

// Show / hide
el.toggle.addEventListener('click', () => {
  const hide = el.input.type === 'password';
  el.input.type            = hide ? 'text' : 'password';
  el.eyeShow.style.display = hide ? 'none' : '';
  el.eyeHide.style.display = hide ? '' : 'none';
});

// Copy
el.copy.addEventListener('click', async () => {
  const pw = el.input.value;
  if (!pw) return;
  try {
    await navigator.clipboard.writeText(pw);
  } catch {
    el.input.select();
    document.execCommand('copy');
  }
  el.copyMsg.classList.add('show');
  clearTimeout(copyTimer);
  copyTimer = setTimeout(() => el.copyMsg.classList.remove('show'), 2000);
});

// Generate
el.gen.addEventListener('click', () => {
  const pw = generatePassword(18);
  el.input.value = pw;
  el.input.type  = 'text';
  el.eyeShow.style.display = 'none';
  el.eyeHide.style.display = '';
  render(pw);
  addHistory(pw, checkStrength(pw).level);
  // Spin icon once
  el.gen.style.transition = 'transform .5s ease';
  el.gen.style.transform  = 'rotate(360deg)';
  setTimeout(() => { el.gen.style.transform = ''; el.gen.style.transition = ''; }, 520);
});

// Clear history
el.clearBtn.addEventListener('click', () => {
  history = [];
  renderHistory();
});

// Theme
el.themeBtn.addEventListener('click', () => {
  dark = !dark;
  document.documentElement.setAttribute('data-theme', dark ? 'dark' : '');
  el.iconMoon.style.display = dark ? 'none' : '';
  el.iconSun.style.display  = dark ? '' : 'none';
});

/* ─── Init ────────────────────────────────────────────── */

if (window.innerWidth >= 600) el.input.focus();