<div align="center">

<img src="https://img.shields.io/badge/PassCheck-Password%20Strength%20Analyzer-2563eb?style=for-the-badge&logo=lock&logoColor=white" alt="PassCheck" />

<br/><br/>

![HTML](https://img.shields.io/badge/HTML5-E34F26?style=flat-square&logo=html5&logoColor=white)
![CSS](https://img.shields.io/badge/CSS3-1572B6?style=flat-square&logo=css3&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=flat-square&logo=javascript&logoColor=black)
![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)

<p><strong>Instant password strength analysis. No frameworks. No backend. Nothing leaves your device.</strong></p>

[Features](#features) · [How It Works](#how-it-works) · [Getting Started](#getting-started) · [Security](#security--privacy)

</div>

---

## Features

- 🔐 **Real-time strength analysis** — instant feedback as you type
- 📏 **NIST SP 800-63B Rev. 4 aligned** — length over complexity
- 🧮 **Entropy estimation** — password strength in bits
- ⏱️ **Crack time estimate** — assumes 10 billion guesses/sec (GPU cluster)
- 🚫 **Breached password detection** — checks against common/leaked passwords
- 🔁 **Pattern detection** — flags repeats (`aaa`) and sequences (`1234`, `abcd`)
- ⚡ **Secure password generator** — cryptographically random, 18 chars by default
- 🕓 **Recent history** — last 5 passwords (masked) with strength ratings
- 📋 **Copy to clipboard** — one-click with confirmation toast
- 🌙 **Dark / light theme toggle**
- 📦 **Zero dependencies** — no libraries, no telemetry, no network calls

---

## Getting Started

No build step required. Clone and open.

```bash
git clone https://github.com/your-username/passcheck.git
cd passcheck
open index.html
```

Or serve it locally to avoid any `file://` quirks:

```bash
npx serve .
# or
python3 -m http.server
```

Then visit `http://localhost:3000` (or whichever port is shown).

---

## File Structure

```
passcheck/
├── index.html   # Markup and layout
├── style.css    # CSS variables, light/dark themes, animations
└── script.js    # Scoring engine, DOM interactions, generator
```

---

## How It Works

### Scoring Model

Scoring follows NIST SP 800-63B Rev. 4 — **length is the primary strength signal**, not character variety:

| Password Length | Base Score |
|----------------|------------|
| < 8 chars      | 0 – 25%    |
| 8 – 14 chars   | 25 – 75%   |
| 15+ chars      | 75 – 100%  |

Small bonuses apply for character variety, but these never gate the rating on their own. Penalties apply for repeated characters (−15%) and sequential patterns (−15%). Blocklisted passwords are always rated **Weak**.

| Score  | Level  |
|--------|--------|
| < 40%  | 🔴 Weak   |
| 40–74% | 🟡 Medium |
| 75%+   | 🟢 Strong |

### Entropy

```
entropy = length × log₂(pool size)
```

Pool size is the union of character sets present: lowercase (26), uppercase (26), digits (10), symbols (32).

### Crack Time

Assumes an average-case attack at **10 billion guesses/second**:

```
seconds = 2^bits / 1e10 / 2
```

### Password Generator

Uses `crypto.getRandomValues()` (CSPRNG — not `Math.random()`). Guarantees at least one character from each set:

| Set | Characters |
|-----|-----------|
| Uppercase | `A–Z` (excluding `I`, `O`) |
| Lowercase | `a–z` (excluding `l`) |
| Digits | `2–9` (excluding `0`, `1`) |
| Symbols | `!@#$%^&*-_=+?` |

---

## Security & Privacy

- ✅ **Fully client-side** — no passwords or scores ever leave your browser
- ✅ **CSPRNG** — uses `crypto.getRandomValues()` for generation
- ✅ `autocomplete="new-password"` and `spellcheck="false"` on the input field
- ✅ No analytics, no cookies, no external requests at runtime

---

## Browser Support

Any modern browser supporting:

- CSS custom properties
- `crypto.getRandomValues`
- `navigator.clipboard` (falls back to `execCommand`)
- `color-mix()` in sRGB (progressive enhancement)

---

## References

- [NIST SP 800-63B Rev. 4 — Digital Identity Guidelines](https://pages.nist.gov/800-63-4/)

---

## License

[MIT](LICENSE) — free to use, modify, and distribute.
