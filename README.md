# true-links
**TrueLinks** is a Chrome extension that provides **transparent, real-time** safety insights for any link on the web.
By simply hovering over a link, users can see its true destination, risk indicators, and reasoning - before clicking.

TrueLinks is designed to **increase awareness**, not to block content or replace security software.

## Why TrueLinks exists
Most users click links without ever seeing where they truly lead.
Shortened URLs, misleading anchor text, and unfamiliar domains make it difficult to judge link safety at a glance.
TrueLinks addresses this by:
* Revealing the actual destination URL
* Highlighting common risk indicators
* presenting results in a clear, understandable UI
No clicks required, just hover.

## Key Features
* **Instant link analysis** on hover
* **Risk score with color-coded levels** (Safe / Moderate / Risky)
* **Transparent reasoning** for each risk indicator
* **Optional details view**, including:
  * full destination URL
  * detected tags and factors
* **Works on any `<a>` element**, including:
  * search results
  * messaging apps
  * regular websites
* All analysis is designed to be fast, readable, and non-intrusive.

## How it works (high-level)
TrueLinks evaluates link using **multiple independent signals**, such as:
* protocol security (e.g. HTTP vs HTTPS)
* URL structure and obfuscation
* known shortening patterns
* domain characteristics
Each signal contributes to an overall risk score, which is shown alongside a human-readable explanation.

## What TrueLinks does *not* do
* It does **not** block links
* It does **not** claim to detect all malicious URLs
* It does **not** replace antivirus software or professional security tools
TrueLinks is an **informational aid**, not an authority.

## Privacy & Transparency
* TrueLinks does **not collect or sell user data**
* Link analysis is performed locally whenever possible
* The project is **open source** to allow inspiration and feedback
Transparency is a core design principle. See our [Privacy Policy](PRIVACY.md).

## Installation (Development / Testing)
1. Clone or download this repository
2. Open Chrome and navigate `chrome://extensions`
3. Enable **Developer Mode**
4. Click **Load unpacked**
5. Select the project directory
(Chrome Web Store release planned after extended testing.)

## Limitations & Accuracy
TrueLinks reports **risk indicators**, not certainties.
Some legitimate links may appear risky due to:
* uncommon domain structures
* new or rarely used domains
* URL shortening
Users are encouraged to interpret results using context and judgment.

## Feedback & Contributions
Feedback from security-aware users, developers, and testers is welcome.
If you find:
* false positives
* missed indicators
* UI clarity issues
Please open an issue or reach out with details.

## License
This project is licensed under the **MIT License**.
