let enabled = true;
let detailed = false;
let tooltip = null;


chrome.storage.sync.get(["toggleTrueLinks"], res => {
    enabled = res.toggleTrueLinks ?? true;
    updateListeners();
});
chrome.storage.sync.get(["detailTrueLinks"], res => {
    detailed = res.detailTrueLinks ?? false;
});

chrome.storage.onChanged.addListener(changes => {
    if ("toggleTrueLinks" in changes) {
        enabled = changes.toggleTrueLinks.newValue;
        updateListeners();
    }
    if ("detailTrueLinks" in changes) 
        detailed = changes.detailTrueLinks.newValue;
});

function updateListeners() {
    if (enabled) {
        addListeners();
    } else {
        removeListeners();
    }
}

function addListeners() {
    document.addEventListener("mouseover", onMouseOver);
    document.addEventListener("mouseout", onMouseOut);
}

function removeListeners() {
    document.removeEventListener("mouseover", onMouseOver);
    document.removeEventListener("mouseout", onMouseOut);
    if (tooltip) {
        tooltip.remove();
        tooltip = null;
    }
}

function onMouseOver(e) {
    const link = e.target.closest("a");
    if (!link || !enabled) return;
    if (tooltip) {
        tooltip.remove();
        tooltip = null;
    }

    tooltip = document.createElement("div");
    tooltip.id = "tooltipDiv-TrueLinks";
    //tooltip.textContent = link.href;
    const rawHref = link.getAttribute("href");
    const parsed = new URL(link.href);

    let category = classifyURL(rawHref, parsed);
    if (category.classification == "Safe") link.style.outline = "2px solid green";
    else if (category.classification == "Risky") link.style.outline = "2px solid red";
    else link.style.outline = "2px solid yellow";
    
    tooltip.innerHTML = formatTooltip(parsed, category);
    if (detailed) colorizeTooltipTags(tooltip, category);
    document.body.appendChild(tooltip);

    positionTooltip(link);
}

function onMouseOut(e) {
    const link = e.target.closest("a");
    if (!link || !enabled) return;

    if (tooltip) {
        tooltip.remove();
        tooltip = null;
    }
    link.style.outline = "";
}

function classifyURL(raw, urlObj) {
    const rawS = -3; const rawM = -15; const rawR = -120;
    const normS = 30; const normM = 60; const normR = 100;
    function normalizeHelper(x, rraw, lraw, lnorm, rnorm){
        return Math.round((x - lraw) * ((rnorm - lnorm) / (rraw - lraw)) + lnorm);
    }
    function normalize(rawScore){
        if (rawScore >= rawS) return normalizeHelper(rawScore, rawS, 0, 0, normS);
        if (rawScore >= rawM) return normalizeHelper(rawScore, rawM, rawS, normS, normM);
        if (rawScore >= rawR) return normalizeHelper(rawScore, rawR, rawM, normM, normR);
        return null;
    }
    const fullRaw = raw.toLowerCase();
    const full = urlObj.href.toLowerCase();
    const hostname = urlObj.hostname.toLowerCase();
    const pathname = urlObj.pathname;
    const protocol = urlObj.protocol.replace(':', '').toLowerCase();
    const query = urlObj.search.toLowerCase();

    const allReasoning = {
        protocol:    { text: "Insecure Protocol",      risk: "lo"  },
        tlds:        { text: "Risky TLD",              risk: "me"  },
        shortener:   { text: "URL Shortener",          risk: "hi"  },
        long:        { text: "Unusually Long",         risk: "lo"  },
        chars:       { text: "Suspicious Characters",  risk: "me"  },
        at:          { text: "@ Symbol",               risk: "hi"  },
        subdomains:  { text: "Many Subdomains",        risk: "me"  },
        track:       { text: "Tracking Parameters",    risk: "lo"  },
        encode:      { text: "Encoded URL",            risk: "lo"  },
        traversal:   { text: "Path Traversal",         risk: "vhi" },
        punycode:    { text: "Punycode Domain",        risk: "hi"  },
        hyphen:      { text: "Hyphen Overload",        risk: "me"  },
        keyword:     { text: "Phishing Keyword",       risk: "hi"  },
        executable:  { text: "Executable URL Scheme",  risk: "lo"  },
        heuristic:   { text: "Minor Heuristic Signal", risk: "lo"  }
    };

    let totalScore = 0;
    let reasoning = [];

    // --------------------------
    // 1. Protocol (Weak signal)
    // --------------------------
    const protocolScore = protocol === "http" ? -2 : 0;
    totalScore += protocolScore;
    if (protocolScore !== 0) reasoning.push(allReasoning.protocol);

    // --------------------------
    // 2. Risky TLDs (Medium)
    // --------------------------
    const riskyTLDs = ["xyz", "top", "club", "icu", "click", "work", "link"];
    const tld = hostname.split(".").pop();
    const riskyTLDScore = riskyTLDs.includes(tld) ? -8 : 0;
    totalScore += riskyTLDScore;
    if (riskyTLDScore !== 0) reasoning.push(allReasoning.tlds);

    // --------------------------
    // 3. Shorteners (Medium-high)
    // --------------------------
    const shorteners = new Set([
        "bit.ly", "t.co", "tinyurl.com", "goo.gl", 
        "ow.ly", "buff.ly", "is.gd"
    ]);
    const shortenerScore = shorteners.has(hostname) ? -10 : 0;
    totalScore += shortenerScore;
    if (shortenerScore !== 0) reasoning.push(allReasoning.shortener);

    // --------------------------
    // 4. Excessive length (Weak)
    // --------------------------
    const lengthPenalty = -Math.floor(full.length / 60);  
    const lengthScore = Math.max(lengthPenalty, -10);
    totalScore += lengthScore;
    if (lengthScore !== 0) reasoning.push(allReasoning.long);

    // --------------------------
    // 5. Suspicious characters (Medium)
    // --------------------------
    const suspiciousChars = /['"<>|{}\\;$]/g;
    const suspMatches = (full.match(suspiciousChars) || []).length;
    const suspiciousCharPenalty = suspMatches * 2;
    const suspiciousCharScore = -Math.min(suspiciousCharPenalty, 10); // cap penalty
    totalScore += suspiciousCharScore;
    if (suspiciousCharScore !== 0) reasoning.push(allReasoning.chars);

    // --------------------------
    // 6. @ symbol (Login phishing) (High)
    // --------------------------
    const atSymbolScore = full.includes("@") ? -12 : 0;
    totalScore += atSymbolScore;
    if (atSymbolScore !== 0) reasoning.push(allReasoning.at);

    // --------------------------
    // 7. Excessive subdomains (Medium)
    // --------------------------
    const subdomainCount = hostname.split(".").length - 2;
    const subdomainScore = subdomainCount >= 3 ? -5 : 0;
    totalScore += subdomainScore;
    if (subdomainScore !== 0) reasoning.push(allReasoning.subdomains);

    // --------------------------
    // 8. Tracking parameters (Weak)
    // --------------------------
    const trackingParams = ["utm_", "gclid", "fbclid", "ref=", "aff="];
    const trackingScore = trackingParams.some(p => query.includes(p)) ? -1 : 0;
    totalScore += trackingScore;
    if (trackingScore !== 0) reasoning.push(allReasoning.track);

    // --------------------------
    // 9. URL Encoding (Low)
    // --------------------------
    const enc = full.match(/%[0-9a-f]{2}/gi) || [];
    let encodingScore = -1 * Math.min(enc.length, 6); // cap penalty
    totalScore += encodingScore;
    if (encodingScore !== 0) reasoning.push(allReasoning.encode);

    // --------------------------
    // 10. Traversal attack (VERY HIGH)
    // --------------------------
    const traversalEncoded = /%2e%2e|%2f%2e%2e|%5c%2e%2e/i;
    const traversalDecoded = /\.\.\//;
    if (traversalEncoded.test(fullRaw) || traversalDecoded.test(pathname)) {
        totalScore -= 25;
        reasoning.push(allReasoning.traversal);
    }

    // --------------------------
    // 11. Punycode domain (High)
    // --------------------------
    const punycodeScore = hostname.includes("xn--") ? -15 : 0;
    totalScore += punycodeScore;
    if (punycodeScore !== 0) reasoning.push(allReasoning.punycode);

    // --------------------------
    // 12. Hyphen overload (Phishing mimic) (Medium)
    // --------------------------
    const hyphenCount = hostname.split("-").length - 1;
    const hyphenScore = hyphenCount >= 4 ? -6 : 0;
    totalScore += hyphenScore;
    if (hyphenScore !== 0) reasoning.push(allReasoning.hyphen);

    // --------------------------
    // 13. Keyword phishing (Medium-high)
    // --------------------------
    const phishingKeywords = ["login", "verify", "secure", "update", "account"];
    const brandKeywords = ["paypal", "microsoft", "apple", "google", "bank"];

    let keywordScore = 0;
    if (phishingKeywords.some(k => hostname.includes(k))) keywordScore -= 2;
    if (phishingKeywords.some(k => pathname.includes(k))) keywordScore -= 5;
    if (brandKeywords.some(k => hostname.includes(k))) keywordScore -= 1;
    if (brandKeywords.some(k => pathname.includes(k))) keywordScore -= 4;

    totalScore += keywordScore;
    if (keywordScore !== 0) reasoning.push(allReasoning.keyword);

    // --------------------------
    // 14. Executable URL Scheme (Low)
    // --------------------------
    const executableSchemes = ["javascript", "data", "vbscript"];
    const execSchemeScore = executableSchemes.includes(protocol) ? -1 : 0;

    totalScore += execSchemeScore;
    if (execSchemeScore !== 0) reasoning.push(allReasoning.executable);

    // --------------------------

    let classs = "Risky";
    if (totalScore >= rawS) classs = "Safe";
    else if (totalScore >= rawM) classs = "Moderate";
    
    if (classs !== "Safe" && reasoning.length === 0) reasoning.push(allReasoning.heuristic);

    const riskRank = { vhi: 3, hi: 2, me: 1, lo: 0 };

    reasoning = reasoning.sort((a, b) => {
        if (typeof a === "string") return 1;
        if (typeof b === "string") return -1;

        return riskRank[b.risk] - riskRank[a.risk];
    });

    return { classification: classs, score: totalScore, normalScore: normalize(totalScore), reasons: reasoning };
}

function colorizeTooltipTags(tooltip, category) {
    if (!category.reasons || category.reasons.length === 0) return;

    let html = tooltip.innerHTML;

    const visibleReasons = category.reasons.slice(0, 3);

    for (const reason of visibleReasons) {
        const txt = reason.text;
        const cls = `tag-${reason.risk}-TrueLinks`;

        const escaped = txt.replace(/[-/\\^$*+?.()|[\]{}]/g, "\\$&");

        const useWordBoundaries = /^[A-Za-z0-9 ]+$/.test(txt);

        const pattern = useWordBoundaries
            ? `\\b${escaped}\\b`
            : escaped;

        const regex = new RegExp(pattern, "g");

        html = html.replace(regex, `<span class="${cls}">${txt}</span>`);
    }

    tooltip.innerHTML = html;
}


function formatTooltip(parsedUrl, category) {
    let cls = "";
    switch (category.classification) {
        case "Safe":
            cls = "risk-safe-TrueLinks";
            break;
        case "Moderate":
            cls = "risk-moderate-TrueLinks";
            break;
        case "Risky":
            cls = "risk-risky-TrueLinks";
            break;
    }

    const shortPath = parsedUrl.pathname.length > 40
        ? parsedUrl.pathname.slice(0, 40) + "..."
        : parsedUrl.pathname;

    const line1 = `${parsedUrl.hostname}${shortPath}`;

    const line2 = `<span class="${cls}">Risk: ${category.classification.toUpperCase()} (${category.normalScore}/100)</span>`;

    const tags = category.reasons && category.reasons.length > 0
        ? category.reasons
            .slice(0, 3)
            .map(r => r.text)
            .join(", ") + (category.reasons.length > 3 ? "..." : "")
        : "None";

    const line3 = `Tags: ${tags}`;

    if (detailed) return `${line1}\n${line2}\n${line3}`;
    else return `${line2}`;
}


function positionTooltip(link) {
    const r = link.getBoundingClientRect();

    const left = r.left + window.scrollX;
    const top = r.bottom + window.scrollY + 6;

    tooltip.style.left = left + "px";
    tooltip.style.top = top + "px";

    // Now clamp to viewport
    requestAnimationFrame(() => {
        const rect = tooltip.getBoundingClientRect();

        // clamp X (right edge)
        if (rect.right > window.innerWidth - 4) {
            tooltip.style.left =
                (window.innerWidth - rect.width - 4 + window.scrollX) + "px";
        }

        // clamp X (left edge)
        if (rect.left < 4) {
            tooltip.style.left = (4 + window.scrollX) + "px";
        }

        // clamp Y (bottom)
        if (rect.bottom > window.innerHeight - 4) {
            tooltip.style.top =
                (r.top + window.scrollY - rect.height - 6) + "px";
        }

        // clamp Y (top)
        if (rect.top < 4) {
            tooltip.style.top = (4 + window.scrollY) + "px";
        }
    });
}


// Tooltip styles
const style = document.createElement("style");
style.textContent = `
#tooltipDiv-TrueLinks {
    position: absolute;
    z-index: 999999;
    background: #333;
    color: #fff;
    padding: 6px 10px;
    border-radius: 6px;
    font-size: 13px;
    pointer-events: none;
    white-space: pre-wrap;
    line-height: 17px;
    max-width: 260px;
    overflow-wrap: break-word;
    font-family: system-ui, -apple-system, BlinkMacSystemFont,
             "Segoe UI", Roboto, Helvetica, Arial, sans-serif;

}

.risk-safe-TrueLinks     { color: #65d96d; font-weight: bold; }
.risk-moderate-TrueLinks { color: #ffd84a; font-weight: bold; }
.risk-risky-TrueLinks    { color: #ff5d5d; font-weight: bold; }

.tag-lo-TrueLinks  { color: #65d96d; }
.tag-me-TrueLinks  { color: #ffd84a; }
.tag-hi-TrueLinks  { color: #ff5d5d; }
.tag-vhi-TrueLinks { color: #ff3b3b; }
`;
document.head.appendChild(style);