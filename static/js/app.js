/**
 * EmailGuard - Client-side Interactive Logic & Asynchronous API Client
 */

// Cache sample data loaded from server
let globalSampleData = null;

// Initialize on DOM ready
document.addEventListener("DOMContentLoaded", () => {
    initTabs();
    fetchSampleData();
    fetchHealthStatus();
});

/**
 * Tab Navigation Controller
 */
function initTabs() {
    const tabButtons = document.querySelectorAll(".tab-btn");
    const tabPanes = document.querySelectorAll(".tab-pane");

    tabButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            tabButtons.forEach(b => b.classList.remove("active"));
            tabPanes.forEach(p => p.classList.remove("active"));

            btn.classList.add("active");
            const targetId = btn.getAttribute("data-tab");
            const targetPane = document.getElementById(targetId);
            if (targetPane) {
                targetPane.classList.add("active");
            }
        });
    });
}

/**
 * Fetch Health & Model Status
 */
async function fetchHealthStatus() {
    try {
        const res = await fetch("/api/health");
        const data = await res.json();
        const statusEl = document.getElementById("model-status-text");
        if (data.status === "healthy" && data.model_trained) {
            statusEl.textContent = "AI Model: Active & Ready";
        }
    } catch (e) {
        console.warn("Health check error:", e);
    }
}

/**
 * Preload Sample Data from Server
 */
async function fetchSampleData() {
    try {
        const res = await fetch("/api/sample-data");
        globalSampleData = await res.json();
    } catch (e) {
        console.warn("Could not preload sample data:", e);
    }
}

/**
 * Quick Load Sample for Spam Detection
 */
function loadSpamSample(index) {
    if (!globalSampleData || !globalSampleData.spam_samples[index]) return;
    const sample = globalSampleData.spam_samples[index];
    document.getElementById("spam-subject").value = sample.subject;
    document.getElementById("spam-body").value = sample.body;
    analyzeSpam();
}

function loadHamSample(index) {
    if (!globalSampleData || !globalSampleData.ham_samples[index]) return;
    const sample = globalSampleData.ham_samples[index];
    document.getElementById("spam-subject").value = sample.subject;
    document.getElementById("spam-body").value = sample.body;
    analyzeSpam();
}

function clearSpamForm() {
    document.getElementById("spam-subject").value = "";
    document.getElementById("spam-body").value = "";
    document.getElementById("spam-result-content").classList.add("hidden");
    document.getElementById("spam-empty-state").classList.remove("hidden");
    const badge = document.getElementById("verdict-badge");
    badge.className = "badge badge-neutral";
    badge.textContent = "Awaiting Input";
}

/**
 * Analyze Email Security (Spam / Phishing Detection)
 */
async function analyzeSpam() {
    const subject = document.getElementById("spam-subject").value.trim();
    const body = document.getElementById("spam-body").value.trim();

    if (!subject && !body) {
        alert("Please enter email text or subject to analyze.");
        return;
    }

    const btn = document.getElementById("btn-detect-spam");
    const originalText = btn.innerHTML;
    btn.innerHTML = "<span>Analyzing Email...</span>";
    btn.disabled = true;

    try {
        const response = await fetch("/api/detect-spam", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ subject, body })
        });

        const result = await response.json();

        if (result.success) {
            renderSpamResult(result.data);
        } else {
            alert("Error: " + (result.error || "Unable to analyze email"));
        }
    } catch (err) {
        alert("Network or server error while contacting API: " + err.message);
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}

function renderSpamResult(data) {
    document.getElementById("spam-empty-state").classList.add("hidden");
    const resultContent = document.getElementById("spam-result-content");
    resultContent.classList.remove("hidden");

    // Verdict Badge
    const badge = document.getElementById("verdict-badge");
    if (data.is_spam) {
        badge.className = "badge badge-danger";
        badge.textContent = "SPAM / PHISHING DETECTED";
    } else if (data.risk_level === "Suspicious") {
        badge.className = "badge badge-warning";
        badge.textContent = "SUSPICIOUS EMAIL";
    } else {
        badge.className = "badge badge-success";
        badge.textContent = "SAFE EMAIL (HAM)";
    }

    // Risk Circle Gradient & Score
    const circle = document.getElementById("risk-circle");
    const scoreText = document.getElementById("risk-score");
    const prob = data.spam_probability;
    scoreText.textContent = `${Math.round(prob)}%`;

    let color = "#10b981"; // green
    if (prob >= 75) color = "#ef4444"; // red
    else if (prob >= 50) color = "#f97316"; // orange
    else if (prob >= 25) color = "#f59e0b"; // yellow

    circle.style.background = `conic-gradient(${color} ${prob}%, #e2e8f0 ${prob}%)`;

    // Metrics
    document.getElementById("metric-label").textContent = data.label;
    document.getElementById("metric-risk").textContent = data.risk_level;
    document.getElementById("metric-confidence").textContent = `${data.confidence}%`;
    document.getElementById("metric-ham-prob").textContent = `${data.ham_probability}%`;

    // Colorize risk level
    const riskEl = document.getElementById("metric-risk");
    if (data.risk_level === "Dangerous" || data.risk_level === "High Risk") {
        riskEl.style.color = "#dc2626";
    } else if (data.risk_level === "Suspicious") {
        riskEl.style.color = "#d97706";
    } else {
        riskEl.style.color = "#16a34a";
    }

    // Explanation
    document.getElementById("explanation-text").textContent = data.explanation;

    // Trigger Words Chips
    const triggersSection = document.getElementById("triggers-section");
    const triggersList = document.getElementById("triggers-list");
    triggersList.innerHTML = "";

    if (data.trigger_words && data.trigger_words.length > 0) {
        triggersSection.classList.remove("hidden");
        data.trigger_words.forEach(t => {
            const chip = document.createElement("span");
            chip.className = "trigger-chip";
            chip.textContent = `${t.keyword} (${t.count}x)`;
            triggersList.appendChild(chip);
        });
    } else {
        triggersSection.classList.add("hidden");
    }

    // Heuristics
    const heuristicsSection = document.getElementById("heuristics-section");
    const heuristicsList = document.getElementById("heuristics-list");
    heuristicsList.innerHTML = "";

    if (data.heuristics && data.heuristics.length > 0) {
        heuristicsSection.classList.remove("hidden");
        data.heuristics.forEach(h => {
            const li = document.createElement("li");
            li.textContent = "⚠️ " + h;
            heuristicsList.appendChild(li);
        });
    } else {
        heuristicsSection.classList.add("hidden");
    }
}

/**
 * Quick Load Sample for Similarity / Same Detection
 */
function loadSimilarityPair(index) {
    if (!globalSampleData || !globalSampleData.similarity_pairs[index]) return;
    const pair = globalSampleData.similarity_pairs[index];
    document.getElementById("compare-email-1").value = pair.email1;
    document.getElementById("compare-email-2").value = pair.email2;
    compareEmails();
}

/**
 * Compare Two Emails for Similarity & Duplicate Detection
 */
async function compareEmails() {
    const email1 = document.getElementById("compare-email-1").value.trim();
    const email2 = document.getElementById("compare-email-2").value.trim();

    if (!email1 || !email2) {
        alert("Please enter both email texts to compare.");
        return;
    }

    const btn = document.getElementById("btn-compare");
    const originalText = btn.innerHTML;
    btn.innerHTML = "<span>Comparing Emails...</span>";
    btn.disabled = true;

    try {
        const response = await fetch("/api/check-similarity", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email1, email2 })
        });

        const result = await response.json();

        if (result.success) {
            renderSimilarityResult(result.data);
        } else {
            alert("Error: " + (result.error || "Unable to compare emails"));
        }
    } catch (err) {
        alert("Network or server error while contacting API: " + err.message);
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}

function renderSimilarityResult(data) {
    document.getElementById("sim-empty-state").classList.add("hidden");
    const content = document.getElementById("sim-result-content");
    content.classList.remove("hidden");

    // Verdict Badge
    const badge = document.getElementById("same-verdict-badge");
    if (data.is_same) {
        badge.className = "badge badge-danger";
        badge.textContent = "DUPLICATE / SAME EMAIL";
    } else if (data.similarity_percentage >= 50) {
        badge.className = "badge badge-warning";
        badge.textContent = "PARTIAL MATCH";
    } else {
        badge.className = "badge badge-success";
        badge.textContent = "DIFFERENT / UNIQUE";
    }

    // Match Meter
    const pct = data.similarity_percentage;
    document.getElementById("meter-percentage").textContent = `${pct}%`;
    document.getElementById("meter-bar-fill").style.width = `${pct}%`;
    document.getElementById("meter-match-type").textContent = `Match Type: ${data.match_type}`;
    document.getElementById("sim-summary").textContent = data.summary;

    // Metrics
    document.getElementById("val-cosine").textContent = data.metrics.cosine_similarity.toFixed(3);
    document.getElementById("val-jaccard").textContent = data.metrics.jaccard_similarity.toFixed(3);
    document.getElementById("val-sequence").textContent = data.metrics.character_ratio.toFixed(3);
    
    const isSameEl = document.getElementById("val-is-same");
    isSameEl.textContent = data.is_same ? "YES (DUPLICATE)" : "NO (DISTINCT)";
    isSameEl.style.color = data.is_same ? "#dc2626" : "#16a34a";

    // Matching Tokens
    const tokensList = document.getElementById("matching-tokens-list");
    tokensList.innerHTML = "";
    if (data.matching_tokens && data.matching_tokens.length > 0) {
        data.matching_tokens.forEach(tok => {
            const chip = document.createElement("span");
            chip.className = "token-chip";
            chip.textContent = tok;
            tokensList.appendChild(chip);
        });
    } else {
        tokensList.innerHTML = "<span style='color: var(--text-muted); font-size: 0.85rem;'>No shared significant keywords found.</span>";
    }
}

/**
 * Library Duplicate Scanner
 */
function loadLibraryTest(type) {
    const input = document.getElementById("library-test-input");
    if (type === 1) {
        input.value = "Scheduled Maintenance Reminder: Production servers are going to be taken down this Saturday between 01:00 UTC and 04:00 UTC for routine hardware maintenance.";
    } else {
        input.value = "Security Notice: Unfamiliar login detected from IP 192.168.1.1. If this was not you, please secure your credentials immediately.";
    }
    checkAgainstLibrary();
}

async function checkAgainstLibrary() {
    const email = document.getElementById("library-test-input").value.trim();
    if (!email) {
        alert("Please enter email text to scan against the database library.");
        return;
    }

    try {
        const response = await fetch("/api/check-library", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email })
        });
        const result = await response.json();

        if (result.success) {
            renderLibraryResults(result.data);
        } else {
            alert("Error: " + result.error);
        }
    } catch (err) {
        alert("Error connecting to server: " + err.message);
    }
}

function renderLibraryResults(data) {
    document.getElementById("lib-empty-state").classList.add("hidden");
    document.getElementById("lib-results-table-wrap").classList.remove("hidden");

    const badge = document.getElementById("lib-verdict-badge");
    if (data.is_duplicate) {
        badge.className = "badge badge-danger";
        badge.textContent = `DUPLICATE FOUND (${data.highest_similarity}% match)`;
    } else {
        badge.className = "badge badge-success";
        badge.textContent = "NO DUPLICATES FOUND";
    }

    const tbody = document.getElementById("lib-results-tbody");
    tbody.innerHTML = "";

    data.comparisons.forEach(item => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td><code>${item.id}</code></td>
            <td><strong>${item.subject}</strong></td>
            <td><strong>${item.similarity_percentage}%</strong></td>
            <td>${item.match_type}</td>
            <td>
                <span class="badge ${item.is_same ? 'badge-danger' : 'badge-neutral'}">
                    ${item.is_same ? 'Duplicate Match' : 'Unique'}
                </span>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

/**
 * Batch Scanner
 */
function loadBatchSample() {
    const input = document.getElementById("batch-input");
    input.value = 
`Subject: Free iPhone 15 Pro Winner!
Congratulations! You have been selected to receive a brand new iPhone 15 Pro. Click here now to claim your free reward!
---
Subject: Engineering Sprint Review
Hi team, please find attached the slide deck for tomorrow's engineering sprint review. See you all at 10 AM.
---
Subject: Immediate Action Required: Account Suspension
Dear user, your bank profile has been locked due to unauthorized access. Verify your details within 24 hours.`;
}

async function runBatchScan() {
    const raw = document.getElementById("batch-input").value.trim();
    if (!raw) {
        alert("Please enter emails to scan.");
        return;
    }

    const parts = raw.split(/---+/).map(p => p.trim()).filter(p => p.length > 0);
    const emailsPayload = parts.map((chunk, idx) => {
        const lines = chunk.split("\n");
        let subject = "";
        let body = chunk;
        if (lines[0].toLowerCase().startsWith("subject:")) {
            subject = lines[0].replace(/subject:/i, "").trim();
            body = lines.slice(1).join("\n").trim();
        }
        return { id: `Email #${idx + 1}`, subject, body };
    });

    try {
        const res = await fetch("/api/batch-detect", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ emails: emailsPayload })
        });
        const result = await res.json();

        if (result.success) {
            renderBatchResults(result.data);
        } else {
            alert("Error: " + result.error);
        }
    } catch (e) {
        alert("Batch scan error: " + e.message);
    }
}

function renderBatchResults(items) {
    document.getElementById("batch-empty-state").classList.add("hidden");
    document.getElementById("batch-results-wrap").classList.remove("hidden");
    document.getElementById("batch-count-badge").textContent = `${items.length} Emails Scanned`;

    const tbody = document.getElementById("batch-results-tbody");
    tbody.innerHTML = "";

    items.forEach(item => {
        const tr = document.createElement("tr");
        const isSpam = item.label === "SPAM";
        tr.innerHTML = `
            <td><code>${item.id}</code></td>
            <td>
                <span class="badge ${isSpam ? 'badge-danger' : 'badge-success'}">
                    ${item.label}
                </span>
            </td>
            <td><strong>${item.spam_probability}%</strong></td>
            <td>${item.risk_level}</td>
            <td>${item.trigger_words.length > 0 ? item.trigger_words.slice(0, 3).join(", ") : "None"}</td>
            <td><small>${item.explanation}</small></td>
        `;
        tbody.appendChild(tr);
    });
}
