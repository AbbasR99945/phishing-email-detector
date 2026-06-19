const emailInput = document.querySelector("#email-input");
const analyzeButton = document.querySelector("#analyze");
const sampleButton = document.querySelector("#sample");
const clearButton = document.querySelector("#clear");
const exportButton = document.querySelector("#export");
const scoreBox = document.querySelector("#score");
const findingsBox = document.querySelector("#findings");
const linksBox = document.querySelector("#links");

let lastReport = null;

const sampleEmail = `From: Security Team <security-update@paypa1-support.example>
Subject: Urgent account verification required today

Dear customer,

Your account will be suspended in 24 hours unless you confirm your password and billing details.
Visit https://paypa1-support.example/login now to restore access.

Regards,
Account Support`;

const phraseRules = [
  ["Urgency language", /\burgent\b|\b24 hours\b|\bimmediately\b|\btoday\b|\bfinal warning\b/i, 14],
  ["Credential request", /\bpassword\b|\blogin\b|\bverify\b|\bconfirm\b|\bbilling\b/i, 16],
  ["Threat or pressure", /\bsuspended\b|\blocked\b|\bclosed\b|\bpenalty\b|\bunauthori[sz]ed\b/i, 13],
  ["Generic greeting", /\bdear customer\b|\bdear user\b|\bvalued customer\b/i, 8],
  ["Attachment bait", /\binvoice attached\b|\bopen attachment\b|\bdownload the file\b/i, 10]
];

function extractUrls(text) {
  return [...text.matchAll(/https?:\/\/[^\s<>"')]+/gi)].map(match => match[0].replace(/[.,;]+$/, ""));
}

function getHost(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return "invalid-url";
  }
}

function analyzeEmail(text) {
  const findings = [];
  let score = 0;
  phraseRules.forEach(([label, pattern, points]) => {
    if (pattern.test(text)) {
      findings.push({ label, points, detail: "Matched wording in the email body or headers." });
      score += points;
    }
  });

  const urls = extractUrls(text).map(url => {
    const host = getHost(url);
    const flags = [];
    if (/\d+\.\d+\.\d+\.\d+/.test(host)) flags.push("IP address host");
    if (/(bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly)/i.test(host)) flags.push("Shortened URL");
    if (/(paypa1|micros0ft|g00gle|arnazon|faceb00k)/i.test(host)) flags.push("Lookalike brand spelling");
    if (host.split(".").length > 3) flags.push("Deep subdomain chain");
    if (!/^https:\/\//i.test(url)) flags.push("No HTTPS");
    score += flags.length * 14;
    return { url, host, flags };
  });

  if (urls.length === 0) {
    findings.push({ label: "No links found", points: 0, detail: "This lowers link risk but does not prove the message is safe." });
  }

  const fromMatch = text.match(/^from:\s*(.+)$/im);
  if (fromMatch && /support|security|billing/i.test(fromMatch[1]) && !/@[a-z0-9.-]+\.[a-z]{2,}/i.test(fromMatch[1])) {
    findings.push({ label: "Unclear sender domain", points: 8, detail: "Sender claims authority but the domain is not clear." });
    score += 8;
  }

  score = Math.min(100, score);
  return {
    generatedAt: new Date().toISOString(),
    score,
    level: score >= 70 ? "High risk" : score >= 40 ? "Suspicious" : "Low risk",
    findings,
    urls
  };
}

function render(report) {
  const levelClass = report.score >= 70 ? "danger" : report.score >= 40 ? "warning" : "success";
  scoreBox.innerHTML = `
    <div class="metric"><span class="muted">Score</span><strong class="${levelClass}">${report.score}</strong></div>
    <div class="metric"><span class="muted">Level</span><strong>${report.level}</strong></div>
    <div class="metric"><span class="muted">Links</span><strong>${report.urls.length}</strong></div>
    <div class="metric"><span class="muted">Findings</span><strong>${report.findings.length}</strong></div>
  `;
  findingsBox.innerHTML = report.findings.length
    ? report.findings.map(item => `
      <div class="item">
        <strong>${item.label}</strong>
        <span class="tag">${item.points} points</span>
        <p class="muted">${item.detail}</p>
      </div>
    `).join("")
    : "<p class=\"muted\">No major wording warnings found.</p>";
  linksBox.innerHTML = report.urls.length
    ? report.urls.map(item => `
      <div class="item">
        <strong>${item.host}</strong>
        <code>${escapeHtml(item.url)}</code>
        <div>${item.flags.length ? item.flags.map(flag => `<span class="tag">${flag}</span>`).join("") : "<span class=\"tag\">No link flags</span>"}</div>
      </div>
    `).join("")
    : "<p class=\"muted\">No URLs detected.</p>";
}

function escapeHtml(value) {
  return value.replace(/[&<>"']/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#039;" }[char]));
}

function download(filename, content) {
  const blob = new Blob([content], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

analyzeButton.addEventListener("click", () => {
  lastReport = analyzeEmail(emailInput.value);
  render(lastReport);
});
sampleButton.addEventListener("click", () => {
  emailInput.value = sampleEmail;
  lastReport = analyzeEmail(emailInput.value);
  render(lastReport);
});
clearButton.addEventListener("click", () => {
  emailInput.value = "";
  scoreBox.innerHTML = "";
  findingsBox.innerHTML = "";
  linksBox.innerHTML = "";
  lastReport = null;
});
exportButton.addEventListener("click", () => {
  if (lastReport) download("phishing-email-report.json", JSON.stringify(lastReport, null, 2));
});
