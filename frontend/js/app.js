// Frontend logic. PRIVACY: the password lives only in the input field's memory.
// It is never written to localStorage/sessionStorage/cookies/URLs and never printed to the console.
"use strict";
const $ = (id) => document.getElementById(id);
const COLORS = { "VERY WEAK": "#ff5d6c", "WEAK": "#ff8a4c", "MODERATE": "#ffb454", "STRONG": "#7ddf64", "VERY STRONG": "#38d6a8" };
let timer = null, last = null, charts = {};

function ctx() {
  return { first_name: $("ctx-name").value, birth_year: $("ctx-year").value, organization: $("ctx-org").value };
}
async function post(url, body) {
  const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  if (!r.ok) throw new Error((await r.json()).error || "Request failed");
  return r.json();
}
function li(parent, text, cls) { const e = document.createElement("li"); e.textContent = text; e.className = cls; parent.appendChild(e); }

function render(res) {
  last = res;
  $("result").hidden = false;
  const col = COLORS[res.classification];
  $("bar").style.width = res.score + "%"; $("bar").style.background = col;
  const filled = Math.round(res.score / 10);
  $("blocks").textContent = "█".repeat(filled) + "░".repeat(10 - filled);
  $("label").textContent = res.classification; $("label").style.color = col;
  $("score").textContent = `Score: ${res.score}/100`;
  const pol = $("policy"); pol.textContent = res.policy.passed ? "POLICY PASS" : "POLICY FAIL";
  pol.className = "pill " + (res.policy.passed ? "ok" : "fail"); pol.title = res.policy.rules.map(r => (r.passed ? "✓ " : "✗ ") + r.rule).join("\n");
  const checks = $("checks"); checks.replaceChildren();
  res.strengths.forEach(s => li(checks, s, "good"));
  res.findings.forEach(f => li(checks, f.description, "bad"));
  const sug = $("suggestions"); sug.replaceChildren(); res.suggestions.forEach(s => li(sug, s, "tip"));
  const m = res.metrics, t = $("metrics"); t.replaceChildren();
  [["Length", `${m.length} (${m.band})`], ["Character types", m.character_type_count], ["Unique characters", `${m.unique_character_count} (ratio ${m.unique_character_ratio})`],
   ["Theoretical entropy", `${m.theoretical_entropy_bits} bits`], ["Effective entropy (patterns removed)", `${m.effective_entropy_bits} bits`],
   ["Guess resistance", m.guess_resistance_estimate + " — educational estimate only"], ["Patterns detected", m.pattern_count]].forEach(([k, v]) => {
    const tr = t.insertRow(); tr.insertCell().textContent = k; tr.insertCell().textContent = v; });
  $("entropy-note").textContent = "Theoretical entropy ≈ L × log₂(N) assumes random choice, so it is optimistic for human-made passwords. Effective entropy gives no credit to predictable parts.";
  $("disclaimer").textContent = res.disclaimer;
}

async function analyze(record = false) {
  const pw = $("pw").value;
  try {
    const res = await post("/api/analyze", { password: pw, context: ctx(), policy: { minimum_length: Number($("pol-min").value) || 12 }, record });
    if (record) $("record-msg").textContent = " Saved: score, class, length and finding types only.";
    else { render(res); $("record-msg").textContent = ""; }
  } catch (e) { $("result").hidden = false; $("disclaimer").textContent = e.message; }
}
["pw", "ctx-name", "ctx-year", "ctx-org", "pol-min"].forEach(id => $(id).addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(() => analyze(false), 250); }));
$("record").addEventListener("click", () => analyze(true));
$("toggle").addEventListener("click", () => {
  const show = $("pw").type === "password"; $("pw").type = show ? "text" : "password";
  $("toggle").textContent = show ? "🙈 Hide Password" : "👁 Show Password"; $("toggle").setAttribute("aria-pressed", show);
});

// Tabs
document.querySelectorAll(".tab").forEach(b => b.addEventListener("click", () => {
  document.querySelectorAll(".tab").forEach(x => x.classList.toggle("active", x === b));
  document.querySelectorAll(".panel").forEach(p => p.hidden = p.id !== b.dataset.tab);
  if (b.dataset.tab === "dashboard") loadDashboard();
}));

// Generator
async function gen(body) {
  try {
    const r = await post("/api/generate-password", body);
    $("gen-out").textContent = r.password; $("gen-analyze").hidden = false;
    $("gen-note").textContent = r.type === "passphrase" ? `~${r.estimated_bits} bits. ${r.note}` : "Generated locally with a cryptographically secure source. Not stored.";
  } catch (e) { $("gen-note").textContent = e.message; }
}
$("gen-pw").addEventListener("click", () => gen({ mode: "password", length: Number($("gen-len").value), uppercase: $("g-up").checked, lowercase: $("g-low").checked, numbers: $("g-num").checked, symbols: $("g-sym").checked }));
$("gen-phrase").addEventListener("click", () => gen({ mode: "passphrase", words: 5 }));
$("gen-analyze").addEventListener("click", () => { $("pw").value = $("gen-out").textContent; document.querySelector('[data-tab="analyzer"]').click(); analyze(false); });

// Dashboard
function chart(id, type, labels, data, title, colors) {
  if (charts[id]) charts[id].destroy();
  if (typeof Chart === "undefined") { $("dash-msg").textContent = "Chart.js could not load (offline?). KPIs are still shown."; return; }
  charts[id] = new Chart($(id), { type, data: { labels, datasets: [{ data, backgroundColor: colors || "#38d6a8" }] },
    options: { plugins: { title: { display: true, text: title, color: "#e6edf7" }, legend: { display: type === "doughnut", labels: { color: "#8da0bd" } } },
      scales: type === "doughnut" ? {} : { x: { ticks: { color: "#8da0bd" } }, y: { ticks: { color: "#8da0bd", precision: 0 }, beginAtZero: true } } } });
}
async function loadDashboard() {
  try {
    const [s, w] = await Promise.all([fetch("/api/dashboard/stats").then(r => r.json()), fetch("/api/analytics/weaknesses").then(r => r.json())]);
    const k = $("kpis"); k.replaceChildren();
    [["Total", s.total_analyses], ["Average", s.average_score], ...Object.entries(s.strength_distribution)].forEach(([n, v]) => {
      const d = document.createElement("div"); d.className = "kpi"; const b = document.createElement("b"); b.textContent = v; d.append(b, n); k.appendChild(d); });
    chart("c-strength", "doughnut", Object.keys(s.strength_distribution), Object.values(s.strength_distribution), "Strength distribution", Object.keys(s.strength_distribution).map(x => COLORS[x]));
    chart("c-score", "bar", Object.keys(s.score_distribution), Object.values(s.score_distribution), "Score distribution");
    chart("c-weak", "bar", Object.keys(w.weaknesses), Object.values(w.weaknesses), "Weakness / pattern detection frequency", "#ffb454");
    chart("c-length", "bar", Object.keys(s.length_distribution), Object.values(s.length_distribution), "Password length distribution", "#7ddf64");
    $("dash-msg").textContent = s.total_analyses ? "" : "No data yet. Run: python -m scripts.seed_demo (synthetic data) or click 'Save safe metrics'.";
  } catch (e) { $("dash-msg").textContent = "Analytics unavailable."; }
}
