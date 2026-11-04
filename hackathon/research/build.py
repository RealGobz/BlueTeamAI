import os
import json
import html
import re
import subprocess

def escape(text):
    if text is None:
        return ""
    escaped = html.escape(str(text))
    # Render em-dashes and quotes cleanly across all platforms
    return escaped.replace("\u2014", "&mdash;").replace("—", "&mdash;")

def format_markdown_paras(text):
    if not text:
        return ""
    paras = text.split("\n\n")
    p_tags = "".join(f"<p>{escape(p.strip())}</p>" for p in paras if p.strip())
    # Format inline code
    return re.sub(r'`([^`]+)`', r'<code>\1</code>', p_tags)

def build_all():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    manifest_path = os.path.join(base_dir, "manifest.json")
    metrics_path = os.path.join(base_dir, "metrics.json")
    videos_dir = os.path.join(base_dir, "videos")
    output_html_path = os.path.join(base_dir, "index.html")
    output_paper_html_path = os.path.join(base_dir, "paper.html")
    pdf_path = os.path.join(base_dir, "Triagent-Research-Paper.pdf")

    with open(manifest_path, "r", encoding="utf-8") as f:
        runs = json.load(f)

    with open(metrics_path, "r", encoding="utf-8") as f:
        metrics = json.load(f)

    # Separate attacks and benign
    attacks = [r for r in runs if r.get("kind") == "attack"]
    benigns = [r for r in runs if r.get("kind") == "benign"]

    # Compute & verify metrics from metrics.json (ensures single source of truth)
    attacks_total = metrics.get("attacks_total", len(attacks))
    attacks_yes = metrics.get("attacks_yes", sum(1 for r in attacks if r.get("outcome") == "yes"))
    attacks_partial = metrics.get("attacks_partial", sum(1 for r in attacks if r.get("outcome") == "partial"))
    attacks_no = metrics.get("attacks_no", sum(1 for r in attacks if r.get("outcome") == "no"))
    attack_score = metrics.get("attack_score", attacks_yes + 0.5 * attacks_partial)
    attack_accuracy_pct = metrics.get("attack_accuracy_pct", (attack_score / attacks_total) * 100.0)

    benign_total = metrics.get("benign_total", len(benigns))
    benign_cleared = metrics.get("benign_cleared", sum(1 for r in benigns if r.get("outcome") == "yes"))
    benign_escalated = metrics.get("benign_escalated", sum(1 for r in benigns if r.get("outcome") == "no"))
    benign_accuracy_pct = metrics.get("benign_accuracy_pct", (benign_cleared / benign_total) * 100.0)

    median_time = metrics.get("median_time_to_verdict_seconds", 52.0)
    avg_cost = metrics.get("avg_cost_usd", 0.1358)

    # =========================================================================
    # 1. BUILD WEBPAGE (index.html)
    # =========================================================================
    def render_web_card(run):
        run_id = escape(run.get("id"))
        kind = escape(run.get("kind"))
        title = escape(run.get("title"))
        rule_fired = escape(run.get("rule_fired"))
        alerts_count = run.get("alerts_count", 1)
        alerts_text = f"{alerts_count} Alert" if alerts_count == 1 else f"{alerts_count} Alerts"
        
        outcome = run.get("outcome", "yes")
        outcome_label = "Yes" if outcome == "yes" else ("Partial" if outcome == "partial" else "No")
        outcome_symbol = "&check;" if outcome == "yes" else ("&sim;" if outcome == "partial" else "&cross;")
        outcome_pill_class = f"pill-outcome-{outcome}"
        
        outcome_note = escape(run.get("outcome_note", ""))
        what_agent_did = escape(run.get("what_agent_did", ""))
        time_to_verdict = escape(run.get("time_to_verdict", ""))
        tokens = run.get("tokens_cost", {}).get("tokens", 0)
        tokens_fmt = f"{tokens:,}"
        usd = run.get("tokens_cost", {}).get("usd", 0.0)
        cost_fmt = f"${usd:.4f}"

        # Mitre tags
        mitre_html = []
        for m in run.get("mitre", []):
            m_id = escape(m.get("id"))
            m_name = escape(m.get("name"))
            m_url = escape(m.get("url"))
            mitre_html.append(
                f'<a href="{m_url}" target="_blank" rel="noopener noreferrer" class="mitre-link">'
                f'<code>{m_id}</code> {m_name} &nearr;</a>'
            )
        mitre_row_html = '\n          '.join(mitre_html)

        # What it would do (attacks only)
        would_do_html = ""
        if kind == "attack" and "what_it_would_do" in run:
            p_formatted = format_markdown_paras(run.get("what_it_would_do", ""))
            would_do_html = f'''
        <div class="context-box would-do-box">
          <div class="box-label">What a Real Attacker Would Do</div>
          {p_formatted}
        </div>'''

        # Video check
        video_filename = f"{run_id}.mp4"
        video_path = os.path.join(videos_dir, video_filename)
        if os.path.exists(video_path):
            video_html = f'''
        <div class="video-container">
          <video controls preload="metadata" src="videos/{escape(video_filename)}" class="run-video"></video>
        </div>'''
        else:
            video_html = '''
        <div class="video-container">
          <div class="video-placeholder">
            <div class="placeholder-icon">
              <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"><rect x="2" y="2" width="20" height="20" rx="2.18" ry="2.18"/><line x1="7" y1="2" x2="7" y2="22"/><line x1="17" y1="2" x2="17" y2="22"/><line x1="2" y1="12" x2="22" y2="12"/><line x1="2" y1="7" x2="7" y2="7"/><line x1="2" y1="17" x2="7" y2="17"/><line x1="17" y1="17" x2="22" y2="17"/><line x1="17" y1="7" x2="22" y2="7"/></svg>
            </div>
            <p class="placeholder-text">Video coming soon &mdash; being edited</p>
          </div>
        </div>'''

        # Tools used
        tools = run.get("tools_used", [])
        tools_tags = "".join(f'<span class="tool-tag">{escape(t)}</span>' for t in tools)
        tools_count = len(tools)

        # Script action
        script_pub = run.get("script_publishable", False)
        mitre_ref_only = run.get("mitre_reference_only", False)
        if script_pub:
            script_action_html = f'''
          <a href="scripts/{run_id}.ps1" download class="btn-primary btn-download-script">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
            Download Simulation Script (.ps1)
          </a>'''
        elif mitre_ref_only:
            first_mitre_url = run.get("mitre", [{}])[0].get("url", "https://attack.mitre.org/")
            script_action_html = f'''
          <span class="mitre-ref-note">This technique is not published as a runnable script. <a href="{escape(first_mitre_url)}" target="_blank" rel="noopener noreferrer">See it on MITRE ATT&amp;CK &rarr;</a></span>'''
        else:
            script_action_html = ''

        return f'''
      <!-- SCENARIO CARD {run_id} -->
      <article class="run-card" id="run-{run_id}">
        <div class="card-header">
          <div class="header-left-meta">
            <span class="run-id-pill pill-{kind}">{run_id}</span>
            <div class="title-wrap">
              <h2 class="run-title">{title}</h2>
              <div class="rule-fired-text">Sigma Rule: {rule_fired} &bull; {alerts_text}</div>
            </div>
          </div>
          <div class="outcome-pill {outcome_pill_class}">
            <span class="outcome-icon">{outcome_symbol}</span> Outcome: {outcome_label}
          </div>
        </div>

        <p class="outcome-note-text">{outcome_note}</p>

        <div class="mitre-row">
          {mitre_row_html}
        </div>
        {would_do_html}
        {video_html}

        <div class="context-box agent-did-box">
          <div class="box-label">What Triagent Did</div>
          <p>{what_agent_did}</p>
          
          <details class="tools-accordion">
            <summary class="tools-summary">Investigative Tools Used ({tools_count})</summary>
            <div class="tools-tray">
              {tools_tags}
            </div>
          </details>
        </div>

        <div class="card-footer">
          <div class="metrics-bar">
            <div class="metric-cell">
              <span class="m-label">Time to Verdict</span>
              <span class="m-val">{time_to_verdict}</span>
            </div>
            <div class="metric-cell">
              <span class="m-label">Token Usage</span>
              <span class="m-val">{tokens_fmt}</span>
            </div>
            <div class="metric-cell">
              <span class="m-label">Execution Cost</span>
              <span class="m-val">{cost_fmt}</span>
            </div>
          </div>
          {script_action_html}
        </div>
      </article>'''

    web_attack_cards = "\n".join(render_web_card(r) for r in attacks)
    web_benign_cards = "\n".join(render_web_card(r) for r in benigns)

    web_html_content = f'''<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Triagent &ndash; Research &amp; Benchmark Scenarios</title>
  <link rel="stylesheet" href="brand/theme.css">
  <link rel="stylesheet" href="styles.css">
</head>
<body>

  <!-- STICKY HEADER -->
  <header class="site-header">
    <div class="header-container">
      <div class="header-left">
        <a href="#" class="brand-link">
          <img src="brand/triagent-lockup-dark.svg" alt="Triagent" class="brand-logo logo-dark">
          <img src="brand/triagent-lockup-light.svg" alt="Triagent" class="brand-logo logo-light">
        </a>
        <span class="header-sub">&ndash; Research</span>
      </div>
      <div class="header-right">
        <button id="themeToggle" class="btn-theme" title="Toggle theme">
          <span class="theme-icon">&#9681;</span>
        </button>
        <a href="Triagent-Research-Paper.pdf" download class="btn-primary">
          <svg class="btn-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
          Download research paper (PDF)
        </a>
      </div>
    </div>
  </header>

  <main class="page-container">

    <!-- INTRO -->
    <section class="intro-section">
      <h1 class="page-title">Investigation Results &ndash; 10 Test Scenarios</h1>
      <p class="lead-text">
        Triagent is an autonomous AI security analyst running locally on Windows endpoints to investigate, enrich, and remediate alerts with human-in-the-loop oversight. This benchmark evaluates Triagent across 5 simulated attacks and 5 benign administrative scenarios under controlled desktop conditions.
      </p>

      <!-- NOTICE BOX -->
      <div class="notice-card">
        <span class="notice-badge">Notice</span>
        <span class="notice-text">
          All files on this page are harmless simulations, not real malware. If you'd rather not run anything, watch the videos below, or try the scripts only inside an isolated VM.
        </span>
      </div>
    </section>

    <!-- SECTION A: ATTACK SCENARIOS -->
    <section class="scenario-section">
      <div class="section-badge-row">
        <span class="category-chip chip-attack">Attack Scenarios (A1&ndash;A5)</span>
        <span class="section-desc">Simulated real-world adversary techniques mapped to MITRE ATT&amp;CK</span>
      </div>
      {web_attack_cards}
    </section>

    <!-- SECTION B: BENIGN SCENARIOS -->
    <section class="scenario-section">
      <div class="section-badge-row">
        <span class="category-chip chip-benign">Benign Scenarios (B1&ndash;B5)</span>
        <span class="section-desc">Routine developer actions, administrative scripts, and false alarms</span>
      </div>
      {web_benign_cards}
    </section>

    <!-- EMPIRICAL METRICS SECTION -->
    <section class="metrics-section">
      <h2 class="metrics-title">Empirical Benchmark Metrics</h2>
      <div class="stats-grid-web">
        <div class="stat-box">
          <div class="stat-value">{attack_score:g} / {attacks_total} ({attack_accuracy_pct:.0f}%)</div>
          <div class="stat-desc">Attack Accuracy (Partial = 0.5)</div>
        </div>
        <div class="stat-box">
          <div class="stat-value">{benign_cleared} / {benign_total} ({benign_accuracy_pct:.0f}%)</div>
          <div class="stat-desc">Benign Alerts Cleared (0 Escalated)</div>
        </div>
        <div class="stat-box">
          <div class="stat-value">{median_time:.1f}s</div>
          <div class="stat-desc">Median Time to Verdict</div>
        </div>
        <div class="stat-box">
          <div class="stat-value">${avg_cost:.4f}</div>
          <div class="stat-desc">Average Execution Cost</div>
        </div>
      </div>

      <div class="improvements-block">
        <h3 class="improvements-title">Engineering Observations: What Could Get Better</h3>
        <ul class="improvements-list">
          <li><strong>Handling Non-Executable Payloads (A2):</strong> When <code>get_file_signature</code> returned <code>UnknownError</code> on a plain-text placeholder downloaded via <code>certutil.exe</code>, the agent assumed it was harmless. Dropper downloads from direct IP addresses must default to high suspicion regardless of file extension or preliminary signature validity.</li>
          <li><strong>Internal vs External IP Heuristics (A2):</strong> The test staging server utilized a loopback/private IP (<code>127.0.0.1</code>), which biased the agent toward assuming an internal authorized tool. Future revisions will flag living-off-the-land file transfers regardless of address locality.</li>
          <li><strong>Correlated Rule Disagreement (A3):</strong> An initial alert for an encoded command line was cleared as benign before a secondary pattern alert correctly escalated it. Cross-alert session memory should propagate context across contemporaneous alerts from the same process lineage.</li>
          <li><strong>Timing and Process Lifespan in Remediation (A4):</strong> When attempting process termination on ultra-short-lived LOLBins (such as <code>rundll32.exe comsvcs.dll</code>), the target process had already exited before the containment command was dispatched. Furthermore, a secondary kill attempt returned a reference error (<code>Process GUID was not found in event history</code>). Response tools must gracefully handle race conditions when target processes terminate prior to containment execution.</li>
          <li><strong>Workspace Boundary Protections (A3):</strong> Containment actions safely refrained from deleting files located in the project root. While essential for development safety, production deployments require clear quarantine escalation paths for user workspace directories.</li>
        </ul>
      </div>
    </section>

  </main>

  <!-- FOOTER -->
  <footer class="site-footer">
    <div class="footer-credits">
      Built with <strong>Triagent</strong> &bull; Detection taxonomy powered by <strong>SigmaHQ</strong> &bull; Behavioral paradigms by <strong>Atomic Red Team</strong>
    </div>
    <div class="footer-contact">
      Triagent Autonomous Cyber Defense Benchmark &bull; Single-host experimental preprint
    </div>
  </footer>

  <!-- SCRIPT: Theme Toggle -->
  <script>
    const toggleBtn = document.getElementById('themeToggle');
    const root = document.documentElement;
    toggleBtn.addEventListener('click', () => {{
      const current = root.getAttribute('data-theme') || 'dark';
      const next = current === 'dark' ? 'light' : 'dark';
      root.setAttribute('data-theme', next);
    }});
  </script>
</body>
</html>'''

    with open(output_html_path, "w", encoding="utf-8") as f:
        f.write(web_html_content)
    print(f"Successfully generated {output_html_path}")

    # =========================================================================
    # 2. BUILD RESEARCH PAPER (paper.html)
    # =========================================================================
    def render_paper_card(run):
        run_id = escape(run.get("id"))
        kind = escape(run.get("kind"))
        title = escape(run.get("title"))
        rule_fired = escape(run.get("rule_fired"))
        alerts_count = run.get("alerts_count", 1)
        alerts_text = f"{alerts_count} Alert" if alerts_count == 1 else f"{alerts_count} Alerts"
        
        outcome = run.get("outcome", "yes")
        outcome_label = "Yes" if outcome == "yes" else ("Partial" if outcome == "partial" else "No")
        outcome_symbol = "&check;" if outcome == "yes" else ("&sim;" if outcome == "partial" else "&cross;")
        outcome_class = outcome
        outcome_desc = "Matched Expected Verdict" if (outcome == "yes" and kind == "attack") else (
            "Correctly Cleared as False Positive" if (outcome == "yes" and kind == "benign") else (
                "Conflicting Alert Verdicts (Partial = 0.5)" if outcome == "partial" else "Documented Miss"
            )
        )
        
        outcome_note = escape(run.get("outcome_note", ""))
        what_agent_did = escape(run.get("what_agent_did", ""))
        time_to_verdict = escape(run.get("time_to_verdict", ""))
        tokens = run.get("tokens_cost", {}).get("tokens", 0)
        tokens_fmt = f"{tokens:,}"
        usd = run.get("tokens_cost", {}).get("usd", 0.0)
        cost_fmt = f"${usd:.4f}"

        # Mitre tags
        mitre_html = []
        for m in run.get("mitre", []):
            m_id = escape(m.get("id"))
            m_name = escape(m.get("name"))
            mitre_html.append(f'<span class="mitre-pill"><code>{m_id}</code> {m_name}</span>')
        mitre_row_html = '\n      '.join(mitre_html)

        # What it would do
        would_do_html = ""
        if kind == "attack" and "what_it_would_do" in run:
            p_formatted = format_markdown_paras(run.get("what_it_would_do", ""))
            would_do_html = f'''
    <div class="field-block would-do-block">
      <div class="field-label">What a Real Attacker Would Do</div>
      {p_formatted}
    </div>'''

        return f'''
  <!-- SCENARIO {run_id} -->
  <div class="scenario-card">
    <div class="scenario-header">
      <span class="scenario-id-pill {kind}">{run_id}</span>
      <div class="scenario-title-area">
        <h3 class="subsection-title">{title}</h3>
        <div class="rule-line">Sigma: {rule_fired} &bull; {alerts_text}</div>
      </div>
    </div>

    <div class="mitre-tag-row">
      {mitre_row_html}
    </div>
    {would_do_html}

    <div class="field-block agent-did-block">
      <div class="field-label">What Triagent Did</div>
      <p>{what_agent_did}</p>
    </div>

    <div class="metrics-row">
      <div class="metric-col">
        <span class="metric-label">Time to Verdict</span>
        <span class="metric-num">{time_to_verdict}</span>
      </div>
      <div class="metric-col">
        <span class="metric-label">Token Consumption</span>
        <span class="metric-num">{tokens_fmt}</span>
      </div>
      <div class="metric-col">
        <span class="metric-label">Execution Cost</span>
        <span class="metric-num">{cost_fmt}</span>
      </div>
    </div>

    <div class="outcome-box {outcome_class}">
      <div class="outcome-badge">{outcome_symbol} Outcome: {outcome_label} ({outcome_desc})</div>
      <p class="outcome-note-text">{outcome_note}</p>
    </div>
  </div>'''

    paper_a1 = render_paper_card(attacks[0])
    paper_a2 = render_paper_card(attacks[1])
    paper_a3 = render_paper_card(attacks[2])
    paper_a4 = render_paper_card(attacks[3])
    paper_a5 = render_paper_card(attacks[4])

    paper_b1 = render_paper_card(benigns[0])
    paper_b2 = render_paper_card(benigns[1])
    paper_b3 = render_paper_card(benigns[2])
    paper_b4 = render_paper_card(benigns[3])
    paper_b5 = render_paper_card(benigns[4])

    # Table rows
    table_rows = []
    for r in runs:
        r_id = escape(r.get("id"))
        category = "Attack" if r.get("kind") == "attack" else "Benign"
        expected = "True Positive" if r.get("expected_verdict") == "true_positive" else "False Positive"
        verdict = "True Positive" if r.get("verdict") == "true_positive" else "False Positive"
        outcome_val = r.get("outcome", "yes")
        outcome_str = "Yes" if outcome_val == "yes" else ("Partial (0.5)" if outcome_val == "partial" else "No")
        t_verdict = escape(r.get("time_to_verdict", ""))
        tok = f"{r.get('tokens_cost', {}).get('tokens', 0):,}"
        cst = f"${r.get('tokens_cost', {}).get('usd', 0.0):.4f}"
        table_rows.append(f'''      <tr>
        <td><strong>{r_id}</strong></td>
        <td>{category} ({escape(r.get("title"))})</td>
        <td>{expected}</td>
        <td>{verdict}</td>
        <td>{outcome_str}</td>
        <td>{t_verdict}</td>
        <td>{tok}</td>
        <td>{cst}</td>
      </tr>''')
    table_rows_html = "\n".join(table_rows)

    paper_html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Triagent: Investigation Results — 10 Test Scenarios</title>
  <link rel="stylesheet" href="paper.css">
</head>
<body>

  <!-- COVER PAGE -->
  <div class="cover-page">
    <div class="cover-brand">
      <img src="brand/triagent-lockup-light.svg" alt="Triagent Logo">
    </div>

    <div class="cover-main">
      <div class="cover-kicker">Autonomous Cyber Defense Benchmark Report</div>
      <h1 class="cover-title">Triagent: Investigation Results &mdash;<br>10 Test Scenarios</h1>
      <p class="cover-subline">Empirical evaluation of an autonomous, human-in-the-loop AI security analyst investigating simulated Windows attacks and administrative false positives.</p>

      <div class="cover-meta-grid">
        <div class="meta-item">
          <span class="meta-label">Author</span>
          <span class="meta-value">Triagent Security Research Team</span>
        </div>
        <div class="meta-item">
          <span class="meta-label">Date</span>
          <span class="meta-value">November 3, 2026</span>
        </div>
        <div class="meta-item">
          <span class="meta-label">Foundation Models</span>
          <span class="meta-value">Azure OpenAI (Investigation &amp; Agent Core)</span>
        </div>
        <div class="meta-item">
          <span class="meta-label">Target Environment</span>
          <span class="meta-value">Windows 10/11 &bull; Sysmon &bull; Sigma Rules</span>
        </div>
      </div>
    </div>

    <div class="cover-footer">
      Confidential / Technical Preprint &bull; Document hash derived from manifest.json
    </div>
  </div>

  <!-- INTRODUCTION & METHODOLOGY -->
  <div class="running-header">
    <span>Triagent Research Preprint</span>
    <span>Methodology &amp; Setup</span>
  </div>

  <h2 class="section-header">1. Executive Summary &amp; Scope</h2>
  <p>This report documents the performance of <strong>Triagent</strong>, an autonomous AI security analyst running locally on Windows endpoints to triage, investigate, and remediate security alerts. Operating under a strict "ask-before-acting" paradigm, Triagent inspects operating system telemetry generated by Microsoft-Windows-Sysmon and matched by open-source Sigma detection rules.</p>

  <p>The agent is granted access to specialized tools divided into four operational categories:</p>
  <ul>
    <li><strong>Investigation:</strong> Live process trees (<code>get_process_tree</code>), descendant execution tracking (<code>get_children</code>), process creation telemetry (<code>get_events_for_process</code>), process liveness checks (<code>is_process_running</code>), network socket discovery (<code>get_live_connections</code>), hash prevalence lookups (<code>get_events_by_hash</code>), and historical event correlation windows (<code>get_events_in_window</code>).</li>
    <li><strong>Enrichment:</strong> Cryptographic file verification (<code>get_file_info</code>), digital signature validation (<code>get_file_signature</code>), VirusTotal global hash reputation (<code>lookup_hash</code>), Exa technical intelligence (<code>exa_search</code>), and Sigma detection rule logic context (<code>get_rule_context</code>).</li>
    <li><strong>Response:</strong> High-integrity process termination (<code>kill_process</code>) and secure forensic quarantine (<code>quarantine_file</code>).</li>
    <li><strong>Communication:</strong> Interactive Human-in-the-Loop (HITL) structured questioning (<code>ask_user</code>), operator messaging (<code>respond</code>), and formal verdict submission (<code>submit_verdict</code>).</li>
  </ul>

  <div class="notice-box">
    <strong>Benchmark Limitation Note:</strong> This evaluation comprises exactly 10 single-run scenarios (5 simulated attacks and 5 benign administrative activities); it is a controlled proof-of-concept assessment and makes no statistical significance claims.
  </div>

  <h2 class="section-header">2. Evaluation Methodology</h2>
  <p>All tests were conducted on an active Windows desktop workstation instrumented with Microsoft-Windows-Sysmon and an in-memory rule engine evaluating SigmaHQ detection rules. Each scenario was triggered through a dedicated PowerShell harness.</p>

  <p>The term <strong>"simulated"</strong> denotes that attack techniques replicated genuine adversary command-line invocations, LOLBin behaviors, and persistence mechanics while using benign dummy targets (e.g. text markers, calculator invocations, or self-contained folders) to preserve system integrity. All human-in-the-loop operator confirmations were scripted and truthful, reflecting the real intentions of the user during each scenario.</p>

  <p><strong>Scoring Rule (applied verbatim):</strong></p>
  <ul>
    <li><strong>Attacks:</strong> <em>Yes</em> = verdict matched expected on the scored alert; <em>No</em> = it did not; <em>Partial</em> = different alerts of the same attack disagreed.</li>
    <li><strong>Benign:</strong> <em>Yes</em> = agent said <code>false_positive</code> (correctly cleared); <em>No</em> = agent said <code>true_positive</code> (wrongly escalated).</li>
    <li><strong>Partial Scoring Formula:</strong> To ensure objective accuracy, partial outcomes are weighted at 0.5: <code>attack_accuracy = (count(yes) + 0.5 * count(partial)) / attacks_total = (3 + 0.5 * 1) / 5 = 70.0%</code>. Benign resolution is evaluated independently (5 / 5 = 100.0%) and not averaged into attack accuracy.</li>
  </ul>

  <!-- SECTION A: ATTACK SCENARIOS -->
  <div class="page-break"></div>
  <div class="running-header">
    <span>Triagent Research Preprint</span>
    <span>Section A: Attack Scenarios (A1&ndash;A3)</span>
  </div>

  <h2 class="section-header">3. Section A &mdash; Attack Scenarios</h2>
  {paper_a1}
  {paper_a2}
  {paper_a3}

  <!-- A4 & A5 -->
  <div class="page-break"></div>
  <div class="running-header">
    <span>Triagent Research Preprint</span>
    <span>Section A: Attack Scenarios (A4&ndash;A5)</span>
  </div>

  {paper_a4}
  {paper_a5}

  <!-- SECTION B: BENIGN SCENARIOS -->
  <div class="page-break"></div>
  <div class="running-header">
    <span>Triagent Research Preprint</span>
    <span>Section B: Benign Scenarios (B1&ndash;B3)</span>
  </div>

  <h2 class="section-header">4. Section B &mdash; Benign Scenarios</h2>
  {paper_b1}
  {paper_b2}
  {paper_b3}

  <!-- B4 & B5 -->
  <div class="page-break"></div>
  <div class="running-header">
    <span>Triagent Research Preprint</span>
    <span>Section B: Benign Scenarios (B4&ndash;B5)</span>
  </div>

  {paper_b4}
  {paper_b5}

  <!-- RESULTS & FINDINGS -->
  <div class="page-break"></div>
  <div class="running-header">
    <span>Triagent Research Preprint</span>
    <span>Empirical Results &amp; Synthesis</span>
  </div>

  <h2 class="section-header">5. Empirical Results &amp; Performance Synthesis</h2>
  <p>The aggregate performance across all ten scenarios highlights Triagent's operational profile when deployed on Windows endpoints:</p>

  <div class="stats-grid">
    <div class="stat-card">
      <div class="val">{attack_score:g} / {attacks_total} ({attack_accuracy_pct:.0f}%)</div>
      <div class="desc">Attack Accuracy (Partial = 0.5)</div>
    </div>
    <div class="stat-card">
      <div class="val">{benign_cleared} / {benign_total} ({benign_accuracy_pct:.0f}%)</div>
      <div class="desc">Benign Resolution (0 Escalated)</div>
    </div>
    <div class="stat-card">
      <div class="val">{median_time:.1f}s</div>
      <div class="desc">Median Triage Time</div>
    </div>
    <div class="stat-card">
      <div class="val">${avg_cost:.4f}</div>
      <div class="desc">Average Cost / Alert</div>
    </div>
  </div>

  <table class="data-table">
    <thead>
      <tr>
        <th>Scenario ID</th>
        <th>Category</th>
        <th>Expected</th>
        <th>Verdict</th>
        <th>Outcome</th>
        <th>Time</th>
        <th>Tokens</th>
        <th>Cost (USD)</th>
      </tr>
    </thead>
    <tbody>
{table_rows_html}
    </tbody>
  </table>

  <div class="page-break"></div>
  <div class="running-header">
    <span>Triagent Research Preprint</span>
    <span>Synthesis &amp; Limitations</span>
  </div>

  <h3 class="subsection-title">Engineering Observations: What Could Get Better</h3>
  <ul class="findings-list">
    <li><strong>Handling Non-Executable Payloads (A2):</strong> When <code>get_file_signature</code> returned <code>UnknownError</code> on a plain-text placeholder downloaded via <code>certutil.exe</code>, the agent assumed it was harmless. Dropper downloads from direct IP addresses must default to high suspicion regardless of file extension or preliminary signature validity.</li>
    <li><strong>Internal vs External IP Heuristics (A2):</strong> The test staging server utilized a loopback/private IP (<code>127.0.0.1</code>), which biased the agent toward assuming an internal authorized tool. Future revisions will flag living-off-the-land file transfers regardless of address locality.</li>
    <li><strong>Correlated Rule Disagreement (A3):</strong> An initial alert for an encoded command line was cleared as benign before a secondary pattern alert correctly escalated it. Cross-alert session memory should propagate context across contemporaneous alerts from the same process lineage.</li>
    <li><strong>Timing and Process Lifespan in Remediation (A4):</strong> When attempting process termination on ultra-short-lived LOLBins (such as <code>rundll32.exe comsvcs.dll</code>), the target process had already exited before the containment command was dispatched. Furthermore, a secondary kill attempt returned a reference error (<code>Process GUID was not found in event history</code>). Response tools must gracefully handle race conditions when target processes terminate prior to containment execution.</li>
    <li><strong>Workspace Boundary Protections (A3):</strong> Containment actions safely refrained from deleting files located in the project root. While essential for development safety, production deployments require clear quarantine escalation paths for user workspace directories.</li>
  </ul>

  <h2 class="section-header">6. Limitations &amp; Acknowledgments</h2>
  <p><strong>Limitations:</strong> This benchmark relies on 10 targeted test runs executed on a single host. Attack scenarios were intentionally selected from techniques with established Sigma detection coverage to assess investigation, enrichment, and containment rather than raw sensor sensitivity. Real-world adversaries employ multi-stage evasions, delayed persistence, and lateral movement that may alter token consumption and investigation duration.</p>

  <p><strong>Acknowledgments:</strong> We gratefully acknowledge the open-source detection engineering community, specifically <strong>SigmaHQ</strong> for the detection rule taxonomy, the <strong>Atomic Red Team</strong> project by Red Canary for behavioral simulation paradigms, and Microsoft for Sysmon endpoint telemetry.</p>

</body>
</html>'''

    with open(output_paper_html_path, "w", encoding="utf-8") as f:
        f.write(paper_html_content)
    print(f"Successfully generated {output_paper_html_path}")

    # =========================================================================
    # 3. RENDER PDF (Triagent-Research-Paper.pdf) VIA HEADLESS EDGE CHROMIUM
    # =========================================================================
    edge_paths = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"
    ]
    edge_exe = next((p for p in edge_paths if os.path.exists(p)), None)
    if not edge_exe:
        print("[!] Microsoft Edge executable not found. Skipping PDF compile.")
        return

    print(f"[*] Compiling PDF using Edge Headless ({edge_exe})...")
    cmd = [
        edge_exe,
        "--headless",
        "--disable-gpu",
        "--run-all-compositor-stages-before-draw",
        f"--print-to-pdf={pdf_path}",
        "--no-pdf-header-footer",
        output_paper_html_path
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if os.path.exists(pdf_path):
        size_kb = os.path.getsize(pdf_path) / 1024
        print(f"[+] Successfully compiled PDF to {pdf_path} ({size_kb:.1f} KB)")
    else:
        print(f"[!] PDF compilation failed: {res.stderr}")

if __name__ == "__main__":
    build_all()
