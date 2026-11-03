# Next Steps: Triagent submission (Sun Nov 1 to Wed Nov 11)

This file replaces the old `next_steps.md` (the agent-tools plan, now archived) and the schedule in Part 3 of `hackathon_plan.md`. The booth and stage prep in `hackathon_plan.md` Part 4 still applies after we qualify. `brand/brand.md` is the guide for everything visual.

---

## 0. Where we are (Nov 1)

Done: detection layer, the investigator agent and all its tools, the approval and question screens, the main UI, the brand (name Triagent, calm theme, logo). Agent model: gpt 5.6 sol. A1 (the fake "invoice" file) ran well: about 3 minutes, about $0.16, kill and quarantine worked.

Left, in order:
1. Fix a few small things, then **freeze** the agent (section 4).
2. Record and document A1 to A10, plus the benign set (section 5).
3. Numbers, research paper, research page, repo (sections 6, 9, 10).
4. Main video, deck (sections 7, 8).
5. Intro video, LinkedIn, final form text (sections 2, 11).


## 1. How the judges read us (this decides the order of our effort)

Their order, from what you saw at these events:

1. **Main video** (so it must be understood by anyone, with no security knowledge)
2. **Deck**
3. **The text fields** (if they are curious)
4. **The team's LinkedIn and the intro video**
5. **Verdict**

So: the video gets the most polish, then the deck, then the text, then LinkedIn and the intro video. Every item must stand alone: a reader should never wonder what is going on or what they are looking at.

---

## 2. The form (what each field needs)

Fields and limits come from `submission.md`. Choices marked "your call" are recommendations.

| Field | Limit | What to put |
|---|---|---|
| Project name | | Triagent |
| Brief description | 10-100 words | For investors AND technical judges. See below. |
| Problem, solution, added value | 20-150 words | Why would a company or a person use it? See below. |
| Technology areas (multi-select) | | Cybersecurity + Data & AI. Add Cloud only if you want to stress Azure; I'd leave it off so we look focused. (your call) |
| Type of solution | | Application (your call) |
| Geographic market | | Nationwide (Saudi Arabia) as the first market, and say in the text it works anywhere. (your call) |
| Beneficiaries | | Individuals, Businesses and Organizations, Developers and Technology Professionals. Skip Government unless you can justify it. |
| How it works technically | 15-150 words | Detect, investigate, ask permission, act, verdict. Tools: Azure, gpt 5.6 sol, LangGraph. Privacy sentence (below). |
| Current stage | | **Working Prototype / Proof of Concept.** "MVP / Pilot" means ready for early users, which we are not yet. |
| Previous hackathons / other competitions | | Answer truthfully. |
| How you heard | | Telegram |
| Primary objective | | "Showcase my solution to industry experts and potential adopters" fits the investor strategy. (your call) |

**Text field rules**
- Field 1 (100 words): the hook. One sentence on the problem in plain words, one on what Triagent does, one result with its sample size, one line on why it is different (it asks before it acts, and it runs on your own PC).
- Field 2 (150 words): who has the problem (a freelancer, a small business, an overloaded team), why they cannot solve it today, what Triagent gives them, and the measured result.
- Field 3 (150 words): the four steps in order, then the technologies, then the privacy sentence, then the safety sentence.
- Write all three AFTER the numbers are final. Never write a number you have not measured.

**The privacy sentence must be exact.** "Everything is stored locally, we only call the LLM" is not quite true: file fingerprints (hashes) also go to VirusTotal. Say: "Events, verdicts, and logs stay on the PC. The AI model receives the alert details it needs to investigate, and file fingerprints are checked against a reputation service." Do not say "fully private" or "nothing leaves the PC".

---

## 3. The deliverables (and the form's limits)

| Item | Where it goes on the form | Spec |
|---|---|---|
| **Deck** | Supporting file | Under 25 MB. Submit a **PDF** (renders the same everywhere); keep the PPTX as backup. |
| **Main video** (about 3 min) | Supporting link 1 | YouTube, **Unlisted** (not Private). |
| **Research page** | Supporting link 2 | Google Drive or Doc, "Anyone with the link can view". |
| **GitHub repo** | Supporting link 3 | Public, with a README anyone can follow. |
| **Intro video** (2 min MAX) | Introduction Video field | Highly preferred now, **mandatory if we are shortlisted**. A YouTube Unlisted link or an upload. |

Facts to remember:
- **There are only 3 link slots.** They are all used: video, research page, repo.
- The research paper PDF can also go in as a supporting file (up to 10 files, 25 MB each, formats: pdf, png, jpg, mp4, mov, pptx, docx, zip).
- **Test every link in a private (incognito) window, with no login.** If a judge has to "request access", we lose them.
- Do not put secrets, personal data, or malware in any shared file.

---

## 4. Do first (before recording A1)

Small fixes, then freeze. These came from the A1 trace and the screenshot.

1. **Event store gap:** `get_events_for_process` returns 0 events and `get_events_by_hash` returns "seen 0x" for the attack's own process. Query SQLite by hand for that process GUID. Check Sysmon logs file creation and registry writes, and that events are saved before the agent starts.
2. **Rename the VM** to a neutral computer name (for example `DESKTOP-4F2K9`). The agent called the test an "authorized security simulation on host tesing-blueteam", so the name gives away the answer.
3. **Rejection memory:** every action shows "rejected, then approved". If you did not click Reject on purpose, check that the "already rejected" memory is based on the tool and the target only, not the reason text.
4. **Host shows as "Unknown host"** in the thread list and the header. Pass the host from the alert into the thread data.
5. **Harness:** cut each run's record at the first verdict. Log later chat messages and extra actions separately. Fill `left_behind` from the verdict's `remaining_risk`.
6. **Pilot vs official:** move the old runs into `hackathon/runs/pilot/` and keep them out of the numbers. The two "Suspicious Double Extension File Execution: incomplete" threads in the UI are old pilot runs.
7. **Brand match:** update `brand.md` to the palette that now ships in the UI, so the video and deck match what people see. Keep the three rules: one amber per screen, red only for "Real attack", color never the only signal. Optional: the MEDIUM and HIGH badges are close to the red of "Real attack", and on video that can confuse people, so consider making level badges neutral.

**Freeze:** after these fixes and a clean re-run of A1, nothing changes in the agent, the prompt, the tools, or the model (gpt 5.6 sol). If something changes later, the affected runs are repeated. Write the model name, prompt version, and date in the results.

---

## 5. Test phase: A1 to A10, plus the benign set

You said 1 run per attack. That is fine, but the paper and the video must say "one run per scenario".

### Folder layout (per attack)

```
hackathon/runs/run_a1/
    conclusion.csv        the result row (from the harness)
    video.csv             your timeline file for the video (keep what your harness produces)
    recording.mp4         the screen recording, if video.csv is only a log
    alert.json, trace.txt (from the run)
    what_it_would_do.md   see below
```

### For every attack (A2 to A10), in this order
1. Revert the VM snapshot. Neutral computer name. Pipeline on.
2. Write the expected verdict in the scenario sheet BEFORE running.
3. Detection gate: confirm a detection rule fires. If not, swap in a reserve (R1, R2).
4. Start screen recording (dark theme UI, full flow from alert to verdict).
5. Run the script, from a neutral file name and folder (not `simulate_A#.ps1`).
6. Answer any question the agent asks with the scripted truthful reply (attacks: "No, I didn't do this"; benign: "Yes, I did this"). Write the answer down.
7. Fill `conclusion.csv`, write `what_it_would_do.md`, save the alert and trace.
8. Revert.

### The 10 attacks

| ID | What it does (plain words) | Status |
|---|---|---|
| A1 | Fake invoice file runs a hidden program and sets itself to start with the PC | recording now |
| A2 | Windows tool used to download a file | todo |
| A3 | Hidden PowerShell downloads and runs a script | todo |
| A4 | Stealing passwords from memory | todo |
| A5 | Deleting Windows backups (ransomware warning sign) | todo |
| A6 | Mass-encrypting files in a dummy folder (or the "ransomware warning" variant if no rule fires) | todo |
| A7 | Packing up documents and sending them out | todo |
| A8 | Scheduled task that runs a suspicious file | todo |
| A9 | Turning off antivirus | todo |
| A10 | A built-in Windows tool runs a remote script | todo |

Use the harmless Atomic Red Team tests where possible. Everything in the VM only, simulations only. Defender may block some tests: add exclusions in the VM, and note it.

### The benign set (needed for the false-positive number)

You listed only the 10 attacks, but **the false-positive number needs its own benign runs**. Without them we cannot say "cleared X% of false alarms". Plan:
- 10 to 12 benign alerts that look suspicious but are not: Pcalua launching Calculator (B1), an encoded PowerShell command that only prints text, a dev tool launching PowerShell and git, an installer creating a scheduled task, a normal program adding a startup entry, and so on.
- Run a **baseline day** (normal use, no attacks) and use the real alerts it produces.
- Scripted user answer for benign runs: "Yes, I did this". Record whether the agent cleared it **without asking** or **after the answer**.
- Your current Pcalua thread in the UI shows **"Real attack"**. If that Pcalua command was your own harmless test, that is a false escalation, and it counts in the benign results. Re-run it after the freeze with the truthful answer and record both.

### `what_it_would_do.md` (for every attack)

Be careful here. It is a "what could have happened", not something we observed.

```
# A#: <name>
## What we ran
The simulated attack in two sentences (label: SIMULATED).
## What a real attacker could have done next
3 to 5 bullets, plain words, each taken from the MITRE ATT&CK page of the technique
(link it). Label this section: "Illustrative, based on the documented technique."
## What Triagent did
Timeline: alert time, verdict time, action approved time. What it found, what it
proposed, what you approved, what it stopped.
## What was left behind
The honest list (startup entries, dropped files, copies). Triagent has no tool to
remove these, so a human must.
## Numbers
Time to verdict (agent time only, without waiting for human clicks), tool calls, cost.
```

Rules: never write "Triagent stopped a hacker". Write "stopped the simulated attack at <step>". Do not claim it prevented damage that the simulation could not cause.

---

## 6. The numbers we will report

Compute from the results of all runs. Always show the sample size.
- **Real attacks caught:** x of 10 (one run each).
- **False alarms cleared:** y of N benign (and how many of those after the user confirmed).
- **Real attacks wrongly dismissed:** report the number even if it is 0.
- **Time to verdict** (agent time, excluding human waiting) and **cost per alert**: use the median.
- **Consistency** is not measured (one run each), so we say so.
- Do not quote how long a human analyst takes unless we have a source. If we estimate, label it "estimate".
- The attacks were chosen because the detection layer catches them. We do not claim a detection rate.

---

## 7. The main video (about 3 minutes)

**Goal:** anyone understands the problem, the solution, who it is for, and why it can be trusted. Technical details come last and stay in plain words.

**How we make it:** interactive slides (built with Gemini) that already have animations. We click through them while talking and screen-record it. The real UI recordings from the test runs are the proof clips. No editing software needed beyond a trim.

**Script length:** about 390 to 420 words (a calm 130 words a minute).

| Time | Beat | Notes |
|---|---|---|
| 0:00 to 0:15 | **Hook:** a small business owner, a Friday evening, an alert nobody checks. "What if every alert came with an answer?" | Calm navy, one amber light. No red yet. |
| 0:15 to 0:35 | **Who has this problem:** freelancers, small businesses, overloaded security teams | One line each. No statistics without a source. |
| 0:35 to 1:35 | **The case (A1):** the "invoice" file. The alert arrives, Triagent investigates (plain captions: checking where it came from, what it did, whether the file is known), asks the user one question, proposes stopping it, the user clicks Approve, verdict card. Label: **SIMULATED ATTACK**. | The one red moment: "Real attack". Use the real recording. |
| 1:35 to 2:00 | **Results:** tested on 10 simulated attacks and N false alarms. Numbers, each with its sample size. | Large numbers, small sample size underneath. |
| 2:00 to 2:30 | **Why you can trust it** (technical, in plain words): known attack patterns trigger it; the AI only gets read-only tools to investigate; it cannot act without your click; critical Windows processes are blocked; every action is logged and reversible where possible; everything it records stays on your PC; light enough for one computer. | No names of tools or frameworks. "The AI cannot make things up and act on them." |
| 2:30 to 2:50 | **Who it is for and the business:** individuals and small businesses first; one agent can handle thousands of alerts, so teams get time back and small companies get a first-line analyst; how it earns money (the hypothesis from the deck). | Investor beats. |
| 2:50 to 3:00 | **Close:** logo, the punchline, a one-line ask. | |

**Rules:** English voice-over, your own voice, a clean mic. Every attack marked "simulated". No jargon (see the word table in `hackathon_plan.md` 1.3b). Captions on. Check the video in a loud room with the sound off: the visuals alone should tell the story.

---

## 8. The deck

Same story and design as the video, with more detail. Under 25 MB, exported as a PDF.

1. Cover: logo and punchline
2. The problem
3. Who it is for
4. The solution in one sentence, plus one small diagram: detect, investigate, ask permission, act, verdict
5. The case (A1) with screenshots
6. Results: the numbers, with sample sizes (more than in the video)
7. Why you can trust it: the safety design in plain words (what the AI can and cannot do)
8. How it works (more detail than the video: the pipeline, the tools by category, the approval step, what stays local and what goes to the cloud). Names of Azure, the model, and LangGraph can appear here.
9. Business model: who pays, per what, first customers, why it scales (cost per alert measured, runs on the customer's PC). **Decide the model and one price hypothesis, and label it "hypothesis".**
10. How we differ (one slide, use the positioning line from `brand.md` section 7 for booth questions; keep this slide factual and short)
11. Roadmap
12. About me / team
13. Links: the research page, the repo, contact

Follow `brand.md`. Check Gemini's output against it: colors, no red except the attack moment, no clichés, readable text sizes, no invented numbers.

---

## 9. Research page and paper

**Page** (one Drive page or Doc, view-only), top to bottom:
1. The research paper PDF at the top (read-only).
2. One section per attack (A1 to A10), each with: name, what it does in plain words, how dangerous it is (MITRE technique, one line why), the video of Triagent stopping it, the verdict and numbers, and what remained.
3. The benign set results (the false-alarm side).
4. Limitations and notes.

**Videos:** host them on YouTube as Unlisted and embed or link them. Drive video playback is slower and sometimes unavailable for big files.

**Attack scripts:** include only the harmless simulation scripts, labeled "run only in a virtual machine". For the more sensitive ones (password stealing, deleting backups), link to the Atomic Red Team test instead of publishing the script.

**Paper outline (4 to 8 pages):** abstract; the problem; how we tested (VM, simulations, one run each, attacks chosen because they are detectable, scripted user answers); results table; one section per attack; mistakes and what we changed; limitations; safety design; future work.

---

## 10. GitHub repo and README

- **Before the first push:** check that `.env`, API keys, the Azure endpoint, databases, audit logs, the quarantine folder, recordings, and your machine and user names are excluded, and **check the git history too**.
- **README, in this order:** logo, punchline, one screenshot, what it is (3 lines), requirements (Windows VM, Python version, Sysmon with its link and a note that it is not bundled), setup in 3 steps (`setup.ps1`, `.env.example`, run), how to run a harmless test, safety warnings (VM only, simulations only), how it works (the one diagram), results summary with the link to the research page, limitations, credits and licenses (Sigma rules, Atomic Red Team, Sysmon), contact.
- Add `.env.example` and a LICENSE (your IP stays yours; choose the license on purpose).
- Setup needs an Azure account. Tech judges may not run it, so also describe what they can see without running anything (the screenshots, the videos, the research page).

---

## 11. Intro video (2 minutes MAX) and LinkedIn

They check the team before deciding, so this is who you are.

**Intro video (about 250 words):**
1. Who I am, in one sentence (your name, what you do).
2. My background (your AI engineering work, the THM JPT1, hackathons, and the Tahaluf story, told briefly and truthfully).
3. The problem I saw, and Triagent in one sentence.
4. Why IS CyberNext, and what I want from it (investors, adopters, feedback).
5. Close.

Record on camera, eye level, good light, a quiet room, English captions. Keep it under 2:00. It is optional now and mandatory if we are shortlisted, but record it now.

**LinkedIn (before Nov 11):** update your headline (AI engineer, building Triagent), the About section, add the main video and repo under "Featured", and post once about Triagent with the video. Make sure the profile matches what you say in the intro video.

---

## 12. Schedule (Nov 1 to Nov 11)

| Date | Testing and product | Video, deck, writing |
|---|---|---|
| **Sun Nov 1** | Section 4 fixes. Freeze. Re-run and record A1, write its folder and `what_it_would_do.md`. | Update `brand.md` to the shipped palette. Brief Gemini with the brand rules. |
| **Mon Nov 2** | A2 to A4. Start the baseline day in the evening. | Video script draft with placeholders. |
| **Tue Nov 3** | A5 to A7. | Slides in Gemini (video version). Deck outline. |
| **Wed Nov 4** | A8 to A10. Collect the baseline-day alerts. | Business model decision. Research page skeleton. |
| **Thu Nov 5** | Benign runs. Compute all numbers. **Numbers are final.** | Fill numbers into the script and slides. |
| **Fri Nov 6** | Re-runs only if a run was invalid. Write the paper. | Record voice-over and screen clips. |
| **Sat Nov 7** | | Finish and upload the main video (Unlisted). Build the deck. |
| **Sun Nov 8** | Repo cleanup, secret scan, README, push. | Research page finished. Deck exported to PDF (under 25 MB). |
| **Mon Nov 9** | | Record the intro video. LinkedIn updates. Write the three text fields. |
| **Tue Nov 10** | | **Review round:** a friend, a non-technical person, an Arabic speaker. Fix everything. Test every link in a private window. |
| **Wed Nov 11** | | Final read-through. **Submit.** Save the confirmation. Nov 12 is only for upload problems. |

If the testing slips, cut in this order: extra pilot runs, the optional benign scenarios beyond 8, deck extras. **Never cut:** the benign set, the honesty notes, and the review round.

---

## 13. Honesty checklist (every claim)

- [ ] "Tested on 10 simulated attacks, one run each", never "100% accurate"
- [ ] The attacks were chosen because the detection layer catches them
- [ ] Questions to the user were answered with scripted truthful replies
- [ ] Every attack is labeled SIMULATED
- [ ] Privacy sentence mentions the AI model and the reputation lookup
- [ ] "It asks before it acts" is true for every action it takes
- [ ] No number appears that is not in `results.csv`
- [ ] No claim about replacing analysts or beating other products
- [ ] Third-party parts are credited (Sigma rules, Sysmon, Atomic Red Team, reputation service)

---

## 14. Risks

| Risk | What to do |
|---|---|
| Testing takes longer than 3 days | Run attacks in batches, record every run, and write documents later. |
| The numbers are weaker than hoped | Report them honestly and show what was fixed. A modest, true number beats a big, shaky one. |
| Links need a login or are broken | Test every link in a private window on a phone. |
| Gemini slides drift from the brand or invent numbers | Review every slide against `brand.md` and `results.csv`. |
| Secrets in the repo | Scan the history before pushing. |
| Only 3 link slots | Use video, research page, repo. The deck and the paper go in as files. |
| Intro video becomes mandatory if shortlisted | Record it now, under 2 minutes. |
| A scenario writes persistence or deletes backups on the VM | Revert the snapshot after every run. |

---

## 15. After submitting (Nov 12 onward)

Follow `hackathon_plan.md` Part 4: the demo screen as the booth demo, the three booth scenarios rehearsed until they work 10 times in a row, the booth kit, the 3-minute and 5-minute stage pitches, and Q&A drills. What we show must match what we submitted.