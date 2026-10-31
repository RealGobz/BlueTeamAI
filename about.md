I'm an AI engineer building a Windows security tool. I'm not a security expert, so explain security terms simply and ask me questions whenever something is unclear instead of guessing.

THE GOAL
A program that watches Windows activity, detects attacks using open rules, and creates an alert for each one. Later, an AI agent will investigate each alert, but that is NOT part of this task.

WHAT TO BUILD NOW (detection only)
1. Read Windows event logs written by Sysmon (a Microsoft tool that records what programs do). First read saved .evtx log files, later read live logs.
2. Turn each log entry into a simple Python dict.
3. Load Sigma rules (YAML files from the SigmaHQ/sigma GitHub repo, "rules/windows" folder). Start with level high/critical and process-creation rules only.
4. Write my OWN code that checks each event against each rule. Do not use a Sigma library, because I want to understand how it works.
5. When a rule matches, output an alert as JSON with: rule name, severity, attack type tag, the matching event, and the parent programs that started it.
6. Save all events in a SQLite database for 24 hours, so the future agent can look up "what else did this program do?"
7. Don't send the same alert over and over (deduplicate).

RULES
- Python only, standard library plus pywin32, pyyaml, python-evtx. Ask before adding anything else.
- Small readable code. Unit tests.
- Never run malware on my computer. Use saved sample logs from the GitHub repo sbousseaden/EVTX-ATTACK-SAMPLES.
- The program only watches. It never deletes or blocks anything.

HOW TO WORK
- One small step at a time. After each step, tell me what you built and how to run it, then wait.
- Ask me before big decisions.

FIRST STEP
Ask me your questions, then propose the folder layout and what the alert JSON should look like.