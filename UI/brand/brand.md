# Triagent: brand sheet

## 1. Name
**Triagent** = *triage* + *agent*. Said "TRY-uh-jent".

- **The story (use this everywhere):** in a hospital emergency room, a triage nurse looks at everyone who walks in, sends the fine ones home, and rushes the real emergencies to a doctor. Security alerts are the same: most are fine, a few are emergencies. Triagent is the triage nurse, and it never sleeps.
- Plain English, no security knowledge needed, works for investors and for technical judges.
- **Why not "Vigil":** it was our first pick, but a project with the same name already exists in exactly this space (an open-source agentic AI SOC). Do not use it.
- **Still to check before we lock it:** (1) domain (.com / .ai), (2) trademark search, (3) a web search for "Triagent" + security. A small tool called Triagent already exists (a three-agent framework on pip). It is not a security product, but confirm it does not get in our way.

## 2. Punchline
**"What if every alert came with an answer?"**

Subline (deck cover, booth banner, handout):
**An AI security analyst that investigates every alert, and asks before it acts.**

Why: the question carries the problem (alerts with no answers) and the offer (an answer for each one). It is a question, not a claim, so it cannot be fact-checked into trouble.

## 3. Theme: "calm, not alarm"
Most teams will show dark red and neon. We do the opposite on purpose.

**Idea:** a quiet night, one light on. Deep navy background, one warm amber light as our signature.

**Three rules (video, deck, and UI):**
1. **One amber per screen.** Amber marks the single thing to look at. If everything glows, nothing does.
2. **Red appears only for a confirmed real attack.** Everything else is calm. So when red finally shows up, people feel it. In the video, build the calm first, then let the red moment land.
3. **No cliché.** No hooded hackers, skulls, padlocks, shields, matrix rain, scanlines, or circuit boards.

### Palette
| Role | Dark (default) | Light |
|---|---|---|
| Background | #0E1424 | #FAF8F3 |
| Surface | #151C30 | #FFFFFF |
| Border | #2A3453 | #DDD8CB |
| Text | #E8EBF4 | #141A2E |
| Muted text | #9AA3BD | #5A6280 |
| Brand (amber) | #F4B63F | #E3A008 (use #9A6700 for amber text) |
| Real attack | #F0524F | #C62F2C |
| False alarm | #3DBE8B | #187A52 |
| Needs more info | #8E9BFF | #4A5BD6 |

Contrast was checked by hand. Run the final colors through a contrast checker before shipping. Always pair color with a text label (never color alone).

**UI note:** in the earlier UI prompt, "needs more info" was amber. Change it to the periwinkle above, so amber stays the brand color only.

Tokens are in `theme.css` (CSS variables, dark default with a light mode). Use it for UI/main and UI/HITL. If HITL pages need it, the server must allow a stylesheet from itself (`style-src 'self'`) and serve this file.

### Type
- UI: system font stack (already in `theme.css`), no web fonts.
- Deck and video: **Inter** (free, open license). Large type, few words, generous space.
- The wordmark is drawn as shapes, so it needs no font.

## 4. Logo
Files in this folder:
- `triagent-wordmark-dark.svg` / `-light.svg`: the word "triagent", lowercase. The dot of the "i" is the amber light.
- `triagent-icon.svg`: app icon / favicon / avatar. Three dots, one lit: out of many alerts, one needs you.
- `triagent-lockup-dark.svg` / `-light.svg`: icon + wordmark side by side (cover slides, video end card, README header).

Usage:
- Use the dark files on dark backgrounds, the light files on light ones.
- Clear space around the logo: at least the height of the "t".
- Minimum size: wordmark 90 px wide, icon 16 px.
- Do not recolor the amber, stretch, add shadows, or put it on busy images.

## 5. Where the name goes
- **System prompt:** add one line at the top: `You are Triagent's investigator: an AI security analyst running on the user's Windows PC.`
- **README:** header with the lockup, the punchline, then the subline.
- **UI:** page title "Triagent", favicon = icon, left panel header = lockup. Update the notification title in UI/HITL too.
- **Windows notification:** "Triagent: approval needed" (keep untrusted text out of it, as before).
- Do not rename internal folders, files, or database tables now. Only user-facing text.

## 6. Video and deck rules
- Open on calm: dark navy, one amber light. No red until the real attack is confirmed.
- Captions in plain words (see plan: "checking where it came from", etc.).
- Closing card: the lockup + the punchline.
- Mark every attack "simulated attack".
- One idea per slide. Numbers shown large, with the sample size small underneath.

## 7. Positioning note
"AI SOC analyst" is already a category. Competitors such as Dropzone AI and Darktrace sell to big security teams. Our difference, for questions at the booth: Triagent starts from one PC and the person who has no security team, runs the investigation itself, and does nothing without a click. Say that in one sentence and move on.
