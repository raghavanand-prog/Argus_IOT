# docs/paper/

Two portfolio documents, both generated from real, inspected project content (no
fabricated features, results, or references — see each document's own honesty
notes).

- `ieee-paper.html` / `ARGUS-IEEE-Paper.pdf` — an IEEE-conference-style two-column
  paper describing the system, its evaluation, and the measured ablation result.
  All six references were individually verified (title, authors, venue, DOI) via
  web search before inclusion; one citation error inherited from an earlier
  documentation pass (`docs/00-problem-and-threat-model.md`) was found and
  corrected in the same pass — see that file's correction note.
- `project-guide.html` / `ARGUS-Project-Guide.pdf` — a 23-section technical
  project guide/manual for viva, project presentation, technical interviews, and
  resume discussion, with implemented-vs-proposed features and security measures
  kept explicitly separate throughout.

To regenerate a PDF after editing the HTML source:

```bash
node -e "
const { chromium } = require('playwright');
const path = require('path');
(async () => {
  const browser = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium-1194/chrome-linux/chrome' });
  const page = await browser.newPage();
  await page.goto('file://' + path.resolve(process.argv[1]));
  await page.pdf({ path: process.argv[2], format: 'A4', printBackground: true,
    margin: { top: '0mm', bottom: '0mm', left: '0mm', right: '0mm' } });
  await browser.close();
})();
" docs/paper/ieee-paper.html docs/paper/ARGUS-IEEE-Paper.pdf
```

(Substitute `project-guide.html` / `ARGUS-Project-Guide.pdf` for the guide.) The
`executablePath` above matches this repository's dev-container Playwright install;
on another machine, omit it to use Playwright's own managed browser after running
`npx playwright install chromium`.
