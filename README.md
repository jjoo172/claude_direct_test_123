# claude_direct_test_123

A Python (Flask) web app that scans a GitHub repository for memory-unsafe code and lists each risky spot with the file, line, an explanation, and a safer alternative.

Paste a repo URL (or `owner/repo`) on the home page and click **Scan repo**.

## What it checks

| Language | Examples of what gets flagged |
| --- | --- |
| C / C++ / Objective-C | `gets`, `strcpy`, `strcat`, `sprintf`, `scanf("%s")`, variable format strings, `memcpy`, `strncpy`, `alloca`, VLAs, `realloc` into the same pointer, multiplication inside `malloc`, `free` without clearing, `reinterpret_cast` |
| Rust | `unsafe` blocks, `transmute`, `from_raw_parts`, `get_unchecked`, `set_len` |
| Go | `unsafe.Pointer` and friends, cgo |
| C# | `unsafe`, `stackalloc`, `fixed`, manual `Marshal` copies |
| Python | `ctypes` raw memory access |
| Zig | `@ptrCast`, `@ptrFromInt`, `@alignCast` |

Findings are ranked critical, high, medium, or low. Click the colored bar or the legend to filter by severity.

This is a pattern scanner: it reads code line by line and doesn't compile or trace it, so some findings are safe in context and some real bugs won't be caught. Use it as a review list. Folders named `vendor`, `third_party`, `external`, `deps`, and `node_modules` are skipped, and so are `test`/`tests` unless you tick **Include test folders**.

The repo is downloaded as a zip and read in memory only; nothing from it is written to disk or run.

## Deploying (no local setup)

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/jjoo172/claude_direct_test_123)

1. Click the button above and sign in to Render with GitHub.
2. Approve the service it reads from `render.yaml` (free plan). You can leave `GITHUB_TOKEN` blank.
3. When the build finishes, Render gives you a public `.onrender.com` URL that works from any computer.

Every push to `main` redeploys automatically. On the free plan the app sleeps after a period of no traffic, so the first visit after a while can take up to a minute.

### Optional: GITHUB_TOKEN

Without a token, GitHub allows about 60 scans per hour from the server and only public repos. To raise that and scan private repos, create a [fine-grained personal access token](https://github.com/settings/personal-access-tokens/new) with read-only **Contents** access, then add it as the `GITHUB_TOKEN` environment variable in the Render dashboard.

## Limits

- Repos whose zip is over 60 MB are refused.
- Source files over 1 MB are skipped.
- A scan stops after 2,000 findings.

## Files

- `app.py` – Flask routes: `/` (the scanner page), `/api/scan` (POST `{"repo": "owner/repo"}`), `/api/hello`.
- `scanner.py` – downloads the repo and applies the rules. Add or tune rules in the `RULES` list.
- `templates/index.html` – the page.
- `render.yaml` – Render deployment config.

## Running it locally (optional)

```bash
pip install -r requirements.txt
python app.py
```
