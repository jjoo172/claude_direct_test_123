# claude_direct_test_123

A minimal starter: a Python (Flask) backend that serves a page saying **Hello, World!**.
The page fetches its message from the backend at `/api/hello`, so you can see the frontend and backend talking.

## Put it on the web (no local setup)

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/jjoo172/claude_direct_test_123)

1. Click the button above and sign in to Render with GitHub.
2. Approve the service it reads from `render.yaml` (free plan).
3. When the build finishes, Render gives you a public URL like `https://claude-direct-test-123.onrender.com` that works from any computer.

Every push to `main` redeploys automatically. On the free plan the app sleeps after a period of no traffic, so the first visit after a while can take up to a minute.

## Files

- `app.py` – Flask app: `/` serves the page, `/api/hello` returns JSON.
- `requirements.txt` – Flask plus gunicorn (the production server).
- `render.yaml` – Render deployment config.

## Running it locally (optional)

```bash
pip install -r requirements.txt
python app.py
```
