"""FastAPI server for the GUI prototype."""

import asyncio
import re
from pathlib import Path

import yaml
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from env_checker import check_environment
from claude_backend import ClaudeBackend

# ── Paths ─────────────────────────────────────────────
HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent  # tools/gui-prototype -> repo root
SKILLS_DIR = REPO_ROOT / ".claude" / "skills"

# ── App setup ─────────────────────────────────────────
app = FastAPI(title="Malware Analysis Toolkit GUI")
app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")

backend = ClaudeBackend(str(REPO_ROOT), mode="auto")


# ── REST endpoints ────────────────────────────────────

@app.get("/")
async def index():
    return FileResponse(str(HERE / "static" / "index.html"))


@app.get("/api/status")
async def get_status():
    """Return environment status."""
    loop = asyncio.get_event_loop()
    status = await loop.run_in_executor(None, check_environment, str(REPO_ROOT))
    return status


@app.get("/api/skills")
async def get_skills():
    """Parse SKILL.md frontmatter from all skills."""
    skills = []
    if not SKILLS_DIR.exists():
        return skills

    for skill_dir in sorted(SKILLS_DIR.iterdir()):
        skill_md = skill_dir / "SKILL.md"
        if not skill_md.exists():
            continue
        try:
            text = skill_md.read_text(encoding="utf-8")
            # Extract YAML frontmatter between --- delimiters
            m = re.match(r"^---\s*\n(.+?)\n---", text, re.DOTALL)
            if not m:
                continue
            fm = yaml.safe_load(m.group(1))
            if not isinstance(fm, dict):
                continue
            skills.append({
                "name": fm.get("name", skill_dir.name),
                "description": (fm.get("description", "") or "")[:200],
            })
        except Exception:
            continue

    return skills


@app.get("/api/mode")
async def get_mode():
    return {"mode": backend.mode}


@app.post("/api/mode/{new_mode}")
async def set_mode(new_mode: str):
    if new_mode in ("sdk", "subprocess"):
        backend.mode = new_mode
        return {"mode": backend.mode}
    return {"error": "invalid mode"}


# ── WebSocket chat ────────────────────────────────────

@app.websocket("/ws/chat")
async def ws_chat(ws: WebSocket):
    await ws.accept()
    try:
        while True:
            data = await ws.receive_json()
            msg_type = data.get("type", "")

            if msg_type == "execute":
                prompt = data.get("prompt", "").strip()
                if not prompt:
                    await ws.send_json({"type": "error", "message": "empty prompt"})
                    continue

                try:
                    async for msg in backend.execute(prompt):
                        await ws.send_json(msg)
                except Exception as e:
                    await ws.send_json({"type": "error", "message": str(e)})

            elif msg_type == "cancel":
                await backend.cancel()
                await ws.send_json({"type": "system", "subtype": "cancelled", "data": {}})

    except WebSocketDisconnect:
        await backend.cancel()


# ── Entry point ───────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    print(f"Repo root: {REPO_ROOT}")
    print(f"Backend mode: {backend.mode}")
    print(f"Starting server at http://localhost:8765")
    uvicorn.run(app, host="127.0.0.1", port=8765, log_level="info")
