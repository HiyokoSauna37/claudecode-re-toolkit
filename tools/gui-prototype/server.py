"""FastAPI server for the GUI prototype."""

import asyncio
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import yaml
from dotenv import load_dotenv
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from env_checker import check_environment
from claude_backend import ClaudeBackend

# ── Paths ─────────────────────────────────────────────
HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent  # tools/gui-prototype -> repo root
SKILLS_DIR = REPO_ROOT / ".claude" / "skills"
REPORTS_DIR = REPO_ROOT / "reports"
UPLOAD_DIR = HERE / "uploads"
QUARANTINE_DIR = REPO_ROOT / "tools" / "proxy-web" / "Quarantine"
GHIDRA_LOGS_DIR = REPO_ROOT / "tools" / "ghidra-headless" / "logs"

# Load .env from repo root into environment
load_dotenv(REPO_ROOT / ".env")

# Ensure upload dir exists
UPLOAD_DIR.mkdir(exist_ok=True)

# VM screenshot temp file
VM_SCREENSHOT = HERE / "uploads" / "_vm_screenshot.png"

# ── App setup ─────────────────────────────────────────
app = FastAPI(title="Malware Analysis Toolkit GUI")
app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")

backend = ClaudeBackend(str(REPO_ROOT))


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
            m = re.match(r"^---\s*\n(.+?)\n---\s*\n", text, re.DOTALL)
            if not m:
                continue
            fm_text = m.group(1)
            name = skill_dir.name
            description = ""
            try:
                fm = yaml.safe_load(fm_text)
                if isinstance(fm, dict):
                    name = fm.get("name", name)
                    description = fm.get("description", "") or ""
            except Exception:
                nm = re.search(r"^name:\s*(.+)", fm_text, re.MULTILINE)
                if nm:
                    name = nm.group(1).strip()
                dm = re.search(r"^description:\s*(.+)", fm_text, re.MULTILINE)
                if dm:
                    description = dm.group(1).strip()
            skills.append({
                "name": name,
                "description": description[:200],
            })
        except Exception:
            continue

    return skills


@app.get("/api/reports")
async def get_reports():
    """List analysis reports."""
    reports = []
    if not REPORTS_DIR.exists():
        return reports

    for report_file in sorted(REPORTS_DIR.rglob("*.md"), reverse=True):
        rel = report_file.relative_to(REPORTS_DIR)
        try:
            stat = report_file.stat()
            reports.append({
                "path": str(rel),
                "name": report_file.stem,
                "category": rel.parts[0] if len(rel.parts) > 1 else "general",
                "size": stat.st_size,
                "modified": stat.st_mtime,
            })
        except Exception:
            continue

    return reports[:50]  # Limit to 50 most recent


@app.get("/api/reports/{path:path}")
async def get_report(path: str):
    """Read a specific report."""
    report_path = REPORTS_DIR / path
    if not report_path.exists() or not report_path.is_file():
        return JSONResponse({"error": "not found"}, status_code=404)
    # Prevent path traversal
    try:
        report_path.resolve().relative_to(REPORTS_DIR.resolve())
    except ValueError:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    content = report_path.read_text(encoding="utf-8", errors="replace")
    return {"path": path, "content": content}


def _collect_report_hashes() -> set[str]:
    """Extract all SHA256 hashes mentioned in reports."""
    hashes = set()
    if not REPORTS_DIR.exists():
        return hashes
    sha256_re = re.compile(r"[a-fA-F0-9]{64}")
    for report_file in REPORTS_DIR.rglob("*.md"):
        try:
            text = report_file.read_text(encoding="utf-8", errors="replace")
            hashes.update(sha256_re.findall(text))
        except Exception:
            continue
    return {h.lower() for h in hashes}


def _read_session_hashes(session_dir: Path) -> set[str]:
    """Read SHA256 hashes from metadata.json in a quarantine session."""
    hashes = set()
    meta = session_dir / "metadata.json"
    if not meta.exists():
        return hashes
    try:
        data = json.loads(meta.read_text(encoding="utf-8"))
        for dl in data.get("downloads", []):
            h = dl.get("hashes", {}).get("sha256", "")
            if h:
                hashes.add(h.lower())
    except Exception:
        pass
    return hashes


@app.get("/api/quarantine")
async def get_quarantine():
    """List files in Quarantine directory as a tree."""
    if not QUARANTINE_DIR.exists():
        return []

    report_hashes = _collect_report_hashes()
    entries = []
    try:
        for host_dir in QUARANTINE_DIR.iterdir():
            if not host_dir.is_dir():
                continue
            host_entry = {"name": host_dir.name, "sessions": [], "_sort_key": ""}
            for session_dir in sorted(host_dir.iterdir(), key=lambda p: p.name, reverse=True):
                if not session_dir.is_dir():
                    continue
                session_hashes = _read_session_hashes(session_dir)
                analyzed = bool(session_hashes & report_hashes)
                files = []
                for f in sorted(session_dir.iterdir()):
                    if not f.is_file():
                        continue
                    files.append({
                        "name": f.name,
                        "path": str(f.resolve()),
                        "size": f.stat().st_size,
                        "is_encrypted": f.name.endswith(".enc.gz"),
                    })
                if files:
                    host_entry["sessions"].append({
                        "name": session_dir.name,
                        "files": files,
                        "analyzed": analyzed,
                    })
            if host_entry["sessions"]:
                # Sort key = newest session name (YYYYMMDD_HHMMSS format)
                host_entry["_sort_key"] = host_entry["sessions"][0]["name"]
                entries.append(host_entry)
        # Sort hosts by newest session (descending)
        entries.sort(key=lambda e: e.pop("_sort_key"), reverse=True)
    except Exception:
        pass
    return entries


@app.get("/api/quarantine/file")
async def get_quarantine_file(path: str):
    """Serve a file from Quarantine or Ghidra logs directory."""
    file_path = Path(path).resolve()
    # Security: must be inside Quarantine or Ghidra logs directory
    allowed = False
    for allowed_dir in [QUARANTINE_DIR, GHIDRA_LOGS_DIR]:
        try:
            file_path.relative_to(allowed_dir.resolve())
            allowed = True
            break
        except ValueError:
            continue
    if not allowed:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    if not file_path.exists() or not file_path.is_file():
        return JSONResponse({"error": "not found"}, status_code=404)
    # Only allow safe file types
    suffix = file_path.suffix.lower()
    type_map = {".html": "text/html", ".png": "image/png", ".json": "application/json",
                ".csv": "text/csv", ".txt": "text/plain", ".jpg": "image/jpeg",
                ".jpeg": "image/jpeg", ".md": "text/plain", ".log": "text/plain"}
    media_type = type_map.get(suffix)
    if not media_type:
        return JSONResponse({"error": "file type not allowed"}, status_code=403)
    return FileResponse(str(file_path), media_type=media_type)


@app.get("/api/ghidra-logs")
async def get_ghidra_logs():
    """List Ghidra analysis logs."""
    if not GHIDRA_LOGS_DIR.exists():
        return []
    logs = []
    for f in sorted(GHIDRA_LOGS_DIR.iterdir(), reverse=True):
        if not f.is_file():
            continue
        try:
            stat = f.stat()
            logs.append({
                "name": f.name,
                "path": str(f.resolve()),
                "size": stat.st_size,
                "modified": stat.st_mtime,
            })
        except Exception:
            continue
    return logs[:50]


@app.get("/api/vm/screenshot")
async def get_vm_screenshot():
    """Capture VM screenshot via vmrun."""
    vmrun = os.environ.get("VMRUN_PATH", "")
    vmx = os.environ.get("VM_VMX_PATH", "")
    if not vmrun or not vmx:
        return JSONResponse({"error": "VM not configured"}, status_code=404)
    if not Path(vmrun).exists():
        return JSONResponse({"error": "vmrun not found"}, status_code=404)

    try:
        # Check if VM is running
        result = subprocess.run(
            [vmrun, "list"], capture_output=True, text=True, timeout=5
        )
        if vmx.lower() not in result.stdout.lower():
            return JSONResponse({"error": "VM not running"}, status_code=404)

        # Delete old screenshot to avoid stale cache
        if VM_SCREENSHOT.exists():
            VM_SCREENSHOT.unlink()

        # Capture screenshot (try without -T flag first, then with -T ws)
        result = subprocess.run(
            [vmrun, "captureScreen", vmx, str(VM_SCREENSHOT)],
            capture_output=True, text=True, timeout=10
        )
        if not VM_SCREENSHOT.exists():
            # Retry with -T ws for Workstation
            result = subprocess.run(
                [vmrun, "-T", "ws", "captureScreen", vmx, str(VM_SCREENSHOT)],
                capture_output=True, text=True, timeout=10
            )

        if VM_SCREENSHOT.exists() and VM_SCREENSHOT.stat().st_size > 0:
            return FileResponse(
                str(VM_SCREENSHOT),
                media_type="image/png",
                headers={"Cache-Control": "no-cache, no-store"},
            )
        return JSONResponse(
            {"error": f"capture failed: {result.stderr.strip()}"},
            status_code=500,
        )
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


MAX_UPLOAD_SIZE = 100 * 1024 * 1024  # 100 MB


@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...)):
    """Upload a file for analysis."""
    if not file.filename:
        return JSONResponse({"error": "no filename"}, status_code=400)
    # Sanitize filename
    safe_name = re.sub(r"[^\w\-.]", "_", file.filename)
    dest = UPLOAD_DIR / safe_name
    total = 0
    with open(dest, "wb") as f:
        while chunk := await file.read(1024 * 1024):
            total += len(chunk)
            if total > MAX_UPLOAD_SIZE:
                dest.unlink(missing_ok=True)
                return JSONResponse(
                    {"error": f"file too large (max {MAX_UPLOAD_SIZE // 1024 // 1024}MB)"},
                    status_code=413,
                )
            f.write(chunk)
    return {"path": str(dest), "name": safe_name, "size": dest.stat().st_size}


@app.get("/api/config")
async def get_config():
    """Return backend capabilities and limits."""
    return {
        "max_upload_size": MAX_UPLOAD_SIZE,
        "max_upload_size_mb": MAX_UPLOAD_SIZE // 1024 // 1024,
    }


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
                session_id = data.get("session_id", "")
                if not prompt:
                    await ws.send_json({"type": "error", "message": "empty prompt"})
                    continue

                try:
                    async for msg in backend.execute(prompt, session_id=session_id):
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
    print(f"Starting server at http://localhost:8765")
    uvicorn.run(app, host="127.0.0.1", port=8765, log_level="info")
