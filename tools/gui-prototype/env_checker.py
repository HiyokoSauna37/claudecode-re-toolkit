"""Environment status checker for the malware analysis toolkit."""

import os
import subprocess
import shutil
from pathlib import Path
from dotenv import dotenv_values


def _run(cmd: list[str], timeout: int = 10) -> tuple[int, str, str]:
    """Run a command and return (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except FileNotFoundError:
        return -1, "", "command not found"
    except subprocess.TimeoutExpired:
        return -2, "", "timeout"
    except Exception as e:
        return -3, "", str(e)


def _status(ok: bool, detail: str = "") -> dict:
    return {"status": "ok" if ok else "missing", "detail": detail}


def check_environment(repo_root: str) -> dict:
    """Check all toolkit components and return status dict."""
    root = Path(repo_root)
    result = {}

    # .env
    env_path = root / ".env"
    if env_path.exists():
        vals = dotenv_values(env_path)
        configured = [k for k, v in vals.items() if v and v != "changeme"]
        result["env_file"] = {"status": "ok", "detail": f"{len(configured)} vars configured"}
    else:
        result["env_file"] = {"status": "missing", "detail": ".env not found — run /toolkit-setup"}

    # Docker Desktop
    rc, out, err = _run(["docker", "info"])
    if rc == 0:
        result["docker"] = {"status": "ok", "detail": "running"}
    else:
        result["docker"] = {"status": "missing", "detail": "Docker Desktop not running"}

    # proxy-web-browser image
    rc, out, _ = _run(["docker", "images", "proxy-web-browser:latest", "--format", "{{.ID}} {{.CreatedAt}}"])
    if rc == 0 and out:
        result["proxy_web_image"] = {"status": "ok", "detail": out.split("\n")[0]}
    else:
        result["proxy_web_image"] = {"status": "missing", "detail": "image not built"}

    # ghidra-headless container
    rc, out, _ = _run(["docker", "ps", "-a", "--filter", "name=ghidra-headless", "--format", "{{.Status}}"])
    if rc == 0 and out:
        status = "running" if "Up" in out else "stopped"
        result["ghidra_container"] = {"status": status, "detail": out.split("\n")[0]}
    else:
        result["ghidra_container"] = {"status": "missing", "detail": "container not created"}

    # VMware
    env_vals = dotenv_values(env_path) if env_path.exists() else {}
    vmrun_path = env_vals.get("VMRUN_PATH", "")
    if vmrun_path and Path(vmrun_path).exists():
        rc, out, _ = _run([vmrun_path, "-T", "ws", "list"], timeout=5)
        result["vmware"] = {"status": "ok" if rc == 0 else "error", "detail": out or "vmrun failed"}
    else:
        result["vmware"] = {"status": "not_configured", "detail": "VMRUN_PATH not set or not found"}

    # Claude CLI
    rc, out, _ = _run(["claude", "--version"])
    if rc == 0:
        result["claude_cli"] = {"status": "ok", "detail": out}
    else:
        result["claude_cli"] = {"status": "missing", "detail": "claude CLI not found"}

    # Agent SDK
    try:
        import claude_code_sdk  # noqa: F401
        result["agent_sdk"] = {"status": "ok", "detail": "claude-code-sdk installed"}
    except ImportError:
        try:
            import claude_agent_sdk  # noqa: F401
            result["agent_sdk"] = {"status": "ok", "detail": "claude-agent-sdk installed"}
        except ImportError:
            result["agent_sdk"] = {"status": "missing", "detail": "pip install claude-code-sdk"}

    # ANTHROPIC_API_KEY
    has_key = bool(os.environ.get("ANTHROPIC_API_KEY"))
    result["api_key"] = {
        "status": "ok" if has_key else "missing",
        "detail": "set" if has_key else "ANTHROPIC_API_KEY not set — subprocess mode only",
    }

    # YARA rules
    yara_dir = root / "tools" / "ghidra-headless" / "yara-rules"
    if yara_dir.exists() and any(yara_dir.iterdir()):
        result["yara_rules"] = {"status": "ok", "detail": str(yara_dir)}
    else:
        result["yara_rules"] = {"status": "missing", "detail": "run setup_yara_rules.sh"}

    # Determine backend mode
    sdk_ok = result["agent_sdk"]["status"] == "ok"
    key_ok = result["api_key"]["status"] == "ok"
    result["backend_mode"] = "sdk" if (sdk_ok and key_ok) else "subprocess"

    return result
