"""Claude backend — subprocess mode using claude -p."""

import asyncio
import json
import os
import signal
import subprocess
import sys
from pathlib import Path
from typing import AsyncIterator


class ClaudeBackend:
    """Async streaming interface for Claude Code via subprocess."""

    def __init__(self, repo_root: str):
        self.repo_root = str(Path(repo_root).resolve())
        self._process: asyncio.subprocess.Process | None = None

    SAFETY_PREFIX = (
        "[SYSTEM RULE — ABSOLUTE] "
        "ホストOS上でマルウェアを復号化・展開しないこと。"
        "暗号化ファイル(.enc.gz)はそのままDockerコンテナまたはVM内にコピーし、内部で復号すること。"
        "ホスト上に生のマルウェアバイナリを保存するBashコマンドを実行してはならない。"
        "docker cpでコンテナ内からホストへマルウェアをコピーしてはならない。"
        "解析結果（テキスト/JSON）のみホストに保存すること。\n\n"
    )

    async def execute(self, prompt: str, session_id: str = "") -> AsyncIterator[dict]:
        """Execute a prompt and yield normalized message dicts.

        Args:
            prompt: The user prompt.
            session_id: Claude Code session ID. If provided, resumes that session.
        """
        safe_prompt = self.SAFETY_PREFIX + prompt
        cmd = [
            "claude", "-p", safe_prompt,
            "--output-format", "stream-json",
            "--verbose",
            "--max-turns", "30",
            "--permission-mode", "bypassPermissions",
            "--allowedTools", "Bash", "Read", "Glob", "Grep",
            "WebFetch", "WebSearch", "Skill", "Agent",
        ]

        # Resume existing session if session_id is provided
        if session_id:
            cmd.extend(["--resume", session_id])

        env = os.environ.copy()
        # Prevent nested session error
        env.pop("CLAUDECODE", None)
        env.pop("CLAUDE_CODE_SESSION", None)

        yield {"type": "system", "subtype": "start", "data": {"mode": "subprocess"}}

        # Platform-specific flags so we can kill the entire process tree on cancel.
        # Windows: CREATE_NEW_PROCESS_GROUP allows CTRL_BREAK and lets taskkill /T target descendants.
        # Unix: start_new_session creates a new process group for os.killpg().
        popen_kwargs = {}
        if sys.platform == "win32":
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            popen_kwargs["start_new_session"] = True

        try:
            self._process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.repo_root,
                env=env,
                limit=10 * 1024 * 1024,  # 10 MB line buffer for large tool results
                **popen_kwargs,
            )

            async for msg in self._read_stream_json(self._process.stdout):
                yield msg

            await self._process.wait()

            if self._process.returncode != 0:
                stderr = ""
                if self._process.stderr:
                    stderr_bytes = await self._process.stderr.read()
                    stderr = stderr_bytes.decode(errors="replace")
                if stderr:
                    yield {"type": "error", "message": f"Exit code {self._process.returncode}: {stderr[:500]}"}

        except Exception as e:
            yield {"type": "error", "message": f"Subprocess error: {e}"}
        finally:
            self._process = None

    async def cancel(self):
        """Cancel current execution by killing the entire process tree.

        On Windows the `claude` shim spawns node.exe which spawns further node/
        bash/git/sub-agent processes; terminate() only kills the shim, leaving
        the actual inference + tools running. We kill the whole tree.
        """
        proc = self._process
        if not proc or proc.returncode is not None:
            return

        pid = proc.pid

        if sys.platform == "win32":
            # /F = force, /T = kill descendants
            try:
                await asyncio.to_thread(
                    subprocess.run,
                    ["taskkill", "/F", "/T", "/PID", str(pid)],
                    capture_output=True, timeout=5, check=False,
                )
            except Exception:
                pass
            # Fallback in case taskkill is unavailable for some reason
            try:
                proc.kill()
            except (ProcessLookupError, OSError):
                pass
        else:
            # POSIX: send SIGKILL to the entire process group
            try:
                os.killpg(os.getpgid(pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                try:
                    proc.kill()
                except (ProcessLookupError, OSError):
                    pass

    async def _read_stream_json(self, stream) -> AsyncIterator[dict]:
        """Parse stream-json (NDJSON) output from claude -p."""
        while True:
            try:
                line_bytes = await stream.readline()
            except ValueError:
                # Line exceeds buffer limit — read and discard the chunk
                chunk = await stream.read(65536)
                if not chunk:
                    break
                continue
            if not line_bytes:
                break
            line = line_bytes.decode(errors="replace").strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            for msg in self._normalize_stream_json(data):
                yield msg

    def _normalize_stream_json(self, data: dict) -> list[dict]:
        """Normalize a stream-json line to our message format."""
        results = []
        msg_type = data.get("type", "")

        if msg_type == "assistant":
            content = data.get("message", {}).get("content", [])
            if isinstance(content, list):
                for block in content:
                    if block.get("type") == "text":
                        results.append({"type": "text", "content": block.get("text", "")})
                    elif block.get("type") == "tool_use":
                        results.append({
                            "type": "tool_use",
                            "name": block.get("name", ""),
                            "input": block.get("input", {}),
                            "id": block.get("id", ""),
                        })
        elif msg_type == "user":
            content = data.get("message", {}).get("content", [])
            if isinstance(content, list):
                for block in content:
                    if block.get("type") == "tool_result":
                        text = block.get("content", "")
                        if isinstance(text, list):
                            text = " ".join(b.get("text", str(b)) for b in text)
                        results.append({
                            "type": "tool_result",
                            "tool_use_id": block.get("tool_use_id", ""),
                            "content": str(text)[:2000],
                            "is_error": block.get("is_error", False),
                        })
        elif msg_type == "result":
            results.append({
                "type": "result",
                "cost_usd": data.get("cost_usd", 0),
                "duration_ms": data.get("duration_ms", 0),
                "session_id": data.get("session_id", ""),
            })

        return results
