"""Claude backend abstraction — SDK or subprocess mode."""

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import AsyncIterator


class ClaudeBackend:
    """Unified async streaming interface for Claude Code execution."""

    def __init__(self, repo_root: str, mode: str = "auto"):
        self.repo_root = str(Path(repo_root).resolve())
        self._mode = mode
        self._process: asyncio.subprocess.Process | None = None

        if mode == "auto":
            self._mode = self._detect_mode()

    @property
    def mode(self) -> str:
        return self._mode

    @mode.setter
    def mode(self, value: str):
        if value in ("sdk", "subprocess"):
            self._mode = value

    def _detect_mode(self) -> str:
        """Detect best available mode."""
        if not os.environ.get("ANTHROPIC_API_KEY"):
            return "subprocess"
        try:
            import claude_code_sdk  # noqa: F401
            return "sdk"
        except ImportError:
            try:
                import claude_agent_sdk  # noqa: F401
                return "sdk"
            except ImportError:
                return "subprocess"

    async def execute(self, prompt: str) -> AsyncIterator[dict]:
        """Execute a prompt and yield normalized message dicts."""
        if self._mode == "sdk":
            async for msg in self._execute_sdk(prompt):
                yield msg
        else:
            async for msg in self._execute_subprocess(prompt):
                yield msg

    async def cancel(self):
        """Cancel current execution."""
        if self._process and self._process.returncode is None:
            try:
                self._process.terminate()
            except ProcessLookupError:
                pass

    # ── SDK mode ──────────────────────────────────────────

    async def _execute_sdk(self, prompt: str) -> AsyncIterator[dict]:
        """Execute via Claude Agent SDK."""
        try:
            # Try both package names
            try:
                from claude_code_sdk import query as sdk_query
                from claude_code_sdk import ClaudeCodeOptions
                options_cls = ClaudeCodeOptions
            except ImportError:
                from claude_agent_sdk import query as sdk_query
                from claude_agent_sdk import ClaudeAgentOptions
                options_cls = ClaudeAgentOptions

            options = options_cls(
                cwd=self.repo_root,
                allowed_tools=[
                    "Bash", "Read", "Write", "Edit", "Glob", "Grep",
                    "Skill", "Agent", "WebFetch", "WebSearch",
                ],
                permission_mode="acceptEdits",
                max_turns=30,
            )

            yield {"type": "system", "subtype": "start", "data": {"mode": "sdk"}}

            async for message in sdk_query(prompt=prompt, options=options):
                # Normalize SDK message types
                for normalized in self._normalize_sdk_message(message):
                    yield normalized

        except Exception as e:
            yield {"type": "error", "message": f"SDK error: {e}"}

    def _normalize_sdk_message(self, message) -> list[dict]:
        """Convert SDK message to normalized format."""
        results = []
        msg_type = getattr(message, "type", None) or type(message).__name__

        if msg_type == "assistant":
            content = getattr(message, "content", [])
            if isinstance(content, str):
                results.append({"type": "text", "content": content})
            elif isinstance(content, list):
                for block in content:
                    block_type = getattr(block, "type", None)
                    if block_type == "text":
                        results.append({"type": "text", "content": block.text})
                    elif block_type == "tool_use":
                        results.append({
                            "type": "tool_use",
                            "name": block.name,
                            "input": block.input if isinstance(block.input, dict) else str(block.input),
                            "id": getattr(block, "id", ""),
                        })
        elif msg_type == "user":
            content = getattr(message, "content", [])
            if isinstance(content, list):
                for block in content:
                    block_type = getattr(block, "type", None)
                    if block_type == "tool_result":
                        text = getattr(block, "content", "")
                        if isinstance(text, list):
                            text = " ".join(
                                getattr(b, "text", str(b)) for b in text
                            )
                        results.append({
                            "type": "tool_result",
                            "tool_use_id": getattr(block, "tool_use_id", ""),
                            "content": str(text)[:2000],
                            "is_error": getattr(block, "is_error", False),
                        })
        elif msg_type == "result":
            results.append({
                "type": "result",
                "cost_usd": getattr(message, "cost_usd", 0),
                "duration_ms": getattr(message, "duration_ms", 0),
                "session_id": getattr(message, "session_id", ""),
            })

        return results

    # ── Subprocess mode ───────────────────────────────────

    async def _execute_subprocess(self, prompt: str) -> AsyncIterator[dict]:
        """Execute via claude -p subprocess."""
        cmd = [
            "claude", "-p", prompt,
            "--output-format", "stream-json",
            "--verbose",
            "--max-turns", "30",
        ]

        env = os.environ.copy()
        # Prevent nested session error
        env.pop("CLAUDECODE", None)
        env.pop("CLAUDE_CODE_SESSION", None)

        yield {"type": "system", "subtype": "start", "data": {"mode": "subprocess"}}

        try:
            self._process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.repo_root,
                env=env,
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

    async def _read_stream_json(self, stream) -> AsyncIterator[dict]:
        """Parse stream-json (NDJSON) output from claude -p."""
        while True:
            line_bytes = await stream.readline()
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
