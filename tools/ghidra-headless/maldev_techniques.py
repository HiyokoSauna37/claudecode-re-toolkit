#!/usr/bin/env python3
"""Malware Development Techniques (MDT) detector — めい用ツール.

f00crew 0x33「Malware Development Essentials for Operators」のテクニックスタックを、
**3 つの実行モード**で検出する:

  1. analyze       既存の Ghidra output を読んで検出（フル analyze-full の後）
  2. scan-binary   生バイナリを直接読んで検出（Ghidra 不要・最速）
  3. list          検出可能な全テクニックのカタログを表示

検出対象:
  • Dynamic API resolution  PEB walking (x86/x64), API hashing (ROR13/FNV-1a/djb2)
  • Process injection       Hollowing, Early Bird APC, NtCreateThreadEx, Reflective, Stomping
  • Kernel-mode             callback abuse, DKOM, token steal, direct syscalls (Hell's Gate)
  • Multi-layer crypto      XOR + CryptoAPI/Bcrypt staging, inline AES
  • IAT hooking             ImportAddressTable 書き換え

出力: <output_dir>/<binary>_maldev.json (severity / confidence / 証拠 / ATT&CK 付き)

使い方の例 (めい向け):

  # 1) 一番速い: バイナリを直接スキャン（Ghidra 不要、5秒以内）
  python tools/ghidra-headless/maldev_techniques.py scan-binary input/sample.exe

  # 2) 既に analyze-full 済み: そのまま検出（より精度高い）
  python tools/ghidra-headless/maldev_techniques.py analyze sample

  # 3) どんなテクニックを検出できるか確認
  python tools/ghidra-headless/maldev_techniques.py list

  # ghidra.sh 経由（短縮）
  bash tools/ghidra-headless/ghidra.sh maldev-detect sample
  bash tools/ghidra-headless/ghidra.sh maldev-detect input/sample.exe   # パスでも OK
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

TOOL_VERSION = "2.0.0"
SCRIPT_DIR = Path(__file__).parent
DEFAULT_OUTPUT_DIR = SCRIPT_DIR / "output"

if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))


# ════════════════════════════════════════════════════════════════════════════
#  ANSI colors (TTY のみ。NO_COLOR / 非TTY では自動無効化)
# ════════════════════════════════════════════════════════════════════════════

def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if not sys.stdout.isatty():
        return False
    return True


_COLOR = _supports_color()


def c(code: str, text: str) -> str:
    if not _COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


def red(s):    return c("31", s)
def green(s):  return c("32", s)
def yellow(s): return c("33", s)
def blue(s):   return c("34", s)
def mag(s):    return c("35", s)
def cyan(s):   return c("36", s)
def bold(s):   return c("1", s)
def dim(s):    return c("2", s)


# ════════════════════════════════════════════════════════════════════════════
#  Technique catalog
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class Technique:
    tid: str
    name: str
    name_ja: str
    attack: str
    severity: str  # low / medium / high / critical
    description: str
    require: list[list[str]] = field(default_factory=list)
    boost: list[str] = field(default_factory=list)
    veto: list[str] = field(default_factory=list)


def _api(*names: str) -> list[str]:
    """API 名のワード境界アンカー regex リストを生成."""
    return [rf"\b{re.escape(n)}\b" for n in names]


CATALOG: list[Technique] = [
    # ── Dynamic API resolution ────────────────────────────────────────────
    Technique(
        tid="MDT-001",
        name="PEB Walking (Dynamic API Resolution)",
        name_ja="PEB ウォーキングによる動的 API 解決",
        attack="T1027.007",
        severity="medium",
        description="PEB.Ldr 経由で kernel32/ntdll を辿り GetProcAddress を回避",
        require=[
            [
                r"__readgsqword\s*\(\s*0x60",
                r"__readfsdword\s*\(\s*0x30",
                r"\bPEB_LDR_DATA\b",
                r"\bInMemoryOrderModuleList\b",
                r"\bInLoadOrderModuleList\b",
                r"fs:\[\s*0x?30",
                r"gs:\[\s*0x?60",
            ],
        ],
        boost=[
            r"\bLDR_DATA_TABLE_ENTRY\b",
            r"\bIMAGE_EXPORT_DIRECTORY\b",
            r"\bAddressOfNames\b",
            r"\bAddressOfNameOrdinals\b",
            r"\bAddressOfFunctions\b",
        ],
    ),
    Technique(
        tid="MDT-002",
        name="API Hashing (ROR13)",
        name_ja="ROR13 API ハッシュ",
        attack="T1027.007",
        severity="high",
        description="Metasploit/Cobalt Strike 系の事前計算 ROR13 ハッシュ",
        require=[
            [
                r"0x?0726774C",   # LoadLibraryA
                r"0x?EC0E4E8E",   # LoadLibraryA (alt)
                r"0x?7C0DFCAA",   # GetProcAddress
                r"0x?91AFCA54",   # VirtualAlloc
                r"0x?73E2D87E",   # ExitProcess
                r"0x?CEF676C9",   # RtlExitUserThread
                r"0x?0E8AFE98",   # WinExec
                r"\brorl?\s*\$?\s*0?x?0?d\b",
                r"_rotr\s*\([^,]+,\s*13\s*\)",
            ],
        ],
        boost=[r"\bROR13\b", r"hash_api", r"api_hash", r"resolve_api"],
    ),
    Technique(
        tid="MDT-003",
        name="API Hashing (FNV-1a / djb2)",
        name_ja="FNV-1a / djb2 API ハッシュ",
        attack="T1027.007",
        severity="medium",
        description="API 名を FNV-1a もしくは djb2 でハッシュ化して保管",
        require=[
            [
                r"0x?01000193",
                r"0x?811C9DC5",
                r"0x?100000001b3",
                r"0xCBF29CE484222325",
                r"0x?00001505",
            ],
        ],
        boost=[r"fnv1a?", r"djb2", r"hash[_-]?djb"],
    ),

    # ── Process injection variants ────────────────────────────────────────
    Technique(
        tid="MDT-010",
        name="Process Hollowing (RunPE)",
        name_ja="プロセスホロウイング (RunPE)",
        attack="T1055.012",
        severity="high",
        description="正規プロセスをアンマップしてペイロードを書き込み再開する古典手法",
        require=[
            _api("NtUnmapViewOfSection", "ZwUnmapViewOfSection"),
            _api("VirtualAllocEx"),
            _api("WriteProcessMemory"),
            _api("SetThreadContext", "NtSetContextThread", "ZwSetContextThread"),
            _api("ResumeThread", "NtResumeThread"),
        ],
        boost=[
            r"CREATE_SUSPENDED",
            _api("GetThreadContext")[0],
        ],
    ),
    Technique(
        tid="MDT-011",
        name="Early Bird APC Injection",
        name_ja="Early Bird APC インジェクション",
        attack="T1055.004",
        severity="high",
        description="サスペンド状態のスレッドに APC を queue してフック前に実行 (APT33)",
        require=[
            _api("CreateProcessA", "CreateProcessW", "CreateProcessAsUserA",
                 "CreateProcessAsUserW", "NtCreateUserProcess"),
            _api("VirtualAllocEx"),
            _api("WriteProcessMemory"),
            _api("QueueUserAPC", "NtQueueApcThread", "NtQueueApcThreadEx"),
            _api("ResumeThread"),
        ],
        boost=[r"CREATE_SUSPENDED", r"\bAPC\b"],
    ),
    Technique(
        tid="MDT-012",
        name="NtCreateThreadEx Remote Injection",
        name_ja="NtCreateThreadEx クロスセッション注入",
        attack="T1055.002",
        severity="medium",
        description="未文書化 NtCreateThreadEx でセッション境界を越えるリモートスレッド",
        require=[
            _api("NtCreateThreadEx", "ZwCreateThreadEx", "RtlCreateUserThread"),
            _api("VirtualAllocEx", "NtAllocateVirtualMemory"),
            _api("WriteProcessMemory", "NtWriteVirtualMemory"),
        ],
    ),
    Technique(
        tid="MDT-013",
        name="Reflective DLL Injection",
        name_ja="Reflective DLL Injection",
        attack="T1620",
        severity="high",
        description="Stephen Fewer 系セルフマッピング DLL ローダ (Cobalt Strike 系)",
        require=[
            [r"\bReflectiveLoader\b", r"_ReflectiveLoader@4"],
        ],
        boost=[
            _api("FlushInstructionCache")[0],
            r"\bIMAGE_NT_HEADERS\b",
            r"\bDllMain\b",
        ],
    ),
    Technique(
        tid="MDT-014",
        name="Module Stomping / DLL Hollowing",
        name_ja="モジュールスタンピング / DLL ホロウイング",
        attack="T1055.013",
        severity="high",
        description="正規ロード済み DLL の .text セクションを上書きしてペイロード化",
        require=[
            _api("LoadLibraryExA", "LoadLibraryExW", "LoadLibraryA", "LoadLibraryW"),
            _api("VirtualProtect", "VirtualProtectEx", "NtProtectVirtualMemory"),
            _api("WriteProcessMemory", "memcpy", "RtlCopyMemory"),
        ],
        boost=[
            r"DONT_RESOLVE_DLL_REFERENCES",
            r"\.text\b",
            r"PAGE_EXECUTE_READWRITE",
        ],
    ),

    # ── Kernel-mode techniques ────────────────────────────────────────────
    Technique(
        tid="MDT-020",
        name="Kernel Callback Registration (defense evasion)",
        name_ja="カーネルコールバック登録による防御回避",
        attack="T1547.006",
        severity="critical",
        description="ドライバが AV/EDR の動作監視・遮断のためコールバック登録",
        require=[
            [
                r"\bPsSetCreateProcessNotifyRoutineEx\b",
                r"\bPsSetCreateProcessNotifyRoutine\b",
                r"\bPsSetLoadImageNotifyRoutine\b",
                r"\bPsSetCreateThreadNotifyRoutine\b",
                r"\bObRegisterCallbacks\b",
                r"\bCmRegisterCallbackEx\b",
                r"\bCmRegisterCallback\b",
            ],
        ],
    ),
    Technique(
        tid="MDT-021",
        name="DKOM — PsInitialSystemProcess token steal",
        name_ja="DKOM トークン奪取 (SYSTEM 権限昇格)",
        attack="T1014",
        severity="critical",
        description="EPROCESS リストを辿って SYSTEM プロセスのトークンを盗用",
        require=[
            [r"\bPsInitialSystemProcess\b"],
            [
                r"0x?4B8\b", r"0x?448\b", r"0x?2F0\b", r"0x?440\b",
                r"\bActiveProcessLinks\b", r"\bUniqueProcessId\b",
            ],
        ],
    ),
    Technique(
        tid="MDT-022",
        name="Driver Self-Hide (DKOM unlink)",
        name_ja="ドライバ自己隠蔽 (DKOM unlink)",
        attack="T1014",
        severity="critical",
        description="PsLoadedModuleList から自身の DRIVER_OBJECT をアンリンク",
        require=[
            [r"\bDriverSection\b", r"\bPsLoadedModuleList\b"],
        ],
        boost=[
            r"\bDriverEntry\b",
            r"\bMmGetSystemRoutineAddress\b",
            r"\bInLoadOrderLinks\b",
        ],
    ),
    Technique(
        tid="MDT-023",
        name="Direct Syscalls (Hell's/Halo's/Tartarus Gate)",
        name_ja="Direct Syscalls (Hell's Gate 系)",
        attack="T1106",
        severity="high",
        description="ユーザーモードフックを回避するインライン syscall スタブ",
        require=[
            [
                r"\bsyscall\b\s*$",
                r"\bsysenter\b",
                r"\bHellsGate\b",
                r"\bHalosGate\b",
                r"\bTartarusGate\b",
                r"\bSW2_GetSyscallNumber\b",
                r"\bSW3_GetSyscallNumber\b",
                r"\bSyscallTable\b",
            ],
        ],
        boost=[
            r"\bGetSSN\b",
        ],
    ),

    # ── Multi-layer encryption ────────────────────────────────────────────
    Technique(
        tid="MDT-030",
        name="Multi-layer Crypto (XOR + CryptoAPI/Bcrypt)",
        name_ja="多層暗号化 (XOR + CryptoAPI/Bcrypt)",
        attack="T1027",
        severity="medium",
        description="XOR 前段で AES の API シグネチャを隠す 2 段階復号",
        require=[
            [
                r"\bCryptDecrypt\b",
                r"\bBCryptDecrypt\b",
                r"\bBCryptOpenAlgorithmProvider\b",
                r"\bBCryptGenerateSymmetricKey\b",
            ],
            [
                r"\^=\s*[A-Za-z_][A-Za-z0-9_]*\s*\[",
                r"xor\s+(byte|word|dword)\s+ptr",
                r"\bxor\s+[er]?[abcd][lhx]\b",
            ],
        ],
        boost=[
            r"BCRYPT_AES_ALGORITHM",
            r"\bAES-?256\b",
            r"BCRYPT_CHAINING_MODE",
        ],
    ),
    Technique(
        tid="MDT-031",
        name="Inline AES (no CryptoAPI)",
        name_ja="インライン AES (CryptoAPI 不使用)",
        attack="T1027",
        severity="low",
        description="AES S-box / RCON テーブル埋め込み — API 使わずにインライン暗号化",
        require=[
            [
                r"63[\s,]*7c[\s,]*77[\s,]*7b[\s,]*f2[\s,]*6b[\s,]*6f[\s,]*c5",
                r"\b0x63\b\s*,\s*\b0x7c\b\s*,\s*\b0x77\b",
                r"0x?8d[\s,]+0x?01[\s,]+0x?02[\s,]+0x?04",
            ],
        ],
    ),

    # ── IAT hooking ───────────────────────────────────────────────────────
    Technique(
        tid="MDT-040",
        name="IAT Hooking",
        name_ja="IAT 書き換えフック",
        attack="T1574.013",
        severity="medium",
        description="ImportAddressTable のエントリを書き換えて関数呼び出しを横取り",
        require=[
            [
                r"\bIMAGE_IMPORT_DESCRIPTOR\b",
                r"\bFirstThunk\b",
                r"\bOriginalFirstThunk\b",
            ],
            _api("VirtualProtect", "VirtualProtectEx", "NtProtectVirtualMemory"),
        ],
        boost=[r"\bGetModuleHandle[AW]?\b", r"PAGE_READWRITE"],
    ),

    # ── Anti-VM / Anti-Sandbox ───────────────────────────────────────────
    Technique(
        tid="MDT-016",
        name="VM Detection (Hardware Fingerprint)",
        name_ja="VM 検出 (ハードウェアフィンガープリント)",
        attack="T1497.001",
        severity="high",
        description="仮想化ドライバや MAC アドレス OUI でVM環境を検知し実行回避",
        require=[
            [
                r"\bvmhgfs\.sys\b",
                r"\bvmmouse\.sys\b",
                r"\bprl_tg\.sys\b",
                r"\bvmci\.sys\b",
                r"\bvboxguest\.sys\b",
                r"00:0C:29|00-0C-29",
                r"00:50:56|00-50-56",
                r"08:00:27|08-00-27",
                r"\bGetSystemFirmwareTable\b",
            ],
        ],
    ),
    Technique(
        tid="MDT-017",
        name="VM Detection (Software Fingerprint)",
        name_ja="VM 検出 (ソフトウェアフィンガープリント)",
        attack="T1497.001",
        severity="high",
        description="BIOS 文字列・CPUID・プロセス名・レジストリで仮想環境を検知",
        require=[
            [
                r"\bVMware, Inc\b",
                r"\bVMWARE\b",
                r"\bVBOX\b",
                r"\bQEMU\b",
                r"\bvmtoolsd\b",
                r"\bvm3dservice\b",
                r"\bVBoxService\b",
                r"SOFTWARE\\\\VMware,\s*Inc\.\\\\VMware\s*Tools",
                r"\bIsDebuggerPresent\b",
            ],
        ],
    ),
    Technique(
        tid="MDT-018",
        name="Time-Based Evasion",
        name_ja="時間ベースの回避 (サンドボックス検知)",
        attack="T1497.003",
        severity="medium",
        description="CPU タイムスタンプやタイマー API でサンドボックス短時間実行を検知",
        require=[
            [
                r"\brdtsc\b",
                r"\bGetTickCount\b",
                r"\bQueryPerformanceCounter\b",
                r"\bNtDelayExecution\b",
            ],
        ],
    ),
]


# ════════════════════════════════════════════════════════════════════════════
#  Detection engine
# ════════════════════════════════════════════════════════════════════════════

def _scan(text: str, patterns: list[str]) -> list[str]:
    hits: list[str] = []
    for pat in patterns:
        try:
            if re.search(pat, text, re.IGNORECASE | re.MULTILINE):
                hits.append(pat)
        except re.error:
            continue
    return hits


def evaluate(tech: Technique, corpus: str) -> Optional[dict]:
    group_hits: list[list[str]] = []
    for group in tech.require:
        hits = _scan(corpus, group)
        if not hits:
            return None
        group_hits.append(hits)

    if tech.veto and _scan(corpus, tech.veto):
        return None

    boost_hits = _scan(corpus, tech.boost) if tech.boost else []

    base = 0.5 + 0.1 * (len(group_hits) - 1)
    confidence = min(1.0, base + 0.05 * len(boost_hits))

    evidence = []
    for group, hits in zip(tech.require, group_hits):
        evidence.append({
            "required_group_size": len(group),
            "matched": hits[:5],
        })
    return {
        "id":          tech.tid,
        "name":        tech.name,
        "name_ja":     tech.name_ja,
        "attack":      tech.attack,
        "severity":    tech.severity,
        "description": tech.description,
        "confidence":  round(confidence, 2),
        "evidence":    evidence,
        "boost_hits":  boost_hits[:5],
    }


# ════════════════════════════════════════════════════════════════════════════
#  Corpus loaders
# ════════════════════════════════════════════════════════════════════════════

def load_corpus_from_ghidra(binary_name: str, output_dir: Path) -> tuple[str, list[str]]:
    """Ghidra の output ディレクトリから analyze 結果を読み出す."""
    from ghidra_output_utils import find_ghidra_outputs
    files = find_ghidra_outputs(binary_name, output_dir)
    parts: list[str] = []
    sources: list[str] = []
    for key, path in files.items():
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        parts.append(f"\n\n# --- {key} ({path.name}) ---\n{content}")
        sources.append(path.name)
    return "\n".join(parts), sources


# Strings extraction (printable ASCII + UTF-16LE) — 最小実装、依存なし
_PRINTABLE = set(range(0x20, 0x7F))


def _extract_strings(data: bytes, min_len: int = 6) -> list[str]:
    out: list[str] = []
    # ASCII
    cur = bytearray()
    for b in data:
        if b in _PRINTABLE:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii", errors="ignore"))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append(cur.decode("ascii", errors="ignore"))
    # UTF-16LE: scan even offsets
    for off in (0, 1):
        cur = bytearray()
        for i in range(off, len(data) - 1, 2):
            lo, hi = data[i], data[i + 1]
            if hi == 0 and lo in _PRINTABLE:
                cur.append(lo)
            else:
                if len(cur) >= min_len:
                    out.append(cur.decode("ascii", errors="ignore"))
                cur = bytearray()
        if len(cur) >= min_len:
            out.append(cur.decode("ascii", errors="ignore"))
    return out


def load_corpus_from_binary(path: Path) -> tuple[str, list[str]]:
    """生バイナリから直接 corpus を構築 (Ghidra なし)."""
    if not path.is_file():
        raise FileNotFoundError(f"binary not found: {path}")
    data = path.read_bytes()
    if len(data) > 200 * 1024 * 1024:
        # 200MB cap
        data = data[: 200 * 1024 * 1024]
    strings = _extract_strings(data, min_len=6)
    # Hex dump of small files / small windows for hash constants
    # (full hex dump is too big — instead we emit hex of the whole file as one string
    #  joined with spaces so byte-pattern regex can match.)
    hex_dump = data.hex()
    corpus = (
        f"# --- binary: {path.name} ({len(data)} bytes) ---\n"
        + "\n".join(strings)
        + "\n\n# --- hex ---\n"
        + " ".join(hex_dump[i : i + 80] for i in range(0, len(hex_dump), 80))
    )
    return corpus, [f"{path.name} (raw bytes + extracted strings)"]


# ════════════════════════════════════════════════════════════════════════════
#  Result formatting
# ════════════════════════════════════════════════════════════════════════════

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_COLOR = {
    "critical": red,
    "high":     mag,
    "medium":   yellow,
    "low":      cyan,
}


def build_result(binary_name: str, corpus: str, sources: list[str],
                 min_severity: str) -> dict:
    min_rank = SEVERITY_RANK[min_severity]
    findings: list[dict] = []
    for tech in CATALOG:
        f = evaluate(tech, corpus)
        if f and SEVERITY_RANK[f["severity"]] >= min_rank:
            findings.append(f)
    findings.sort(key=lambda x: (-SEVERITY_RANK[x["severity"]], -x["confidence"]))

    by_severity: dict[str, int] = {}
    for f in findings:
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1

    attack_ids = sorted({a.strip() for f in findings for a in f["attack"].split(",")})

    return {
        "tool":     "maldev_techniques",
        "version":  TOOL_VERSION,
        "binary":   binary_name,
        "sources":  sources,
        "summary": {
            "total_findings": len(findings),
            "by_severity":    by_severity,
            "attack_ids":     attack_ids,
            "operator_tier":  any(
                f["severity"] in ("high", "critical") for f in findings
            ),
        },
        "findings": findings,
    }


def print_summary(result: dict) -> None:
    name = result["binary"]
    findings = result["findings"]
    summary = result["summary"]

    print()
    print(bold(f"=== Malware Development Techniques: {name} ==="))
    print(f"  Sources    : {', '.join(result['sources']) or dim('(none)')}")
    print(f"  Findings   : {bold(str(len(findings)))}")

    if summary["by_severity"]:
        parts = []
        for sev in ("critical", "high", "medium", "low"):
            n = summary["by_severity"].get(sev)
            if n:
                parts.append(SEVERITY_COLOR[sev](f"{sev}={n}"))
        print(f"  Severity   : {', '.join(parts)}")
    if summary["attack_ids"]:
        print(f"  ATT&CK     : {', '.join(summary['attack_ids'])}")
    if summary["operator_tier"]:
        print(f"  {bold(red('>>> Operator-tier implant indicators present <<<'))}")

    if findings:
        print()
        for f in findings:
            sev = f["severity"]
            color = SEVERITY_COLOR[sev]
            tag = color(f"[{sev.upper():<8}]")
            print(f"  {tag} {bold(f['id'])}  {f['name_ja']}")
            print(
                f"            {dim('attack=' + f['attack'])}  "
                f"{dim('confidence=' + str(f['confidence']))}"
            )
            for ev in f["evidence"][:2]:
                ev_text = ", ".join(ev["matched"][:3])
                print(f"            {dim('evidence:')} {ev_text}")
    else:
        print(f"  {green('No operator-tier techniques detected.')}")


def print_catalog() -> None:
    print(bold("=== MDT Detection Catalog ==="))
    print()
    by_sev: dict[str, list[Technique]] = {}
    for t in CATALOG:
        by_sev.setdefault(t.severity, []).append(t)

    for sev in ("critical", "high", "medium", "low"):
        techs = by_sev.get(sev, [])
        if not techs:
            continue
        color = SEVERITY_COLOR[sev]
        print(color(bold(f"  [{sev.upper()}]")))
        for t in techs:
            print(f"    {bold(t.tid)}  {t.name_ja}")
            print(f"              {dim(t.name)}")
            print(f"              {dim('ATT&CK: ' + t.attack)}  {dim(t.description)}")
        print()
    print(dim(f"  Total: {len(CATALOG)} techniques"))


# ════════════════════════════════════════════════════════════════════════════
#  Binary-name resolution helpers
# ════════════════════════════════════════════════════════════════════════════

def resolve_binary_stem(name_or_path: str, output_dir: Path) -> str:
    """ユーザー指定が path / file / stem のいずれでも、ステム名に正規化."""
    p = Path(name_or_path)
    # 1) ホストパスとして存在する場合 → ステムを抽出（.enc.gz を考慮）
    if p.is_file():
        stem = p.name
        for suf in (".enc.gz", ".exe", ".dll", ".bin", ".sys"):
            if stem.lower().endswith(suf):
                stem = stem[: -len(suf)]
                break
        return stem
    # 2) <output_dir>/<name>_*.txt が見つかれば、それがステム
    candidates = list(output_dir.glob(f"{p.name}_*.txt")) + \
                 list(output_dir.glob(f"{p.name}_*.json"))
    if candidates:
        return p.name
    # 3) フォールバック: ユーザー入力をそのまま使う（後段でエラーになる）
    return p.name


def find_binary_path(name_or_path: str) -> Optional[Path]:
    """scan-binary 用: 生ファイルの絶対パスを解決."""
    p = Path(name_or_path)
    if p.is_file():
        return p
    # よくある場所を順に探す
    candidates = [
        SCRIPT_DIR / "input" / name_or_path,
        SCRIPT_DIR.parent / "malware-sandbox" / "input" / name_or_path,
        SCRIPT_DIR.parent.parent / "input" / name_or_path,
    ]
    for c in candidates:
        if c.is_file():
            return c
    return None


# ════════════════════════════════════════════════════════════════════════════
#  Main entry
# ════════════════════════════════════════════════════════════════════════════

EPILOG = """\
モード解説:
  analyze       Ghidra analyze-full の output を読んで検出する精密モード
                imports/strings/decompiled C を全部使うので一番精度が高い
                先に `bash tools/ghidra-headless/ghidra.sh analyze <bin>` が必要

  scan-binary   生バイナリを直接スキャンする高速モード（Ghidra 不要）
                strings 抽出 + hex dump で検出する
                analyze の前段、サンプル受領直後の即時トリアージに最適

  list          検出可能テクニック一覧を表示

例:
  # ステム名で指定（output/<stem>_imports.txt が必要）
  python maldev_techniques.py analyze stealc

  # 生バイナリパスで指定（Ghidra 不要、5秒以内）
  python maldev_techniques.py scan-binary input/sample.exe

  # JSON だけ欲しい場合
  python maldev_techniques.py scan-binary sample.exe --json-only

  # critical / high のみ表示
  python maldev_techniques.py analyze stealc --min-severity high

  # カタログ確認
  python maldev_techniques.py list

出力:
  <output-dir>/<binary>_maldev.json  構造化結果 (severity, confidence, ATT&CK, 証拠)
"""


def cmd_analyze(args) -> int:
    output_dir = Path(args.output_dir)
    if not output_dir.is_dir():
        print(red(f"Error: output dir が見つからない: {output_dir}"), file=sys.stderr)
        print(dim(f"  ヒント: --output-dir で指定するか、先に analyze-full を実行"),
              file=sys.stderr)
        return 1

    stem = resolve_binary_stem(args.binary, output_dir)
    corpus, sources = load_corpus_from_ghidra(stem, output_dir)
    if not corpus:
        print(red(f"Error: '{stem}' の Ghidra output が無い ({output_dir})"),
              file=sys.stderr)
        print(dim(f"  実行例: bash tools/ghidra-headless/ghidra.sh analyze <binary>"),
              file=sys.stderr)
        print(dim(f"  もしくは scan-binary モード:"), file=sys.stderr)
        print(dim(f"    python maldev_techniques.py scan-binary <path>"), file=sys.stderr)
        return 1

    return _emit_result(stem, corpus, sources, output_dir, args)


def cmd_scan_binary(args) -> int:
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    bin_path = find_binary_path(args.binary)
    if not bin_path:
        print(red(f"Error: バイナリが見つからない: {args.binary}"), file=sys.stderr)
        print(dim("  探した場所: 指定パス / tools/*/input/"), file=sys.stderr)
        return 1

    stem = resolve_binary_stem(str(bin_path), output_dir)
    try:
        corpus, sources = load_corpus_from_binary(bin_path)
    except OSError as e:
        print(red(f"Error: バイナリ読み込み失敗: {e}"), file=sys.stderr)
        return 1

    return _emit_result(stem, corpus, sources, output_dir, args)


def cmd_list(_args) -> int:
    print_catalog()
    return 0


def _emit_result(stem: str, corpus: str, sources: list[str],
                 output_dir: Path, args) -> int:
    result = build_result(stem, corpus, sources, args.min_severity)

    out_path = output_dir / f"{stem}_maldev.json"
    try:
        out_path.write_text(
            json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8"
        )
    except OSError as e:
        print(red(f"Error: 結果を書き込めない {out_path}: {e}"), file=sys.stderr)
        return 1

    if args.json_only:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0

    print_summary(result)
    print()
    print(f"  {dim('Saved:')} {out_path}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="maldev_techniques",
        description=(
            "Malware Development Techniques 検出器 — "
            "f00crew 0x33 系のオペレータ技術スタックを検出してATT&CKにマップ"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EPILOG,
    )
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {TOOL_VERSION}")

    subs = parser.add_subparsers(dest="mode", metavar="MODE")

    # analyze
    p_an = subs.add_parser(
        "analyze",
        help="Ghidra analyze-full の output から検出（精密）",
        description="Ghidra output (imports/strings/decompiled) を読んで検出",
    )
    p_an.add_argument("binary",
                      help="バイナリのステム名 or パス (例: stealc, input/stealc.exe)")
    p_an.add_argument("-o", "--output-dir", default=str(DEFAULT_OUTPUT_DIR),
                      help=f"Ghidra output ディレクトリ (default: {DEFAULT_OUTPUT_DIR})")
    p_an.add_argument("--min-severity",
                      choices=("low", "medium", "high", "critical"), default="low",
                      help="このレベル未満を非表示 (default: low)")
    p_an.add_argument("--json-only", action="store_true",
                      help="JSON のみ出力（コンソール要約を抑制）")
    p_an.set_defaults(func=cmd_analyze)

    # scan-binary
    p_sb = subs.add_parser(
        "scan-binary",
        help="生バイナリから直接検出（Ghidra 不要・高速）",
        description="strings + hex dump で生バイナリから直接検出する（5 秒以内）",
    )
    p_sb.add_argument("binary",
                      help="バイナリのパス (例: input/sample.exe)")
    p_sb.add_argument("-o", "--output-dir", default=str(DEFAULT_OUTPUT_DIR),
                      help=f"結果 JSON の保存先 (default: {DEFAULT_OUTPUT_DIR})")
    p_sb.add_argument("--min-severity",
                      choices=("low", "medium", "high", "critical"), default="low",
                      help="このレベル未満を非表示 (default: low)")
    p_sb.add_argument("--json-only", action="store_true",
                      help="JSON のみ出力")
    p_sb.set_defaults(func=cmd_scan_binary)

    # list
    p_li = subs.add_parser(
        "list",
        help="検出可能な全テクニックのカタログを表示",
        description="このツールが検出できる全 MDT テクニックを表示",
    )
    p_li.set_defaults(func=cmd_list)

    # ── Backward compatibility shim ─────────────────────────────────────
    # 旧バージョンは `python maldev_techniques.py <binary>` だった。
    # 第 1 引数がサブコマンド名でない場合は analyze として扱う。
    args_in = sys.argv[1:]
    if args_in and args_in[0] not in {
        "analyze", "scan-binary", "list", "-h", "--help", "--version",
    }:
        args_in = ["analyze"] + args_in

    args = parser.parse_args(args_in)
    if not args.mode:
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
