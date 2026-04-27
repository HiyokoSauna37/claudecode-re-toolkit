# VMProtect解析のフォールバック戦略

3-Level Unpacking / Mergen devirt / Frida DBI の各段階で失敗した場合のエスカレーションパス。

## パッキング層除去の失敗時

| 段階 | 失敗パターン | 対処 |
|---|---|---|
| L1 memdump-racer | ディレイが合わない（POOR判定） | ディレイを50ms刻みで0-1000msにスイープ（デフォルトの5点では不足な場合） |
| L2 TinyTracer | OEP検出失敗（.tagにセクション遷移なし） | Intel PINバージョン（3.31必須）とTinyTracerの互換性を確認 |
| L3 x64dbg手動 | Anti-Debugが強力でブレーク不可 | ScyllaHideプラグインでNtQueryInformationProcess等を偽装 |
| **全Level失敗** | パッキング層が特殊（VMP以外の独自パッカー等） | Frida DBIで VirtualProtect/VirtualAlloc をフックし、RWX→RX遷移時にメモリダンプ（dump_payload.jsが対応済み） |

## コード仮想化層（Mergen）の失敗時

| 失敗パターン | 原因 | 対処 |
|---|---|---|
| devirt失敗（間接ジャンプ3分岐以上） | Mergenの制限 | 対象関数を手動で分割し、個別にdevirt |
| 未対応VMPハンドラ | VMP 3.x新バージョン | Triton（動的シンボリック実行）でPythonスクリプトを手動構築。**未ツール化、手動対応が必要** |
| dump-triageのVMPアドレス検出失敗 | セクション構造が想定外 | Ghidraのセクション解析で手動特定 |

## VM検知によりプロセスが即終了する場合

| 検知レベル | 例 | 対処 | 状態 |
|---|---|---|---|
| ユーザーモードAPI | IsDebuggerPresent, CheckRemoteDebuggerPresent | Frida bypass_vmdetect.js | 対処済み |
| レジストリ/プロセス/ドライバ | VMware Tools, vmci.sys | VMware Tools停止は**禁止**（vmrun通信不可になる）。許容する | 許容 |
| カーネルレベル | CPUID Hypervisor bit, VMware I/Oポート (IN 0x5658) | VMX設定で偽装。`hypervisor.cpuid.v0 = "FALSE"` 等 | **未実装（harden-vmx計画中）** |
| SMBIOS/DMI | BIOS文字列に"VMware" | VMX設定で偽装。`smbios.reflectHost = "TRUE"` 等 | **未実装（harden-vmx計画中）** |

## harden-vmx（計画中）で対処予定のVMX設定項目

```
hypervisor.cpuid.v0 = "FALSE"          # CPUID Hypervisor bitを隠蔽
smbios.reflectHost = "TRUE"            # ホストのSMBIOS情報を反映
board-id.reflectHost = "TRUE"          # ボードIDをホストから反映
ethernet0.address = "XX:XX:XX:XX:XX:XX"  # MACアドレスを非VMwareベンダーに変更
monitor_control.restrict_backdoor = "TRUE"  # VMwareバックドアI/Oポートを制限
```

注意: これらの設定はVMware Toolsの通信にも影響する可能性がある。変更後のvmrun動作検証が必須。

## フォールバック全体フロー

```
unpack auto
  → L1 POOR → L2 POOR → L3 手動失敗
    → Frida DBI (VirtualProtect/VirtualAllocフック) でメモリダンプ
      → 成功 → Ghidra再解析
      → 失敗（VM検知で即終了）
        → harden-vmx でVMX設定変更後に再試行
        → Frida bypass + harden-vmx でもVM検知突破不可
          → ユーザに「この検体はカーネルレベルVM検知が強力で現環境では解析困難」と報告

devirt (Mergen)
  → 成功 → LLVM IR出力 → Ghidra照合
  → 失敗 → 関数分割して個別devirt
    → 失敗 → Triton手動スクリプト（未ツール化）
      → 対応不可 → ユーザに「VMP仮想化層の解析は現ツールでは限界」と報告
```
