# install.exeで確認されたVM検知手法

install.exe（VMProtect 3.x）が使用するVM検知手法の完全リスト:

| カテゴリ | 検知手法 | 詳細 |
|----------|---------|------|
| SMBIOS | DMIテーブル読取 | "VMware"文字列をBIOS情報から検出 |
| CPUID | CPUID命令 | Hypervisor bit (ECX bit 31)、VMwareシグネチャ |
| MACアドレス | NICベンダープレフィクス | 00:0C:29, 00:50:56 (VMware OUI) |
| プロセス | プロセス名チェック | vmtoolsd.exe, vmwaretray.exe, vmwareuser.exe |
| レジストリ | サービスキー | HKLM\SYSTEM\...\VMware Tools, VMware Physical Disk Helper |
| ドライバ | カーネルドライバ | vmci.sys, vsock.sys, vmhgfs.sys, vmmouse.sys |
| デバイス | デバイス名 | \\.\VMwareVMDeviceDrv, VMware SVGA 3D |
| ユーザー名 | パターンマッチ | "malware"部分一致で検知の可能性 |
| パス名 | ディレクトリ名 | "analysis"、"sandbox"等のキーワード |
| HW仕様 | ディスクサイズ/RAM | 小さすぎるディスク(<80GB)やRAM(<4GB)でVM判定 |
