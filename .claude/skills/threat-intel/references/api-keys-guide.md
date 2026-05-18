# Threat-Intel API Keys Reference

すべてリポジトリルート `.env` に設定する。`.env.example` 参照。

## 必須 (cc-re-toolkit 既存)

| サービス | 環境変数 | 取得先 | 備考 |
|---|---|---|---|
| VirusTotal | `VIRUSTOTAL_API_KEY` | https://www.virustotal.com/gui/join-us | community 無料 |
| abuse.ch (Bazaar/ThreatFox/URLHaus共通) | `ABUSECH_AUTH_KEY` | https://auth.abuse.ch/ | 無料、2025後半から必須 |

## 追加 (本スキルで使用)

| サービス | 環境変数 | 取得先 | 備考 |
|---|---|---|---|
| AlienVault OTX | `ALIENVAULT_API_KEY` | https://otx.alienvault.com/api | 無料 |
| Hybrid Analysis | `HYBRID_ANALYSIS_API_KEY` | https://www.hybrid-analysis.com/signup | 無料 (Falcon Sandbox) |
| Triage | `TRIAGE_API_KEY` | https://tria.ge/signup | community / paid |
| URLScan.io | `URLSCANIO_API_KEY` | https://urlscan.io/user/signup | 無料 (rate制限あり) |
| Shodan | `SHODAN_API_KEY` | https://account.shodan.io/register | freemium |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | https://www.abuseipdb.com/register | 無料1k/day |
| GreyNoise (community) | `GREYNOISE_API_KEY` | https://viz.greynoise.io/signup | community 無料 |
| IPInfo | `IPINFO_API_KEY` | https://ipinfo.io/ | optional (キーなしでも限定動作) |
| VulnCheck (community) | `VULNCHECK_API_KEY` | https://vulncheck.com/signin | community/free tier |
| NIST NVD | `NIST_API_KEY` | https://nvd.nist.gov/developers/request-an-api-key | optional (rate up) |
| Malshare | `MALSHARE_API_KEY` | https://malshare.com/doc.php | 無料 |
| Malpedia | `MALPEDIA_API_KEY` | DM @malpedia (Twitter) | community vetted |

## キーが取れないサービス

- BGPView: 認証不要 (動作する)
- python-whois: 認証不要 (CLIでwhois実行)
- ipwhois (RDAP): 認証不要

## キー設定例

```bash
# .env
VIRUSTOTAL_API_KEY=xxx
ABUSECH_AUTH_KEY=xxx
ALIENVAULT_API_KEY=xxx
HYBRID_ANALYSIS_API_KEY=xxx
TRIAGE_API_KEY=xxx
URLSCANIO_API_KEY=xxx
SHODAN_API_KEY=xxx
ABUSEIPDB_API_KEY=xxx
GREYNOISE_API_KEY=xxx
IPINFO_API_KEY=
VULNCHECK_API_KEY=xxx
NIST_API_KEY=
MALSHARE_API_KEY=
MALPEDIA_API_KEY=
```

## キーを取れない時の代替

- VTなしで hash → bazaar / urlhaus / OTX
- Shodanなしで IP → AbuseIPDB / GreyNoise / VT
- Triageなしで dynamic → Hybrid Analysis
- Malpediaなしで family → MalwareBazaar の `signature` field

## 注意

- **abuse.ch の3サービス (MalwareBazaar / ThreatFox / URLHaus) は同一 Auth-Key**
- Triage / Hybrid Analysis は提出系操作で **NDA 配慮** — 本ツールは検索のみ実装
- Malpedia は **business email** で申請推奨 (gmail等の個人メールは却下されやすい)
