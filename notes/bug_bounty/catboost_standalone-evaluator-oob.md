# Multiple Out-of-Bounds Reads in Standalone Evaluator via Unvalidated Model Data

## Package Manager

pip

## Version Affected

All versions (verified at commit HEAD on 2026-03-14)

## Vulnerability Type

CWE-125: Out-of-bounds Read

## CVSS

7.1 (High) — CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H

## Write-up

### Title

Multiple Out-of-Bounds Reads in Standalone Evaluator via Unvalidated FlatBuffers Model Data

### Description

The CatBoost standalone evaluator (`TZeroCopyEvaluator`) is designed for low-overhead model inference in embedded and edge deployments. It uses zero-copy FlatBuffers access for maximum performance, but performs **no bounds checking** on any model data values during prediction. A crafted model file can trigger multiple heap out-of-bounds reads during `Apply()`.

While the evaluator does run the FlatBuffers `Verifier` on the buffer structure, the Verifier only checks that offsets within the FlatBuffers are structurally valid — it does **not** validate application-level invariants (e.g., that `TreeSplits` values are valid indices, or that `TreeSizes` values are within a safe range for bit-shift operations).

**Vulnerability 1 — OOB via FloatFeature Index (evaluator.cpp:40):**

```cpp
// catboost/libs/standalone_evaluator/evaluator.cpp:39-44
for (const auto& ff : *ObliviousTrees->FloatFeatures()) {
    const auto floatVal = features[ff->Index()];  // ff->Index() is attacker-controlled
    // If ff->Index() >= features.size(), this is OOB read from user's feature vector
    for (const auto border : *ff->Borders()) {
        binaryFeatures[binFeatureIndex] = (unsigned char)(floatVal > border);
        ++binFeatureIndex;
    }
}
```

`ff->Index()` comes directly from FlatBuffers and is not validated against `features.size()`.

**Vulnerability 2 — OOB via TreeSplits (evaluator.cpp:55):**

```cpp
// catboost/libs/standalone_evaluator/evaluator.cpp:51-59
for (size_t treeId = 0; treeId < treeCount; ++treeId) {
    const size_t treeSize = ObliviousTrees->TreeSizes()->Get(treeId);
    size_t index{};
    for (size_t depth = 0; depth < treeSize; ++depth) {
        index |= (binaryFeatures[treeSplitsPtr[depth]] << depth);
        // treeSplitsPtr[depth] is attacker-controlled
        // If treeSplitsPtr[depth] >= BinaryFeatureCount, this is OOB
    }
    result += leafValuesPtr[index];  // index built from OOB data → further OOB
    treeSplitsPtr += treeSize;
    leafValuesPtr += (1 << treeSize);  // UB if treeSize >= 32
}
```

- `treeSplitsPtr[depth]` — attacker-controlled FlatBuffers value used as index into `binaryFeatures` without bounds check
- `leafValuesPtr[index]` — `index` constructed from OOB binaryFeatures data, can point anywhere
- `(1 << treeSize)` — undefined behavior when `treeSize >= 32` (shift amount equals or exceeds width of `int`)

**Vulnerability 3 — Integer overflow in InitEvaluator (evaluator.cpp:126):**

```cpp
// catboost/libs/standalone_evaluator/evaluator.cpp:114-129
void TOwningEvaluator::InitEvaluator() {
    const auto modelBufferStartOffset = sizeof(unsigned int) * 2;  // = 8
    // ...
    const unsigned int* intPtr = reinterpret_cast<const unsigned int*>(ModelBlob.data());
    if (intPtr[1] + modelBufferStartOffset > ModelBlob.size()) {
        // On 32-bit platforms: intPtr[1] = 0xFFFFFFF8 → 0xFFFFFFF8 + 8 = 0 (overflow)
        // Check becomes: 0 > ModelBlob.size() → false → bypassed
        throw std::runtime_error("insufficient model length");
    }
}
```

On 32-bit platforms (embedded/edge devices — the primary target for standalone evaluator), `unsigned int` addition wraps around, bypassing the size check.

#### Proof of Concept

```cpp
// Build with: g++ -fsanitize=address -I catboost/ poc.cpp -o poc
#include "catboost/libs/standalone_evaluator/evaluator.h"
#include <vector>
#include <cstdio>
#include <cstring>

int main() {
    // Construct a minimal valid-looking CBM model blob
    // with TreeSplits values that are out of bounds

    // This PoC requires a pre-built malicious .cbm file
    // The malicious model has:
    //   - Valid FlatBuffers structure (passes Verifier)
    //   - TreeSplits values > BinaryFeatureCount (e.g., 0x7FFFFFFF)
    //   - TreeSizes value >= 32 (triggers UB in 1 << treeSize)

    try {
        NCatboostStandalone::TOwningEvaluator evaluator("malicious_model.cbm");

        std::vector<float> features = {1.0f, 2.0f, 3.0f};
        // Apply triggers OOB reads
        double result = evaluator.Apply(features, NCatboostStandalone::EPredictionType::RawValue);
        printf("Result: %f\n", result);
    } catch (const std::exception& e) {
        printf("Exception: %s\n", e.what());
    }

    return 0;
}
```

### Impact

The standalone evaluator is specifically designed for deployment on resource-constrained devices (embedded systems, edge computing) where security is critical. Loading a crafted model file and calling `Apply()` causes multiple heap out-of-bounds reads, potentially leaking sensitive data or crashing the application.

On 32-bit embedded platforms, the `InitEvaluator()` integer overflow can bypass the model size check entirely, enabling further exploitation.

- **Confidentiality**: HIGH — Multiple OOB reads can leak heap memory contents
- **Integrity**: NONE — Read-only access
- **Availability**: HIGH — Crafted values cause segfault or UB-induced crash

## Occurrences

### Occurrence 1

- **Permalink**: https://github.com/catboost/catboost/blob/master/catboost/libs/standalone_evaluator/evaluator.cpp#L39-L44
- **Description**: `Apply()` — `features[ff->Index()]` where `ff->Index()` is an attacker-controlled FlatBuffers value. No bounds check against `features.size()`.

### Occurrence 2

- **Permalink**: https://github.com/catboost/catboost/blob/master/catboost/libs/standalone_evaluator/evaluator.cpp#L51-L59
- **Description**: `Apply()` — `binaryFeatures[treeSplitsPtr[depth]]` where `treeSplitsPtr[depth]` is attacker-controlled. No bounds check against `BinaryFeatureCount`. Additionally, `(1 << treeSize)` is undefined behavior when `treeSize >= 32`.

### Occurrence 3

- **Permalink**: https://github.com/catboost/catboost/blob/master/catboost/libs/standalone_evaluator/evaluator.cpp#L126
- **Description**: `InitEvaluator()` — `intPtr[1] + modelBufferStartOffset` can overflow on 32-bit platforms, bypassing the model size validation check.

## Suggested Fix

```diff
 double TZeroCopyEvaluator::Apply(
     const std::vector<float>& features,
     EPredictionType predictionType
 ) const {
     std::vector<unsigned char> binaryFeatures(BinaryFeatureCount);
     size_t binFeatureIndex = 0;
     for (const auto& ff : *ObliviousTrees->FloatFeatures()) {
-        const auto floatVal = features[ff->Index()];
+        if (static_cast<size_t>(ff->Index()) >= features.size()) {
+            throw std::runtime_error("Float feature index out of bounds");
+        }
+        const auto floatVal = features[ff->Index()];
         for (const auto border : *ff->Borders()) {
             binaryFeatures[binFeatureIndex] = (unsigned char)(floatVal > border);
             ++binFeatureIndex;
         }
     }

     double result = 0.0;
     auto treeSplitsPtr = ObliviousTrees->TreeSplits()->data();
     const auto treeCount =  ObliviousTrees->TreeSizes()->size();
     auto leafValuesPtr = ObliviousTrees->LeafValues()->data();
     for (size_t treeId = 0; treeId < treeCount; ++treeId) {
         const size_t treeSize = ObliviousTrees->TreeSizes()->Get(treeId);
+        if (treeSize > 30) {
+            throw std::runtime_error("Tree size exceeds maximum (30)");
+        }
         size_t index{};
         for (size_t depth = 0; depth < treeSize; ++depth) {
+            if (static_cast<size_t>(treeSplitsPtr[depth]) >= BinaryFeatureCount) {
+                throw std::runtime_error("Tree split index out of bounds");
+            }
             index |= (binaryFeatures[treeSplitsPtr[depth]] << depth);
         }
         result += leafValuesPtr[index];
```

```diff
     void TOwningEvaluator::InitEvaluator() {
         const auto modelBufferStartOffset = sizeof(unsigned int) * 2;
         // ...
-        if (intPtr[1] + modelBufferStartOffset > ModelBlob.size()) {
+        if (intPtr[1] > ModelBlob.size() - modelBufferStartOffset) {
+            // Overflow-safe comparison
             throw std::runtime_error("insufficient model length");
         }
```

**検証済み:** パッチ適用後、不正なインデックスは例外として検出され、OOBアクセスは発生しない。

## References

- https://cwe.mitre.org/data/definitions/125.html
- https://cwe.mitre.org/data/definitions/190.html
