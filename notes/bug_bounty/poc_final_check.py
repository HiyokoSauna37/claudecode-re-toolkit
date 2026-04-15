import struct, tempfile, os, json, subprocess, sys
import numpy as np
sys.stdout.reconfigure(line_buffering=True)

from catboost import CatBoostClassifier

np.random.seed(42)
X = np.random.rand(200, 4)
y = np.random.randint(0, 2, 200)
model = CatBoostClassifier(iterations=10, depth=4, verbose=0, random_seed=42)
model.fit(X, y)

json_path = tempfile.mktemp(suffix='.json')
model.save_model(json_path, format='json')
with open(json_path) as f:
    mj = json.load(f)
expected_splits = [s['split_index'] for tree in mj['oblivious_trees'] for s in tree['splits']]
os.unlink(json_path)

valid_path = tempfile.mktemp(suffix='.cbm')
model.save_model(valid_path)
with open(valid_path, 'rb') as f:
    data = bytearray(f.read())

size_marker = struct.unpack('<I', data[4:8])[0]
core_size = size_marker if size_marker != 0xFFFFFFFF else struct.unpack('<Q', data[8:16])[0]
fb_start = 8 if size_marker != 0xFFFFFFFF else 16
fb_data = data[fb_start:fb_start + core_size]

vec_len = len(expected_splits)
ts_offset = None
for offset in range(0, len(fb_data) - (vec_len+1)*4, 4):
    if struct.unpack('<I', fb_data[offset:offset+4])[0] != vec_len:
        continue
    if all(struct.unpack('<i', fb_data[offset+4+i*4:offset+8+i*4])[0] == expected_splits[i] for i in range(5)):
        ts_offset = offset
        break

assert ts_offset is not None

# Create crash model
corrupted = bytearray(data)
struct.pack_into('<i', corrupted, fb_start + ts_offset + 4, 0x7FFFFFFF)
crash_path = tempfile.mktemp(suffix='.cbm')
with open(crash_path, 'wb') as f:
    f.write(corrupted)

# Write a separate loader script
loader_script = tempfile.mktemp(suffix='.py')
with open(loader_script, 'w') as f:
    f.write(f'''
import catboost
m = catboost.CatBoostClassifier()
m.load_model("{crash_path}")
print("LOADED OK")
''')

print("Running crash test in subprocess...", flush=True)
ret = subprocess.run(
    [sys.executable, loader_script],
    capture_output=True, timeout=15, text=True
)
print(f"Return code: {ret.returncode}", flush=True)
print(f"Stdout: {ret.stdout.strip()}", flush=True)
print(f"Stderr (last 300 chars): {ret.stderr.strip()[-300:]}", flush=True)

os.unlink(crash_path)
os.unlink(valid_path)
os.unlink(loader_script)
