# Ghidra Headless Script: extract_string.py
# Extract a full wide string at a given absolute address.
# @category Analysis
# @runtime Jython
#
# Usage:
#   analyzeHeadless ... -process binary.dll -noanalysis \
#     -scriptPath /opt/ghidra-scripts \
#     -postScript extract_string.py /analysis/output/string.txt 0x1801521a0
#
# The address is absolute (virtual address in the loaded binary).
# Output is UTF-8 text of the decoded wide string.

import codecs
import os

SCRIPT_NAME = "extract_string.py"

args = getScriptArgs()
if len(args) < 2:
    print("[ERROR] %s: Usage: extract_string.py <output_path> <address_hex>" % SCRIPT_NAME)
    import sys
    sys.exit(1)

output_path = args[0]
addr_hex = args[1]

program = currentProgram
addr_space = program.getAddressFactory().getDefaultAddressSpace()
addr = addr_space.getAddress(int(addr_hex, 16))

mem = program.getMemory()
chars = []
offset = 0
while True:
    try:
        lo = mem.getByte(addr.add(offset)) & 0xFF
        hi = mem.getByte(addr.add(offset + 1)) & 0xFF
        code_point = lo | (hi << 8)
        if code_point == 0:
            break
        chars.append(chr(code_point))
        offset += 2
    except:
        break

result = ''.join(chars)
print("[INFO] %s: Address: 0x%x" % (SCRIPT_NAME, addr.getOffset()))
print("[INFO] %s: String length: %d chars" % (SCRIPT_NAME, len(result)))
if len(result) > 0:
    print("[INFO] %s: First 100: %s" % (SCRIPT_NAME, result[:100]))

output_dir = os.path.dirname(output_path)
if output_dir and not os.path.exists(output_dir):
    os.makedirs(output_dir)

with codecs.open(output_path, 'w', encoding='utf-8') as f:
    f.write(result)
print("[INFO] %s: Saved to %s" % (SCRIPT_NAME, output_path))
