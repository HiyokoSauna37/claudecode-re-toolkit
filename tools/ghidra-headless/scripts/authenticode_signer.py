#!/usr/bin/env python3
"""Extract Authenticode signer info from a PE without external tools.

Reads IMAGE_DIRECTORY_ENTRY_SECURITY, pulls the PKCS#7 blob, and prints
human-readable X.509 fields (CN/O/OU + timestamp authority) by scanning
printable strings in the DER. Intended to run inside the analysis container
against an already-decrypted PE — no host decryption.
"""
import sys
import re

try:
    import pefile
except ImportError:
    print("pefile not available")
    sys.exit(1)


def main(path):
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
    )
    sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
    ]
    if sec.VirtualAddress == 0 or sec.Size == 0:
        print("SIGNED: NO (no certificate table / Authenticode signature)")
        return

    print("SIGNED: YES (certificate table present)")
    print("Cert table offset: 0x%x  size: %d bytes" % (sec.VirtualAddress, sec.Size))

    with open(path, "rb") as f:
        f.seek(sec.VirtualAddress)
        blob = f.read(sec.Size)

    # WIN_CERTIFICATE header: dwLength(4) wRevision(2) wCertType(2) then bCertificate (PKCS#7 DER)
    der = blob[8:] if len(blob) > 8 else blob

    # Extract ASN.1 PrintableString / UTF8String / IA5String values (tags 0x13, 0x0c, 0x16)
    found = []
    i = 0
    n = len(der)
    while i < n - 2:
        tag = der[i]
        if tag in (0x13, 0x0C, 0x16):
            ln = der[i + 1]
            if ln < 0x80 and 1 <= ln <= 128 and i + 2 + ln <= n:
                s = der[i + 2:i + 2 + ln]
                try:
                    txt = s.decode("utf-8")
                    if txt.isprintable() and len(txt.strip()) >= 2:
                        found.append(txt)
                    i += 2 + ln
                    continue
                except UnicodeDecodeError:
                    pass
        i += 1

    # Dedup preserving order
    seen = set()
    ordered = []
    for x in found:
        if x not in seen:
            seen.add(x)
            ordered.append(x)

    print("\n--- ASN.1 string fields in PKCS#7 (signer/issuer/OIDs) ---")
    for x in ordered:
        print("  " + x)

    # Also surface any obvious org/timestamp hints
    print("\n--- Notable (org / CA / timestamp) ---")
    kw = re.compile(r"(CN=|O=|Co\.|Ltd|Inc|Technolog|Security|Trust|Sign|Cert|Time[sS]tamp|DigiCert|GlobalSign|Sectigo|Symantec|VeriSign|WoSign|安恒|中粮|COFCO|DBAPP|Hangzhou|Beijing|Shanghai)", re.I)
    for x in ordered:
        if kw.search(x):
            print("  * " + x)


if __name__ == "__main__":
    main(sys.argv[1])
