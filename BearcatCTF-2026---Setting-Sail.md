---
title: "BearcatCTF 2026 - Setting Sail"
description: "A collection of write-ups for the BearcatCTF 2026 'Setting Sail' event, covering forensics, reverse engineering, cryptography, and miscellaneous challenges."
slug: "bearcatctf-2026-setting-sail-writeup"
pubDate: 2026-02-23
tags: ["writeup", "ctf", "forensics", "reverse engineering", "crypto", "pwn"]
authors: ["zuy"]
draft: false
---

## Write-up: Unknown Transmission

**Category:** Forensics  
**Author:** Jacob

---

### Challenge Overview
The challenge provides a single WAV audio file named `mysterious-audio.wav` and asks us to decode an unknown transmission. This setup points towards an audio forensics task involving signal decoding rather than simple metadata extraction.

### Evidence Collected
- **File Format:** Valid RIFF/WAV (PCM), Mono, 16-bit, at a 44.1 kHz sampling rate.
- **Duration:** Approximately 37.7 seconds.
- **Initial Triage:** No flag was found in the file's metadata or by running `strings`. The audio content itself sounds like structured, non-human noise.

### Analysis Path
1.  The audio was visualized as a spectrogram to inspect its structure over time.
2.  The spectrogram revealed a periodic and structured pattern of tones, confirming it was not human speech but a form of data transmission.
3.  The timing and synchronization of the signal were consistent with Slow-Scan Television (SSTV) protocols.
4.  By comparing the frame duration and line timing against common SSTV modes, the **Robot36** mode was identified as the most likely candidate.

### Recovery
The audio signal was processed using an SSTV decoder configured for the Robot36 mode. The successful decoding rendered an image containing diagonally oriented text, which held the flag.

### Validation
- Decoding with other SSTV modes (e.g., Scottie, Martin) produced garbled or incomplete images.
- Only the Robot36 mode yielded a clean, fully-readable image with a string matching the standard CTF flag format.

### Flag
`BCCTF{4mAt3uR_r4dio_ru135}`

### Takeaway
When faced with audio that sounds "strange" yet structured, suspect digital radio signaling formats like SSTV, FSK, or PSK before investing time in more obscure steganography techniques.

---

## Write-up: Poem About Pirates

**Category:** Forensics  
**Author:** Ian

---

### Challenge Overview
We are told a flag was once written in a poem but was later overwritten. The challenge files are located within a folder containing a `.git` directory, strongly suggesting the solution lies in Git forensics to recover historical or lost data.

### Evidence Collected
- A local Git repository exists in the `poems/` challenge folder.
- The current working tree is "clean," meaning the flag is not present in the latest version of the files.
- The nature of Git implies that the old data might still exist as an unreachable object in the repository's database.

### Analysis Path
The investigation focused on finding dangling or unreachable Git objects that might contain the previous version of the poem.
1.  The `git fsck` command was used to check the repository's integrity and list any unreachable objects.
    ```bash
    git fsck --full --no-reflogs --unreachable
    ```
2.  This command revealed a dangling blob object, which was a prime candidate for holding the lost data.
3.  The content of this blob was inspected using `git cat-file`.
    ```bash
    git cat-file -p <unreachable_blob_hash>
    ```

### Recovery
Inspecting the unreachable blob revealed an older version of the villanelle poem. This version contained the flag string that had been removed in later commits.

### Validation
- The flag was successfully recovered from a historical Git object, not from the active file system.
- The recovered string matched the `BCCTF{...}` format.
<img width="626" height="63" alt="2026-02-23_09-22-43" src="https://github.com/user-attachments/assets/0a1a6970-fb47-43fa-9fab-c2cdc436b443" />

### Flag
`BCCTF{1gN0r3_4ll_PreV1OU5_1n57Ruc7iOns}`

### Takeaway
Overwriting a file in a Git repository does not immediately erase the old content. Until the repository is garbage-collected (`git gc`), historical objects remain recoverable, making `git fsck` a critical tool in forensics.

---

## Write-up: The Crew Ledger

**Category:** Forensics  
**Author:** Sean

---

### Challenge Overview
The task is to verify crew data from a set of emails and ensure no sensitive information has been leaked. The evidence is a collection of `.eml` files with various attachments.

### Evidence Collected
- **`11.eml`:** Contains an encrypted attachment, `secret_location.zip`.
- **`81.eml` & `82.eml`:** Provide hints about old data or a potential key.
- **`92__2__lost_supplies.xlsx`:** An Excel file that appears normal on the surface but is suspicious due to its context.

### Analysis Path
1.  Since `.xlsx` files are fundamentally ZIP archives, the `lost_supplies.xlsx` file was unzipped to inspect its internal structure.
2.  Inside the archive, two interesting files were discovered: `xl/theme/pass.xml` and `xl/theme/secret.xml`.
3.  `pass.xml` contained a clear-text string: `Ah0y_m4t3y_801ecc51`. This was likely the password for the encrypted ZIP.
4.  `secret.xml` was not a valid XML file. Its magic bytes (`PK\x03\x04`) identified it as another ZIP archive stream embedded within the XLSX container.

### Recovery
1.  The ZIP stream from `secret.xml` was extracted.
2.  The extracted archive was unzipped using the password found in `pass.xml`. This produced a file named `treasure_map.png`.
3.  The image appeared to be a dead end, so it was analyzed for digital steganography. An LSB (Least Significant Bit) analysis was performed on its color channels.
4.  The flag's text became clearly visible when viewing the LSB of the **red channel** (`r_bit0`).

### Validation
- The flag was invisible in the normal image view.
- The flag only appeared consistently and clearly on the correct bit-plane (LSB of the red channel).
- The resulting string adheres to the CTF's flag format.
<img width="846" height="434" alt="image" src="https://github.com/user-attachments/assets/4484d274-da38-417e-a72d-a96de5ae2be2" />

### Flag
`BCCTF{X_M4rk3Sss_th3_Sp0T}`

### Takeaway
Modern Office files (OOXML) are complex containers. Never trust their surface appearance; always investigate their internal structure for hidden payloads, embedded files, or metadata abuse.

---

## Write-up: Gone 4 Ever

**Category:** Forensics  
**Author:** Sean

---

### Challenge Overview
The challenge presents 101 JPG images of numbers (0-100) and a `.bash_history` file. The goal is to find a "dark number" that holds a secret, implying one of the images contains hidden data.

### Evidence Collected
The `.bash_history` file contained the following sequence of commands, revealing the entire process:
```bash
vi flag.txt
export pass=`hexdump -n 4 -e '4/1 "%02x"' /dev/urandom`
for i in {0..100}; do wget "https://placehold.co/400x400.jpg?text="$i -O $i".jpg"; done
steghide embed -ef flag.txt -cf $((RANDOM % 101))".jpg" -p $pass
rm flag.txt
```
This tells us:
- A flag was hidden using `steghide`.
- The carrier file was a randomly chosen image between `0.jpg` and `100.jpg`.
- The passphrase is an 8-character hex string (32 bits of random data).

### Analysis Path
Instead of blindly brute-forcing the passphrase against all 101 images, the investigation focused on first identifying the correct carrier file.
1.  The `wget` command showed that the images were downloaded from `placehold.co`. The original, unaltered images could be re-downloaded for comparison.
2.  A script was used to download the pristine images and compare their file hashes against the provided challenge files.
3.  Only one image, `29.jpg`, had a different hash from its original version, confirming it as the carrier for the `steghide` payload.
4.  With the carrier identified, the next step was to recover the 32-bit passphrase. A brute-force attack on the passphrase for `29.jpg` is feasible.

### Recovery
A passphrase cracking tool was run against `29.jpg`. Once the correct 8-character hex passphrase was found, `steghide` was used to extract the payload, which contained the flag.

### Validation
- The extracted payload was a non-empty file.
- Its content was readable ASCII text and matched the `BCCTF{...}` format.
<img width="359" height="64" alt="image" src="https://github.com/user-attachments/assets/8fec0b44-c73d-48b6-a0ef-2e763a3e47b2" />

### Flag
`BCCTF{GonE_But_nOt_4GottEn}`

### Takeaway
In multi-step steganography challenges, reducing the search space is key. Combining file differential analysis (to find the carrier) with a targeted brute-force (for the key) is far more efficient than a purely blind approach.

---

## Write-up: Cursed Map

**Category:** Forensics  
**Author:** Sean

---

### Challenge Overview
We are given a PCAP file (`map.pcap`) with a hint that the "map" is dangerous when opened. This suggests a payload that exploits parsers, such as a compression bomb delivered over the network.

### Evidence Collected
- **Network Flow:** Analysis of the PCAP in Wireshark revealed a key HTTP flow between a client (`172.29.73.206`) and a server (`10.11.157.174`).
- **HTTP Request:** The client made a `GET /flag.txt` request.
- **HTTP Response:** The server responded with `HTTP/1.1 200 OK` and a `Content-Encoding: br` header, indicating the payload was compressed with Brotli.

### Analysis Path
1.  The HTTP response body was extracted as raw Brotli-compressed data.
2.  An initial assessment showed the compressed size was small (a few hundred kilobytes).
3.  Attempting to decompress the data directly revealed its true nature: it expanded to an enormous size (over 900 GB), confirming it was a **decompression bomb**.

### Recovery
Decompressing the entire file to disk was impractical and dangerous. The solution was to process the data as a stream:
1.  A script was written to decompress the Brotli stream chunk by chunk.
2.  Each decompressed chunk was scanned for the flag pattern (`BCCTF{...}`) incrementally.
3.  The process was stopped as soon as the complete flag was found, avoiding the need to handle the massive full output.

### Validation
- The flag was successfully extracted without writing the multi-gigabyte decompressed payload to disk.
- The stream-based method was safe, repeatable, and did not require massive system resources.
<img width="1191" height="382" alt="image" src="https://github.com/user-attachments/assets/95485ec0-4778-4ea4-8cf6-e08b502ca369" />

### Flag
`BCCTF{00H_1M_bR07l1_f33ls_S0_g0Od!}`

### Takeaway
When dealing with network captures involving compressed data, the first priority should be safe extraction. Using streaming parsers is a critical technique to avoid resource exhaustion from attacks like decompression bombs.

---

## Write-up: Treasure Hunt 3 - PCAPSIZED

**Category:** Forensics  
**Author:** Ian

---

### Challenge Overview
The challenge provides a network capture file, `pcapsized.pcap`, from a folder named "flag transfers." The goal is to find a flag hidden within the network traffic.

### Evidence Collected
- The PCAP file contains a small number of packets (124 total).
- Most traffic (TLS, DHCP, mDNS) appears normal.
- A highly anomalous TCP flow stands out: traffic from `237.84.138.236:1337` to `192.168.4.3:5748`.
- This flow consists of many packets with `Len=0` and unusual combinations of TCP flags (SYN, FIN, RST, PSH, URG all mixed). This is a strong indicator of a **covert channel** using TCP headers.

### Analysis Path
Since the packets had no payload, the data had to be encoded in the headers themselves. The `tcp.flags` field was the most likely candidate.
1.  The numerical values of the `tcp.flags` field were extracted from each packet in the anomalous flow.
2.  The values were observed to be within a small, consistent range (e.g., `0x10`, `0x24`, `0x0d`), corresponding to values from 0 to 63.
3.  This range perfectly matches the 6-bit index used in the **Base64 alphabet**. The hypothesis was that each packet's flag value represented one Base64 character.

### Recovery
1.  The suspicious TCP flow was isolated using a Wireshark/tshark filter.
2.  The sequence of `tcp.flags` values was extracted in order.
3.  Each flag value was treated as an index into the Base64 character set (`A-Z`, `a-z`, `0-9`, `+`, `/`).
4.  The resulting string of Base64 characters was assembled: `QkNDVEZ7QzBuUzkxY3VvVTVfY0g0Tm4zMXNfNE0xcjFUMz99`.
5.  Decoding this Base64 string revealed the plaintext flag.

### Validation
- The decoded Base64 string produced a human-readable message.
- The message followed the expected `BCCTF{...}` format, confirming the decoding method was correct.
```
#!/usr/bin/env python3
import argparse
import base64
import socket
import struct
from collections import Counter


B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def ip_to_str(raw: bytes) -> str:
    return socket.inet_ntoa(raw)


def parse_pcap(path: str):
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) != 24:
            raise ValueError("invalid pcap: header too short")

        magic = gh[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            endian = "<"
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian = ">"
        else:
            raise ValueError("unsupported pcap magic")

        ph_fmt = endian + "IIII"
        while True:
            ph = f.read(16)
            if not ph:
                break
            if len(ph) != 16:
                raise ValueError("invalid pcap: truncated packet header")

            _, _, incl_len, _ = struct.unpack(ph_fmt, ph)
            pkt = f.read(incl_len)
            if len(pkt) != incl_len:
                raise ValueError("invalid pcap: truncated packet payload")
            yield pkt


def extract_tcp_flags(pkt: bytes):
    # Ethernet II only.
    if len(pkt) < 14:
        return None
    eth_type = struct.unpack("!H", pkt[12:14])[0]
    if eth_type != 0x0800:
        return None

    ip = pkt[14:]
    if len(ip) < 20:
        return None

    ver_ihl = ip[0]
    version = ver_ihl >> 4
    ihl = (ver_ihl & 0x0F) * 4
    if version != 4 or ihl < 20 or len(ip) < ihl:
        return None

    proto = ip[9]
    if proto != 6:  # TCP
        return None

    src_ip = ip_to_str(ip[12:16])
    dst_ip = ip_to_str(ip[16:20])
    tcp = ip[ihl:]
    if len(tcp) < 20:
        return None

    src_port, dst_port = struct.unpack("!HH", tcp[:4])
    flags = tcp[13] & 0x3F  # UAPRSF bits

    return src_ip, dst_ip, src_port, dst_port, flags


def main():
    ap = argparse.ArgumentParser(description="Solve BCCTF PCAPSIZED covert TCP flags challenge")
    ap.add_argument("pcap", help="path to pcapsized.pcap")
    ap.add_argument("--src-ip", default="237.84.138.236")
    ap.add_argument("--dst-ip", default="192.168.4.3")
    ap.add_argument("--src-port", type=int, default=1337)
    ap.add_argument("--dst-port", type=int, default=5748)
    ap.add_argument(
        "--auto-flow",
        action="store_true",
        help="auto-pick the most common TCP flow with src port 1337 instead of fixed endpoints",
    )
    args = ap.parse_args()

    rows = []
    for pkt in parse_pcap(args.pcap):
        item = extract_tcp_flags(pkt)
        if item:
            rows.append(item)

    if not rows:
        raise SystemExit("No TCP packets parsed.")

    if args.auto_flow:
        cand = [r for r in rows if r[2] == 1337]
        if not cand:
            raise SystemExit("No flow with src port 1337 found.")
        flow = Counter((r[0], r[1], r[2], r[3]) for r in cand).most_common(1)[0][0]
        src_ip, dst_ip, src_port, dst_port = flow
    else:
        src_ip, dst_ip = args.src_ip, args.dst_ip
        src_port, dst_port = args.src_port, args.dst_port

    flags = [
        r[4]
        for r in rows
        if r[0] == src_ip and r[1] == dst_ip and r[2] == src_port and r[3] == dst_port
    ]

    if not flags:
        raise SystemExit("Target flow not found or contains no packets.")
    if any(v > 63 for v in flags):
        raise SystemExit("Found flag value outside 6-bit range.")

    b64_text = "".join(B64_ALPHABET[v] for v in flags)
    try:
        decoded = base64.b64decode(b64_text, validate=True)
    except Exception as e:
        raise SystemExit(f"Base64 decode failed: {e}")

    print(f"[+] Flow: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
    print(f"[+] Symbols: {len(flags)}")
    print(f"[+] Base64: {b64_text}")
    print(f"[+] Decoded: {decoded.decode('utf-8', errors='replace')}")


if __name__ == "__main__":
    main()
```
<img width="892" height="109" alt="image" src="https://github.com/user-attachments/assets/e3699075-844c-4180-b3e4-3c70e026e8f6" />

### Flag
`BCCTF{C0nS91cuoU5_cH4Nn31s_4M1r1T3?}`

### Takeaway
Data can be exfiltrated without any TCP/UDP payload by encoding it in packet headers. Unusual patterns in header fields like TCP flags, sequence numbers, or IP ID fields should always be investigated as potential covert channels.

---

## Write-up: Polly The Parrot

**Category:** Forensics  
**Author:** Ben

---

### Challenge Overview
The challenge is an audio file, `polly_recording.wav`. The description mentions a parrot's voice holding a "secret code," which suggests an audio steganography task.

### Evidence Collected
- The file is a standard WAV audio file.
- Listening to the audio reveals mostly bird-like squawking noises. No clear speech or Morse code is audible.

### Analysis Path
When audible data is meaningless, the next logical step in audio forensics is to analyze its visual representation.
1.  The audio file was loaded into an analysis tool like Audacity or Sonic Visualiser.
2.  The view was switched from the standard waveform to a **spectrogram**, which displays frequency intensity over time.
3.  In the spectrogram view, a clear pattern of high-intensity vertical lines was visible in the lower frequency bands, forming distinct shapes.
4.  By adjusting the contrast and zoom, these shapes were clearly identified as text characters.

### Recovery
The text characters spelling out the flag were read directly from the spectrogram image. The text read: `BCCTF{CrAk3rs_P3lZ}`.

### Validation
- The text was unambiguous once the spectrogram was correctly configured.
- The string matched the CTF flag format.
<img width="2126" height="390" alt="image" src="https://github.com/user-attachments/assets/e9ed85fa-ea44-4281-9d66-b7feb6b33f71" />

### Flag
`BCCTF{CrAk3rs_P3lZ}`

### Takeaway
This is a classic example of audio steganography where information is hidden as text in a spectrogram. It's a fundamental technique to check whenever an audio challenge doesn't have an obvious audible solution.

---

## Write-up: Captain Morgan

**Category:** Reverse Engineering  
**Author:** Sean

---

### Challenge Overview
The challenge is a heavily obfuscated Python script, `chall.py`, that checks a user-provided flag. The goal is to reverse-engineer the logic to find the correct input.

### Evidence Collected
- The script checks that the input starts with `BCCTF{` and ends with `}`.
- The core content of the flag (between the braces) is converted into a large integer.
- This integer is then subjected to thousands of bitwise operations (`&`, `|`, `^`, `>>`) using walrus operators, making manual analysis nearly impossible.

### Analysis Path
Instead of manually tracing the obfuscated logic, the script was treated as a **boolean satisfiability problem (SMT/SAT)**.
1.  The script was modified to be solved with the Z3 SMT solver.
2.  The input part of the flag was declared as a symbolic `BitVec` (a vector of symbolic bits).
3.  The final `print` statement, which determines success or failure, was replaced with a constraint. The script outputs `"correct"` when a variable `bfu` is `0`. So, the constraint `RESULT == 0` was added to the solver.
4.  The Z3 solver was then tasked with finding a value for the symbolic `BitVec` that satisfied all the bitwise operations and resulted in `bfu` being `0`.

### Recovery
The Z3 solver successfully found a model for the constraints. This model provided the integer value for the flag's content. Converting this integer back to bytes yielded the string: `Y00_hO_Ho_anD_4_B07Tl3_oF_rUm`.

### Validation
- The recovered string was combined with the prefix and suffix to form the full flag: `BCCTF{Y00_hO_Ho_anD_4_B07Tl3_oF_rUm}`.
- When this flag was provided as input to the original Python script, it printed "correct."
```
#!/usr/bin/env python3
from pathlib import Path
from z3 import BitVec, BitVecVal, Optimize, sat


TARGET_PREFIX = 'agu=input();bhy=agu.startswith("BCCTF{");aja=agu[-1]=="}";ari=int.from_bytes(agu[6:-1].encode());'
TARGET_SUFFIX = 'print("in"*bfu+"correct")'


def patch_source(src: str, width_bits: int) -> str:
    replacement_prefix = (
        "from z3 import *;"
        "agu='BCCTF{{X}}';"
        "bhy=BitVecVal(1,{w});"
        "aja=BitVecVal(1,{w});"
        "ari=BitVec('ari',{w});"
    ).format(w=width_bits)

    if TARGET_PREFIX not in src:
        raise ValueError("unexpected chall.py prefix; patch signature not found")
    if TARGET_SUFFIX not in src:
        raise ValueError("unexpected chall.py suffix; patch signature not found")

    patched = src.replace(TARGET_PREFIX, replacement_prefix, 1)
    patched = patched.replace(TARGET_SUFFIX, "RESULT=bfu", 1)
    return patched


def solve(chall_path: Path, width_bits: int = 256) -> str:
    src = chall_path.read_text(encoding="utf-8")
    patched = patch_source(src, width_bits)

    scope = {}
    exec(patched, scope, scope)

    result = scope["RESULT"]
    ari = scope["ari"]

    opt = Optimize()
    opt.add(result == 0)
    # Minimize removes unconstrained high bits and stabilizes output.
    opt.minimize(ari)
    if opt.check() != sat:
        raise RuntimeError("solver failed to find satisfiable model")

    model = opt.model()
    ari_val = model.eval(ari).as_long()

    # int.from_bytes default is big-endian in py3.12; recover minimal byte form.
    blen = max(1, (ari_val.bit_length() + 7) // 8)
    inner = ari_val.to_bytes(blen, "big").decode("ascii", errors="strict")
    return f"BCCTF{{{inner}}}"


def main():
    chall_path = Path("chall.py")
    flag = solve(chall_path)
    print(flag)


if __name__ == "__main__":
    main()
```
<img width="544" height="61" alt="image" src="https://github.com/user-attachments/assets/5f2503a0-8568-437a-aa3e-1f3179be95b8" />


### Flag
`BCCTF{Y00_hO_Ho_anD_4_B07Tl3_oF_rUm}`

### Takeaway
For heavily obfuscated programs based on mathematical or bitwise logic, automated solving with SMT/SAT solvers like Z3 is often more effective than manual reverse engineering. Treat the program as a system of constraints to be solved.

---

## Write-up: Polly's Key

**Category:** Reverse Engineering  
**Author:** Ian

---

### Challenge Overview
We are given a file `pollys_key`. The challenge description hints that a pirate and a parrot are talking simultaneously in different languages. This strongly suggests the file is a **polyglot**, a script valid in multiple programming languages.

### Evidence Collected
- Executing the file with `ruby pollys_key` runs without error.
- Executing the file with `perl pollys_key` also runs without error.
- The file uses a mix of syntax (`=begin`/`=cut`, heredocs) that allows it to be interpreted by both Ruby and Perl.
- The key must therefore satisfy the validation logic of **both** interpreters simultaneously.

### Analysis Path
The investigation required understanding the constraints imposed by each language's execution path.
1.  **Ruby Path Analysis:** The Ruby interpreter imposed constraints on character ordering, uniqueness, and certain modular arithmetic properties of character groups.
2.  **Perl Path Analysis:** The Perl interpreter had a different set of constraints, including character transformations and a validation based on an array's sorting properties (similar to an inversion count).
3.  A key that passed only one set of checks would fail the overall challenge. The true key had to be at the intersection of both constraint sets.

### Recovery
A solver-based approach was used to find a key that satisfied the combined logic.
1.  All active constraints from both the Ruby and Perl execution paths were extracted.
2.  These constraints were modeled in a solver (like Z3). This included character uniqueness, ordering rules, and the custom array validation from Perl.
3.  The solver was tasked with finding a 50-character string that met all conditions simultaneously.
4.  The solver produced a unique valid key: ``}O;m`pHw[Gq(g1\5@W6~Uu8{v7jnE?=9yRZ|$f#],ceCbkF+Qz``

### Validation
- When the recovered key was provided as input to the `pollys_key` script, it produced the flag as output.
- This confirmed that the key successfully passed both the Ruby and Perl validation paths.
```
#!/usr/bin/env python3
import argparse
import hashlib
import re
import subprocess
import sys
from pathlib import Path


# Key recovered from dual Ruby+Perl constraints.
SOLVED_KEY = r"}O;m`pHw[Gq(g1\5@W6~Uu8{v7jnE?=9yRZ|$f#],ceCbkF+Qz"


def extract_enc_treasure(src: str):
    m = re.search(r"\$encTreasure\s*=\s*\[([^\]]+)\]", src)
    if not m:
        raise ValueError("encTreasure not found")
    nums = [int(x.strip()) for x in m.group(1).split(",")]
    if len(nums) != 32:
        raise ValueError(f"encTreasure length mismatch: {len(nums)}")
    return nums


def decrypt_flag(key: str, enc: list[int]) -> str:
    md5_hex = hashlib.md5(key[:50].encode()).hexdigest()
    nibbles = [int(c, 16) for c in md5_hex[:32]]
    out = bytes((nibbles[i] ^ enc[i]) for i in range(32))
    return out.decode("utf-8", errors="strict")


def run_interpreter(interp: str, chall: Path, key: str) -> str:
    p = subprocess.run(
        [interp, str(chall)],
        input=key + "\n",
        text=True,
        capture_output=True,
        check=False,
    )
    return p.stdout + p.stderr


def main():
    ap = argparse.ArgumentParser(description="Auto solver for Polly's Key")
    ap.add_argument(
        "chall",
        nargs="?",
        default="/Users/zuy/Documents/ikan/pollys_key",
        help="path to pollys_key",
    )
    args = ap.parse_args()

    chall = Path(args.chall)
    src = chall.read_text(encoding="utf-8", errors="replace")

    enc = extract_enc_treasure(src)
    flag = decrypt_flag(SOLVED_KEY, enc)

    print(f"[+] Key ({len(SOLVED_KEY)} chars): {SOLVED_KEY}")
    print(f"[+] Decoded flag: {flag}")

    ok = True
    for interp in ("ruby", "perl"):
        try:
            out = run_interpreter(interp, chall, SOLVED_KEY)
        except FileNotFoundError:
            print(f"[!] {interp} not found, skip runtime verification")
            continue
        passed = "BCCTF{" in out and "WRONG" not in out.upper() and "fix it" not in out.lower()
        print(f"[+] {interp} check: {'PASS' if passed else 'FAIL'}")
        if not passed:
            ok = False
            print(f"--- {interp} output ---")
            print(out.strip())
            print("--- end ---")

    if not ok:
        sys.exit(1)


if __name__ == "__main__":
    main()
```
<img width="728" height="111" alt="image" src="https://github.com/user-attachments/assets/394eff87-f78b-4243-9b21-6ffc4b83094f" />

### Flag
`BCCTF{Th3_P05h_9oLly61Ot_p4rr0t}`

### Takeaway
Polyglot challenges require reversing multiple execution paths at once. The solution lies in finding the intersection of constraints from all involved languages. Simply solving for one language will often lead to a dead end.

---

## Write-up: Treasure Hunt 4 - HORIZON

**Category:** Reverse Engineering  
**Author:** Ian

---

### Challenge Overview
The challenge is a 64-bit ELF binary named `horizon`. It takes a string input and checks it against some internal logic to determine if it's the correct flag.

### Evidence Collected
- The binary is stripped but dynamically linked.
- Disassembly reveals a main loop that iterates 337 times.
- In each iteration, it calls a checker function and compares its result to a byte from a hardcoded table located at address `0x4020` in the `.data` section.
- A single mismatch causes the program to fail.

### Analysis Path
Two key functions were identified in the binary's logic:
1.  `get_bit(pos, input)`: This function retrieves a single bit from the input string at a given position.
2.  `count16(i, input)`: This function calculates the population count (popcount) of a **16-bit sliding window** over the input's bitstream, starting from bit position `i`.

This means the hardcoded table at `0x4020` stores the results of a sliding window popcount.
- The table has 337 values. If the window size is 16, the total number of bits `N` in the input can be calculated: `N - 16 + 1 = 337`, which gives `N = 352` bits, or **44 bytes**.

### Recovery
The relationship between adjacent window sums provides a way to reconstruct the bitstream without brute-forcing the entire 44-byte input.
The popcount sum at position `i` is `S[i] = b[i] + ... + b[i+15]`.
The sum at `i+1` is `S[i+1] = b[i+1] + ... + b[i+16]`.
Subtracting these gives `S[i+1] - S[i] = b[i+16] - b[i]`, which rearranges to a recurrence relation:
`b[i+16] = b[i] + (S[i+1] - S[i])`.

The solving strategy was:
1.  Extract the 337 target sum values from the binary's data section.
2.  Brute-force the first 16 bits of the input (a feasible `2^16` possibilities).
3.  For each 16-bit seed, reconstruct the remaining 336 bits using the recurrence relation.
4.  Validate that the reconstructed bitstream produces the correct popcount sums for all windows.
5.  Convert the valid 352-bit stream back into 44 bytes and check if it's a printable ASCII string starting with `BCCTF{`. This yielded a unique result.

### Validation
- The derived flag, when given as input to the `horizon` binary, resulted in the success message.
- The logic of the recurrence relation was proven correct by the unique, valid solution it produced.
```
#!/usr/bin/env python3
import argparse
import struct
from pathlib import Path


def parse_elf64_le_sections(blob: bytes):
    if blob[:4] != b"\x7fELF":
        raise ValueError("not ELF")
    if blob[4] != 2 or blob[5] != 1:
        raise ValueError("only ELF64 little-endian is supported")

    hdr = struct.unpack_from("<HHIQQQIHHHHHH", blob, 16)
    (
        _e_type,
        _e_machine,
        _e_version,
        _e_entry,
        _e_phoff,
        e_shoff,
        _e_flags,
        _e_ehsize,
        _e_phentsize,
        _e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    ) = hdr

    shdr_fmt = "<IIQQQQIIQQ"
    shstr_hdr_off = e_shoff + e_shstrndx * e_shentsize
    shstr_hdr = struct.unpack_from(shdr_fmt, blob, shstr_hdr_off)
    shstr_off, shstr_size = shstr_hdr[4], shstr_hdr[5]
    shstr = blob[shstr_off : shstr_off + shstr_size]

    def sname(off: int) -> str:
        end = shstr.find(b"\x00", off)
        return shstr[off:end].decode("ascii", errors="replace")

    out = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh = struct.unpack_from(shdr_fmt, blob, off)
        out.append(
            {
                "idx": i,
                "name": sname(sh[0]),
                "addr": sh[3],
                "off": sh[4],
                "size": sh[5],
            }
        )
    return out


def vaddr_to_offset(sections, vaddr: int) -> int:
    for s in sections:
        start = s["addr"]
        end = s["addr"] + s["size"]
        if start <= vaddr < end:
            return s["off"] + (vaddr - start)
    raise ValueError(f"vaddr {hex(vaddr)} not mapped to any section")


def bits_to_bytes_msb(bits):
    assert len(bits) % 8 == 0
    out = bytearray()
    for i in range(0, len(bits), 8):
        b = 0
        for k in range(8):
            b = (b << 1) | bits[i + k]
        out.append(b)
    return bytes(out)


def reconstruct_candidates(S):
    # S[i] = sum(b[i:i+16]), len(S)=337 => len(b)=352
    n_windows = len(S)
    n_bits = n_windows + 15

    candidates = []
    for seed in range(1 << 16):
        b = [0] * n_bits
        for i in range(16):
            b[i] = (seed >> (15 - i)) & 1

        ok = True
        for i in range(n_windows - 1):
            nxt = b[i] + (S[i + 1] - S[i])
            if nxt not in (0, 1):
                ok = False
                break
            b[i + 16] = nxt
        if not ok:
            continue

        # Verify all window sums exactly.
        w = sum(b[:16])
        if w != S[0]:
            continue
        for i in range(1, n_windows):
            w += b[i + 15] - b[i - 1]
            if w != S[i]:
                ok = False
                break
        if not ok:
            continue

        candidates.append(bits_to_bytes_msb(b))
    return candidates


def main():
    ap = argparse.ArgumentParser(description="Auto solver for BCCTF horizon")
    ap.add_argument(
        "binary",
        nargs="?",
        default="/Users/zuy/Documents/ikan/horizon",
        help="path to horizon binary",
    )
    ap.add_argument("--table-vaddr", type=lambda x: int(x, 0), default=0x4020)
    ap.add_argument("--table-len", type=int, default=0x151)  # 337
    args = ap.parse_args()

    p = Path(args.binary)
    blob = p.read_bytes()
    sections = parse_elf64_le_sections(blob)
    data_off = vaddr_to_offset(sections, args.table_vaddr)
    S = list(blob[data_off : data_off + args.table_len])
    if len(S) != args.table_len:
        raise SystemExit("failed to read full table")

    cands = reconstruct_candidates(S)
    if not cands:
        raise SystemExit("no candidate found")

    print(f"[+] candidates: {len(cands)}")
    printed = 0
    for c in cands:
        # Typical CTF filter.
        if not all(32 <= ch <= 126 for ch in c):
            continue
        s = c.decode("ascii", errors="replace")
        if s.startswith("BCCTF{") and s.endswith("}"):
            print(f"[+] flag: {s}")
            printed += 1
    if printed == 0:
        print("[+] no printable BCCTF candidate; dumping first 3 raw candidates:")
        for c in cands[:3]:
            print(repr(c))


if __name__ == "__main__":
    main()
```
<img width="737" height="73" alt="image" src="https://github.com/user-attachments/assets/e24544ce-39e7-4710-90da-88bbd21543fd" />

### Flag
`BCCTF{5LiD1n6_W1nd0w5_B3_L1k3:1m_C0nvo1v1nG}`

### Takeaway
This challenge demonstrates an attack on a linear constraint system disguised as a string check. The key was identifying the sliding window popcount and using the resulting recurrence relation to reduce an impossibly large search space to a manageable one.

---

## Write-up: Blackbeard's Tomb

**Category:** Reverse Engineering  
**Author:** Sean

---

### Challenge Overview
The file `tomb` is a 64-bit ELF binary. The goal is to find the correct input that allows us to "escape the tomb."

### Evidence Collected
- **Binary Type:** Statically linked ELF, not stripped, which helps in identifying function names.
- **Key Strings:** Success and failure messages like "You have entered my tomb!" and "You have defied the odds..."
- **Custom Functions:** `proc`, `main`, `hash`, `xor`.
- **Execution Flow:** The entry point is not `main` but `proc`, indicating some pre-setup or anti-analysis tricks.

### Analysis Path
1.  **Anti-Analysis in `proc`:** The `proc` function was found to read `/proc/self/status` to check its `TracerPid`. This is a common anti-debugging trick. The result is used to modify a global key variable, `tomb_key`.
2.  **More Anti-Analysis:** A custom `puts` function contained further anti-debug shellcode (`ptrace` checks) that also mutated `tomb_key`. This means the key used for validation is dynamic and depends on the execution environment.
3.  **Stage 1 Validation:** The `main` function performs the first stage of checks.
    - It verifies the input prefix by comparing `SHA256("BCCTF{")` to the hash of the first 6 bytes of the input.
    - It then validates the next 20 characters using a chained SHA256 comparison against a hardcoded `lock` array. Each character's validity depends on the previous one, allowing for sequential recovery. This chain revealed the segment: `Buri3d_at_sea_Ent0m3d`.
4.  **Stage 2 Validation:** After stage 1 passes, the binary decrypts a second-stage checker from the stack. This checker validates the next 18 characters of the flag by XORing them against the `tomb_key` derived earlier.

### Recovery
1.  The first part of the flag, `Buri3d_at_sea_Ent0m3d`, was recovered by reversing the chained SHA256 logic from Stage 1.
2.  The runtime value of `tomb_key` was determined by running the program outside a debugger.
3.  This key was used to reverse the XOR logic in the Stage 2 checker, revealing the next segment: `_amm0nG_th3_w4v3S`.
4.  The final flag was constructed by concatenating all parts.
```
#!/usr/bin/env python3
import argparse
import hashlib
import os
import subprocess
from pathlib import Path


def build_digest_maps():
    # Map digest suffix[1:] -> byte value, and first digest byte -> possible bytes.
    suf_to_byte = {}
    first_to_bytes = {}
    for b in range(256):
        d = hashlib.sha256(bytes([b])).digest()
        suf = d[1:]
        # In practice these are unique for byte inputs.
        suf_to_byte.setdefault(suf, []).append(b)
        first_to_bytes.setdefault(d[0], []).append(b)
    return suf_to_byte, first_to_bytes


def find_lock_and_recover_stage1(blob: bytes):
    suf_to_byte, first_to_bytes = build_digest_maps()
    block_count = 20
    block_size = 32
    total = block_count * block_size

    for off in range(0, len(blob) - total + 1):
        chunk = blob[off : off + total]

        # Recover c[i+1] from suffixes at each block i.
        next_bytes = []
        ok = True
        for i in range(block_count):
            blk = chunk[i * block_size : (i + 1) * block_size]
            matches = suf_to_byte.get(blk[1:], [])
            if len(matches) != 1:
                ok = False
                break
            next_bytes.append(matches[0])
        if not ok:
            continue

        # Recover c0 from block0 first-byte xor relation:
        # blk0[0] == sha(c0)[0] ^ sha(c1)[0]
        c1 = next_bytes[0]
        h1_0 = hashlib.sha256(bytes([c1])).digest()[0]
        need_h0 = chunk[0] ^ h1_0
        c0_candidates = first_to_bytes.get(need_h0, [])
        if len(c0_candidates) != 1:
            continue
        c0 = c0_candidates[0]

        # Build chain c0..c20, where next_bytes[i] is c(i+1).
        chain = [c0] + next_bytes

        # Validate xor first-byte relation for all blocks.
        for i in range(block_count):
            ci = chain[i]
            ci1 = chain[i + 1]
            lhs = chunk[i * block_size]
            rhs = hashlib.sha256(bytes([ci])).digest()[0] ^ hashlib.sha256(bytes([ci1])).digest()[0]
            if lhs != rhs:
                ok = False
                break
        if not ok:
            continue

        # Stage-1 recovered section is index 6..25 = first 20 bytes of chain.
        stage1 = bytes(chain[:20]).decode("ascii", errors="replace")
        return off, stage1, bytes(chain)

    raise RuntimeError("lock table not found")


def main():
    ap = argparse.ArgumentParser(description="Auto solver for Blackbeard's Tomb")
    ap.add_argument("binary", nargs="?", default="/Users/zuy/Documents/ikan/tomb", help="path to tomb binary")
    ap.add_argument(
        "--stage2-suffix",
        default="_amm0nG_th3_w4v3S",
        help="18-byte stage-2 segment recovered from runtime checker",
    )
    ap.add_argument("--run", action="store_true", help="run binary with recovered flag (if executable on this host)")
    args = ap.parse_args()

    p = Path(args.binary)
    blob = p.read_bytes()

    off, stage1, chain = find_lock_and_recover_stage1(blob)

    # Prefix from stage-0 SHA256(prefix) logic in binary.
    prefix = "BCCTF{"
    suffix = args.stage2_suffix
    flag = f"{prefix}{stage1}{suffix}}}"

    print(f"[+] lock offset: 0x{off:x}")
    print(f"[+] stage1: {stage1}")
    print(f"[+] chain c0..c20: {chain.decode('ascii', errors='replace')}")
    print(f"[+] flag: {flag}")

    if args.run:
        if not os.access(p, os.X_OK):
            print("[!] binary is not executable; skipping run")
            return
        try:
            out = subprocess.check_output([str(p), flag], stderr=subprocess.STDOUT, timeout=5)
            print("[+] binary output:")
            print(out.decode("utf-8", errors="replace"))
        except Exception as e:
            print(f"[!] run failed: {e}")


if __name__ == "__main__":
    main()
```

### Validation
The full flag was assembled: `BCCTF{Buri3d_at_sea_Ent0m3d_amm0nG_th3_w4v3S}`. When this string was passed as an argument to the `./tomb` binary, it printed the success message, confirming the analysis was correct.
<img width="608" height="76" alt="image" src="https://github.com/user-attachments/assets/37cfe267-073d-48f3-866d-cc3eaa395e64" />

### Flag
`BCCTF{Buri3d_at_sea_Ent0m3d_amm0nG_th3_w4v3S}`

### Takeaway
Multi-stage binaries with anti-debugging tricks require careful analysis. It's often necessary to defeat or bypass the anti-analysis measures first to determine the correct runtime state (like dynamic keys) before the main validation logic can be reversed.

---

## Write-up: Block Cipher Buccaneers

**Category:** Cryptography  
**Author:** Jacob

---

### Challenge Overview
We are given three files: `left.bmp`, `middle.bin`, and `right.bmp`. The goal is to reconstruct a flag that has been split across these three parts, where the middle part is encrypted.

### Evidence Collected
- `left.bmp` and `right.bmp` are valid bitmap images containing parts of the flag text.
- `middle.bin` is not an image but an OpenSSL-encrypted data blob, identifiable by its `Salted__` header.
- We have the plaintext (image) for the left and right parts, and the ciphertext for the middle.

### Analysis Path
Brute-forcing the password for `middle.bin` would be difficult. However, the description hints at a weakness in the block cipher mode.
1.  The most common block cipher mode vulnerable to pattern analysis is **Electronic Codebook (ECB)**, where identical plaintext blocks encrypt to identical ciphertext blocks.
2.  Even without the key, if the encryption used an ECB-like mode, patterns in the ciphertext could reveal patterns in the original plaintext.
3.  The `middle.bin` ciphertext was visualized by assigning a unique color or shade to each unique 16-byte block. This "equal-block map" revealed a clear visual silhouette of text characters.

### Recovery
1.  The plaintext was read from the left image: `BCCTF{BL`.
2.  The plaintext was read from the right image: `3r_Mod3}`.
3.  The text pattern was visually reconstructed from the ECB block visualization of `middle.bin`, revealing the middle segment: `oCk_c1pH`.
4.  All three parts were concatenated in order to form the complete flag.
```
#!/usr/bin/env python3
import argparse
import binascii
import struct
import zlib
from collections import Counter
from pathlib import Path


def png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    crc = binascii.crc32(chunk_type + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", crc)


def write_png_rgb(path: Path, width: int, height: int, rows_rgb: list[bytes]) -> None:
    raw = bytearray()
    for row in rows_rgb:
        raw.append(0)  # filter type 0
        raw.extend(row)

    image = b"".join(
        [
            b"\x89PNG\r\n\x1a\n",
            png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)),
            png_chunk(b"IDAT", zlib.compress(bytes(raw), 9)),
            png_chunk(b"IEND", b""),
        ]
    )
    path.write_bytes(image)


def read_png_rgb(path: Path) -> tuple[int, int, list[list[tuple[int, int, int]]]]:
    data = path.read_bytes()
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("not a png")

    i = 8
    width = height = 0
    idat = bytearray()

    while i < len(data):
        ln = struct.unpack(">I", data[i : i + 4])[0]
        ctype = data[i + 4 : i + 8]
        chunk = data[i + 8 : i + 8 + ln]
        i += 12 + ln
        if ctype == b"IHDR":
            width, height, bit_depth, color_type, comp, flt, interlace = struct.unpack(">IIBBBBB", chunk)
            if not (bit_depth == 8 and color_type == 2 and comp == 0 and flt == 0 and interlace == 0):
                raise ValueError("unsupported png format")
        elif ctype == b"IDAT":
            idat.extend(chunk)
        elif ctype == b"IEND":
            break

    raw = zlib.decompress(bytes(idat))
    rows: list[list[tuple[int, int, int]]] = []
    p = 0
    for _ in range(height):
        filter_type = raw[p]
        p += 1
        if filter_type != 0:
            raise ValueError("unsupported png filter (expected 0)")
        row = []
        for _ in range(width):
            row.append((raw[p], raw[p + 1], raw[p + 2]))
            p += 3
        rows.append(row)
    return width, height, rows


def write_zoom_crop(
    src_png: Path,
    out_png: Path,
    x0: int,
    y0: int,
    x1: int,
    y1: int,
    scale: int,
) -> None:
    w, h, rows = read_png_rgb(src_png)
    x0 = max(0, min(w, x0))
    x1 = max(0, min(w, x1))
    y0 = max(0, min(h, y0))
    y1 = max(0, min(h, y1))
    if x1 <= x0 or y1 <= y0:
        raise ValueError("invalid crop box")

    crop = [row[x0:x1] for row in rows[y0:y1]]
    out_rows: list[bytes] = []
    for row in crop:
        scaled_row = []
        for rgb in row:
            scaled_row.extend([rgb] * scale)
        row_bytes = bytearray()
        for rgb in scaled_row:
            row_bytes.extend(rgb)
        for _ in range(scale):
            out_rows.append(bytes(row_bytes))
    write_png_rgb(out_png, (x1 - x0) * scale, (y1 - y0) * scale, out_rows)


def salted_openssl_payload(data: bytes) -> bytes:
    if data.startswith(b"Salted__") and len(data) >= 16:
        return data[16:]
    return data


def build_visual_rows(
    blocks: list[bytes],
    width: int,
    bytes_per_pixel: int,
    mode: str,
    top_k_background: int,
) -> tuple[list[bytes], int]:
    if width % (16 // bytes_per_pixel) != 0:
        raise ValueError("width must be divisible by block-pixel-width (16 / bytes_per_pixel).")

    pixels_per_block = 16 // bytes_per_pixel
    blocks_per_row = width // pixels_per_block
    rows_count = (len(blocks) + blocks_per_row - 1) // blocks_per_row

    if rows_count == 0:
        return [], 0

    blocks = blocks + [b""] * (rows_count * blocks_per_row - len(blocks))
    row_bytes = width * 3
    rows_rgb: list[bytes] = []

    if mode == "binary":
        top = Counter(b for b in blocks if b).most_common(top_k_background)
        background_blocks = {b for b, _ in top}

    palette_map: dict[bytes, int] = {}
    next_id = 0

    for y in range(rows_count):
        row = bytearray()
        for bx in range(blocks_per_row):
            block = blocks[y * blocks_per_row + bx]
            if not block:
                color = (0, 0, 0)
            elif mode == "binary":
                color = (230, 230, 230) if block in background_blocks else (0, 0, 0)
            else:
                if block not in palette_map:
                    palette_map[block] = next_id
                    next_id += 1
                v = palette_map[block]
                color = ((v * 53 + 29) % 256, (v * 97 + 71) % 256, (v * 193 + 11) % 256)

            row.extend(color * pixels_per_block)

        if len(row) != row_bytes:
            raise RuntimeError("unexpected row size")
        rows_rgb.append(bytes(row))

    return rows_rgb, rows_count


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Render ECB block-equality visualizations from encrypted middle.bin."
    )
    parser.add_argument("--middle", default="images/middle.bin", help="Path to encrypted middle file.")
    parser.add_argument("--width", type=int, default=1024, help="Expected plaintext image width.")
    parser.add_argument(
        "--bytes-per-pixel",
        type=int,
        default=4,
        choices=[1, 2, 4, 8, 16],
        help="Plaintext bytes per pixel (BMP32 uses 4).",
    )
    parser.add_argument(
        "--binary-out",
        default="images/middle_binary.png",
        help="Output PNG path for binary (bg/fg) visualization.",
    )
    parser.add_argument(
        "--palette-out",
        default="images/middle_palette.png",
        help="Output PNG path for color-palette visualization.",
    )
    parser.add_argument(
        "--top-k-background",
        type=int,
        default=1,
        help="How many most-common blocks to treat as background in binary mode.",
    )
    parser.add_argument(
        "--zoom-out",
        default="images/middle_binary_zoom.png",
        help="Output PNG path for zoomed text crop from binary visualization.",
    )
    parser.add_argument("--zoom-scale", type=int, default=3, help="Nearest-neighbor upscale for zoom crop.")
    parser.add_argument(
        "--zoom-box",
        default="160,360,980,700",
        help="Crop box x0,y0,x1,y1 on binary image before scaling.",
    )
    args = parser.parse_args()

    data = Path(args.middle).read_bytes()
    payload = salted_openssl_payload(data)
    blocks = [payload[i : i + 16] for i in range(0, len(payload), 16) if len(payload[i : i + 16]) == 16]

    binary_rows, h_bin = build_visual_rows(
        blocks=blocks,
        width=args.width,
        bytes_per_pixel=args.bytes_per_pixel,
        mode="binary",
        top_k_background=args.top_k_background,
    )
    palette_rows, h_pal = build_visual_rows(
        blocks=blocks,
        width=args.width,
        bytes_per_pixel=args.bytes_per_pixel,
        mode="palette",
        top_k_background=args.top_k_background,
    )

    write_png_rgb(Path(args.binary_out), args.width, h_bin, binary_rows)
    write_png_rgb(Path(args.palette_out), args.width, h_pal, palette_rows)
    x0, y0, x1, y1 = [int(v) for v in args.zoom_box.split(",")]
    write_zoom_crop(
        src_png=Path(args.binary_out),
        out_png=Path(args.zoom_out),
        x0=x0,
        y0=y0,
        x1=x1,
        y1=y1,
        scale=max(1, args.zoom_scale),
    )

    print(f"[+] blocks: {len(blocks)}")
    print(f"[+] wrote: {args.binary_out} ({args.width}x{h_bin})")
    print(f"[+] wrote: {args.palette_out} ({args.width}x{h_pal})")
    print(f"[+] wrote: {args.zoom_out}")


if __name__ == "__main__":
    main()
```

### Validation
- The reconstructed flag was a coherent and correctly formatted string.
- The concept aligns perfectly with a known weakness of ECB mode, validating the analysis path.
<img width="1558" height="349" alt="image" src="https://github.com/user-attachments/assets/9916854e-985d-41e5-8293-ad691de2360d" />

### Flag
`BCCTF{BLoCk_c1pH3r_Mod3}`

### Takeaway
This challenge is a classic demonstration of ECB mode's weakness. Even when data is encrypted, using ECB on structured data (like images or text) leaks significant information about the original content, often enough to reconstruct it visually without needing the key.

---

## Write-up: Crazy Curves

**Category:** Cryptography  
**Author:** Sean

---

### Challenge Overview
Provided are a Sage script (`crazy_curve.sage`) and an output file (`output.txt`). The script performs a key exchange to derive an AES key, which then encrypts a flag. The goal is to recover the shared secret to decrypt the flag.

### Evidence Collected
- `output.txt` contains Alice's public key, Bob's public key, and an AES-CBC ciphertext with its IV.
- `crazy_curve.sage` shows that the server selects a curve, performs an ECDH-like exchange, and uses the shared secret's x-coordinate to derive an AES key.
- The "curve" is not a standard elliptic curve.

### Analysis Path
1.  **Identify the Curve:** The first step was to determine which curve from the script's dictionary was used. By testing the public keys against each curve equation, only one matched: a curve defined by `(x-a)² + (y-b)² ≡ c² (mod p)`.
2.  **Analyze the Group Structure:** This equation describes a circle, not an elliptic curve. The group operation, when transformed, is equivalent to the multiplication of complex numbers on a unit circle over a finite field. The order of this group is related to `p+1`.
3.  **Exploit the Weakness:** The security of discrete logarithm problems (DLP) depends on the group order having a large prime factor. In this case, `p+1` had many small and medium-sized factors, making the DLP vulnerable to the **Pohlig-Hellman algorithm**.
4.  **Partial Key Recovery:** Using Pohlig-Hellman, Alice's private key could be recovered modulo a large composite number `M` (the product of the small factors of `p+1`). This significantly reduced the search space for the private key.

### Recovery
1.  The Pohlig-Hellman attack yielded `privA ≡ x (mod M)`, where `M` was a 113-bit number.
2.  This meant the full private key had to be of the form `privA = x + k*M` for some integer `k`.
3.  A brute-force search was conducted over the remaining possible values of `k`. For each candidate `privA`:
    a. The shared secret was calculated: `ss = Bpub * privA`.
    b. The AES key was derived: `sha1(str(ss.x))[:16]`.
    c. The ciphertext was decrypted.
    d. The resulting plaintext was checked to see if it matched the `BCCTF{...}` format.
4.  One of the candidates produced the correct flag.

### Validation
- The decrypted plaintext was a valid flag, confirming that the recovered private key and shared secret were correct.
- The methodology followed a standard cryptographic attack against a non-standard group, validating the entire analysis.

### Flag
`BCCTF{y0U_sp1n_mE_r1gt_r0und}`

### Takeaway
Just because an algorithm looks like ECDH doesn't mean it's secure. The security relies entirely on the hardness of the DLP in the underlying mathematical group. Non-standard groups, like this "circle-based" one, may have critical weaknesses (like a smooth order) that render them insecure.

---

## Write-up: Ghost Ship

**Category:** Misc  
**Author:** Ian

---

### Challenge Overview
The challenge file `ghost_ship` appears to be a binary, but its content suggests otherwise. It prompts for a flag and outputs a ghost-themed story.

### Evidence Collected
- Inspection of the file's content reveals it contains only the characters `><+-.,[]`, which are the instruction set for the **Brainfuck** esoteric programming language.
- The file is not an ELF binary but Brainfuck source code.

### Analysis Path
The goal was to find the input that leads to the success path in the Brainfuck program.
1.  The program was run in a Brainfuck interpreter with debugging capabilities.
2.  The code contains a loop with 40 `,` instructions, indicating it reads a 40-character input.
3.  A large validation loop determines whether the input is correct. The value in a specific memory cell acts as a mismatch counter; for the input to be correct, this counter must be zero at the end of the loop.
4.  This setup creates a perfect oracle. We can test one character at a time and see if it reduces the mismatch counter. An automated script was used to brute-force each of the 40 characters of the flag sequentially.

### Recovery
Using the mismatch counter as an oracle, the script iterated through all possible characters for each position of the flag until it found the one that was correct. This process was repeated 40 times to reconstruct the entire flag string.
```
#!/usr/bin/env python3
from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path

BF_OPS = set('><+-.,[]')


def load_bf(path: Path) -> str:
    raw = path.read_text(errors='ignore')
    return ''.join(ch for ch in raw if ch in BF_OPS)


def build_bracket_map(code: str) -> dict[int, int]:
    st = []
    bm: dict[int, int] = {}
    for i, ch in enumerate(code):
        if ch == '[':
            st.append(i)
        elif ch == ']':
            if not st:
                raise ValueError(f'unmatched ] at {i}')
            j = st.pop()
            bm[i] = j
            bm[j] = i
    if st:
        raise ValueError('unmatched [')
    return bm


def run_bf_oracle(code: str, bm: dict[int, int], inp: bytes, branch_idx: int) -> int:
    tape = defaultdict(int)
    ptr = 0
    pc = 0
    ip = 0
    n = len(code)

    while pc < n:
        if pc == branch_idx:
            return tape[ptr]

        op = code[pc]
        if op == '>':
            ptr += 1
        elif op == '<':
            ptr -= 1
        elif op == '+':
            tape[ptr] = (tape[ptr] + 1) & 0xFF
        elif op == '-':
            tape[ptr] = (tape[ptr] - 1) & 0xFF
        elif op == ',':
            tape[ptr] = inp[ip] if ip < len(inp) else 0
            ip += 1
        elif op == '.':
            pass
        elif op == '[':
            if tape[ptr] == 0:
                pc = bm[pc]
        elif op == ']':
            if tape[ptr] != 0:
                pc = bm[pc]
        pc += 1

    raise RuntimeError('branch index not reached')


def run_bf_output(code: str, bm: dict[int, int], inp: bytes) -> str:
    tape = defaultdict(int)
    ptr = 0
    pc = 0
    ip = 0
    out = []
    n = len(code)

    while pc < n:
        op = code[pc]
        if op == '>':
            ptr += 1
        elif op == '<':
            ptr -= 1
        elif op == '+':
            tape[ptr] = (tape[ptr] + 1) & 0xFF
        elif op == '-':
            tape[ptr] = (tape[ptr] - 1) & 0xFF
        elif op == ',':
            tape[ptr] = inp[ip] if ip < len(inp) else 0
            ip += 1
        elif op == '.':
            out.append(chr(tape[ptr]))
        elif op == '[':
            if tape[ptr] == 0:
                pc = bm[pc]
        elif op == ']':
            if tape[ptr] != 0:
                pc = bm[pc]
        pc += 1
    return ''.join(out)


def recover_flag(code: str, bm: dict[int, int], branch_idx: int, length: int, charset: str) -> str:
    guess = list("A" * length)
    if length >= 7:
        guess[:6] = list("BCCTF{")
        guess[-1] = "}"

    # Single forward pass is enough for this checker layout.
    for i in range(length):
        if i < 6 or i == length - 1:
            continue
        best_ch = guess[i]
        best_score = None
        for ch in charset:
            guess[i] = ch
            score = run_bf_oracle(code, bm, "".join(guess).encode(), branch_idx)
            if best_score is None or score < best_score:
                best_score = score
                best_ch = ch
        guess[i] = best_ch
        print(f"[*] pos {i:02d} -> {best_ch} (score={best_score})", flush=True)

    return "".join(guess)


def main():
    ap = argparse.ArgumentParser(description='Auto solver for Ghost Ship (Brainfuck oracle)')
    ap.add_argument('path', nargs='?', default='/Users/zuy/Documents/ikan/ghost_ship', help='path to ghost_ship BF file')
    ap.add_argument('--branch', type=int, default=9098, help='checker branch opcode index')
    ap.add_argument('--charset', default='0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ{}_!', help='candidate charset')
    args = ap.parse_args()

    code = load_bf(Path(args.path))
    bm = build_bracket_map(code)
    length = code.count(',')

    flag = recover_flag(code, bm, args.branch, length, args.charset)
    out = run_bf_output(code, bm, flag.encode())
    score = run_bf_oracle(code, bm, flag.encode(), args.branch)

    print(f'[+] code len: {len(code)}')
    print(f'[+] input length: {length}')
    print(f'[+] oracle score: {score}')
    print(f'[+] candidate: {flag}')
    print('[+] tail output:')
    print(out[-500:])


if __name__ == '__main__':
    main()
```
<img width="918" height="247" alt="image" src="https://github.com/user-attachments/assets/37dbb134-a119-461b-81d2-75c2b4fbf08b" />

### Validation
- The reconstructed flag, `BCCTF{N0_moR3_H4un71n6!_N0_M0rE_Gh0575!}`, when provided as input to the Brainfuck interpreter running the script, resulted in the success message.

### Flag
`BCCTF{N0_moR3_H4un71n6!_N0_M0rE_Gh0575!}`

### Takeaway
Challenges involving esoteric languages like Brainfuck often boil down to either direct code analysis or using the program's output as an oracle to guide a brute-force attack.

---

## Write-up: Battleship for One

**Category:** Misc  
**Author:** Sean

---

### Challenge Overview
The challenge is a Python script, `battleship.py`. To get the flag, we must win the "Ultimate Challenge" mode, which requires winning 30 consecutive games of increasing difficulty. Random guessing is not feasible.

### Evidence Collected
- The game involves finding a hidden `0` on a grid.
- The grids are not random; they are created by shuffling the rows and columns of a fixed base grid for each difficulty level (`easy`, `medium`, `hard`).
- Crucially, the values on the base grids are a unique permutation of numbers from `0` to `n²-1`.

### Analysis Path
The fact that the values are unique and the shuffle is only a permutation of rows and columns is the key weakness.
1.  When we make a guess at a display coordinate `(r, c)` and reveal a value `v`, we learn two things simultaneously:
    - The mapping for the row: `display_row[r]` maps to `base_row[br]`, where `br` is the original row of value `v`.
    - The mapping for the column: `display_col[c]` maps to `base_col[bc]`, where `bc` is the original column of value `v`.
2.  With enough guesses, we can fully determine the permutation of rows and columns. For an `n x n` board, `n-1` probes along the diagonal are sufficient to reveal `n-1` row mappings and `n-1` column mappings. The final mapping for each can be deduced.

### Recovery
A deterministic strategy was developed:
1.  For an `n x n` board, probe the `n-1` diagonal cells: `(0,0), (1,1), ..., (n-2, n-2)`.
2.  Use the revealed values to build the mapping between the displayed grid's rows/columns and the base grid's rows/columns.
3.  Find the original coordinate of the `0` in the base grid.
4.  Use the solved mappings to determine which displayed coordinate corresponds to the original location of the `0`.
5.  Make the final, winning guess at that coordinate. This strategy uses at most `n` guesses, which is within the attempt limit even for the hard level (30 attempts for a 30x30 grid).

### Validation
- The deterministic strategy was implemented and successfully solved all 30 rounds of the Ultimate Challenge.
- Upon winning, the script printed the flag.
```
#!/usr/bin/env python3
import ast
import re
import socket
from pathlib import Path

HOST = "chal.bearcatctf.io"
PORT = 45457
PROMPT = b"Where is the battleship > "
CHAL_PATH = "/Users/zuy/Documents/New project 2/ctf/battleship.py"


def load_bases(path: str):
    src = Path(path).read_text()
    tree = ast.parse(src)
    bases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "main":
            for stmt in node.body:
                if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                    name = stmt.targets[0].id
                    if name in {"easy", "medium", "hard"}:
                        val = ast.literal_eval(stmt.value)
                        n, attempts, basis = val
                        bases[n] = {
                            "attempts": attempts,
                            "basis": list(basis),
                        }
    # preprocess inverse maps
    for n, obj in bases.items():
        inv = {}
        for idx, v in enumerate(obj["basis"]):
            inv[v] = (idx // n, idx % n)
        obj["inv"] = inv
        obj["zero_coord"] = obj["inv"][0]
    return bases


BASES = load_bases(CHAL_PATH)


class Conn:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buf = b""

    def recv_until_any(self, markers, timeout=10.0) -> bytes:
        self.sock.settimeout(timeout)
        while True:
            for m in markers:
                if m in self.buf:
                    i = self.buf.index(m) + len(m)
                    out = self.buf[:i]
                    self.buf = self.buf[i:]
                    return out
            chunk = self.sock.recv(8192)
            if not chunk:
                out = self.buf
                self.buf = b""
                return out
            self.buf += chunk

    def send_line(self, s: str):
        self.sock.sendall(s.encode() + b"\n")


def parse_last_board(text: str):
    idx = text.rfind("Attempts left:")
    if idx == -1:
        return None, None
    lines = text[idx:].splitlines()
    m = re.search(r"Attempts left:\s*(\d+)", lines[0])
    if not m:
        return None, None
    attempts = int(m.group(1))

    grid = []
    for line in lines[1:]:
        toks = line.strip().split()
        if not toks:
            continue
        if toks[0] == "Where":
            break
        if len(grid) and len(toks) != len(grid[0]):
            break
        if all(("X" in t) or any(ch.isdigit() for ch in t) or ("\x1b" in t) for t in toks):
            grid.append(toks)
        else:
            break
    return attempts, (grid if grid else None)


def tok_to_int(tok: str):
    tok = re.sub(r"\x1b\[[0-9;]*m", "", tok)
    return int(tok) if tok.isdigit() else None


class BoardState:
    def __init__(self, n):
        self.n = n
        self.inv = BASES[n]["inv"]
        self.r0, self.c0 = BASES[n]["zero_coord"]
        self.row_map = {}  # displayed row -> basis row
        self.col_map = {}  # displayed col -> basis col
        self.probe_i = 0
        self.last_guess = None

    def update_from_grid(self, grid):
        if self.last_guess is None:
            return
        r, c = self.last_guess
        val = tok_to_int(grid[r][c])
        if val is None:
            return
        br, bc = self.inv[val]
        self.row_map[r] = br
        self.col_map[c] = bc

    def next_guess(self):
        # probe n-1 diagonal entries (distinct rows and cols)
        if self.probe_i < self.n - 1:
            g = (self.probe_i, self.probe_i)
            self.probe_i += 1
            self.last_guess = g
            return g

        # fill missing row/col by permutation completion
        all_idx = set(range(self.n))
        mr = list(all_idx - set(self.row_map.keys()))
        mc = list(all_idx - set(self.col_map.keys()))
        if len(mr) == 1:
            self.row_map[mr[0]] = next(iter(all_idx - set(self.row_map.values())))
        if len(mc) == 1:
            self.col_map[mc[0]] = next(iter(all_idx - set(self.col_map.values())))

        tr = next((i for i, br in self.row_map.items() if br == self.r0), self.n - 1)
        tc = next((j for j, bc in self.col_map.items() if bc == self.c0), self.n - 1)
        self.last_guess = (tr, tc)
        return self.last_guess


def main():
    with socket.create_connection((HOST, PORT), timeout=10) as sock:
        c = Conn(sock)

        menu = c.recv_until_any([b"5. Exit"], timeout=10)
        print(menu.decode("utf-8", "replace"), flush=True)
        c.send_line("4")

        markers = [PROMPT, b"Try again", b"Sorry skipper", b"BCCTF{", b"greatest admiral", b"Choose your difficulty"]

        state = None
        wins = 0

        while True:
            chunk = c.recv_until_any(markers, timeout=20)
            if not chunk:
                break
            text = chunk.decode("utf-8", "replace")

            if "BCCTF{" in text:
                # We stop on marker "BCCTF{"; fetch the rest of the flag until '}'
                if "}" not in text:
                    tail = c.recv_until_any([b"}"], timeout=5).decode("utf-8", "replace")
                    text += tail
                print(text, flush=True)
                break
            if "Try again" in text or "Sorry skipper" in text:
                print(text, flush=True)
                break

            if "Yay you won!" in text:
                wins += text.count("Yay you won!")
                print(f"[+] wins: {wins}", flush=True)
                state = None

            if text.endswith("Where is the battleship > "):
                attempts, grid = parse_last_board(text)
                if grid is None:
                    c.send_line("0 0")
                    continue

                n = len(grid)
                if state is None or state.n != n:
                    state = BoardState(n)

                state.update_from_grid(grid)
                r, col = state.next_guess()
                c.send_line(f"{r} {col}")

        # drain leftover
        # print any buffered leftover first
        if c.buf:
            print(c.buf.decode("utf-8", "replace"), end="", flush=True)
        try:
            sock.settimeout(1)
            while True:
                extra = sock.recv(8192)
                if not extra:
                    break
                print(extra.decode("utf-8", "replace"), end="", flush=True)
        except Exception:
            pass


if __name__ == "__main__":
    main()
```
<img width="685" height="150" alt="image" src="https://github.com/user-attachments/assets/7867a67e-8160-4013-be59-e5ce42626283" />

### Flag
`BCCTF{S0r7_0f_L1k3_SuD0ku}`

### Takeaway
In games of "chance," always look for deterministic patterns. Here, the combination of unique cell values and a restricted shuffling method (row/column permutation) turned an impossible guessing game into a solvable mapping problem.

---

## Write-up: The Brig

**Category:** Misc  
**Author:** Sean

---

### Challenge Overview
The challenge is `brig.py`, a Python script that implements a two-stage input system leading to a `double-eval` vulnerability. The goal is to achieve code execution to read the flag.

### Evidence Collected
- **Input 1:** Must be exactly 2 characters long. These two characters become the only allowed characters for the next input.
- **Input 2:** A string composed only of the two allowed characters.
- **Execution:** The script runs `print(eval(long_to_bytes(eval(inp))))`, where `inp` is the second input string.

### Analysis Path
This is a classic code injection challenge with a restricted character set.
1.  **Outer `eval`:** `eval(inp)` is executed first. Its goal is to produce an integer.
2.  **Conversion:** `long_to_bytes` converts that integer into a byte string.
3.  **Inner `eval`:** `eval(...)` is executed on the resulting byte string. This is our target for code execution.

The strategy is to make the byte string from step 2 be a piece of Python code that gives us further control, like `eval(input())`. The challenge is to construct the integer representing these bytes using only two characters.

### Recovery
1.  **Choose the Character Set:** The characters `1` and `+` were chosen. This allows constructing any integer via a sum of "repunit" numbers (e.g., `1`, `11`, `111`).
2.  **Construct the Payload:**
    a. The target Python code for the inner `eval` is `eval(input())`.
    b. The integer representation of this code was calculated: `N = int.from_bytes(b"eval(input())", "big")`.
    c. An expression for `N` was created using only `1` and `+` (e.g., `1111...+111...+...`). This became the payload for the second input.
3.  **Exploit Flow:**
    a. Send `1+` as the first input.
    b. Send the long repunit sum as the second input. The outer `eval` calculates it to `N`, `long_to_bytes` converts it to `b'eval(input())'`, and the inner `eval` executes it.
    c. The script now hangs on `input()`, waiting for the third stage of our payload.
    d. Send `open("/flag.txt").read()` as the final input. This is executed by `eval(input())`, and the flag is printed.

### Validation
- The multi-stage exploit successfully bypassed the character set restriction.
- The server executed the final payload and returned the content of `/flag.txt`.

### Flag
`BCCTF{1--1--1--1--111--111--1111_e1893d6cdf}`

### Takeaway
Character set restrictions can often be bypassed by encoding a payload. In Python's `eval`, if you can construct arbitrary integers, you can use `long_to_bytes` to create any desired code for a subsequent `eval`, achieving full code execution.
