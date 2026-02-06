
# Write-up: NETCOMP 4.0 [Quals] – Sample Smuggling

**Category:** Network Forensics / Scripting
**Files:** `traffics.pcapng`
**Goal:** Recover the hidden flag from captured network traffic.

---

## 1. Initial Analysis (Traffic Analysis)

The first step was analyzing the `traffics.pcapng` file. A large number of suspicious UDP packets were observed on port **9890**. The payloads of these packets contained binary data with a distinctive custom header structure.

Further inspection of the UDP payloads using a hex dump revealed repeating patterns with the string **"CART"** as a header and **"TRAC"** as a footer.

Based on external references, **CaRT** is a file format developed by *Cybercentre Canada* for securely storing malware samples. Its structure consists of:

1. **Header**: Metadata and RC4 key
2. **Encryption**: RC4
3. **Compression**: Zlib

---

## 2. Anomaly Discovery (Fragmentation)

Analysis of the CaRT payloads showed that each packet did not contain a complete file, but rather a **fragment** of a larger dataset.

After decrypting each CaRT payload, it was discovered that each fragment contained a **short Python script**, for example:

```python
import sys
dojLafKU = 40
EmRZOiPD = 92
zaWlhmEL = dojLafKU ^ EmRZOiPD
sys.stdout.write(chr(zaWlhmEL))
```

Each script performs an XOR operation (`^`) on two integers to produce **a single ASCII character**. This indicates that the flag was split character-by-character, with each UDP packet carrying exactly one character.

---

## 3. Ordering Problem

Since the data was transmitted over UDP, packet order is not guaranteed. Therefore, the extracted characters may not be in the correct sequence.

By examining the byte located **immediately before** the `CART` header (offset `-1` from the payload), a pattern of sequential values was observed (0x00, 0x01, 0x02, etc.).

* **Hypothesis:** The byte preceding the `CART` header represents the index of the character in the original flag.

---

## 4. Solution (Native PCAP Solver Script)

To fully solve the challenge, a Python script (`solve_pcap.py`) was created to directly parse the PCAPNG file, extract the payloads, decrypt the CaRT data, and reassemble the flag.

### Script Workflow

1. **PCAPNG Parsing**: Read the PCAPNG structure (Enhanced Packet Blocks).
2. **Packet Filtering**: Select UDP packets with destination port **9890**.
3. **Payload Extraction**: Extract data from the UDP layer.
4. **CaRT Parsing**: Identify headers, keys, and encrypted data.
5. **Decryption & Decompression**: Perform RC4 decryption and Zlib decompression.
6. **Character Extraction**: Extract two integers from the Python script and XOR them.
7. **Reassembly**: Sort characters using the index byte and concatenate them.

### Solver Script

```python
import struct
import zlib
import re

# --- 1. RC4 Decryption Function ---
def rc4_crypt(data, key):
    x = 0
    box = list(range(256))
    for i in range(256):
        x = (x + box[i] + key[i % len(key)]) % 256
        box[i], box[x] = box[x], box[i]
    x = y = 0
    out = bytearray()
    for char in data:
        x = (x + 1) % 256
        y = (y + box[x]) % 256
        box[x], box[y] = box[y], box[x]
        out.append(char ^ box[(box[x] + box[y]) % 256])
    return out

# --- 2. Simple PCAPNG & UDP Parser ---
def parse_pcapng(file_path):
    with open(file_path, "rb") as f:
        data = f.read()

    offset = 0
    packets = []
    
    while offset < len(data):
        try:
            block_type = struct.unpack("<I", data[offset:offset+4])[0]
            block_len = struct.unpack("<I", data[offset+4:offset+8])[0]
        except struct.error:
            break

        # Block type 6 = Enhanced Packet Block
        if block_type == 6:
            cap_len = struct.unpack("<I", data[offset+20:offset+24])[0]
            packet_data = data[offset+28 : offset+28+cap_len]
            packets.append(packet_data)
        
        offset += block_len
        
    return packets

def parse_udp_payload(packet_data):
    if len(packet_data) < 42:
        return None
    
    eth_type = struct.unpack(">H", packet_data[12:14])[0]
    ip_offset = 14
    
    if eth_type == 0x8100:  # VLAN
        eth_type = struct.unpack(">H", packet_data[16:18])[0]
        ip_offset = 18

    if eth_type != 0x0800:
        return None

    ver_ihl = packet_data[ip_offset]
    ihl = (ver_ihl & 0x0F) * 4
    protocol = packet_data[ip_offset + 9]
    
    if protocol != 17:
        return None
    
    udp_offset = ip_offset + ihl
    dst_port = struct.unpack(">H", packet_data[udp_offset+2:udp_offset+4])[0]
    udp_len = struct.unpack(">H", packet_data[udp_offset+4:udp_offset+6])[0]
    
    payload_offset = udp_offset + 8
    payload = packet_data[payload_offset : payload_offset + (udp_len - 8)]
    
    return dst_port, payload

# --- 3. Main Solver Logic ---
def solve_from_pcap(pcap_path):
    print(f"[*] Analyzing {pcap_path}...")
    
    raw_packets = parse_pcapng(pcap_path)
    extracted_payloads = []
    
    for pkt in raw_packets:
        res = parse_udp_payload(pkt)
        if res:
            dst_port, payload = res
            if dst_port == 9890:
                extracted_payloads.append(payload)

    print(f"[*] Found {len(extracted_payloads)} UDP packets on port 9890.")
    
    results = []
    
    for payload in extracted_payloads:
        cart_idx = payload.find(b"CART")
        if cart_idx == -1:
            continue
        
        idx_byte = payload[cart_idx - 1] if cart_idx > 0 else 0
        header = payload[cart_idx : cart_idx + 38]
        if len(header) < 38:
            continue
        
        arc4_key = header[14:30]
        opt_len = struct.unpack("<Q", header[30:38])[0]
        end_search = payload.find(b"TRAC", cart_idx)
        if end_search == -1:
            continue
        
        encrypted_chunk = payload[cart_idx + 38 + opt_len : end_search]
        
        try:
            decrypted = rc4_crypt(encrypted_chunk, arc4_key)
            decompressed = zlib.decompress(decrypted)
            text = decompressed.decode("utf-8", errors="ignore")
            nums = re.findall(r"(\d+)", text)
            if len(nums) >= 2:
                char = chr(int(nums[0]) ^ int(nums[1]))
                results.append((idx_byte, char))
        except:
            pass
            
    results.sort(key=lambda x: x[0])
    flag = "".join(x[1] for x in results)
    
    print("\n[+] RECOVERED FLAG:")
    print("-" * 50)
    print(flag)
    print("-" * 50)

if __name__ == "__main__":
    solve_from_pcap("traffics.pcapng")
```

---

## 5. Final Result

After running the solver script with:

```bash
python solve_pcap.py
```

The complete flag was successfully recovered:

```
{found_this_cool_method_to_store_malwares_https://github.com/CybercentreCanada/cart}
```

