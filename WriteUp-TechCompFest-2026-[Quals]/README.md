# Write-Up: TechCompFest 2026 - Mosquito

This challenge starts with a single file, `mosquito.pcap`. The primary objective is to analyze this network traffic capture to find a hidden flag.

## Challenge Attachment

- `mosquito.pcap`: The PCAP file containing all the network traffic for analysis.

## Initial Analysis

Upon opening `mosquito.pcap` in Wireshark, two main types of communication immediately stand out:

1.  **ELF File Transfer**: A TCP stream is observed transferring an ELF binary file.
2.  **MQTT Traffic**: There is significant communication using the MQTT protocol on TCP port 1883.

## Understanding MQTT

Before diving deeper, it's helpful to understand the protocol in play. **MQTT (Message Queuing Telemetry Transport)** is a lightweight messaging protocol designed for low-bandwidth, high-latency networks, making it ideal for IoT (Internet of Things) devices.

Key concepts relevant to this challenge include:
- **Publish/Subscribe Model**: Instead of a client-server model, MQTT uses a publish/subscribe pattern. Clients connect to a central server called a **broker**.
- **Broker**: The broker's job is to receive all messages from clients and then route those messages to other clients that have subscribed to receive them.
- **Topics**: Clients publish messages to specific "topics" (e.g., `factory/line1/temp`). Other clients can subscribe to these topics to receive any messages published to them.
- **CONNECT Packet**: When a client first connects to a broker, it sends a `CONNECT` message. This packet can contain authentication details like a username and password.
- **PUBLISH Packet**: To send a message, a client sends a `PUBLISH` packet containing the topic and the message payload.

In this challenge, we see clients publishing messages to topics like `factory/line3/ctrl`, and these messages appear to be encrypted.

## Stream Investigation

### 1. The ELF File Transfer

An early step is to extract the ELF file from the TCP stream. This can be done using Wireshark's "Follow TCP Stream" feature and saving the raw data. This extracted file is `mlaware` from the file listing.

<img width="956" height="100" alt="image" src="https://github.com/user-attachments/assets/c2a0df39-981f-4352-a446-cbf303c51543" />


## 2. The MQTT Traffic

Analyzing the MQTT traffic reveals the following pattern:
- **`CONNECT` Packet**: A connection packet is sent, which contains authentication credentials: a `username` and a `password`.
- **`PUBLISH` Packets**: Multiple publish packets are sent to various topics. The payload of these packets is a JSON object containing encrypted data in hexadecimal format under the `"data"` key.

The hypothesis from this is that the flag is hidden within these encrypted messages.

<img width="1150" height="120" alt="image" src="https://github.com/user-attachments/assets/77a2c644-4667-458a-9a6f-ca2002feca7c" />
<img width="974" height="130" alt="image" src="https://github.com/user-attachments/assets/76555c02-48f7-4668-8462-6b4079a7f758" />


## Reverse Engineering the Encryption Process

The next challenge is to figure out how to decrypt the payloads. The key and IV for decryption must be reverse-engineered. By observing data patterns (or perhaps from clues in the `mlaware` ELF file), the following scheme can be deduced:

-   **Algorithm**: AES-128 in CBC (Cipher Block Chaining) mode.
-   **Encryption Key**: The 16-byte key is derived from the SHA-256 hash of the MQTT `username`.
    -   `key = sha256(mqtt_user.encode())[:16]`
-   **Initialization Vector (IV)**: The 16-byte IV is derived from the SHA-256 hash of the MQTT `password` concatenated with the packet's Unix timestamp.
    -   `iv = sha256(f"{mqtt_pass}:{timestamp}".encode())[:16]`

## The Solution Script

To automate the decryption process, a Python script (`decript.py`) was created. This script performs the following steps:

1.  Reads the `mosquito.pcap` file using `scapy`.
2.  Finds the first MQTT `CONNECT` packet to extract the `username` and `password`.
3.  Iterates through all MQTT `PUBLISH` packets.
4.  For each packet, it extracts the encrypted data and the packet's timestamp.
5.  It reconstructs the `key` and `iv` according to the discovered scheme.
6.  It decrypts the payload using AES-128-CBC and prints the result.

Here is the code for the solution script:

```python
#!/usr/bin/env python3

import os

# Import with IPv6 disabled
import scapy.config
scapy.config.conf.ipv6_enabled = False

from scapy.all import rdpcap, TCP
import struct, json, hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

PCAP = "mosquito.pcap"
mqtt_user = None
mqtt_pass = None

def sha256(x):
    return hashlib.sha256(x).digest()

# ... (MQTT helper functions as in the original script) ...

def read_varlen(buf, i):
    mul = 1
    val = 0
    while True:
        b = buf[i]
        i += 1
        val += (b & 127) * mul
        if not (b & 128):
            return val, i
        mul *= 128

def extract_mqtt(buf):
    out = []
    i = 0
    while i + 2 <= len(buf):
        try:
            b0 = buf[i]
            rem, j = read_varlen(buf, i + 1)
            size = (j - i) + rem
            if i + size > len(buf):
                break
            out.append(buf[i:i+size])
            i += size
        except:
            break
    return out

def mqtt_connect(pkt):
    i = 1
    rem, i = read_varlen(pkt, i)
    body = pkt[i:i+rem]
    # skip protocol name
    pn_len = struct.unpack("!H", body[:2])[0]
    p = 2 + pn_len
    flags = body[p+1]
    p += 4
    def read_str(p):
        l = struct.unpack("!H", body[p:p+2])[0]
        p += 2
        s = body[p:p+l]
        return s, p+l
    _, p = read_str(p)  # client id
    if flags & 0x04:    # will flag
        _, p = read_str(p)
        _, p = read_str(p)
    user = pw = None
    if flags & 0x80:
        user, p = read_str(p)
    if flags & 0x40:
        pw, p = read_str(p)
    return user, pw

def mqtt_publish(pkt):
    i = 1
    rem, i = read_varlen(pkt, i)
    body = pkt[i:i+rem]
    tlen = struct.unpack("!H", body[:2])[0]
    topic = body[2:2+tlen].decode(errors="ignore")
    payload = body[2+tlen:]
    return topic, payload
    
if __name__ == "__main__":
    print("[*] Loading PCAP file:", PCAP)
    pkts = rdpcap(PCAP)
    print(f"[*] Loaded {len(pkts)} packets")
    
    for p in pkts:
        if not p.haslayer(TCP):
            continue
        tcp = p[TCP]
        if tcp.sport != 1883 and tcp.dport != 1883:
            continue
        if not bytes(tcp.payload):
            continue
        raw = bytes(tcp.payload)
        for mp in extract_mqtt(raw):
            ptype = mp[0] >> 4
            # -------- CONNECT --------
            if ptype == 1 and mqtt_user is None:
                try:
                    u, pw = mqtt_connect(mp)
                    mqtt_user = u.decode()
                    mqtt_pass = pw.decode()
                    print("[+] MQTT USER:", mqtt_user)
                    print("[+] MQTT PASS:", mqtt_pass)
                except:
                    pass
            # -------- PUBLISH --------
            if ptype == 3 and mqtt_user:
                try:
                    topic, payload = mqtt_publish(mp)
                    idx = payload.find(b"{ ")
                    if idx == -1:
                        continue
                    obj = json.loads(payload[idx:].decode())
                    if "data" not in obj:
                        continue
                    ts = int(p.time)
                    iv = sha256(f"{mqtt_pass}:{ts}".encode())[:16]
                    key = sha256(mqtt_user.encode())[:16]
                    blob = bytes.fromhex(obj["data"])
                    if len(blob) % 16 != 0:
                        blob = blob[16:]
                    pt = AES.new(key, AES.MODE_CBC, iv).decrypt(blob)
                    try:
                        pt = unpad(pt, 16)
                    except:
                        pass
                    print("\n==============================")
                    print("[*] time :", ts)
                    print("[*] topic:", topic)
                    try:
                        print(pt.decode())
                    except:
                        print(pt)
                except Exception as e:
                    continue
    
    print("\n[*] Done!")
```

### Running the Script to Get the Flag

By running the script, the flag will be revealed from the successfully decrypted messages.

```sh
python decript.py
```

