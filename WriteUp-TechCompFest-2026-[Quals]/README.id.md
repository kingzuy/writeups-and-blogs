# Write-Up: TechCompFest 2026 - Mosquito

Tantangan ini dimulai dengan satu file, `mosquito.pcap`. Tujuan utamanya adalah untuk menganalisis network traffic capture ini untuk menemukan flag yang tersembunyi.

## File Attachment

- `mosquito.pcap`: File PCAP yang berisi semua lalu lintas jaringan untuk dianalisis.

## Analisis Awal

Saat membuka `mosquito.pcap` di Wireshark, dua jenis komunikasi utama langsung menonjol:

1.  **Transfer File ELF**: Terlihat sebuah stream TCP yang mentransfer file biner ELF.
2.  **Lalu Lintas MQTT**: Terdapat komunikasi yang signifikan menggunakan protokol MQTT pada port TCP 1883.

## Memahami MQTT

Sebelum mendalami lebih jauh, ada baiknya kita memahami protokol yang digunakan. **MQTT (Message Queuing Telemetry Transport)** adalah protokol messaging yang ringan yang dirancang untuk jaringan dengan bandwidth rendah dan latensi tinggi, sehingga ideal untuk perangkat IoT (Internet of Things).

Konsep-konkonsep kunci yang relevan dengan tantangan ini meliputi:
- **Model Publish/Subscribe**: Alih-alih model client-server, MQTT menggunakan pola publish/subscribe. Klien terhubung ke server pusat yang disebut **broker**.
- **Broker**: Tugas broker adalah menerima semua pesan dari klien dan kemudian menyalurkan pesan tersebut ke klien lain yang telah melakukan subscribe untuk menerimanya.
- **Topics**: Klien melakukan publish pesan ke "topics" tertentu (misalnya, `factory/line1/temp`). Klien lain dapat melakukan subscribe pada topics ini untuk menerima pesan apa pun yang di-publish ke sana.
- **Paket `CONNECT`**: Saat klien pertama kali terhubung ke broker, ia mengirimkan pesan `CONNECT`. Paket ini dapat berisi detail otentikasi seperti username dan password.
- **Paket `PUBLISH`**: Untuk mengirim pesan, klien mengirimkan paket `PUBLISH` yang berisi topic dan message payload.

Dalam tantangan ini, kita melihat klien mem-publish pesan ke topics seperti `factory/line3/ctrl`, dan pesan-pesan ini tampaknya dienkripsi.

## Investigasi Aliran

### 1. Transfer File ELF

Langkah awal adalah mengekstrak file ELF dari stream TCP. Ini dapat dilakukan dengan menggunakan fitur "Follow TCP Stream" di Wireshark dan menyimpan data mentahnya. File yang diekstrak ini adalah `mlaware` dari daftar file.

### 2. Lalu Lintas MQTT

Menganalisis lalu lintas MQTT mengungkapkan pola berikut:
- **Paket `CONNECT`**: Sebuah paket koneksi dikirim, yang berisi kredensial otentikasi: `username` dan `password`.
- **Paket `PUBLISH`**: Beberapa paket publikasi dikirim ke berbagai topics. Payload dari paket-paket ini adalah objek JSON yang berisi data terenkripsi dalam format heksadesimal di bawah kunci `"data"`.

Hipotesis dari sini adalah bahwa flag tersembunyi di dalam pesan-pesan terenkripsi ini.

## Reverse Engineering Proses Enkripsi

Tantangan berikutnya adalah mencari tahu cara mendekripsi payload tersebut. Key dan IV untuk dekripsi harus di-reverse engineering. Dengan mengamati pola data (atau mungkin dari petunjuk di file ELF `mlaware`), skema berikut dapat disimpulkan:

-   **Algoritma**: AES-128 dalam mode CBC (Cipher Block Chaining).
-   **Encryption Key (Key)**: Kunci 16-byte berasal dari hash SHA-256 dari `username` MQTT.
    -   `key = sha256(mqtt_user.encode())[:16]`
-   **Initialization Vector (IV)**: IV 16-byte berasal dari hash SHA-256 dari `password` MQTT yang digabungkan dengan timestamp Unix dari paket.
    -   `iv = sha256(f"{mqtt_pass}:{timestamp}".encode())[:16]`

## Skrip Solusi

Untuk mengotomatiskan proses dekripsi, sebuah skrip Python (`decript.py`) dibuat. Skrip ini melakukan langkah-langkah berikut:

1.  Membaca file `mosquito.pcap` menggunakan `scapy`.
2.  Menemukan paket `CONNECT` MQTT pertama untuk mengekstrak `username` dan `password`.
3.  Melakukan iterasi melalui semua paket `PUBLISH` MQTT.
4.  Untuk setiap paket, ia mengekstrak data terenkripsi dan timestamp paket.
5.  Ia merekonstruksi `key` dan `iv` sesuai dengan skema yang ditemukan.
6.  Ia mendekripsi payload menggunakan AES-128-CBC dan mencetak hasilnya.

Berikut adalah kode dari skrip solusi tersebut:

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

# ... (Fungsi helper MQTT seperti di skrip asli) ...

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

 menjalankan skrip
```sh
python decript.py
```
