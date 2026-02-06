# Write-up: NETCOM 4.0 - Sample Smuggling

**Category:** Network Forensics / Scripting  
**Files:** `traffics.pcapng`, `cart.py`  
**Goal:** Menemukan flag yang disembunyikan di dalam trafik jaringan.

## 1. Analisis Awal (Traffic Analysis)

Langkah pertama adalah menganalisis file `traffics.pcapng`. Ditemukan banyak paket UDP yang mencurigakan pada port **9890**. Payload dari paket-paket ini berisi data biner yang memiliki struktur header khusus.

Analisis lebih lanjut pada Hex Dump payload UDP menunjukkan pola berulang dengan string **"CART"** dan footer **"TRAC"**.

Berdasarkan referensi , **CaRT** adalah format file dari *Cybercentre Canada* untuk menyimpan malware secara aman. Struktur enkripsinya adalah:
1.  **Header**: Metadata + RC4 Key.
2.  **Encryption**: RC4.
3.  **Compression**: Zlib.

## 2. Temuan Anomali (Fragmentation)

Analisis payload CaRT menunjukkan bahwa setiap paket bukan satu file utuh, melainkan **fragmentasi** dari data yang lebih besar.

Setiap payload CaRT yang berhasil didekripsi ternyata berisi **potongan script Python** pendek, contohnya:
```python
import sys
dojLafKU = 40
EmRZOiPD = 92
zaWlhmEL = dojLafKU ^ EmRZOiPD
sys.stdout.write(chr(zaWlhmEL))
```
Script ini melakukan operasi XOR (`^`) pada dua angka untuk menghasilkan **satu karakter ASCII**. Ini berarti bendera (flag) dipecah menjadi karakter per karakter, di mana setiap paket UDP membawa satu karakter.

## 3. Masalah Pengurutan (Ordering)

Karena ini berasal dari trafik UDP (yang tidak menjamin urutan), posisi paket mungkin tidak teratur. Kita perlu cara untuk mengurutkan karakter-karakter tersebut.

Dengan memeriksa byte tepat **sebelum** header `CART` (Offset -1 dari payload), ditemukan pola angka berurutan (0x00, 0x01, 0x02, dst).
*   **Hipotesis:** Byte sebelum header `CART` adalah index urutan karakter.

## 4. Solusi (Solver Script Native PCAP)

Untuk menyelesaikan tantangan ini secara menyeluruh, kita membuat script Python (`solve_pcap.py`) yang melakukan parsing langsung terhadap file PCAPNG, mengekstrak payload, mendekripsi CaRT, dan menyusun kembali flag.

**Langkah-langkah script:**
1.  **Parsing PCAPNG**: Membaca struktur file pcapng (Enhanced Packet Block).
2.  **Filter Paket**: Mencari paket UDP dengan destination port **9890**.
3.  **Ekstraksi Payload**: Mengambil data dari layer UDP.
4.  **Parsing CaRT**: Mengidentifikasi header, key, dan data terenkripsi.
5.  **Dekripsi & Dekompresi**: Melakukan RC4 decrypt dan Zlib decompress.
6.  **Ekstraksi Karakter**: Mengambil dua angka dari script Python dan melakukan XOR.
7.  **Reassembly**: Mengurutkan hasil berdasarkan index byte dan menggabungkannya.

### Script Solver

```python
import struct
import zlib
import re

# --- 1. Fungsi Dekripsi RC4 ---
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

# --- 2. Parser Sederhana PCAPNG & UDP ---
def parse_pcapng(file_path):
    with open(file_path, "rb") as f:
        data = f.read()

    offset = 0
    packets = []
    
    while offset < len(data):
        # Membaca Tipe Blok (4 byte) dan Panjang Blok (4 byte)
        try:
            block_type = struct.unpack("<I", data[offset:offset+4])[0]
            block_len = struct.unpack("<I", data[offset+4:offset+8])[0]
        except struct.error:
            break

        # Tipe 6 adalah Enhanced Packet Block (berisi data paket)
        if block_type == 6:
            # Mengambil Captured Length di offset 20
            cap_len = struct.unpack("<I", data[offset+20:offset+24])[0]
            # Data paket dimulai di offset 28
            packet_data = data[offset+28 : offset+28+cap_len]
            packets.append(packet_data)
        
        offset += block_len
        
    return packets

def parse_udp_payload(packet_data):
    # Asumsi: Ethernet Header (14 bytes) + IPv4 Header
    if len(packet_data) < 42: return None
    
    # Cek EtherType (0x0800 = IPv4)
    eth_type = struct.unpack(">H", packet_data[12:14])[0]
    ip_offset = 14
    
    # Handle VLAN (0x8100) jika ada
    if eth_type == 0x8100:
        eth_type = struct.unpack(">H", packet_data[16:18])[0]
        ip_offset = 18

    if eth_type != 0x0800: return None # Bukan IPv4

    # Parsing IP Header untuk mendapatkan Protocol dan Header Length
    ver_ihl = packet_data[ip_offset]
    ihl = (ver_ihl & 0x0F) * 4
    protocol = packet_data[ip_offset + 9]
    
    if protocol != 17: return None # 17 adalah UDP
    
    udp_offset = ip_offset + ihl
    
    # Parsing UDP Header
    dst_port = struct.unpack(">H", packet_data[udp_offset+2:udp_offset+4])[0]
    udp_len = struct.unpack(">H", packet_data[udp_offset+4:udp_offset+6])[0]
    
    # Payload dimulai setelah 8 byte header UDP
    payload_offset = udp_offset + 8
    payload = packet_data[payload_offset : payload_offset + (udp_len - 8)]
    
    return dst_port, payload

# --- 3. Logika Utama Solver ---
def solve_from_pcap(pcap_path):
    print(f"[*] Analyzing {pcap_path}...")
    try:
        raw_packets = parse_pcapng(pcap_path)
    except Exception as e:
        print(f"[!] Error parsing PCAPNG: {e}")
        return

    extracted_payloads = []
    
    # Filter paket UDP port 9890
    for pkt in raw_packets:
        res = parse_udp_payload(pkt)
        if res:
            dst_port, payload = res
            if dst_port == 9890:
                extracted_payloads.append(payload)

    print(f"[*] Found {len(extracted_payloads)} UDP packets on port 9890.")
    
    results = []
    
    # Proses setiap payload
    for payload in extracted_payloads:
        # Cari header CART
        cart_idx = payload.find(b"CART")
        if cart_idx == -1: continue
        
        # Ambil Index (1 byte sebelum CART)
        idx_byte = payload[cart_idx - 1] if cart_idx > 0 else 0
        
        # Parsing Header CART
        header = payload[cart_idx : cart_idx + 38]
        if len(header) < 38: continue
        
        arc4_key = header[14:30]
        try:
            opt_len = struct.unpack("<Q", header[30:38])[0]
        except:
            continue
        
        # Cari footer TRAC
        end_search = payload.find(b"TRAC", cart_idx)
        if end_search == -1: continue
        
        encrypted_chunk = payload[cart_idx + 38 + opt_len : end_search]
        
        try:
            # Dekripsi & Dekompresi
            decrypted = rc4_crypt(encrypted_chunk, arc4_key)
            decompressed = zlib.decompress(decrypted)
            text = decompressed.decode("utf-8", errors="ignore")
            
            # Ambil angka untuk XOR
            nums = re.findall(r"(\d+)", text)
            if len(nums) >= 2:
                char = chr(int(nums[0]) ^ int(nums[1]))
                results.append((idx_byte, char))
        except Exception:
            pass
            
    # Urutkan dan gabung
    results.sort(key=lambda x: x[0])
    flag = "".join([x[1] for x in results])
    
    print("\n[+] RECOVERED FLAG:")
    print("-" * 50)
    print(flag)
    print("-" * 50)

if __name__ == "__main__":
    solve_from_pcap("traffics.pcapng")
```

## 5. Hasil Akhir

Setelah menjalankan script di atas: `python solve_pcap.py`, kita mendapatkan flag lengkap:

**Flag:**
```
{found_this_cool_method_to_store_malwares_https://github.com/CybercentreCanada/cart}
```