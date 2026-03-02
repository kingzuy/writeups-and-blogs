
## Write-up: baby serial

**Category:** Forensics  
**Author:** Anonimbus

---

### Challenge Overview
Diberikan file capture serial bernama `babyserial.sal` dengan deskripsi:

> Joe was trying to sniff the data over a serial communication. Was he successful?

Target akhirnya adalah menemukan flag format `EH4X{...}`.

### Evidence Collected
- File utama: `baby serial/babyserial.sal`
- `.sal` ternyata archive (ZIP container), bukan file biner tunggal.
- Setelah diekstrak, terdapat:
  - `meta.json`
  - `digital-0.bin` s.d. `digital-7.bin`
- Dari `meta.json`:
  - Sample rate digital: **1,000,000 Sa/s**
  - Tidak ada analyzer yang sudah dipasang (UART belum didecode otomatis).
- Aktivitas sinyal nyata hanya di **channel 0** (`digital-0.bin` berukuran besar; channel lain hampir kosong).

### Analysis Path
1. Rename/copy `babyserial.sal` menjadi `.zip`, lalu extract.
2. Parse format internal `digital-0.bin` (Saleae run-length encoded digital transitions).
3. Rekonstruksi level logika terhadap waktu dari run durations.
4. Cari edge start-bit (high -> low), lalu brute-force parameter UART:
   - 8 data bits, no parity, 1 stop bit (8N1)
   - baud sekitar **115200** (hasil sampling efektif sekitar 8.4 sample/bit)
5. Hasil decode UART berupa teks yang hampir sepenuhnya Base64.
6. Base64 didecode menjadi image payload (PNG terpotong di header/trailer, tapi isi tetap bisa dibaca).
7. Gambar menampilkan flag.

### Recovery
Payload hasil decode menampilkan teks:

<img width="964" height="385" alt="2026-03-02_08-44-31" src="https://github.com/user-attachments/assets/4bfb25a8-437f-4c88-b69c-f9fbe5141cda" />
`EH4X{baby_U4rt}`

### Validation
- Format flag sesuai requirement challenge: `EH4X{...}`
- Konten flag konsisten dengan tema challenge serial/UART.
- Decode mode lain/parameter baud yang meleset menghasilkan output rusak/garbled.

### Flag
`EH4X{baby_U4rt}`

### Takeaway
File `.sal` forensics sering butuh decoding sinyal mentah manual jika analyzer belum diset. Untuk kasus serial:
- cek sample rate,
- rekonstruksi transition timing,
- lalu brute-force parameter UART (baud/phase/invert) sampai payload terbaca.

---

## Write-up: let-the-penguin-live

**Category:** Forensics  
**Author:** mahekfr

---

### Challenge Overview
Diberikan file video `let-the-penguin-live/challenge.mkv` dengan hint:

> In a colony of many, one penguin's path is an anomaly. Silence the crowd to hear the individual.

Hint ini mengarah ke pemrosesan **selisih antar track audio** untuk memunculkan sinyal tersembunyi.

### Evidence Collected
- `challenge.mkv` memiliki dua audio track utama (stereo dan surround).
- Saat dianalisis terpisah, keduanya berisi ambience/keramaian yang sangat mirip.
- Terdapat string `EH4X{k33p_try1ng}` pada artefak lain, namun ini **decoy**.

### Analysis Path
1. Extract kedua audio track dari MKV ke WAV (`stereo.wav` dan `surround.wav`).
2. Convert ke mono dan align panjang sample.
3. Lakukan crowd cancellation:
   - `diff = stereo - surround`
4. Dari hasil difference, fokus ke burst sinyal sekitar **25.35s - 27.25s**.
5. Render spectrogram burst (NFFT besar, kontras tinggi) untuk membaca teks yang ter-embed.
6. Teks pada spectrogram menghasilkan flag final.

### Recovery
Flag asli terbaca dari spectrogram hasil difference audio:

<img width="957" height="328" alt="image" src="https://github.com/user-attachments/assets/fcbaca23-5685-4d48-94eb-9d3a553b1e11" />
`EH4X{0n3_tr4ck_m1nd_tw0_tr4ck_F1les}`

### Validation
- Format sesuai `EH4X{...}`.
- Konsisten dengan hint challenge:
  - "silence the crowd" -> membatalkan komponen sama di kedua track.
  - "one penguin's path" -> sinyal anomali tersisa pada selisih.
- Pembacaan final paling jelas pada grid spectrogram `let-the-penguin-live/grid_n1024_h16.png`.
- String `EH4X{k33p_try1ng}` terbukti hanya jebakan.

### Flag
`EH4X{0n3_tr4ck_m1nd_tw0_tr4ck_F1les}`

### Solver
Solver Python :
```
#!/usr/bin/env python3
"""
Solver for EHAX CTF - let-the-penguin-live

Strategy:
1. Use two audio tracks from challenge.mkv (or existing stereo.wav/surround.wav).
2. Subtract one track from the other to isolate the anomaly ("one penguin").
3. Render spectrogram around the burst window where text is embedded.
4. Read the flag from generated image.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import wave
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np


def extract_track_if_needed(mkv_path: Path, out_wav: Path, track_idx: int) -> None:
    if out_wav.exists():
        return
    ffmpeg = shutil.which("ffmpeg")
    if ffmpeg is None:
        raise RuntimeError(
            f"{out_wav.name} not found and ffmpeg is not available in PATH."
        )
    cmd = [
        ffmpeg,
        "-y",
        "-i",
        str(mkv_path),
        "-map",
        f"0:a:{track_idx}",
        "-ac",
        "1",
        "-ar",
        "48000",
        "-c:a",
        "pcm_s16le",
        str(out_wav),
    ]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def read_wav_mono(path: Path) -> tuple[np.ndarray, int]:
    with wave.open(str(path), "rb") as wf:
        channels = wf.getnchannels()
        sample_rate = wf.getframerate()
        sample_width = wf.getsampwidth()
        raw = wf.readframes(wf.getnframes())

    if sample_width != 2:
        raise ValueError(f"Unsupported sample width in {path.name}: {sample_width * 8}-bit")

    data = np.frombuffer(raw, dtype=np.int16).astype(np.float32)
    if channels > 1:
        data = data.reshape(-1, channels).mean(axis=1)
    data /= 32768.0
    return data, sample_rate


def write_wav_mono(path: Path, data: np.ndarray, sample_rate: int) -> None:
    x = np.clip(data, -1.0, 1.0)
    pcm = (x * 32767.0).astype(np.int16)
    with wave.open(str(path), "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sample_rate)
        wf.writeframes(pcm.tobytes())


def main() -> None:
    parser = argparse.ArgumentParser(description="Solve let-the-penguin-live from audio track difference.")
    parser.add_argument("--input", default="challenge.mkv", help="Input MKV file")
    parser.add_argument("--start", type=float, default=25.35, help="Burst start time (seconds)")
    parser.add_argument("--end", type=float, default=27.25, help="Burst end time (seconds)")
    parser.add_argument("--nfft", type=int, default=4096, help="FFT size for spectrogram")
    args = parser.parse_args()

    base = Path(__file__).resolve().parent
    mkv = base / args.input
    stereo_wav = base / "stereo.wav"
    surround_wav = base / "surround.wav"

    if not stereo_wav.exists() or not surround_wav.exists():
        if not mkv.exists():
            raise FileNotFoundError("Need challenge.mkv or pre-extracted stereo.wav/surround.wav")
        extract_track_if_needed(mkv, stereo_wav, 0)
        extract_track_if_needed(mkv, surround_wav, 1)

    stereo, sr0 = read_wav_mono(stereo_wav)
    surround, sr1 = read_wav_mono(surround_wav)
    if sr0 != sr1:
        raise ValueError(f"Sample rates differ: {sr0} vs {sr1}")

    n = min(len(stereo), len(surround))
    stereo = stereo[:n]
    surround = surround[:n]

    # Crowd cancellation: isolate hidden signal by track difference.
    diff = stereo - surround
    peak = np.max(np.abs(diff))
    if peak > 0:
        diff /= peak

    diff_wav = base / "solver_diff.wav"
    write_wav_mono(diff_wav, diff, sr0)

    i0 = max(0, int(args.start * sr0))
    i1 = min(len(diff), int(args.end * sr0))
    burst = diff[i0:i1]

    if burst.size == 0:
        raise ValueError("Empty burst segment. Check --start/--end values.")

    spec_path = base / "solver_spec.png"
    plt.figure(figsize=(20, 8))
    plt.specgram(burst, NFFT=args.nfft, Fs=sr0, noverlap=args.nfft - args.nfft // 8, cmap="gray_r")
    plt.ylim(0, 6500)
    plt.xlabel("Time (s)")
    plt.ylabel("Frequency (Hz)")
    plt.title("let-the-penguin-live: diff-track burst spectrogram")
    plt.tight_layout()
    plt.savefig(spec_path, dpi=220)
    plt.close()

    print(f"[+] Wrote diff audio: {diff_wav}")
    print(f"[+] Wrote spectrogram: {spec_path}")

if __name__ == "__main__":
    main()
```

Jalankan dari folder challenge:
```bash
python solver.py
```

Output utama:
- `solver_diff.wav` (audio hasil selisih)
- `solver_spec.png` (spectrogram untuk pembacaan)

---

## Write-up: painter

**Category:** Forensics  
**Author:** stapat

---

### Challenge Overview
Challenge memberikan file network capture `painter/pref.pcap` dengan hint bahwa ada "painter" yang mencoba menipu employee, serta format flag `EH4X{...}`.

### Evidence Collected
- `pref.pcap` bukan traffic TCP/HTTP biasa, melainkan capture USB (`usbmon`).
- Seluruh paket berisi USB interrupt transfer dengan payload `usb.capdata` panjang tetap (7 byte).
- Field report terlihat seperti:
  - byte state/pen (`0`, `1`, `2`)
  - delta koordinat X dan Y signed 16-bit little-endian

### Analysis Path
1. Parse paket dengan `tshark` (di WSL), ambil `usb.capdata`.
2. Decode setiap report:
   - `state = b[1]`
   - `dx = int16_le(b[2:4])`
   - `dy = int16_le(b[4:6])`
3. Rekonstruksi jalur pointer dengan akumulasi:
   - `x += dx`
   - `y += dy`
4. Plot lintasan berdasarkan state untuk memisahkan stroke.
5. Hasil plotting membentuk tulisan tangan yang terbaca sebagai isi flag.

### Recovery
Tulisan hasil rekonstruksi menghasilkan flag:

<img width="953" height="412" alt="image" src="https://github.com/user-attachments/assets/8ad17800-c9a1-46a2-a4f8-bb2f4a054160" />
`EH4X{wh4t_c0l0ur_15_th3_fl4g}`

### Validation
- Format sesuai `EH4X{...}`.
- String terbaca konsisten setelah jalur dipisah per state dan noise garis transisi dihilangkan.
- Flag ini cocok dengan konteks challenge "painter" (data gerakan stylus/mouse membentuk tulisan).

### Flag
`EH4X{wh4t_c0l0ur_15_th3_fl4g}`

### Solver  
Solver Python :
```
import subprocess
import numpy as np
import matplotlib.pyplot as plt

out = subprocess.check_output([
    'wsl','-e','bash','-lc',
    'tshark -r /mnt/e/ctf/ehax/painter/pref.pcap -T fields -e usb.capdata'
], text=True)

rows = []
for s in out.splitlines():
    s = s.strip()
    if not s:
        continue
    b = bytes.fromhex(s)
    st = b[1]
    dx = int.from_bytes(b[2:4], 'little', signed=True)
    dy = int.from_bytes(b[4:6], 'little', signed=True)
    rows.append((st, dx, dy))

pts = []
x = 0
y = 0
for st, dx, dy in rows:
    x += dx
    y += dy
    pts.append((x, y, st))

arr = np.array(pts)

plt.figure(figsize=(14, 6))
for st, c in [(0, '#999999'), (1, '#ff0066'), (2, '#00aaff')]:
    m = arr[:, 2] == st
    plt.scatter(arr[m, 0], -arr[m, 1], s=1, c=c, label=f'st{st}', alpha=0.6)
plt.legend()
plt.axis('equal')
plt.tight_layout()
plt.savefig(r'e:/ctf/ehax/painter/path_scatter.png', dpi=200)
plt.close()

plt.figure(figsize=(14, 6))
for st, c in [(1, '#ff0066'), (2, '#00aaff')]:
    m = arr[:, 2] == st
    plt.plot(arr[m, 0], -arr[m, 1], '.', ms=1, c=c, alpha=0.8)
plt.axis('equal')
plt.tight_layout()
plt.savefig(r'e:/ctf/ehax/painter/path_draw_states12.png', dpi=200)
plt.close()

print('done', arr.shape)
```
---

## Write-up: Lost in Waves

**Category:** Forensics   
**Author:** Anonimbus

---

### Challenge Overview
Challenge memberi paket `Lost in Waves/chall.zip` dengan hint:

> Taru got an intel that a package containing classified documents is being moved in covert channels.

Clue ini mengarah ke data tersembunyi lewat channel bertahap (bukan satu file langsung).

### Evidence Collected
- `chall.zip` berisi:
  - `0.sal`
  - `data` (ASCII hex panjang)
- Dari `0.sal` (Saleae Logic capture), analyzer Async Serial mengarah ke pesan yang berisi password:
  - `ohblimey**ehax`
- File `data` adalah hex stream yang jika dikonversi menghasilkan archive terenkripsi:
  - `data.rar`
- `data.rar` (password di atas) mengekstrak:
  - `1.wav`, `2.wav`, `3.wav`, `4.wav`

### Analysis Path
1. Ekstrak `0.sal`, baca komunikasi serial, ambil password `ohblimey**ehax`.
2. Konversi file `data` (hex text) ke biner lalu identifikasi sebagai RAR.
3. Ekstrak `data.rar` pakai password tadi, dapat empat file WAV.
4. Cek spektrogram: terlihat burst data terstruktur, bukan audio natural.
5. Uji decoder radio/modem pada WAV hasil ekstraksi.
6. Decode berhasil dengan `POCSAG1200` memakai `multimon-ng`.

Contoh command decode final:

```bash
sox concat.wav -t raw -e signed-integer -b 16 -r 22050 -c 1 - | multimon-ng -t raw -a POCSAG1200 -
```
<img width="994" height="260" alt="image" src="https://github.com/user-attachments/assets/501906db-bb74-4eeb-b593-ff834d17f327" />

### Recovery
Output `POCSAG1200` memuat pesan teks:

`Passwordz EH4X{P4g3d_lik3_a_b00k}. Keep it hush, yeah?`

### Validation
- Format sesuai `EH4X{...}`.
- Flag muncul konsisten pada output POCSAG message.
- Metode cocok dengan hint “covert channels”:
  - serial channel -> password,
  - archive terproteksi -> audio channel,
  - pager payload (POCSAG) -> flag.

### Flag
`EH4X{P4g3d_lik3_a_b00k}`

---

## Write-up: Power Leak
**Category:** Forensic  
**Points:** 267  
**Author:** tanishfr

---

### Challenge Overview

Challenge memberikan file `power_traces.csv` dengan hint:

> Power reveals the secret.  
> `EHAX{SHA256(secret)}`

Clue ini mengarahkan ke **power side-channel attack** — teknik mengekstrak secret dengan menganalisis konsumsi daya perangkat saat melakukan komputasi.

### Evidence Collected

- `power_traces.csv` — dataset power traces dengan kolom:
  - `position` (0–5): posisi digit dalam secret (6 digit total)
  - `guess` (0–9): kandidat digit yang diuji
  - `trace_num` (0–19): nomor pengulangan trace
  - `sample` (0–49): titik waktu sampling
  - `power_mW`: konsumsi daya dalam milliwatt

Total: **60.000 baris** (6 × 10 × 20 × 50)

### Analysis Path

#### 1. Memahami Struktur Data

Dataset mensimulasikan skenario di mana perangkat memverifikasi secret digit per digit. Untuk setiap posisi, 10 kandidat digit (0–9) diuji masing-masing sebanyak 20 kali, dengan 50 titik sampling per trace.

```
6 posisi × 10 guess × 20 trace × 50 sample = 60.000 baris
```

#### 2. Identifikasi Metode Serangan

Ini adalah **Simple Power Analysis (SPA)** — bukan korelasi statistik kompleks, melainkan pencarian **spike daya** yang mencolok pada titik waktu tertentu.

Hipotesis: ketika guess **benar**, perangkat melakukan komputasi tambahan (misalnya, perbandingan berhasil lalu lanjut ke langkah berikutnya), yang menghasilkan **lonjakan daya signifikan** di sample tertentu.

#### 3. Menemukan Spike

Dengan menghitung rata-rata daya per `(position, guess, sample)` lalu mencari outlier:

```python
import csv, numpy as np
from collections import defaultdict

data = []
with open('power_traces.csv') as f:
    reader = csv.DictReader(f)
    for row in reader:
        data.append((int(row['position']), int(row['guess']),
                     int(row['trace_num']), int(row['sample']), float(row['power_mW'])))

power_matrix = defaultdict(lambda: defaultdict(lambda: np.zeros((20, 50))))
for pos, guess, trace, sample, pw in data:
    power_matrix[pos][guess][trace][sample] = pw
```

Pada **sample ke-20 dan 21**, ditemukan satu guess per posisi yang memiliki daya jauh di atas yang lain (~78–80 mW vs ~73–77 mW untuk guess yang salah):

| Position | Winner Guess | Power (mW) | Runner-up (mW) | Margin |
|----------|-------------|------------|----------------|--------|
| 0        | **7**       | 79.20      | 76.92          | +2.28  |
| 1        | **9**       | 79.44      | 76.24          | +3.20  |
| 2        | **2**       | 78.13      | 75.38          | +2.75  |
| 3        | **9**       | 78.67      | 76.32          | +2.35  |
| 4        | **6**       | 78.92      | 77.20          | +1.72  |
| 5        | **3**       | 79.98      | 76.44          | +3.54  |

#### 4. Ekstraksi Secret

Digit dengan spike tertinggi di tiap posisi digabung menjadi:

```
secret = "792963"
```

#### 5. Konstruksi Flag

```python
import hashlib
secret = "792963"
h = hashlib.sha256(secret.encode()).hexdigest()
print(f"EHAX{{{h}}}")
```


### Recovery

```
Secret  : 792963
SHA256  : 5bec84ad039e23fcd51d331e662e27be15542ca83fd8ef4d6c5e5a8ad614a54d
```

### Flag

`EHAX{5bec84ad039e23fcd51d331e662e27be15542ca83fd8ef4d6c5e5a8ad614a54d}`

---

### Key Takeaway

Power side-channel bekerja karena **perangkat yang memproses data rahasia bocorkan informasi melalui konsumsi daya**. Dalam challenge ini, guess yang benar menyebabkan spike daya sekitar **3–5 mW lebih tinggi** dari guess yang salah — cukup untuk diekstrak secara visual dari rata-rata trace.

Metode yang digunakan: **Simple Power Analysis (SPA)** dengan observasi langsung pada distribusi daya per sample point.

---

## Write-up: Quantum Message

**Category:** Forensics  
**Points:** 431  
**Author:** stapat

---

### Challenge Overview
Challenge memberikan audio `Quantum Message/challenge.wav` dengan clue:

> my quantum physics professor was teaching us about 1-D harmonic oscillator , he gave me a problem in which the angular frequency was 57 1035 (weird number) and it asked to calculate the energy eigenvalues, then he called someone , who did he call?

Target akhir: menemukan flag format `EH4X{...}`.

### Evidence Collected
- File utama: `Quantum Message/challenge.wav`
- Format audio: mono, 44.1 kHz, durasi ~81.6 detik.
- Spektrogram menunjukkan pola nada diskrit berulang, bukan suara natural.
- Dalam domain frekuensi, komponen dominan muncul di grup:
  - Low group: `300, 900, 1500, 2100` Hz
  - High group: `2700, 3300, 3900` Hz

### Analysis Path
1. Bagi audio menjadi 80 slot waktu yang sama panjang (~1.02 s/slot).
2. Untuk setiap slot, cari puncak frekuensi terkuat di low-group dan high-group.
3. Map pasangan (low, high) ke layout keypad (DTMF-like custom):

```text
low\high  2700 3300 3900
300          1    2    3
900          4    5    6
1500         7    8    9
2100         *    0    #
```

4. Hasil mapping menghasilkan stream digit:

```text
69725288123113117521101161171099511210412111549995395495395534895539952114121125
```

5. Stream tersebut diparse sebagai konkatenasi kode ASCII desimal (2 atau 3 digit), menghasilkan string unik berformat flag.

### Recovery
Hasil parse ASCII:

`EH4X{qu4ntum_phys1c5_15_50_5c4ry}`

### Validation
- Format sesuai `EH4X{...}`.
- Decode konsisten jika pipeline dijalankan ulang.
- Clue angka "57 1035" berfungsi sebagai pengalih/tema, sementara payload utama tersembunyi pada pemetaan frekuensi nada.

### Flag
`EH4X{qu4ntum_phys1c5_15_50_5c4ry}`

### Solver
Solver Python:
```
from __future__ import annotations

import numpy as np
from pathlib import Path
from scipy.io import wavfile


def decode_quantum_message(path: Path) -> str:
    sr, data = wavfile.read(path)
    if data.ndim > 1:
        data = data[:, 0]
    x = data.astype(np.float64)

    # The signal is 80 equal tone windows (81.6s total -> 1.02s each).
    n_sym = 80
    sym_len = len(x) // n_sym
    x = x[: n_sym * sym_len].reshape(n_sym, sym_len)

    freqs = np.fft.rfftfreq(sym_len, d=1.0 / sr)
    window = np.hanning(sym_len)

    low_group = [300, 900, 1500, 2100]
    high_group = [2700, 3300, 3900]

    # Keypad layout (rows=low freq, cols=high freq)
    keypad = [
        ["1", "2", "3"],
        ["4", "5", "6"],
        ["7", "8", "9"],
        ["*", "0", "#"],
    ]

    digit_stream = []
    for i in range(n_sym):
        spectrum = np.abs(np.fft.rfft(x[i] * window))

        low_idx = int(
            np.argmax([spectrum[np.argmin(np.abs(freqs - f))] for f in low_group])
        )
        high_idx = int(
            np.argmax([spectrum[np.argmin(np.abs(freqs - f))] for f in high_group])
        )

        digit_stream.append(keypad[low_idx][high_idx])

    digits = "".join(digit_stream)

    # Parse concatenated ASCII decimal codes (2- or 3-digit), unique in this file.
    from functools import lru_cache

    @lru_cache(None)
    def parse(pos: int) -> list[str]:
        if pos == len(digits):
            return [""]

        out: list[str] = []
        for width in (2, 3):
            if pos + width > len(digits):
                continue
            code = int(digits[pos : pos + width])
            if 32 <= code <= 126:
                ch = chr(code)
                if ch.isalnum() or ch in "{}_":
                    for tail in parse(pos + width):
                        out.append(ch + tail)
        return out

    parsed = parse(0)
    if len(parsed) != 1:
        raise RuntimeError(f"Expected unique parse, got {len(parsed)} candidates")

    return parsed[0]


if __name__ == "__main__":
    wav_path = Path(__file__).with_name("challenge.wav")
    flag = decode_quantum_message(wav_path)
    print(flag)
```

Jalankan:
```bash
python "solver.py"
```

---

## Write-up: Jpeg Soul

**Category:** Forensics  
**Points:** 481  
**Author:** tanish_fr

---

### Challenge Overview
Diberikan file gambar `Jpeg Soul/soul.jpg` dengan clue:

> My soul will guide you, even through what seems insignificant.

Flag format yang diminta: `EHAX{...}`.

### Evidence Collected
- File target: `Jpeg Soul/soul.jpg`
- JPEG valid tanpa metadata menarik dan tanpa appended payload di akhir file.
- Tool `steghide info` menunjukkan kapasitas embed, tetapi brute passphrase umum tidak menghasilkan extract.
- Clue kata **insignificant** mengarah ke bit yang "tidak signifikan" (LSB).

### Analysis Path
1. Parse struktur JPEG secara manual dan ambil segmen **DQT** (`0xFFDB` / quantization tables).
2. Untuk tiap quantization table, ambil **LSB** nilai koefisien.
3. Baca koefisien dalam urutan **zig-zag JPEG**.
4. Pack bit menjadi byte (MSB-first) lalu cek apakah muncul teks printable/flag.
5. Hasil yang valid muncul saat memakai:
   - table index `2` -> `EHAX{jp3`
   - table index `3` -> `g_s3crt}`
6. Gabungkan keduanya menjadi flag final.

### Recovery
Payload yang dibaca dari DQT LSB adalah:

`EHAX{jp3g_s3crt}`

### Validation
- Format sesuai `EHAX{...}`.
- Hasil konsisten saat script dijalankan ulang.
- Clue challenge tepat: informasi disimpan di bagian "insignificant" (LSB quantization coefficients), bukan di tampilan gambar utama.

### Flag
`EHAX{jp3g_s3crt}`

### Solver
Solver Python :
```
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

JPEG_SOI = b"\xFF\xD8"
JPEG_SOS = 0xDA

ZIGZAG = [
    0, 1, 5, 6, 14, 15, 27, 28,
    2, 4, 7, 13, 16, 26, 29, 42,
    3, 8, 12, 17, 25, 30, 41, 43,
    9, 11, 18, 24, 31, 40, 44, 53,
    10, 19, 23, 32, 39, 45, 52, 54,
    20, 22, 33, 38, 46, 51, 55, 60,
    21, 34, 37, 47, 50, 56, 59, 61,
    35, 36, 48, 49, 57, 58, 62, 63,
]

FLAG_RE = re.compile(r"EHAX\{[A-Za-z0-9_\-!@#$%^&*().:+,=/?]{3,80}\}")


@dataclass(frozen=True)
class TableVariant:
    table_idx: int
    bit: int
    order: str
    reverse_bits: bool
    bit_order: str
    payload: bytes


def parse_dqt_tables(jpeg_bytes: bytes) -> list[list[int]]:
    if not jpeg_bytes.startswith(JPEG_SOI):
        raise ValueError("Not a valid JPEG (missing SOI marker)")

    pos = 2
    tables: list[list[int]] = []

    while pos + 1 < len(jpeg_bytes):
        if jpeg_bytes[pos] != 0xFF:
            pos += 1
            continue

        while pos < len(jpeg_bytes) and jpeg_bytes[pos] == 0xFF:
            pos += 1
        if pos >= len(jpeg_bytes):
            break

        marker = jpeg_bytes[pos]
        pos += 1

        if marker == JPEG_SOS:
            break

        if marker in (0xD8, 0xD9, 0x01) or (0xD0 <= marker <= 0xD7):
            continue

        if pos + 2 > len(jpeg_bytes):
            break

        seg_len = (jpeg_bytes[pos] << 8) | jpeg_bytes[pos + 1]
        seg = jpeg_bytes[pos + 2 : pos + seg_len]
        pos += seg_len

        if marker != 0xDB:
            continue

        i = 0
        while i < len(seg):
            pq_tq = seg[i]
            i += 1
            pq = (pq_tq >> 4) & 0x0F

            if pq == 0:
                vals = list(seg[i : i + 64])
                i += 64
            else:
                vals = []
                for _ in range(64):
                    vals.append((seg[i] << 8) | seg[i + 1])
                    i += 2

            tables.append(vals)

    if not tables:
        raise RuntimeError("No DQT tables found")

    return tables


def bits_to_bytes(bits: Iterable[int], bit_order: str) -> bytes:
    out = bytearray()
    chunk: list[int] = []

    for b in bits:
        chunk.append(int(b) & 1)
        if len(chunk) == 8:
            if bit_order == "msb":
                val = 0
                for x in chunk:
                    val = (val << 1) | x
            else:
                val = 0
                for i, x in enumerate(chunk):
                    val |= x << i
            out.append(val)
            chunk.clear()

    return bytes(out)


def generate_variants(tables: list[list[int]]) -> list[TableVariant]:
    variants: list[TableVariant] = []

    for idx, vals in enumerate(tables):
        for bit in range(4):
            for order in ("natural", "zigzag"):
                ordered = vals if order == "natural" else [vals[i] for i in ZIGZAG]
                base_bits = [(x >> bit) & 1 for x in ordered]

                for reverse_bits in (False, True):
                    bits = base_bits[::-1] if reverse_bits else base_bits
                    for bit_order in ("msb", "lsb"):
                        payload = bits_to_bytes(bits, bit_order)
                        variants.append(
                            TableVariant(
                                table_idx=idx,
                                bit=bit,
                                order=order,
                                reverse_bits=reverse_bits,
                                bit_order=bit_order,
                                payload=payload,
                            )
                        )

    return variants


def solve(jpeg_path: Path) -> tuple[str, tuple[TableVariant, TableVariant]]:
    data = jpeg_path.read_bytes()
    tables = parse_dqt_tables(data)
    variants = generate_variants(tables)

    for a in variants:
        for b in variants:
            if a.table_idx == b.table_idx:
                continue
            combined = a.payload + b.payload
            text = combined.decode("latin1", errors="ignore")
            m = FLAG_RE.search(text)
            if m:
                return m.group(0), (a, b)

    raise RuntimeError("Flag not found from DQT variants")


def main() -> None:
    jpeg_path = Path(__file__).with_name("soul.jpg")
    flag, (v1, v2) = solve(jpeg_path)
    print(flag)
    print(
        f"[debug] from tables {v1.table_idx}+{v2.table_idx}, "
        f"bit={v1.bit}, order={v1.order}, reverse={v1.reverse_bits}, bit_order={v1.bit_order}"
    )


if __name__ == "__main__":
    main()
```

Jalankan:
```bash
python "solver.py"
```

---

## Write-up: Kaje

**Category:** Reverse Engineering  
**Author:** Anonimbus

---

### Challenge Overview
We are given a single ELF binary `kaje` and an SSH host to run it.  
At first glance, running the binary only prints unreadable bytes, so the task is to reverse the generation logic and recover the intended plaintext (flag).

### Evidence Collected
- Binary type: `ELF 64-bit PIE, not stripped`
- Interesting symbols:
  - `gen_entropy`
  - `gen_keystream`
- Main flow (from disassembly):
  1. `seed = gen_entropy()`
  2. `gen_keystream(buf, seed)` for 32 bytes
  3. XOR keystream with two 16-byte constants from `.rodata`
  4. Print result via `puts`

### Analysis Path
1. Disassemble binary:
   ```bash
   objdump -d -Mintel kaje
   objdump -s -j .rodata kaje
   ```
2. `gen_entropy` logic:
   - Uses one of two base constants depending on `access("/.dockerenv", 0)`.
   - Opens `/proc/self/mountinfo`.
   - If a line contains `"overlay"`, XOR with `0xabcdef1234567890`.
   - Final value is mixed with MurmurHash-style `fmix64`.
3. `gen_keystream`:
   - Generates 32 bytes by repeatedly applying `fmix64` to evolving state.
4. Output is:
   - `cipher_const ^ keystream`
   - So we can reconstruct offline by reimplementing the same logic.

### Recovery
Reimplemented the two functions (`gen_entropy` + `gen_keystream`) in Python and tested all 4 environment combinations:
- `dockerenv ∈ {0,1}`
- `overlay ∈ {0,1}`

Only one combination produced readable flag text:
- `dockerenv=1`, `overlay=1`

### Validation
Recovered plaintext matched CTF flag format:
- Starts with `EH4X{`
- Ends with `}`

### Flag
`EH4X{dUnn0_wh4tt_1z_1nt3NTenD3d}`

### Takeaway
This challenge is an environment-dependent stream-XOR obfuscation.  
Even when runtime output looks random, static reversing of seed generation + keystream derivation is enough to fully recover the hidden plaintext.

--- 

## Write-up: compute it

**Category:** Reverse / Misc  
**Author:** martin

---

### Challenge Overview
Diberikan:
- `validator` (ELF x64, not stripped)
- `signal_data.txt` (2600 pasangan `real,imag`)

Prompt: *"the computation prof gave me some data and a executable, what does he want from me?"*

Dari string binary:
- `Usage: ./validator <real> <imag>`
- `AUTHORIZATION ACCEPTED: Node Valid.`
- `AUTHORIZATION DENIED: Node Invalid.`

Ternyata validator bukan endpoint flag langsung. Ia dipakai sebagai oracle untuk membuat bitmap tersembunyi dari dataset.

### Reverse Engineering
`main` hanya menerima 2 argumen float (`atof(argv[1])`, `atof(argv[2])`) lalu menjalankan iterasi Newton pada bilangan kompleks.

Persamaan yang dipakai (dengan `z = x + iy`):
- `f(z) = z^3 - 1`

Komponen real/imag:
- `f_re = x^3 - 3xy^2 - 1`
- `f_im = 3x^2y - y^3`

Jacobian:
- `j00 = 3(x^2 - y^2)`
- `j01 = 6xy`
- `den = j00^2 + j01^2`

Update Newton:
- `dx = (f_re*j00 + f_im*j01) / den`
- `dy = (f_im*j00 - f_re*j01) / den`
- `x -= dx`, `y -= dy`

Konstanta penting dari `.rodata`:
- `3.0`, `1.0`, `6.0`
- threshold singularitas: `den < 1e-9` -> stop
- threshold konvergensi: `abs(x-1.0) < 1e-6 && abs(y) < 1e-6`

Kondisi validasi akhir per titik:
- counter iterasi harus **tepat 12** (`count == 12`)

### Solusi
1. Scan seluruh baris `signal_data.txt`, jalankan model validator untuk tiap `(x,y)`.
2. Ubah hasil menjadi bitstream:
   - `1` jika `count == 12` (Node Valid)
   - `0` selain itu
3. Reshape bitstream ke matriks `20 x 130`.  
   Baris aktif membentuk dot-matrix 5 baris yang berisi teks.
4. Segment per karakter (kolom non-kosong dipisah kolom kosong), lalu decode glyph 5-row.

Solver script:
```
#!/usr/bin/env python3
"""Solve script for 'compute it'.

It reconstructs validator logic from reverse engineering and scans signal_data.txt
for telemetry points that pass AUTHORIZATION.
"""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


def validator_model(x: float, y: float) -> tuple[bool, int, float, float]:
    """Return (is_valid, iteration_count, final_x, final_y)."""
    count = 0
    fail = 0

    while fail <= 0x31:  # 49
        # f(z) = z^3 - 1 where z = x + i y
        f_re = x * x * x - 3.0 * x * y * y - 1.0
        f_im = 3.0 * x * x * y - y * y * y

        # Jacobian for Newton step
        j00 = 3.0 * (x * x - y * y)
        j01 = 6.0 * x * y
        den = j00 * j00 + j01 * j01

        if den < 1e-9:
            break

        dx = (f_re * j00 + f_im * j01) / den
        dy = (f_im * j00 - f_re * j01) / den

        x -= dx
        y -= dy
        count += 1

        # converge target: 1 + 0i with eps 1e-6
        if abs(x - 1.0) < 1e-6 and abs(y) < 1e-6:
            break

        fail += 1

    return (count == 12), count, x, y


def parse_signal_data(path: Path) -> list[tuple[int, str, str, float, float]]:
    rows: list[tuple[int, str, str, float, float]] = []
    for idx, raw in enumerate(path.read_text().splitlines(), 1):
        raw = raw.strip()
        if not raw:
            continue
        re_s, im_s = raw.split(",")
        rows.append((idx, re_s, im_s, float(re_s), float(im_s)))
    return rows


def bits_to_flag(bits: list[int], width: int = 130) -> str:
    """Decode the hidden 5-row dot-matrix flag from valid/invalid bits."""
    if len(bits) % width != 0:
        raise ValueError("bitstream length is not divisible by width")

    height = len(bits) // width
    rows = [bits[r * width : (r + 1) * width] for r in range(height)]

    active_rows = [i for i, row in enumerate(rows) if any(row)]
    if not active_rows:
        raise ValueError("no active rows found in bitmap")

    top, bottom = active_rows[0], active_rows[-1]
    matrix = rows[top : bottom + 1]
    if len(matrix) != 5:
        raise ValueError(f"expected 5 active rows, got {len(matrix)}")

    col_sums = [sum(matrix[r][c] for r in range(5)) for c in range(width)]
    runs: list[tuple[int, int]] = []
    in_run = False
    start = 0
    for c, v in enumerate(col_sums):
        if v > 0 and not in_run:
            start = c
            in_run = True
        elif v == 0 and in_run:
            runs.append((start, c - 1))
            in_run = False
    if in_run:
        runs.append((start, width - 1))

    # Glyph map extracted from challenge's own bitmap font (5 rows, variable width).
    glyph_map = {
        ("####", "#...", "###.", "#...", "####"): "E",
        ("#..#", "#..#", "####", "#..#", "#..#"): "H",
        ("#..#", "#..#", "####", "...#", "...#"): "4",
        ("#..#", ".##.", "..#.", ".##.", "#..#"): "X",
        (".##", "##.", "#..", "##.", ".##"): "{",
        ("###.", "#..#", "#..#", "#..#", "#..#"): "N",
        ("####", "...#", ".###", "...#", "####"): "3",
        ("#...#", "#...#", "#.#.#", "##.##", "#...#"): "W",
        ("###", ".#.", ".#.", ".#.", ".#."): "T",
        (".##.", "#..#", "#..#", "#..#", ".##."): "O",
        ("....", "....", "####", "....", "...."): "_",
        ("####", "#..#", "###.", "#.#.", "#..#"): "R",
        ("..#.", ".##.", "..#.", "..#.", "####"): "1",
        ("####", "#...", "#.##", "#..#", "####"): "G",
        ("####", "#...", "###.", "...#", "####"): "5",
    }

    out = []
    for i, (a, b) in enumerate(runs):
        glyph = tuple(
            "".join("#" if matrix[r][c] else "." for c in range(a, b + 1))
            for r in range(5)
        )
        ch = glyph_map.get(glyph)
        if ch is None:
            raise ValueError(f"unknown glyph at cols {a}-{b}: {glyph}")
        # In this challenge font, opening/closing brace share the same 3x5 glyph.
        if ch == "{" and i == len(runs) - 1:
            ch = "}"
        out.append(ch)

    return "".join(out)


def generate_ambiguous_candidates(flag: str) -> list[str]:
    """Generate plausible alternatives for ambiguous OCR glyphs."""
    alts = {flag}
    # Common ambiguities in this bitmap font / leetspeak style.
    swaps = [
        ("O", "0"),
        ("0", "O"),
        ("S", "5"),
        ("5", "S"),
    ]
    changed = True
    while changed:
        changed = False
        cur = list(alts)
        for s in cur:
            for a, b in swaps:
                if a in s:
                    t = s.replace(a, b)
                    if t not in alts:
                        alts.add(t)
                        changed = True
    return sorted(alts)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="/Users/zuy/Documents/New project 2/ctf/signal_data.txt")
    ap.add_argument("--validator", default=None, help="optional path to validator binary for direct verification")
    args = ap.parse_args()

    rows = parse_signal_data(Path(args.data))

    valid_rows: list[tuple[int, str, str, int]] = []
    for idx, re_s, im_s, x, y in rows:
        ok, count, _, _ = validator_model(x, y)
        if ok:
            valid_rows.append((idx, re_s, im_s, count))

    print(f"total_rows={len(rows)}")
    print(f"valid_count={len(valid_rows)}")

    if not valid_rows:
        print("no valid telemetry found")
        return

    print("first_valid_index={}, real={}, imag={}, iter={}".format(*valid_rows[0]))
    print("last_valid_index={}, real={}, imag={}, iter={}".format(*valid_rows[-1]))

    bitstream = [1 if validator_model(x, y)[0] else 0 for _, _, _, x, y in rows]
    flag = bits_to_flag(bitstream, width=130)
    print(f"decoded_flag={flag}")
    print("candidate_flags:")
    for c in generate_ambiguous_candidates(flag):
        print(f"- {c}")

    if args.validator:
        idx, re_s, im_s, _ = valid_rows[0]
        out = subprocess.check_output([args.validator, re_s, im_s], text=True)
        print(f"\nvalidator_check_for_index_{idx}:")
        print(out.strip())


if __name__ == "__main__":
    main()
```

Run:
```bash
python3 "solve_compute_it.py"
```

Output penting dari solver:
- `valid_count = 226`
- `decoded_flag = EH4X{N3WTON_W45_R1GHT}`

Verifikasi oracle ke binary (contoh salah satu Node Valid):
```bash
./validator 0.689743 1.844815
```
Output:
- `AUTHORIZATION ACCEPTED: Node Valid.`

### Flag
`EH4X{N3WTON_W45_R1GHT}`

---

## Write-up: ghostKey

**Category:** Reverse / Crypto  
**Author:** benzo

---

### Challenge Overview
Diberikan binary `ghost` dan petunjuk: *"recover the key and flag"*. Binary meminta argumen key 32 karakter.

Dari eksekusi cepat:
- `Usage: /home/zuy/ghost <32-char key>`
- Wrong key akan menampilkan check yang gagal (mis. `lfsr`, `nibble`, dst.)

Ini memberi indikasi challenge berbasis serangkaian constraint terhadap 32 byte key.

### Reverse Engineering Findings
Dari static reversing, ditemukan komponen validasi berikut:

1. **Printable ASCII**: setiap karakter key harus dalam rentang `0x20..0x7E`.
2. **LFSR check**: state akhir harus `0x4358` (seed awal `0xACE1`, polynomial `0xB400`).
3. **Nibble XOR** per baris 8 byte:
   - target: `[8, 8, 4, 7]`
4. **Column sum mod 97** pada matriks 4x8:
   - target: `[12, 39, 8, 0, 55, 33, 50, 96]`
5. **Pair modular constraints** (12 pasang indeks):
   - `(0,31) mod 127 = 104`
   - `(3,28) mod 131 = 17`
   - `(7,24) mod 113 = 53`
   - `(11,20) mod 109 = 58`
   - `(1,15) mod 103 = 52`
   - `(5,27) mod 97 = 88`
   - `(9,22) mod 107 = 20`
   - `(13,18) mod 101 = 64`
   - `(2,29) mod 127 = 81`
   - `(6,25) mod 131 = 118`
   - `(10,21) mod 113 = 40`
   - `(14,17) mod 109 = 83`
6. **XOR tag** per blok 4 byte:
   - `[0x6c, 0x75, 0x3a, 0x01, 0x7e, 0x2f, 0x34, 0x00]`
7. **AES S-box parity** pada indeks genap:
   - `xor(SBOX[key[0]], SBOX[key[2]], ..., SBOX[key[30]]) == 0x66`

Constraint ini cocok untuk dimodelkan ke SMT (Z3).

### Solver Approach
Saya membangun model bit-vector 8-bit untuk 32 karakter key, lalu memasukkan semua constraint di atas apa adanya.

- Solver: `SolverFor('QF_BV')`
- Domain: 32 byte printable
- Semua check dimasukkan langsung, termasuk LFSR dan AES-SBOX lookup via array `Store/Select`.

Script solver final:
```
#!/usr/bin/env python3
"""
ghostKey solver (Z3)

Usage:
  python3 solve_ghostkey_z3.py
  python3 solve_ghostkey_z3.py --run-binary /home/zuy/ghost

Notes:
- This is the full-constraint model (no hardcoded key).
- Depending on machine/SMT performance, solve time can be long.
"""

from __future__ import annotations

import argparse
import subprocess
import time
from z3 import (
    BitVec,
    BitVecSort,
    BitVecVal,
    K,
    LShR,
    SolverFor,
    Store,
    Select,
    UGE,
    ULE,
    URem,
    ZeroExt,
    sat,
    set_param,
)


AES_SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]


def build_solver():
    # Parallel params help on multi-core machines.
    set_param("parallel.enable", True)
    set_param("smt.threads", 8)
    set_param("sat.threads", 8)

    k = [BitVec(f"k{i}", 8) for i in range(32)]
    s = SolverFor("QF_BV")

    # printable ASCII
    for x in k:
        s.add(UGE(x, 32), ULE(x, 126))

    # LFSR check
    l = BitVecVal(0xACE1, 16)
    for i in range(32):
        b = k[i]
        for _ in range(8):
            fb = (ZeroExt(8, b) ^ l) & 1
            l = LShR(l, 1) ^ (fb * BitVecVal(0xB400, 16))
            b = LShR(b, 1)
    s.add(l == BitVecVal(0x4358, 16))

    # nibble-xor per row
    for r, t in enumerate([8, 8, 4, 7]):
        acc = BitVecVal(0, 8)
        for c in range(8):
            x = k[r * 8 + c]
            acc = acc ^ (LShR(x, 4) ^ (x & 0x0F))
        s.add(acc == t)

    # column sums modulo 97
    for c, t in enumerate([12, 39, 8, 0, 55, 33, 50, 96]):
        sm = BitVecVal(0, 16)
        for r in range(4):
            sm = sm + ZeroExt(8, k[c + 8 * r])
        s.add(URem(sm, BitVecVal(97, 16)) == BitVecVal(t, 16))

    # pair modular constraints
    pairs = [
        (0, 31, 127, 104),
        (3, 28, 131, 17),
        (7, 24, 113, 53),
        (11, 20, 109, 58),
        (1, 15, 103, 52),
        (5, 27, 97, 88),
        (9, 22, 107, 20),
        (13, 18, 101, 64),
        (2, 29, 127, 81),
        (6, 25, 131, 118),
        (10, 21, 113, 40),
        (14, 17, 109, 83),
    ]
    for a, b, m, r in pairs:
        sm = ZeroExt(8, k[a]) + ZeroExt(8, k[b])
        s.add(URem(sm, BitVecVal(m, 16)) == BitVecVal(r, 16))

    # xor tag per group of 4
    for i, v in enumerate([0x6C, 0x75, 0x3A, 0x01, 0x7E, 0x2F, 0x34, 0x00]):
        s.add((k[4 * i] ^ k[4 * i + 1] ^ k[4 * i + 2] ^ k[4 * i + 3]) == v)

    # AES-SBOX parity on even positions
    arr = K(BitVecSort(8), BitVecVal(0, 8))
    for i, v in enumerate(AES_SBOX):
        arr = Store(arr, BitVecVal(i, 8), BitVecVal(v, 8))
    px = BitVecVal(0, 8)
    for i in range(0, 32, 2):
        px = px ^ Select(arr, k[i])
    s.add(px == BitVecVal(0x66, 8))

    return s, k


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-binary", help="optional path to challenge binary for direct verification")
    args = parser.parse_args()

    s, k = build_solver()
    print("[+] solving...")
    t0 = time.time()
    res = s.check()
    dt = time.time() - t0
    print(f"[+] solver result: {res} (time={dt:.2f}s)")

    if res != sat:
        return

    m = s.model()
    key = "".join(chr(m.eval(k[i]).as_long()) for i in range(32))
    print(f"[+] key: {key}")

    if args.run_binary:
        out = subprocess.check_output([args.run_binary, key], text=True)
        print("[+] binary output:")
        print(out)


if __name__ == "__main__":
    main()
```

Jalankan:
```bash
python3 solve_ghostkey_z3.py
```

Opsional verifikasi langsung ke binary:
```bash
python3 solve_ghostkey_z3.py --run-binary /home/zuy/ghost
```

### Result
Solver menghasilkan key:

`Gh0stK3y-R3v3rs3-M3-1f-U-C4n!!!!`

Verifikasi ke binary:

- `[+] All checks passed!`
- `[+] Flag: crackme{AES_gh0stk3y_r3v3rs3d!!}`


### Flag
`crackme{AES_gh0stk3y_r3v3rs3d!!}`


### Notes
- Solve time bisa lama (bergantung mesin dan thread SMT).
- Script ini tidak hardcode key; key benar-benar dicari lewat constraint solving.
