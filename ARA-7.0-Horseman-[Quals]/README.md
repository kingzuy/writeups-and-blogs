# Write‑up: ARA 7.0 [Quals] – horseman

**Category:** Forensic 
**Files:** `horseman.ad1`  

---

## 1. Initial Analysis (disk Inspection)

setelah melakukan analisa terhadap file `horseman.ad1`, di temukan sebuah file exe mencerugakan bernama update.exe python-based. dari analisa tersebut kita dapat menjawab 7 pertanyaan untuk menyelesaikan tantangan ini

ss

---

## 2. Menjawab pertanyaan tantangan

#### Q1. A suspicious executable was found in the Downloads folder. What is the SHA256 Hash of this malware?
ss
Answer: aeb4cc771ae6f76b17ad1e8fb44d69cf5e5cea24adb23af03cae1dc7fd5e743c

#### Q2. The malware targets specific users by incorporating their unique system identifier into the encryption key. What is the SID (Security Identifier) of the infected user?
ss
Answer: S-1-5-21-2472383311-4215914088-769331741

#### Q3. he malware leaves a trace of its initialization within the Windows Event Logs. What is the Event ID used by the malware to log its persistence entry?
ss
Answer: 1337

#### Q4. Within the description of the event log identified in Question 3, the malware stores a unique "Reference ID" or token.What is the value of this Secret Token?
ss
Answer: OOM9OV5VPRNIK3S2

#### Q5. To establish an incident timeline, determine the exact time the malware recorded its persistence log. What is the timestamp in UTC?
ss
Answer: 2026-01-30 16:02:39

#### Q6. Based on the header analysis of the encrypted files and the malware's logic, identify the encryption algorithm and mode used.
ss
Answer: AES-CBC

### Q.7 DATA RECOVERY (FINAL)
The user reports losing a critical file named 'confidential.txt' in the Documents folder.
Using your findings (SID + Token + IV), decrypt the file and reveal the secret string inside.

encrypted file:(https://drive.google.com/file/d/1Ro-DZ8aiLq2XlOzScQVS0gAh64kKyOvE/view?usp=sharing)
ss
Answer: b967081a1a071c25e2c4437e2e124b60b73407ec8eceb52e1eecc00caa1873ba


