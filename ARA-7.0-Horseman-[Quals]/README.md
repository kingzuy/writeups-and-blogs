# Write‑up: ARA 7.0 [Quals] – horseman

**Category:** Forensic  
**Files:** `horseman.ad1`  

---

## 1. Initial Analysis (disk Inspection)

setelah melakukan analisa terhadap file `horseman.ad1`, di temukan sebuah file exe mencerugakan bernama update.exe python-based. dari analisa tersebut kita dapat menjawab 7 pertanyaan untuk menyelesaikan tantangan ini

<img width="1738" height="388" alt="image" src="https://github.com/user-attachments/assets/46342b72-233c-4711-a4cc-c8c9ddfe1103" />


---

## 2. Menjawab pertanyaan tantangan

#### Q1. A suspicious executable was found in the Downloads folder. What is the SHA256 Hash of this malware?
<img width="1316" height="88" alt="image" src="https://github.com/user-attachments/assets/4c207e2a-d3e7-4961-990e-893f609be643" />

Answer: aeb4cc771ae6f76b17ad1e8fb44d69cf5e5cea24adb23af03cae1dc7fd5e743c

#### Q2. The malware targets specific users by incorporating their unique system identifier into the encryption key. What is the SID (Security Identifier) of the infected user?
<img width="1104" height="200" alt="image" src="https://github.com/user-attachments/assets/1873d5dc-0eb7-4b7e-8b66-530edfd02ba1" />

Answer: S-1-5-21-2472383311-4215914088-769331741

#### Q3. he malware leaves a trace of its initialization within the Windows Event Logs. What is the Event ID used by the malware to log its persistence entry?
<img width="2278" height="112" alt="image" src="https://github.com/user-attachments/assets/f9ffd767-d00f-4bf3-9c5b-dfd9d6ba13a4" />

Answer: 1337

#### Q4. Within the description of the event log identified in Question 3, the malware stores a unique "Reference ID" or token.What is the value of this Secret Token?
<img width="1556" height="122" alt="image" src="https://github.com/user-attachments/assets/41cf3d22-76df-43c0-aa8d-7aa887eb2cc7" />

Answer: OOM9OV5VPRNIK3S2

#### Q5. To establish an incident timeline, determine the exact time the malware recorded its persistence log. What is the timestamp in UTC?
<img width="2278" height="112" alt="image" src="https://github.com/user-attachments/assets/f9ffd767-d00f-4bf3-9c5b-dfd9d6ba13a4" />
23.02.39 - 12.00.00  

Answer: 2026-01-30 11:02:39

#### Q6. Based on the header analysis of the encrypted files and the malware's logic, identify the encryption algorithm and mode used.
<img width="940" height="470" alt="image" src="https://github.com/user-attachments/assets/6fe3b76c-076a-4dde-a214-38eb1afc4127" />

Answer: AES-CBC

### Q.7 DATA RECOVERY (FINAL)
The user reports losing a critical file named 'confidential.txt' in the Documents folder.
Using your findings (SID + Token + IV), decrypt the file and reveal the secret string inside.

encrypted file:(https://drive.google.com/file/d/1Ro-DZ8aiLq2XlOzScQVS0gAh64kKyOvE/view?usp=sharing)
<img width="1256" height="114" alt="image" src="https://github.com/user-attachments/assets/e19f7889-9a6f-435d-b198-962c54fe08a0" />

Answer: b967081a1a071c25e2c4437e2e124b60b73407ec8eceb52e1eecc00caa1873ba



