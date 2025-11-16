# 🛡️ Secure Group File Sharing Cryptosystem
*A hybrid ECC + ECDH + AES cryptographic system for multi-recipient secure file distribution.*

This project implements a secure file-sharing mechanism using Bash and OpenSSL, designed for a cybersecurity graduate course. It delivers **Confidentiality**, **Integrity**, and **Authentication** using modern cryptographic standards.

The system enables one sender to encrypt and sign a file for multiple receivers. Each receiver can independently verify the signature and decrypt the shared file securely. Additionally, the cryptosystem supports **key re-wrapping**, allowing new envelopes to be generated for new recipients **without re-encrypting the original data file**.

---

## 📚 Table of Contents
- [Features](#features)
- [System Overview](#system-overview)
- [Cryptographic Design](#cryptographic-design)
- [Elliptic Curve Diffie–Hellman (ECDH)](#elliptic-curve-diffiehellman-ecdh)
- [Project Structure](#project-structure)
- [Usage](#usage)
  - [Task 1: Encryption / Decryption](#task-1-encryption--decryption)
  - [Task 2: Signing / Verification](#task-2-signing--verification)
  - [Task 3: Key Re-Wrapping](#task-3-key-re-wrapping)
- [Security Considerations](#security-considerations)
- [Requirements](#requirements)
- [Lessons Learned](#lessons-learned)
- [License & Academic Integrity](#license-&-academic-integrity)

---

## Features
- 🔐 **AES-256-CBC File Encryption**
- 🔑 **ECC (P-256) Key Pairs for both ECDSA & ECDH**
- 🔏 **Digital Signatures for Integrity & Authentication**
- 📨 **Digital Envelopes** (one per receiver) created using ECDH + PBKDF2
- 🔄 **Key Re-Wrapping** without re-encrypting the original data
- 🧹 **Complete cleanup** of intermediate files in all scripts
- 🛑 **Graceful error handling** with stderr outputs
- 🧪 **Fully automated Bash scripts** using OpenSSL

---

## 🧱 System Overview

### Sender Workflow
1. Generate a random AES session key
2. Encrypt the plaintext file using AES-256
3. For each receiver:
   - Perform ECDH with the receiver’s public key
   - Derive envelope key using PBKDF2-SHA256
   - Encrypt ("wrap") the session key into a digital envelope
4. Package:
   - AES-encrypted file
   - Digital envelopes  
   → into a **zip file**
5. Sign the zip file using ECDSA

### Receiver Workflow
1. Verify the sender’s ECDSA signature
2. Use own ECC **private key** + sender’s **public key** to perform ECDH
3. Derive envelope key using PBKDF2
4. Decrypt the envelope → retrieve AES session key
5. Decrypt the encrypted file

### Key Re-Wrapping (Task 3)
- A designated generator (one of the receivers) re-wraps session keys for a new group
- Enables redistribution without exposing plaintext
- Avoids unnecessary re-encryption

---

## 🔐 Cryptographic Design
---

## 🔑 ECC Key Pair Requirements (For ECDSA & ECDH)

Before running any task, **all participants must generate ECC key pairs**.

These key pairs serve two critical purposes:

### ✔️ ECDSA  
Used for **digital signatures** (Task 2).

### ✔️ ECDH  
Used to derive secure shared secrets for **digital envelopes** (Tasks 1 & 3).

### 🧠 Why ECDH?

### 📚 ECDH / Diffie–Hellman Learning Resources

To better understand how ECDH and Diffie–Hellman key exchange work, review the following:

#### 🎥 Video Explanation  
🔗 https://youtu.be/NmM9HA2MQGI?si=JEjIFdnVwo3-eECy

#### 📖 Article  
🔗 https://www.techtarget.com/searchsecurity/definition/Diffie-Hellman-key-exchange

These resources explain how two parties establish a shared secret over an insecure channel — the core principle behind ECDH in this project.

ECC **cannot directly encrypt** data.  
Instead, we use **Elliptic Curve Diffie–Hellman** to generate a shared secret between:

- Sender ↔ Receiver  
- Generator ↔ New Recipient (Task 3 re-wrapping)

This shared secret is then processed with **PBKDF2** to derive an envelope key.

---

### 📌 Generate ECC Key Pairs (P-256)

#### Generate private key:
```
openssl ecparam -name prime256v1 -genkey -noout -out user.priv
```

#### Extract public key:
```
openssl ec -in user.priv -pubout -out user.pub
```

Repeat for:
- sender  
- receiver1  
- receiver2  
- receiver3  

---


| Component | Algorithm |
|----------|-----------|
| Asymmetric Key System | ECC P-256 |
| Key Exchange | ECDH |
| File Encryption | AES-256-CBC |
| Key Derivation | PBKDF2 (SHA-256) |
| Hashing | SHA-256 |
| Signature | ECDSA |

---

# 🔑 Elliptic Curve Diffie–Hellman (ECDH)

Because ECC does **not** support direct asymmetric encryption, this project uses **ECDH** (Elliptic Curve Diffie–Hellman) to derive secure shared secrets for digital envelopes.

### ❗ ECC Key Pairs Must Be Pre-Generated
Every user (sender + 3 receivers) must generate ECC key pairs **before** running the scripts.

These keys are used for both:
- **ECDSA** (digital signatures)
- **ECDH** (shared-secret generation)

---

## 🧬 How ECDH Works in This Project

### Sender Side (for each receiver)
1. Combine sender’s **private key** with receiver’s **public key**
2. Compute ECDH shared secret
3. Input shared secret into **PBKDF2**
4. Output → hardened envelope key
5. Encrypt session key into a digital envelope

### Receiver Side
1. Combine receiver’s **private key** with sender’s **public key**
2. Compute the same shared secret
3. Derive the same PBKDF2 envelope key
4. Decrypt envelope to obtain session key
5. Decrypt file

---

## 📌 ECC & ECDH Command Guide

### 1️⃣ Generate ECC Key Pair (P-256 Curve)

**Private Key**
```bash
openssl ecparam -name prime256v1 -genkey -noout -out user.priv
```

**Public Key**
```bash
openssl ec -in user.priv -pubout -out user.pub
```

### 2️⃣ Compute ECDH Shared Secret

**Sender → Receiver**
```bash
openssl pkeyutl -derive -inkey sender.priv -peerkey receiver1.pub -out shared_secret.bin
```

**Receiver → Sender**
```bash
openssl pkeyutl -derive -inkey receiver1.priv -peerkey sender.pub -out shared_secret.bin
```

### 3️⃣ Derive Envelope Key (PBKDF2)

```bash
openssl pkcs5 -in shared_secret.bin -pass stdin   -iter 100000 -md sha256 -out envelope_key.bin -binary
```

### 4️⃣ Wrap (Encrypt) AES Session Key

```bash
openssl enc -aes-256-cbc -salt -in session_key.bin   -out envelope.enc -pass file:envelope_key.bin
```

### 5️⃣ Unwrap (Decrypt) AES Session Key

```bash
openssl enc -aes-256-cbc -d -in envelope.enc   -out session_key.bin -pass file:envelope_key.bin
```

---

## 📁 Project Structure

```
.
├── task1.sh
├── task2.sh
├── task3.sh
├── receiver1.pub
├── receiver1.priv
├── receiver2.pub
├── receiver2.priv
├── receiver3.pub
├── receiver3.priv
├── sender.pub
├── sender.priv
└── file1
```

---

# 🚀 Usage

## Task 1: Encryption / Decryption

### Sender
```bash
./task1.sh -sender receiver1.pub receiver2.pub receiver3.pub sender.priv file1 protected.zip
```

### Receiver
```bash
./task1.sh -receiver receiver1.priv sender.pub protected.zip decrypted_output.txt
```

---

## Task 2: Signing / Verification

### Sender
```bash
./task2.sh -sender protected.zip sender.priv protected.zip.sig
```

### Receiver
```bash
./task2.sh -receiver sender.pub protected.zip.sig protected.zip
```

---

## Task 3: Key Re-Wrapping

```bash
./task3.sh protected.zip generator.priv sender.pub receiver1.pub receiver2.pub receiver3.pub new_protected.zip
```

---

## 🔒 Security Considerations
- ECC private keys must remain confidential
- PBKDF2 should use a strong iteration count (≥100k)
- Intermediate files must be securely deleted
- The zip file should be delivered over a secure channel
- Ensures confidentiality, integrity, authenticity

---

## 📘 Lessons Learned
- Implementation of hybrid encryption with ECDH + AES
- Integration of PBKDF2 for hardened key derivation
- Bash automation for complex cryptographic workflows
- Practical ECDSA signing and signature verification
- Secure multi-recipient file distribution architecture

---

## 🧰 Requirements
- Bash
- OpenSSL 3.x
- Linux / macOS
- zip utility

---

## 📎 License & Academic Integrity
This repository is for educational demonstration and reflects my original work for one of my Cybersecurity Master's courses.
Do not reuse it directly for graded submissions in other courses.
