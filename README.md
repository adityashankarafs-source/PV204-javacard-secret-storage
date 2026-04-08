# PV204 JavaCard Secret Storage

## Team Members
- Aditya Shankar
- Ujjawal Kumar
- Khaled Kamal Hegazy

---

## Project Overview

This project implements a **secure secret storage system using JavaCard technology**.

The system allows users to:
- securely store secrets on a smart card
- list stored secret names
- retrieve secrets after PIN verification
- securely change the PIN
- communicate using a **secure channel with replay protection**

---

## Key Features

Core Functionality
- PIN-based authentication
- Secret storage (name + value)
- Secret retrieval
- Secret listing
- Secure PIN change

Security Features
- Secure channel (challenge-response using nonces)
- Session key derivation using SHA-256
- Message authentication (MAC)
- Replay attack protection (counter-based)
- Encrypted communication (stream cipher style XOR)

---

## Repository Structure
