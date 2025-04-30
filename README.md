# GPGap

**Air-gapped GPG signing Bitcoin-style**

GPGap is an experimental Python application that lets you perform GPG signatures on an **air-gapped** device. It leverages a modified version of [PGPy](https://github.com/SecurityInnovation/PGPy) to offload the signing operation to an external hardware signer.

---

## Overview

1. **Local host (GPGap)**
   - Prepares key data or files for signing
   - Let's you store and load public keys
   - Packages data for transport to the signer using QR Codes
2. **External signer (Krux)**  
   - Generate ECDSA keys on secp256k1. Keys are derived from user entropy.
   - Export public keys to the coordinator to be conditioned, stored and shared.
   - Signs and export it back to the coordinator over QR Codes
3. **Backup & recovery**  
   - Keys can be backed up as a BIP39 mnemonic (or other Bitcoin-style methods)  
   - Ensures recoverability even if the hardware is lost

---


## Installation

```bash
# Clone the repo
git clone https://github.com/odudex/gpgap.git
cd gpgap
```

# Install dependencies
```bash
poetry install
```

# Run GPGap
```bash
poetry run python gpgap.py
```

If you’re in a Poetry‐managed virtual environment, just run:

```bash
python gpgap.py
```