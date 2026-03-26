# Getting Started with libpqc-dyber (Python)

## Installation

```bash
pip install pqc-dyber
```

## Key Encapsulation (KEM)

```python
import pqc_dyber as pqc

# Create a KEM instance
kem = pqc.KEM("ML-KEM-768")

# Generate keypair
pk, sk = kem.keygen()

# Encapsulate (produces ciphertext + shared secret)
ct, ss_sender = kem.encaps(pk)

# Decapsulate (recovers shared secret)
ss_receiver = kem.decaps(ct, sk)

assert ss_sender == ss_receiver
print(f"Shared secret: {ss_sender.hex()}")
```

## Digital Signatures

```python
import pqc_dyber as pqc

# Create a signature instance
sig = pqc.Signature("ML-DSA-65")

# Generate keypair
pk, sk = sig.keygen()

# Sign a message
message = b"Hello, post-quantum world!"
signature = sig.sign(message, sk)

# Verify
is_valid = sig.verify(message, signature, pk)
print(f"Signature valid: {is_valid}")
```

## List Available Algorithms

```python
import pqc_dyber as pqc

print("KEM algorithms:", pqc.kem_algorithms())
print("Signature algorithms:", pqc.sig_algorithms())
```
