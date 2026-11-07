# NoEscapeAC Cryptographic Architecture & Formal Security Review

**Project:** NoEscapeAC — Unified Ring-3 Anti-Cheat Architecture  
**Architects:** Omar Yiğitcan Mengü (`@CmdSuv`) & OnlyCosmos (`@OnlyCosmos`)  
**Standard:** Modern C++20  
**Scope:** Formal Verification of Cryptographic Primitives, RFC Compliance, Key Management, and Side-Channel Hardening  

---

## 1. Cryptographic Inventory & Primitives Matrix

| Function | Primitive / Algorithm | Standard Specification | Implementation Details | Side-Channel Resistance | Key Lifecycle & Storage |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Asymmetric Signatures** | Pure Ed25519 | RFC 8032 | Edwards-curve Digital Signature over Curve25519; twisted Edwards curve $ -x^2 + y^2 = 1 - \frac{121665}{121666} x^2 y^2 $ | Constant-time field multiplication; zero branching on secret key bits | 32-byte secret seed; 32-byte public key point. Server retains signing key; client possesses only verification key. |
| **Authenticated Encryption** | ChaCha20-Poly1305 AEAD | RFC 8439 | 20-round stream cipher (quarter-round ARX) coupled with Poly1305 authenticator over $2^{130}-5$ | Constant-time ARX (Add-Rotate-Xor) operations; no S-Boxes (cache-timing immune) | Ephemeral 12-byte CSPRNG nonce per packet; 32-byte session key derived via HKDF-SHA256. |
| **Key Derivation** | HKDF-SHA256 | RFC 5869 | Extract-and-Expand key derivation utilizing HMAC-SHA256 | Constant-time HMAC operations | Dynamic salt input (16 bytes random per session); application domain separation (`info` strings). |
| **Payload Integrity & MAC** | HMAC-SHA256 | RFC 2104 / FIPS 198-1 | Outer and inner padded hash digest using SHA-256 compression function | Constant-time digest verification (`ConstantTimeEquals`) | Secret shared deployment key or derived attestation token. |
| **Hashing & Digests** | SHA-256 | FIPS 180-4 | Pure C++20 implementation; 64-round compression on 512-bit message blocks | Fixed-iteration loop execution independent of input data contents | One-way hashing of files, modules, and attestation tokens. |
| **Device Identification** | HWID Fingerprinting | Proprietary SHA-256 Hash | Combines CPUID feature flags, motherboard UUID, DMI product serial, and root filesystem UUID | Nonce-keyed hash preventing pre-computation attacks | Irreversible salted hash; raw hardware strings are zeroized immediately after hashing. |

---

## 2. Asymmetric Signature Security: Ed25519 (RFC 8032)

### 2.1 The Vulnerability of Homemade / HMAC Fallbacks
In v1.3, builds without OpenSSL defaulted to:
```cpp
// INSECURE FALLBACK (v1.3):
return HmacSha256(public_key_hex, message);
```
In any asymmetric scheme, the public key is distributed to untrusted clients to verify signatures produced by an authoritative server. Under HMAC, the key is symmetric. A client holding the public key is immediately capable of signing arbitrary verdicts, forge attestations, and spoof server approvals.

### 2.2 Reengineered RFC 8032 Pure Ed25519 Architecture
NoEscapeAC v2.0 integrates a dedicated RFC 8032 Pure Ed25519 provider (`src/network/ed25519.cpp`):
1. **Mathematical Foundation:**
   - Field: $\mathbb{F}_p$ where $p = 2^{255} - 19$.
   - Curve: $-x^2 + y^2 = 1 + d x^2 y^2$ where $d = -\frac{121665}{121666} \pmod p$.
   - Base Point: $B = (x, 4/5)$ with order $\ell = 2^{252} + 27742317777372353535851937790883648493$.
2. **Deterministic Signing:**
   - Secret key expansion: $H(k) = (h_0, h_1, \dots, h_{63})$.
   - Scalar clamping: $a = 2^{254} + \sum_{i=3}^{253} 2^i h_i$.
   - Nonce generation: $r = H(h_{32..63} \mathbin{\Vert} M) \pmod \ell$.
   - Point multiplication: $R = rB$.
   - Challenge scalar: $k = H(\underline{R} \mathbin{\Vert} \underline{A} \mathbin{\Vert} M) \pmod \ell$.
   - Signature scalar: $s = (r + k a) \pmod \ell$.
   - Signature: $(R, s)$.
3. **Verification Guarantees:**
   - Decompresses public key point $A$ and signature point $R$. Rejects points not on the curve.
   - Computes $k = H(\underline{R} \mathbin{\Vert} \underline{A} \mathbin{\Vert} M) \pmod \ell$.
   - Validates scalar equation: $8 s B = 8 R + 8 k A$.
   - Rejects unreduced $s \ge \ell$ to eliminate malleable signature exploits.

### 2.3 Formal Test Vectors
Verified against official RFC 8032 vectors:
- **Vector 1:** Empty message signature verification.
- **Vector 2:** 1-byte message `0x72`.
- **Vector 3:** 2-byte message `0xabab`.
- **Negative Forgery Tests:** Verified that tampering with a single message bit, altering signature scalars, substituting non-matching public keys, or truncating signatures yields deterministic rejection.
- **Negative Knowledge Test:** Verified that possessing only the 32-byte public verification key cannot generate a valid signature.

---

## 3. Authenticated Encryption: RFC 8439 ChaCha20-Poly1305 AEAD

### 3.1 Deficiencies of Custom Keystreams
Legacy flight-recorder implementations encrypted dumps using a custom CTR loop hashing `Sha256(derivedKey + ":" + counter)`. Custom stream ciphers lack formal security proofs, risk keystream reuse vulnerabilities upon counter overflow, and offer no native integrity assurance without a secondary MAC.

### 3.2 RFC 8439 AEAD Implementation
NoEscapeAC v2.0 modernizes the blackbox telemetry pipeline to RFC 8439 AEAD:
1. **ChaCha20 State Configuration:**
   - 16 32-bit state words: 4 constant words (`"expand 32-byte k"`), 8 key words (256-bit derived key), 1 block counter, 3 nonce words (96-bit CSPRNG nonce).
   - Quarter-round ARX operations execute 10 column rounds and 10 diagonal rounds (20 total).
2. **One-Time Poly1305 Subkey Generation:**
   - ChaCha20 block 0 is generated.
   - First 16 bytes clamped: $r = \text{clamp}(B_0[0..15])$.
   - Bytes 16..31 serve as additive secret scalar $s = B_0[16..31]$.
3. **Authenticated Additional Data (AAD) Binding:**
   - AAD incorporates the 4-byte Magic header (`"NEBB"`), 2-byte format version (2), 12-byte CSPRNG nonce, and 16-byte random salt.
   - Any modification to header parameters immediately invalidates the Poly1305 authentication tag prior to payload decryption.

---

## 4. Key Derivation & Domain Separation: RFC 5869 HKDF-SHA256

All ephemeral session keys and storage tokens are derived using RFC 5869 HKDF:
$$\text{PRK} = \text{HMAC-SHA256}(\text{salt}, \text{IKM})$$
$$\text{OKM} = \text{HMAC-SHA256}(\text{PRK}, \text{info} \mathbin{\Vert} \text{0x01})$$

Distinct domain separation strings prevent cross-protocol key leakage:
- `"NoEscape-Blackbox-v2"`: Flight-recorder diagnostic AEAD keys.
- `"NoEscape-Session-Token-v2"`: Ephemeral client heartbeat tokens.
- `"NoEscape-Attestation-v2"`: Memory section hash challenge responses.

---

## 5. Side-Channel Hardening & Timing Attack Mitigation

1. **Constant-Time Memory Comparison (`ConstantTimeEquals`)**:
   Standard `std::memcmp` or `std::string::operator==` aborts on the first mismatched byte, creating measurable timing discrepancies proportional to the length of the matching prefix.
   NoEscapeAC enforces bitwise constant-time comparison:
   ```cpp
   bool CryptoUtil::ConstantTimeEquals(const std::string& a, const std::string& b) {
       if (a.size() != b.size()) return false;
       unsigned char diff = 0;
       for (size_t i = 0; i < a.size(); ++i) {
           diff |= static_cast<unsigned char>(a[i] ^ b[i]);
       }
       return diff == 0;
   }
   ```
2. **Cache-Timing Resistance:**
   ChaCha20 and Poly1305 do not rely on lookup tables (S-Boxes), completely eliminating AES cache-line collision timing side-channels on shared hyperthreaded CPU cores.

---

## 6. HWID Entropy Analysis & Device Fingerprinting

Machine hardware identification aggregates high-entropy, low-volatility hardware identifiers:
1. **Entropy Sources:**
   - CPUID Brand, Family, Model, Stepping, and Feature Bitmasks.
   - DMI / SMBIOS Motherboard Serial Number and UUID (`/sys/class/dmi/id/product_uuid` or Win32 `WMI Win32_BaseBoard`).
   - Root Filesystem Block Device UUID (`/dev/disk/by-uuid` or Win32 Volume Serial).
   - Primary Network Adapter Permanent Physical MAC Address (excluding virtual adapters).
2. **Salted Nonce Hardening:**
   Hardware strings are salted with a deployment secret and hashed via SHA-256. Raw serial numbers are never stored in memory or transmitted over the wire, protecting player privacy while generating a deterministic, spoof-resistant 256-bit hardware fingerprint.
