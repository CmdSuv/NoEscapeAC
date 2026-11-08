#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace noescape::network {

class CryptoUtil {
public:
    // Pure C++20 Ring-3 SHA-256 implementation
    static std::string Sha256(const uint8_t* data, size_t length);
    static std::string Sha256(const std::string& input);

    // HMAC-SHA256 for tamper-evident payload signing
    static std::string HmacSha256(const std::string& key, const std::string& data);

    // Machine Hardware ID (HWID) Fingerprinting
    static std::string GetMachineHWID();

    // Constant-time equality for MAC/signature comparison (no early exit on first mismatch)
    static bool ConstantTimeEquals(const std::string& a, const std::string& b);

    // Hex formatting & parsing helpers
    static std::string ToHex(const uint8_t* data, size_t length);
    static std::vector<uint8_t> FromHex(const std::string& hex);

    // Streaming SHA-256 file digest (64KB chunks; empty string on I/O error)
    static std::string Sha256File(const std::string& file_path);

    // OS CSPRNG byte and hex token generation (returns false on entropy failure)
    static bool GenerateRandomBytes(uint8_t* out, size_t length);
    static std::string GenerateRandomHex(size_t byte_length);

    // HKDF-SHA256 (RFC 5869) directional/session key derivation
    static std::string DeriveKeyHkdf(
        const std::string& input_key_material,
        const std::string& salt,
        const std::string& info
    );

    // Ed25519 Asymmetric Keypair & Verification (32-byte raw public key hex / 64-byte signature hex).
    // Uses OpenSSL EVP_PKEY_ED25519 when available, with deterministic portable fallback.
    struct AsymmetricKeyPair {
        std::string private_key_hex;
        std::string public_key_hex;
    };
    static AsymmetricKeyPair GenerateAsymmetricKeyPair();
    static std::string SignAsymmetric(const std::string& private_key_hex, const std::string& message);
    static bool VerifyAsymmetric(
        const std::string& public_key_hex,
        const std::string& message,
        const std::string& signature_hex
    );

    // X25519 Key Exchange (RFC 7748 / RFC 9180 HPKE)
    static AsymmetricKeyPair GenerateX25519KeyPair();
    static std::string DiffieHellmanX25519(
        const std::string& private_key_hex,
        const std::string& peer_public_key_hex
    );

    // RFC 8439 ChaCha20-Poly1305 AEAD authenticated encryption & decryption
    // key: 32 bytes, nonce: 12 bytes, tag: 16 bytes
    static bool AeadChaCha20Poly1305Encrypt(
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& aad,
        const uint8_t key[32],
        const uint8_t nonce[12],
        std::vector<uint8_t>& out_ciphertext,
        uint8_t out_tag[16]
    );

    static bool AeadChaCha20Poly1305Decrypt(
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& aad,
        const uint8_t tag[16],
        const uint8_t key[32],
        const uint8_t nonce[12],
        std::vector<uint8_t>& out_plaintext
    );

    // Semantic version check for anti-rollback protection (returns true if actual >= minimum_required)
    static bool IsVersionAtLeast(const std::string& actual_version, const std::string& minimum_required);
};

} // namespace noescape::network
