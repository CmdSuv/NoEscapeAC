#pragma once

#include <cstdint>
#include <cstddef>

namespace noescape::network::ed25519 {

// Generates an Ed25519 keypair from a 32-byte seed.
// out_public_key: buffer of at least 32 bytes
// out_private_key: buffer of at least 64 bytes (seed || public_key)
bool CreateKeyPair(const uint8_t* seed, uint8_t* out_public_key, uint8_t* out_private_key);

// Signs a message using a 32-byte seed or 64-byte expanded private key.
// out_signature: buffer of at least 64 bytes
bool Sign(const uint8_t* private_key, size_t private_key_len,
          const uint8_t* message, size_t message_len,
          uint8_t* out_signature);

// Verifies a 64-byte detached signature against a 32-byte public key.
bool Verify(const uint8_t* public_key,
            const uint8_t* message, size_t message_len,
            const uint8_t* signature);

// Pure software RFC 8032 verification without external provider
bool VerifySoftware(const uint8_t* public_key,
                    const uint8_t* message, size_t message_len,
                    const uint8_t* signature);

} // namespace noescape::network::ed25519

namespace noescape::network::x25519 {

// Generates an X25519 keypair from a 32-byte seed / private key.
// out_public_key: buffer of at least 32 bytes
// out_private_key: buffer of at least 32 bytes
bool CreateKeyPair(const uint8_t* seed, uint8_t* out_public_key, uint8_t* out_private_key);

// Performs X25519 Diffie-Hellman scalar multiplication (RFC 7748):
// out_shared_secret = private_key * peer_public_key
// out_shared_secret: buffer of at least 32 bytes
bool DiffieHellman(const uint8_t* private_key, const uint8_t* peer_public_key, uint8_t* out_shared_secret);

} // namespace noescape::network::x25519

