#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>

namespace noescape::network::chacha20poly1305 {

// RFC 8439 ChaCha20 block function
void ChaCha20Block(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12], uint8_t out_block[64]);

// RFC 8439 ChaCha20 stream encryption/decryption
void ChaCha20Crypt(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12],
                   const uint8_t* in, size_t len, uint8_t* out);

// RFC 8439 Poly1305 one-time authenticator MAC
void Poly1305Mac(const uint8_t key[32], const uint8_t* msg, size_t msg_len, uint8_t out_tag[16]);

// RFC 8439 AEAD ChaCha20-Poly1305 Authenticated Encryption
bool AeadEncrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* plaintext, size_t plaintext_len,
    std::vector<uint8_t>& out_ciphertext,
    uint8_t out_tag[16]
);

// RFC 8439 AEAD ChaCha20-Poly1305 Authenticated Decryption
bool AeadDecrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t tag[16],
    std::vector<uint8_t>& out_plaintext
);

} // namespace noescape::network::chacha20poly1305
