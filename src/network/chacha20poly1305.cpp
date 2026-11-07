#include "noescape/network/chacha20poly1305.hpp"
#include <cstring>
#include <array>

namespace noescape::network::chacha20poly1305 {

namespace {

inline uint32_t RotL32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

inline void QuarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b; d ^= a; d = RotL32(d, 16);
    c += d; b ^= c; b = RotL32(b, 12);
    a += b; d ^= a; d = RotL32(d, 8);
    c += d; b ^= c; b = RotL32(b, 7);
}

inline uint32_t GetU32LE(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
          (static_cast<uint32_t>(p[1]) << 8) |
          (static_cast<uint32_t>(p[2]) << 16) |
          (static_cast<uint32_t>(p[3]) << 24);
}

inline void PutU32LE(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v & 0xFF);
    p[1] = static_cast<uint8_t>((v >> 8) & 0xFF);
    p[2] = static_cast<uint8_t>((v >> 16) & 0xFF);
    p[3] = static_cast<uint8_t>((v >> 24) & 0xFF);
}

inline uint64_t GetU64LE(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= (static_cast<uint64_t>(p[i]) << (i * 8));
    }
    return v;
}

inline void PutU64LE(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        p[i] = static_cast<uint8_t>((v >> (i * 8)) & 0xFF);
    }
}

} // namespace

void ChaCha20Block(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12], uint8_t out_block[64]) {
    uint32_t state[16];
    // Constants ("expand 32-byte k")
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    for (int i = 0; i < 8; ++i) {
        state[4 + i] = GetU32LE(key + i * 4);
    }
    state[12] = counter;
    for (int i = 0; i < 3; ++i) {
        state[13 + i] = GetU32LE(nonce + i * 4);
    }

    uint32_t working[16];
    std::memcpy(working, state, sizeof(state));

    for (int round = 0; round < 10; ++round) {
        // Column rounds
        QuarterRound(working[0], working[4], working[8],  working[12]);
        QuarterRound(working[1], working[5], working[9],  working[13]);
        QuarterRound(working[2], working[6], working[10], working[14]);
        QuarterRound(working[3], working[7], working[11], working[15]);
        // Diagonal rounds
        QuarterRound(working[0], working[5], working[10], working[15]);
        QuarterRound(working[1], working[6], working[11], working[12]);
        QuarterRound(working[2], working[7], working[8],  working[13]);
        QuarterRound(working[3], working[4], working[9],  working[14]);
    }

    for (int i = 0; i < 16; ++i) {
        PutU32LE(out_block + i * 4, working[i] + state[i]);
    }
}

void ChaCha20Crypt(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12],
                   const uint8_t* in, size_t len, uint8_t* out) {
    uint8_t block[64];
    size_t offset = 0;
    while (offset < len) {
        ChaCha20Block(key, counter++, nonce, block);
        size_t chunk = (len - offset < 64) ? (len - offset) : 64;
        for (size_t i = 0; i < chunk; ++i) {
            out[offset + i] = in[offset + i] ^ block[i];
        }
        offset += chunk;
    }
}

void Poly1305Mac(const uint8_t key[32], const uint8_t* msg, size_t msg_len, uint8_t out_tag[16]) {
    // Clamped r in 26-bit limbs
    uint32_t r0 = (GetU32LE(key + 0)) & 0x3ffffff;
    uint32_t r1 = (GetU32LE(key + 3) >> 2) & 0x3ffff03;
    uint32_t r2 = (GetU32LE(key + 6) >> 4) & 0x3ffc0ff;
    uint32_t r3 = (GetU32LE(key + 9) >> 6) & 0x3f03fff;
    uint32_t r4 = (GetU32LE(key + 12) >> 8) & 0x00fffff;

    uint32_t s1 = r1 * 5;
    uint32_t s2 = r2 * 5;
    uint32_t s3 = r3 * 5;
    uint32_t s4 = r4 * 5;

    uint32_t h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;

    size_t offset = 0;
    while (offset < msg_len) {
        size_t chunk = (msg_len - offset < 16) ? (msg_len - offset) : 16;
        uint8_t buf[16]{};
        std::memcpy(buf, msg + offset, chunk);

        uint32_t c0 = (GetU32LE(buf + 0)) & 0x3ffffff;
        uint32_t c1 = (GetU32LE(buf + 3) >> 2) & 0x3ffffff;
        uint32_t c2 = (GetU32LE(buf + 6) >> 4) & 0x3ffffff;
        uint32_t c3 = (GetU32LE(buf + 9) >> 6) & 0x3ffffff;
        uint32_t c4 = (GetU32LE(buf + 12) >> 8);

        if (chunk == 16) {
            c4 |= (1u << 24);
        } else {
            // Append 0x01 byte at chunk position
            buf[chunk] = 0x01;
            c0 = (GetU32LE(buf + 0)) & 0x3ffffff;
            c1 = (GetU32LE(buf + 3) >> 2) & 0x3ffffff;
            c2 = (GetU32LE(buf + 6) >> 4) & 0x3ffffff;
            c3 = (GetU32LE(buf + 9) >> 6) & 0x3ffffff;
            c4 = (GetU32LE(buf + 12) >> 8);
        }

        h0 += c0;
        h1 += c1;
        h2 += c2;
        h3 += c3;
        h4 += c4;

        uint64_t d0 = static_cast<uint64_t>(h0) * r0 + static_cast<uint64_t>(h1) * s4 +
                      static_cast<uint64_t>(h2) * s3 + static_cast<uint64_t>(h3) * s2 +
                      static_cast<uint64_t>(h4) * s1;
        uint64_t d1 = static_cast<uint64_t>(h0) * r1 + static_cast<uint64_t>(h1) * r0 +
                      static_cast<uint64_t>(h2) * s4 + static_cast<uint64_t>(h3) * s3 +
                      static_cast<uint64_t>(h4) * s2;
        uint64_t d2 = static_cast<uint64_t>(h0) * r2 + static_cast<uint64_t>(h1) * r1 +
                      static_cast<uint64_t>(h2) * r0 + static_cast<uint64_t>(h3) * s4 +
                      static_cast<uint64_t>(h4) * s3;
        uint64_t d3 = static_cast<uint64_t>(h0) * r3 + static_cast<uint64_t>(h1) * r2 +
                      static_cast<uint64_t>(h2) * r1 + static_cast<uint64_t>(h3) * r0 +
                      static_cast<uint64_t>(h4) * s4;
        uint64_t d4 = static_cast<uint64_t>(h0) * r4 + static_cast<uint64_t>(h1) * r3 +
                      static_cast<uint64_t>(h2) * r2 + static_cast<uint64_t>(h3) * r1 +
                      static_cast<uint64_t>(h4) * r0;

        uint64_t c = d0 >> 26; h0 = static_cast<uint32_t>(d0 & 0x3ffffff); d1 += c;
        c = d1 >> 26; h1 = static_cast<uint32_t>(d1 & 0x3ffffff); d2 += c;
        c = d2 >> 26; h2 = static_cast<uint32_t>(d2 & 0x3ffffff); d3 += c;
        c = d3 >> 26; h3 = static_cast<uint32_t>(d3 & 0x3ffffff); d4 += c;
        c = d4 >> 26; h4 = static_cast<uint32_t>(d4 & 0x3ffffff);
        h0 += static_cast<uint32_t>(c * 5);
        c = h0 >> 26; h0 &= 0x3ffffff; h1 += static_cast<uint32_t>(c);

        offset += chunk;
    }

    uint32_t c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

    // Compute h + 5 to subtract 2^130 - 5 if h >= 2^130 - 5
    uint32_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    uint32_t g4 = h4 + c - (1u << 26);

    uint32_t mask = (g4 >> 31) - 1; // 0 if g4 < 0, 0xFFFFFFFF if g4 >= 0
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    uint64_t f0 = (static_cast<uint64_t>(h0)) |
                  (static_cast<uint64_t>(h1) << 26) |
                  ((static_cast<uint64_t>(h2) & 0xFFF) << 52);
    uint64_t f1 = (static_cast<uint64_t>(h2) >> 12) |
                  (static_cast<uint64_t>(h3) << 14) |
                  (static_cast<uint64_t>(h4) << 40);

    uint64_t keyS0 = GetU64LE(key + 16);
    uint64_t keyS1 = GetU64LE(key + 24);

    f0 += keyS0;
    f1 += keyS1 + (f0 < keyS0 ? 1 : 0);

    PutU64LE(out_tag + 0, f0);
    PutU64LE(out_tag + 8, f1);
}

bool AeadEncrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* plaintext, size_t plaintext_len,
    std::vector<uint8_t>& out_ciphertext,
    uint8_t out_tag[16]
) {
    // 1. One-time Poly1305 key: block 0 of ChaCha20
    uint8_t polyKeyBlock[64];
    ChaCha20Block(key, 0, nonce, polyKeyBlock);

    // 2. Encrypt plaintext starting at counter 1
    out_ciphertext.resize(plaintext_len);
    if (plaintext_len > 0) {
        ChaCha20Crypt(key, 1, nonce, plaintext, plaintext_len, out_ciphertext.data());
    }

    // 3. Construct Poly1305 MAC stream:
    // pad16(aad) || pad16(ciphertext) || len(aad) LE64 || len(ciphertext) LE64
    size_t aadPad = (aad_len % 16 != 0) ? (16 - (aad_len % 16)) : 0;
    size_t cipherPad = (plaintext_len % 16 != 0) ? (16 - (plaintext_len % 16)) : 0;
    size_t macLen = aad_len + aadPad + plaintext_len + cipherPad + 16;

    std::vector<uint8_t> macStream;
    macStream.reserve(macLen);
    if (aad && aad_len > 0) {
        macStream.insert(macStream.end(), aad, aad + aad_len);
        macStream.insert(macStream.end(), aadPad, 0);
    }
    if (!out_ciphertext.empty()) {
        macStream.insert(macStream.end(), out_ciphertext.begin(), out_ciphertext.end());
        macStream.insert(macStream.end(), cipherPad, 0);
    }
    uint8_t lenBuf[16]{};
    PutU64LE(lenBuf + 0, static_cast<uint64_t>(aad_len));
    PutU64LE(lenBuf + 8, static_cast<uint64_t>(plaintext_len));
    macStream.insert(macStream.end(), lenBuf, lenBuf + 16);

    Poly1305Mac(polyKeyBlock, macStream.data(), macStream.size(), out_tag);
    return true;
}

bool AeadDecrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t tag[16],
    std::vector<uint8_t>& out_plaintext
) {
    if (!key || !nonce || !tag) return false;

    // 1. One-time Poly1305 key: block 0 of ChaCha20
    uint8_t polyKeyBlock[64];
    ChaCha20Block(key, 0, nonce, polyKeyBlock);

    // 2. Construct Poly1305 MAC stream over ciphertext
    size_t aadPad = (aad_len % 16 != 0) ? (16 - (aad_len % 16)) : 0;
    size_t cipherPad = (ciphertext_len % 16 != 0) ? (16 - (ciphertext_len % 16)) : 0;
    size_t macLen = aad_len + aadPad + ciphertext_len + cipherPad + 16;

    std::vector<uint8_t> macStream;
    macStream.reserve(macLen);
    if (aad && aad_len > 0) {
        macStream.insert(macStream.end(), aad, aad + aad_len);
        macStream.insert(macStream.end(), aadPad, 0);
    }
    if (ciphertext && ciphertext_len > 0) {
        macStream.insert(macStream.end(), ciphertext, ciphertext + ciphertext_len);
        macStream.insert(macStream.end(), cipherPad, 0);
    }
    uint8_t lenBuf[16]{};
    PutU64LE(lenBuf + 0, static_cast<uint64_t>(aad_len));
    PutU64LE(lenBuf + 8, static_cast<uint64_t>(ciphertext_len));
    macStream.insert(macStream.end(), lenBuf, lenBuf + 16);

    uint8_t computedTag[16]{};
    Poly1305Mac(polyKeyBlock, macStream.data(), macStream.size(), computedTag);

    // Constant-time tag check
    uint8_t diff = 0;
    for (int i = 0; i < 16; ++i) {
        diff |= (computedTag[i] ^ tag[i]);
    }
    if (diff != 0) {
        out_plaintext.clear();
        return false;
    }

    // 3. Decrypt ciphertext starting at counter 1
    out_plaintext.resize(ciphertext_len);
    if (ciphertext_len > 0) {
        ChaCha20Crypt(key, 1, nonce, ciphertext, ciphertext_len, out_plaintext.data());
    }
    return true;
}

} // namespace noescape::network::chacha20poly1305
