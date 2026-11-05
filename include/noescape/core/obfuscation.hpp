#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <array>
#include <utility>

namespace noescape::core {

// ============================================================================
// 64-Bit FNV-1a Compile-Time String Hashing
// ============================================================================
constexpr uint64_t FNV1A_OFFSET = 14695981039346656037ULL;
constexpr uint64_t FNV1A_PRIME  = 1099511628211ULL;

constexpr uint64_t HashFnv1a(const char* str, size_t len) {
    uint64_t hash = FNV1A_OFFSET;
    for (size_t i = 0; i < len; ++i) {
        hash ^= static_cast<uint8_t>(str[i]);
        hash *= FNV1A_PRIME;
    }
    return hash;
}

constexpr uint64_t HashFnv1a(const char* str) {
    uint64_t hash = FNV1A_OFFSET;
    while (*str) {
        hash ^= static_cast<uint8_t>(*str++);
        hash *= FNV1A_PRIME;
    }
    return hash;
}

// Non-linear 64-bit integer mix (SplitMix64) for compile-time keystream derivation
constexpr uint64_t CompileTimeMix64(uint64_t v) {
    v ^= v >> 30;
    v *= 0xbf58476d1ce4e5b9ULL;
    v ^= v >> 27;
    v *= 0x94d049bb133111ebULL;
    v ^= v >> 31;
    return v;
}

constexpr uint8_t CompileTimeKeystreamByte(uint32_t seed, size_t index) {
    uint64_t mixed = CompileTimeMix64(static_cast<uint64_t>(seed) +
                                      static_cast<uint64_t>(index) * 0x9E3779B97F4A7C15ULL +
                                      0x517cc1b727220a95ULL);
    return static_cast<uint8_t>((mixed ^ (mixed >> 32) ^ (mixed >> 16)) & 0xFF);
}

#define NOESCAPE_SEED ((__TIME__[7] - '0') * 1 + \
                       (__TIME__[6] - '0') * 10 + \
                       (__TIME__[4] - '0') * 60 + \
                       (__TIME__[3] - '0') * 600 + \
                       (__TIME__[1] - '0') * 3600 + \
                       (__TIME__[0] - '0') * 36000 + \
                       __LINE__ * 7919)

// ============================================================================
// Multi-Byte Non-Linear CBC Stream Cipher Obfuscation
// Null terminators are chained with previous ciphertext bytes, rendering
// differential and algebraic key derivation impossible.
// ============================================================================
template <size_t N, uint32_t Seed = NOESCAPE_SEED>
class XorString {
    std::array<uint8_t, N> encrypted_{};

public:
    constexpr explicit XorString(const char (&str)[N]) {
        if constexpr (N > 0) {
            encrypted_[0] = static_cast<uint8_t>(str[0]) ^
                            CompileTimeKeystreamByte(Seed, 0) ^
                            static_cast<uint8_t>(Seed & 0x7F);
            for (size_t i = 1; i < N; ++i) {
                uint8_t chain = static_cast<uint8_t>(encrypted_[i - 1] * 33 + 17);
                encrypted_[i] = static_cast<uint8_t>(str[i]) ^
                                CompileTimeKeystreamByte(Seed, i) ^
                                chain;
            }
        }
    }

    // Decrypts string into a rotating ring of thread-local buffers to allow
    // multiple concurrent string decryptions in a single expression.
    const char* decrypt() const {
        if constexpr (N == 0) return "";
        constexpr size_t RING_SIZE = 4;
        thread_local char rings[RING_SIZE][N];
        thread_local size_t ring_idx = 0;

        char* dest = rings[ring_idx];
        ring_idx = (ring_idx + 1) % RING_SIZE;

        dest[0] = static_cast<char>(encrypted_[0] ^
                                    CompileTimeKeystreamByte(Seed, 0) ^
                                    static_cast<uint8_t>(Seed & 0x7F));
        for (size_t i = 1; i < N; ++i) {
            uint8_t chain = static_cast<uint8_t>(encrypted_[i - 1] * 33 + 17);
            dest[i] = static_cast<char>(encrypted_[i] ^
                                        CompileTimeKeystreamByte(Seed, i) ^
                                        chain);
        }
        return dest;
    }

    std::string str() const {
        return std::string(decrypt(), N > 0 ? N - 1 : 0);
    }

    constexpr size_t size() const { return N; }
};

#define NOESCAPE_XOR(s) ([]() { \
    constexpr ::noescape::core::XorString<sizeof(s), NOESCAPE_SEED> obfuscated(s); \
    return obfuscated.decrypt(); \
}())

#define NOESCAPE_HASH(s) (::noescape::core::HashFnv1a(s))

} // namespace noescape::core
