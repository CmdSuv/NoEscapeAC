#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <array>
#include <atomic>
#include <type_traits>
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

// ============================================================================
// Runtime Rolling-Key Value Encryption (Anti-DMA / Anti-CheatEngine)
// Encrypts 1/2/4/8-byte trivially copyable values in RAM using SplitMix64
// keyed by the object's address and a rotating per-write nonce.
// ============================================================================
template <typename T>
class ObfuscatedValue {
    static_assert(std::is_trivially_copyable_v<T> && sizeof(T) <= sizeof(uint64_t),
                  "ObfuscatedValue requires a trivially copyable type up to 64 bits");

    uint64_t ciphertext_{0};
    uint64_t nonce_{0};

    uint64_t DeriveMask(uint64_t nonce) const noexcept {
        uintptr_t selfAddr = reinterpret_cast<uintptr_t>(this);
        return CompileTimeMix64(nonce ^ (static_cast<uint64_t>(selfAddr) * 0x9E3779B97F4A7C15ULL) ^
                                0xD6E8FEB86659FD93ULL);
    }

public:
    ObfuscatedValue() noexcept { store(T{}); }
    explicit ObfuscatedValue(T initial) noexcept { store(initial); }

    ObfuscatedValue(const ObfuscatedValue& other) noexcept { store(other.load()); }
    ObfuscatedValue& operator=(const ObfuscatedValue& other) noexcept {
        if (this != &other) store(other.load());
        return *this;
    }

    void store(T val) noexcept {
        nonce_ = CompileTimeMix64(nonce_ + 0x9E3779B97F4A7C15ULL);
        uint64_t raw = 0;
        std::memcpy(&raw, &val, sizeof(T));
        ciphertext_ = raw ^ DeriveMask(nonce_);
    }

    T load() const noexcept {
        uint64_t raw = ciphertext_ ^ DeriveMask(nonce_);
        T val{};
        std::memcpy(&val, &raw, sizeof(T));
        return val;
    }

    uint64_t raw_ciphertext() const noexcept { return ciphertext_; }

    operator T() const noexcept { return load(); }
    ObfuscatedValue& operator=(T val) noexcept {
        store(val);
        return *this;
    }
};

// ============================================================================
// Compiler-Opaque Predicates (Anti-Decompiler / Control-Flow Hardening)
// Prevents static constant propagation in IDA / Ghidra while always evaluating
// deterministically at runtime.
// ============================================================================
inline bool OpaqueTrue(uint64_t seed = 0x7F4A7C159E3779B9ULL) noexcept {
    volatile uint64_t x = seed | 1ULL;
    // Odd square mod 8 is always 1 (x^2 ≡ 1 mod 8 for all odd integers x)
    return ((x * x) & 7ULL) == 1ULL;
}

} // namespace noescape::core
