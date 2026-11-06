#include "noescape/memory/pattern_scanner.hpp"
#include "noescape/memory/cheat_signature.hpp"
#include <sstream>
#include <algorithm>
#include <cstring>
#include <bit>

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#include <immintrin.h>
#define NOESCAPE_X86 1
#endif

// The scanner deliberately reads arbitrary process memory (including allocator redzones), so it
// must not be instrumented by AddressSanitizer / HWASan, or every audit would report a false
// "overflow". Production builds are unaffected.
#if defined(__clang__) || defined(__GNUC__)
#define NOESCAPE_NO_SANITIZE __attribute__((no_sanitize("address", "hwaddress")))
#else
#define NOESCAPE_NO_SANITIZE
#endif

namespace noescape::memory {

Pattern::Pattern(std::string_view ida_pattern, std::string name) 
    : name_(std::move(name)) {
    std::string token;
    std::istringstream stream{std::string(ida_pattern)};

    while (stream >> token) {
        if (token == "?" || token == "??") {
            bytes_.push_back({0, true});
        } else {
            auto val = static_cast<uint8_t>(std::strtoul(token.c_str(), nullptr, 16));
            bytes_.push_back({val, false});
        }
    }

    // Determine first non-wildcard byte
    has_non_wildcard_ = false;
    for (size_t i = 0; i < bytes_.size(); ++i) {
        if (!bytes_[i].is_wildcard) {
            first_byte_ = bytes_[i].value;
            first_byte_offset_ = i;
            has_non_wildcard_ = true;
            break;
        }
    }
}

Pattern::Pattern(const uint8_t* bytes, const char* mask, std::string name)
    : name_(std::move(name)) {
    if (!bytes || !mask) return;
    size_t len = std::strlen(mask);
    bytes_.reserve(len);

    for (size_t i = 0; i < len; ++i) {
        bool wildcard = (mask[i] == '?');
        bytes_.push_back({bytes[i], wildcard});
    }

    has_non_wildcard_ = false;
    for (size_t i = 0; i < bytes_.size(); ++i) {
        if (!bytes_[i].is_wildcard) {
            first_byte_ = bytes_[i].value;
            first_byte_offset_ = i;
            has_non_wildcard_ = true;
            break;
        }
    }
}

NOESCAPE_NO_SANITIZE inline bool PatternScanner::MatchAt(const uint8_t* ptr, const Pattern& pattern) {
    const auto& bytes = pattern.GetBytes();
    const size_t len = bytes.size();
    for (size_t i = 0; i < len; ++i) {
        if (!bytes[i].is_wildcard && ptr[i] != bytes[i].value) {
            return false;
        }
    }
    return true;
}

NOESCAPE_NO_SANITIZE const uint8_t* PatternScanner::ScanScalar(
    const uint8_t* data, 
    size_t size, 
    const Pattern& pattern
) {
    if (size < pattern.Length()) return nullptr;

    const size_t max_scan = size - pattern.Length();
    if (!pattern.HasNonWildcard()) {
        // Pattern contains exclusively wildcards; matches immediately at offset 0
        return data;
    }

    const uint8_t first = pattern.FirstByte();
    const size_t first_offset = pattern.FirstByteOffset();

    for (size_t i = 0; i <= max_scan; ++i) {
        if (data[i + first_offset] == first && MatchAt(data + i, pattern)) {
            return data + i;
        }
    }
    return nullptr;
}

#if defined(NOESCAPE_X86) && (defined(__GNUC__) || defined(__clang__)) && !defined(_MSC_VER)
#define NOESCAPE_RUNTIME_DISPATCH 1
#endif

namespace {

NOESCAPE_NO_SANITIZE inline bool MatchAtFree(const uint8_t* ptr, const Pattern& pattern) {
    const auto& bytes = pattern.GetBytes();
    for (size_t i = 0; i < bytes.size(); ++i) {
        if (!bytes[i].is_wildcard && ptr[i] != bytes[i].value) return false;
    }
    return true;
}

NOESCAPE_NO_SANITIZE const uint8_t* ScanScalarFree(const uint8_t* data, size_t size, const Pattern& pattern) {
    if (size < pattern.Length()) return nullptr;
    if (!pattern.HasNonWildcard()) return data;
    const size_t max_scan = size - pattern.Length();
    const uint8_t first = pattern.FirstByte();
    const size_t off = pattern.FirstByteOffset();
    for (size_t i = 0; i <= max_scan; ++i) {
        if (data[i + off] == first && MatchAtFree(data + i, pattern)) return data + i;
    }
    return nullptr;
}

#if defined(NOESCAPE_X86)
// Shared SIMD driver parametrised on block width; each wrapper below is compiled for its ISA.
#define NOESCAPE_SIMD_BODY(WIDTH, SET1, LOADU, CMPEQ, MOVEMASK, VEC)                                  \
    const size_t pattern_len = pattern.Length();                                                      \
    const size_t max_scan = size - pattern_len;                                                       \
    const uint8_t first = pattern.FirstByte();                                                        \
    const size_t first_offset = pattern.FirstByteOffset();                                            \
    const VEC match_vec = SET1(static_cast<char>(first));                                             \
    size_t i = 0;                                                                                     \
    while (i + first_offset + WIDTH <= size && i <= max_scan) {                                       \
        VEC block = LOADU(reinterpret_cast<const VEC*>(data + i + first_offset));                     \
        uint32_t mask = static_cast<uint32_t>(MOVEMASK(CMPEQ(block, match_vec)));                     \
        while (mask != 0) {                                                                           \
            size_t cand = i + static_cast<size_t>(std::countr_zero(mask));                            \
            if (cand <= max_scan && MatchAtFree(data + cand, pattern)) {            \
                return data + cand;                                                                   \
            }                                                                                         \
            mask &= mask - 1;                                                                         \
        }                                                                                             \
        i += WIDTH;                                                                                   \
    }                                                                                                 \
    if (i <= max_scan) {                                                                              \
        return ScanScalarFree(data + i, size - i, pattern);                         \
    }                                                                                                 \
    return nullptr;

#if defined(NOESCAPE_RUNTIME_DISPATCH)
__attribute__((target("avx2")))
#endif
NOESCAPE_NO_SANITIZE const uint8_t* ScanAvx2Impl(const uint8_t* data, size_t size, const Pattern& pattern) {
#if defined(__AVX2__) || defined(NOESCAPE_RUNTIME_DISPATCH)
    NOESCAPE_SIMD_BODY(32, _mm256_set1_epi8, _mm256_loadu_si256, _mm256_cmpeq_epi8, _mm256_movemask_epi8, __m256i)
#else
    return ScanScalarFree(data, size, pattern);
#endif
}

NOESCAPE_NO_SANITIZE const uint8_t* ScanSse2Impl(const uint8_t* data, size_t size, const Pattern& pattern) {
    NOESCAPE_SIMD_BODY(16, _mm_set1_epi8, _mm_loadu_si128, _mm_cmpeq_epi8, _mm_movemask_epi8, __m128i)
}

bool CpuHasAvx2() {
#if defined(NOESCAPE_RUNTIME_DISPATCH)
    static const bool has = __builtin_cpu_supports("avx2");
    return has;
#elif defined(__AVX2__)
    return true; // MSVC /arch:AVX2 builds are AVX2-only by construction
#else
    return false;
#endif
}
#endif

} // namespace

const uint8_t* PatternScanner::ScanSimd(
    const uint8_t* data, 
    size_t size, 
    const Pattern& pattern
) {
    if (size < pattern.Length()) return nullptr;
    if (!pattern.HasNonWildcard()) {
        return data;
    }
#if defined(NOESCAPE_X86)
    // Runtime dispatch: the library must load and run on CPUs without AVX2
    if (CpuHasAvx2()) return ScanAvx2Impl(data, size, pattern);
    return ScanSse2Impl(data, size, pattern);
#else
    return ScanScalar(data, size, pattern);
#endif
}

std::optional<uintptr_t> PatternScanner::Scan(
    const uint8_t* data, 
    size_t size, 
    const Pattern& pattern,
    uintptr_t base_address
) {
    if (!data || size == 0 || pattern.Empty()) return std::nullopt;

    const uint8_t* match = ScanSimd(data, size, pattern);
    if (match) {
        return base_address + static_cast<uintptr_t>(match - data);
    }
    return std::nullopt;
}

std::vector<uintptr_t> PatternScanner::ScanAll(
    const uint8_t* data, 
    size_t size, 
    const Pattern& pattern,
    uintptr_t base_address,
    size_t max_results
) {
    std::vector<uintptr_t> results;
    if (!data || size == 0 || pattern.Empty()) return results;

    const uint8_t* current = data;
    size_t remaining = size;

    while (remaining >= pattern.Length() && results.size() < max_results) {
        const uint8_t* match = ScanSimd(current, remaining, pattern);
        if (!match) break;

        results.push_back(base_address + static_cast<uintptr_t>(match - data));
        size_t consumed = (match - current) + 1;
        current += consumed;
        remaining -= consumed;
    }

    return results;
}

std::vector<PatternScanner::MatchResult> PatternScanner::ScanBatch(
    const uint8_t* data,
    size_t size,
    const std::vector<Pattern>& patterns,
    uintptr_t base_address,
    size_t max_results
) {
    std::vector<MatchResult> batch_results;
    if (!data || size == 0 || patterns.empty()) return batch_results;

    for (const auto& pat : patterns) {
        if (batch_results.size() >= max_results) break;
        auto matches = ScanAll(data, size, pat, base_address, max_results - batch_results.size());
        for (auto addr : matches) {
            batch_results.push_back({pat.GetName(), addr});
        }
    }

    return batch_results;
}

std::vector<PatternScanner::MatchResult> PatternScanner::ScanBatch(
    const uint8_t* data,
    size_t size,
    const std::vector<CheatSignature>& signatures,
    uintptr_t base_address,
    size_t max_results
) {
    std::vector<MatchResult> batch_results;
    if (!data || size == 0 || signatures.empty()) return batch_results;

    for (const auto& sig : signatures) {
        if (batch_results.size() >= max_results) break;
        auto matches = ScanAll(data, size, sig, base_address, max_results - batch_results.size());
        for (auto addr : matches) {
            batch_results.push_back({sig.GetName(), addr});
        }
    }

    return batch_results;
}

std::vector<PatternScanner::SignatureMatchResult> PatternScanner::ScanSignatures(
    const uint8_t* data,
    size_t size,
    const std::vector<CheatSignature>& signatures,
    uintptr_t base_address,
    size_t max_results
) {
    std::vector<SignatureMatchResult> results;
    if (!data || size == 0 || signatures.empty()) return results;

    for (const auto& sig : signatures) {
        if (results.size() >= max_results) break;
        auto matches = ScanAll(data, size, sig, base_address, max_results - results.size());
        for (auto addr : matches) {
            results.push_back({&sig, sig.GetName(), addr});
        }
    }

    return results;
}

std::vector<PatternScanner::SignatureMatchResult> PatternScanner::ScanSignatures(
    const uint8_t* data,
    size_t size,
    const std::vector<const CheatSignature*>& signatures,
    uintptr_t base_address,
    size_t max_results
) {
    std::vector<SignatureMatchResult> results;
    if (!data || size == 0 || signatures.empty()) return results;

    for (const auto* sig : signatures) {
        if (!sig) continue;
        if (results.size() >= max_results) break;
        auto matches = ScanAll(data, size, *sig, base_address, max_results - results.size());
        for (auto addr : matches) {
            results.push_back({sig, sig->GetName(), addr});
        }
    }

    return results;
}

} // namespace noescape::memory
