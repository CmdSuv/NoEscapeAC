#include "noescape/memory/pattern_scanner.hpp"
#include "noescape/memory/cheat_signature.hpp"
#include <sstream>
#include <algorithm>
#include <cstring>
#include <bit>

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#include <immintrin.h>
#if defined(_MSC_VER)
#include <intrin.h>
#endif
#define NOESCAPE_X86 1
#endif

// The scanner deliberately reads arbitrary process memory (including allocator redzones), so it
// (and memory other threads are concurrently writing) must not be instrumented by
// AddressSanitizer / HWASan / ThreadSanitizer, or every audit would report a false
// "overflow". Production builds are unaffected.
#if defined(__clang__) || defined(__GNUC__)
#define NOESCAPE_NO_SANITIZE __attribute__((no_sanitize("address", "hwaddress", "thread")))
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

    // Determine first and last non-wildcard bytes
    has_non_wildcard_ = false;
    for (size_t i = 0; i < bytes_.size(); ++i) {
        if (!bytes_[i].is_wildcard) {
            if (!has_non_wildcard_) {
                first_byte_ = bytes_[i].value;
                first_byte_offset_ = i;
                has_non_wildcard_ = true;
            }
            last_byte_ = bytes_[i].value;
            last_byte_offset_ = i;
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
            if (!has_non_wildcard_) {
                first_byte_ = bytes_[i].value;
                first_byte_offset_ = i;
                has_non_wildcard_ = true;
            }
            last_byte_ = bytes_[i].value;
            last_byte_offset_ = i;
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
    const uint8_t last = pattern.LastByte();
    const size_t last_offset = pattern.LastByteOffset();

    for (size_t i = 0; i <= max_scan; ++i) {
        if (data[i + first_offset] == first &&
            data[i + last_offset] == last &&
            MatchAt(data + i, pattern)) {
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
    const uint8_t last = pattern.LastByte();
    const size_t last_off = pattern.LastByteOffset();
    for (size_t i = 0; i <= max_scan; ++i) {
        if (data[i + off] == first && data[i + last_off] == last && MatchAtFree(data + i, pattern)) return data + i;
    }
    return nullptr;
}

#if defined(NOESCAPE_X86)
// Shared SIMD driver parametrised on block width; uses dual-anchor (first + last non-wildcard byte) filtering.
#define NOESCAPE_SIMD_BODY(WIDTH, SET1, LOADU, CMPEQ, BITAND, MOVEMASK, VEC)                          \
    const size_t pattern_len = pattern.Length();                                                      \
    const size_t max_scan = size - pattern_len;                                                       \
    const uint8_t first = pattern.FirstByte();                                                        \
    const size_t first_offset = pattern.FirstByteOffset();                                            \
    const uint8_t last = pattern.LastByte();                                                          \
    const size_t last_offset = pattern.LastByteOffset();                                              \
    const VEC first_vec = SET1(static_cast<char>(first));                                             \
    const VEC last_vec = SET1(static_cast<char>(last));                                               \
    const bool dual_anchor = (last_offset != first_offset);                                           \
    size_t i = 0;                                                                                     \
    while (i + last_offset + WIDTH <= size && i <= max_scan) {                                        \
        VEC block_first = LOADU(reinterpret_cast<const VEC*>(data + i + first_offset));               \
        VEC eq = CMPEQ(block_first, first_vec);                                                       \
        if (dual_anchor) {                                                                            \
            VEC block_last = LOADU(reinterpret_cast<const VEC*>(data + i + last_offset));             \
            eq = BITAND(eq, CMPEQ(block_last, last_vec));                                             \
        }                                                                                             \
        uint32_t mask = static_cast<uint32_t>(MOVEMASK(eq));                                          \
        while (mask != 0) {                                                                           \
            size_t cand = i + static_cast<size_t>(std::countr_zero(mask));                            \
            if (cand <= max_scan && MatchAtFree(data + cand, pattern)) {                              \
                return data + cand;                                                                   \
            }                                                                                         \
            mask &= mask - 1;                                                                         \
        }                                                                                             \
        i += WIDTH;                                                                                   \
    }                                                                                                 \
    if (i <= max_scan) {                                                                              \
        const uint8_t* tail = ScanScalarFree(data + i, size - i, pattern);                            \
        return tail;                                                                                  \
    }                                                                                                 \
    return nullptr;

#if defined(NOESCAPE_RUNTIME_DISPATCH)
__attribute__((target("avx2")))
#endif
NOESCAPE_NO_SANITIZE const uint8_t* ScanAvx2Impl(const uint8_t* data, size_t size, const Pattern& pattern) {
#if defined(__AVX2__) || defined(NOESCAPE_RUNTIME_DISPATCH) || defined(_MSC_VER)
    NOESCAPE_SIMD_BODY(32, _mm256_set1_epi8, _mm256_loadu_si256, _mm256_cmpeq_epi8, _mm256_and_si256, _mm256_movemask_epi8, __m256i)
#else
    return ScanScalarFree(data, size, pattern);
#endif
}

NOESCAPE_NO_SANITIZE const uint8_t* ScanSse2Impl(const uint8_t* data, size_t size, const Pattern& pattern) {
    NOESCAPE_SIMD_BODY(16, _mm_set1_epi8, _mm_loadu_si128, _mm_cmpeq_epi8, _mm_and_si128, _mm_movemask_epi8, __m128i)
}

bool CpuHasAvx2() {
#if defined(NOESCAPE_RUNTIME_DISPATCH)
    static const bool has = __builtin_cpu_supports("avx2");
    return has;
#elif defined(_MSC_VER) && defined(NOESCAPE_X86)
    static const bool has = []() {
        int cpuInfo[4] = {0, 0, 0, 0};
        __cpuid(cpuInfo, 0);
        if (cpuInfo[0] < 7) return false;
        __cpuid(cpuInfo, 1);
        // Check OSXSAVE (ECX bit 27) and AVX (ECX bit 28)
        if ((cpuInfo[2] & ((1 << 27) | (1 << 28))) != ((1 << 27) | (1 << 28))) return false;
        // Verify OS has enabled XMM (bit 1) and YMM (bit 2) state saving via XGETBV(0)
        unsigned long long xcrFeatureMask = _xgetbv(0);
        if ((xcrFeatureMask & 0x6ULL) != 0x6ULL) return false;
        __cpuidex(cpuInfo, 7, 0);
        // Check AVX2 (EBX bit 5)
        return (cpuInfo[1] & (1 << 5)) != 0;
    }();
    return has;
#elif defined(__AVX2__)
    return true;
#else
    return false;
#endif
}
#endif

struct BucketHit {
    size_t pattern_index;
    uintptr_t address;
};

[[maybe_unused]] NOESCAPE_NO_SANITIZE void ScanBucketScalarFree(
    const uint8_t* data,
    size_t size,
    uint8_t first,
    size_t first_offset,
    size_t min_len,
    const Pattern* const* patterns,
    const size_t* indices,
    size_t count,
    uintptr_t base_address,
    size_t max_results,
    std::vector<BucketHit>& out_hits
) {
    if (size < min_len) return;
    const size_t max_scan = size - min_len;
    for (size_t i = 0; i <= max_scan && out_hits.size() < max_results; ++i) {
        if (data[i + first_offset] == first) {
            for (size_t b = 0; b < count && out_hits.size() < max_results; ++b) {
                const Pattern* pat = patterns[b];
                if (i + pat->Length() <= size && MatchAtFree(data + i, *pat)) {
                    out_hits.push_back({indices[b], base_address + i});
                }
            }
        }
    }
}

#if defined(NOESCAPE_X86)
#define NOESCAPE_SIMD_BUCKET_BODY(WIDTH, SET1, LOADU, CMPEQ, MOVEMASK, VEC)                           \
    if (size < min_len) return;                                                                       \
    const size_t max_scan = size - min_len;                                                           \
    const VEC match_vec = SET1(static_cast<char>(first));                                             \
    size_t i = 0;                                                                                     \
    while (i + first_offset + WIDTH <= size && i <= max_scan && out_hits.size() < max_results) {      \
        VEC block = LOADU(reinterpret_cast<const VEC*>(data + i + first_offset));                     \
        uint32_t mask = static_cast<uint32_t>(MOVEMASK(CMPEQ(block, match_vec)));                     \
        while (mask != 0 && out_hits.size() < max_results) {                                          \
            size_t cand = i + static_cast<size_t>(std::countr_zero(mask));                            \
            if (cand <= max_scan) {                                                                   \
                for (size_t b = 0; b < count && out_hits.size() < max_results; ++b) {                 \
                    const Pattern* pat = patterns[b];                                                 \
                    if (cand + pat->Length() <= size && MatchAtFree(data + cand, *pat)) {             \
                        out_hits.push_back({indices[b], base_address + cand});                        \
                    }                                                                                 \
                }                                                                                     \
            }                                                                                         \
            mask &= mask - 1;                                                                         \
        }                                                                                             \
        i += WIDTH;                                                                                   \
    }                                                                                                 \
    while (i <= max_scan && out_hits.size() < max_results) {                                          \
        if (data[i + first_offset] == first) {                                                        \
            for (size_t b = 0; b < count && out_hits.size() < max_results; ++b) {                     \
                const Pattern* pat = patterns[b];                                                     \
                if (i + pat->Length() <= size && MatchAtFree(data + i, *pat)) {                       \
                    out_hits.push_back({indices[b], base_address + i});                               \
                }                                                                                     \
            }                                                                                         \
        }                                                                                             \
        ++i;                                                                                          \
    }

#if defined(NOESCAPE_RUNTIME_DISPATCH)
__attribute__((target("avx2")))
#endif
NOESCAPE_NO_SANITIZE void ScanBucketAvx2Impl(
    const uint8_t* data,
    size_t size,
    uint8_t first,
    size_t first_offset,
    size_t min_len,
    const Pattern* const* patterns,
    const size_t* indices,
    size_t count,
    uintptr_t base_address,
    size_t max_results,
    std::vector<BucketHit>& out_hits
) {
#if defined(__AVX2__) || defined(NOESCAPE_RUNTIME_DISPATCH) || defined(_MSC_VER)
    NOESCAPE_SIMD_BUCKET_BODY(32, _mm256_set1_epi8, _mm256_loadu_si256, _mm256_cmpeq_epi8, _mm256_movemask_epi8, __m256i)
#else
    ScanBucketScalarFree(data, size, first, first_offset, min_len, patterns, indices, count, base_address, max_results, out_hits);
#endif
}

NOESCAPE_NO_SANITIZE void ScanBucketSse2Impl(
    const uint8_t* data,
    size_t size,
    uint8_t first,
    size_t first_offset,
    size_t min_len,
    const Pattern* const* patterns,
    const size_t* indices,
    size_t count,
    uintptr_t base_address,
    size_t max_results,
    std::vector<BucketHit>& out_hits
) {
    NOESCAPE_SIMD_BUCKET_BODY(16, _mm_set1_epi8, _mm_loadu_si128, _mm_cmpeq_epi8, _mm_movemask_epi8, __m128i)
}
#endif

void ScanPatternGroup(
    const uint8_t* data,
    size_t size,
    const std::vector<const Pattern*>& pats,
    uintptr_t base_address,
    size_t max_results,
    std::vector<BucketHit>& out_hits
) {
    struct Bucket {
        uint8_t first_byte{0};
        size_t first_offset{0};
        size_t min_len{SIZE_MAX};
        std::vector<const Pattern*> patterns;
        std::vector<size_t> indices;
    };

    std::vector<Bucket> buckets;
    buckets.reserve(pats.size());

    for (size_t idx = 0; idx < pats.size(); ++idx) {
        const Pattern* p = pats[idx];
        if (!p || p->Empty() || p->Length() > size) continue;
        if (!p->HasNonWildcard()) {
            // Pure wildcard pattern
            const size_t max_scan = size - p->Length();
            for (size_t i = 0; i <= max_scan && out_hits.size() < max_results; ++i) {
                out_hits.push_back({idx, base_address + i});
            }
            continue;
        }
        const uint8_t fb = p->FirstByte();
        const size_t fo = p->FirstByteOffset();
        Bucket* found = nullptr;
        for (auto& b : buckets) {
            if (b.first_byte == fb && b.first_offset == fo) {
                found = &b;
                break;
            }
        }
        if (!found) {
            buckets.push_back({fb, fo, p->Length(), {p}, {idx}});
        } else {
            found->min_len = std::min(found->min_len, p->Length());
            found->patterns.push_back(p);
            found->indices.push_back(idx);
        }
    }

#if defined(NOESCAPE_X86)
    const bool useAvx2 = CpuHasAvx2();
#endif
    for (const auto& b : buckets) {
        if (out_hits.size() >= max_results) break;
        if (b.patterns.size() == 1) {
            const Pattern* pat = b.patterns[0];
            const size_t idx = b.indices[0];
            const uint8_t* current = data;
            size_t remaining = size;
            while (remaining >= pat->Length() && out_hits.size() < max_results) {
#if defined(NOESCAPE_X86)
                const uint8_t* match = useAvx2
                    ? ScanAvx2Impl(current, remaining, *pat)
                    : ScanSse2Impl(current, remaining, *pat);
#else
                const uint8_t* match = ScanScalarFree(current, remaining, *pat);
#endif
                if (!match) break;
                out_hits.push_back({idx, base_address + static_cast<uintptr_t>(match - data)});
                size_t consumed = static_cast<size_t>(match - current) + 1;
                current += consumed;
                remaining -= consumed;
            }
        } else {
#if defined(NOESCAPE_X86)
            if (useAvx2) {
                ScanBucketAvx2Impl(data, size, b.first_byte, b.first_offset, b.min_len,
                                   b.patterns.data(), b.indices.data(), b.patterns.size(),
                                   base_address, max_results, out_hits);
            } else {
                ScanBucketSse2Impl(data, size, b.first_byte, b.first_offset, b.min_len,
                                   b.patterns.data(), b.indices.data(), b.patterns.size(),
                                   base_address, max_results, out_hits);
            }
#else
            ScanBucketScalarFree(data, size, b.first_byte, b.first_offset, b.min_len,
                                 b.patterns.data(), b.indices.data(), b.patterns.size(),
                                 base_address, max_results, out_hits);
#endif
        }
    }
}

} // namespace

bool PatternScanner::HasAvx2Support() {
#if defined(NOESCAPE_X86)
    return CpuHasAvx2();
#else
    return false;
#endif
}

bool PatternScanner::HasSse2Support() {
#if defined(NOESCAPE_X86)
    return true;
#else
    return false;
#endif
}

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

std::optional<uintptr_t> PatternScanner::ScanWithIsa(
    const uint8_t* data,
    size_t size,
    const Pattern& pattern,
    SimdIsa isa,
    uintptr_t base_address
) {
    if (!data || size == 0 || pattern.Empty() || size < pattern.Length()) return std::nullopt;
    if (!pattern.HasNonWildcard()) return base_address;

    const uint8_t* match = nullptr;
    switch (isa) {
        case SimdIsa::SCALAR:
            match = ScanScalar(data, size, pattern);
            break;
        case SimdIsa::SSE2:
#if defined(NOESCAPE_X86)
            match = ScanSse2Impl(data, size, pattern);
#else
            match = ScanScalar(data, size, pattern);
#endif
            break;
        case SimdIsa::AVX2:
#if defined(NOESCAPE_X86)
            if (CpuHasAvx2()) {
                match = ScanAvx2Impl(data, size, pattern);
            } else {
                match = ScanSse2Impl(data, size, pattern);
            }
#else
            match = ScanScalar(data, size, pattern);
#endif
            break;
        case SimdIsa::AUTO:
        default:
            match = ScanSimd(data, size, pattern);
            break;
    }
    if (match) {
        return base_address + static_cast<uintptr_t>(match - data);
    }
    return std::nullopt;
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
    if (!data || size == 0 || patterns.empty() || max_results == 0) return batch_results;

    std::vector<const Pattern*> ptrs;
    ptrs.reserve(patterns.size());
    for (const auto& pat : patterns) ptrs.push_back(&pat);

    std::vector<BucketHit> hits;
    ScanPatternGroup(data, size, ptrs, base_address, max_results, hits);
    batch_results.reserve(hits.size());
    for (const auto& h : hits) {
        batch_results.push_back({patterns[h.pattern_index].GetName(), h.address});
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
    if (!data || size == 0 || signatures.empty() || max_results == 0) return batch_results;

    std::vector<const Pattern*> ptrs;
    ptrs.reserve(signatures.size());
    for (const auto& sig : signatures) ptrs.push_back(&sig);

    std::vector<BucketHit> hits;
    ScanPatternGroup(data, size, ptrs, base_address, max_results, hits);
    batch_results.reserve(hits.size());
    for (const auto& h : hits) {
        batch_results.push_back({signatures[h.pattern_index].GetName(), h.address});
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
    if (!data || size == 0 || signatures.empty() || max_results == 0) return results;

    std::vector<const Pattern*> ptrs;
    ptrs.reserve(signatures.size());
    for (const auto& sig : signatures) ptrs.push_back(&sig);

    std::vector<BucketHit> hits;
    ScanPatternGroup(data, size, ptrs, base_address, max_results, hits);
    results.reserve(hits.size());
    for (const auto& h : hits) {
        const auto& sig = signatures[h.pattern_index];
        results.push_back({&sig, sig.GetName(), h.address});
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
    if (!data || size == 0 || signatures.empty() || max_results == 0) return results;

    std::vector<const Pattern*> ptrs;
    ptrs.reserve(signatures.size());
    for (const auto* sig : signatures) ptrs.push_back(sig);

    std::vector<BucketHit> hits;
    ScanPatternGroup(data, size, ptrs, base_address, max_results, hits);
    results.reserve(hits.size());
    for (const auto& h : hits) {
        const CheatSignature* sig = signatures[h.pattern_index];
        results.push_back({sig, sig->GetName(), h.address});
    }

    return results;
}

} // namespace noescape::memory
