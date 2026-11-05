#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <optional>
#include <string_view>

namespace noescape::memory {

struct PatternByte {
    uint8_t value{0};
    bool is_wildcard{false};
};

class Pattern {
public:
    Pattern() = default;
    explicit Pattern(std::string_view ida_pattern, std::string name = "");
    Pattern(const uint8_t* bytes, const char* mask, std::string name = "");

    virtual ~Pattern() = default;

    bool Empty() const { return bytes_.empty(); }
    size_t Length() const { return bytes_.size(); }
    const std::vector<PatternByte>& GetBytes() const { return bytes_; }
    const std::string& GetName() const { return name_; }

    // First non-wildcard byte and its offset for SIMD quick skipping
    bool HasNonWildcard() const { return has_non_wildcard_; }
    uint8_t FirstByte() const { return first_byte_; }
    size_t FirstByteOffset() const { return first_byte_offset_; }

private:
    std::vector<PatternByte> bytes_;
    std::string name_;
    bool has_non_wildcard_{false};
    uint8_t first_byte_{0};
    size_t first_byte_offset_{0};
};

class CheatSignature;

class PatternScanner {
public:
    // Scans a memory buffer for a single pattern
    static std::optional<uintptr_t> Scan(
        const uint8_t* data, 
        size_t size, 
        const Pattern& pattern,
        uintptr_t base_address = 0
    );

    // Scans a memory buffer for all occurrences of a pattern
    static std::vector<uintptr_t> ScanAll(
        const uint8_t* data, 
        size_t size, 
        const Pattern& pattern,
        uintptr_t base_address = 0,
        size_t max_results = 256
    );

    // Multi-pattern batch scanning in a single pass
    struct MatchResult {
        std::string pattern_name;
        uintptr_t address{0};
    };

    static std::vector<MatchResult> ScanBatch(
        const uint8_t* data, 
        size_t size, 
        const std::vector<Pattern>& patterns,
        uintptr_t base_address = 0,
        size_t max_results = 1024
    );

    static std::vector<MatchResult> ScanBatch(
        const uint8_t* data, 
        size_t size, 
        const std::vector<CheatSignature>& signatures,
        uintptr_t base_address = 0,
        size_t max_results = 1024
    );

    struct SignatureMatchResult {
        const CheatSignature* signature{nullptr};
        std::string signature_name;
        uintptr_t address{0};
    };

    static std::vector<SignatureMatchResult> ScanSignatures(
        const uint8_t* data, 
        size_t size, 
        const std::vector<CheatSignature>& signatures,
        uintptr_t base_address = 0,
        size_t max_results = 1024
    );

    static std::vector<SignatureMatchResult> ScanSignatures(
        const uint8_t* data, 
        size_t size, 
        const std::vector<const CheatSignature*>& signatures,
        uintptr_t base_address = 0,
        size_t max_results = 1024
    );

private:
    // Architecture-specific SIMD implementations
    static const uint8_t* ScanSimd(
        const uint8_t* data, 
        size_t size, 
        const Pattern& pattern
    );

    static const uint8_t* ScanScalar(
        const uint8_t* data, 
        size_t size, 
        const Pattern& pattern
    );

    static bool MatchAt(
        const uint8_t* ptr, 
        const Pattern& pattern
    );
};

} // namespace noescape::memory
