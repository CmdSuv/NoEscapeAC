#pragma once

#include <vector>
#include <optional>
#include <string_view>
#include "noescape/memory/cheat_signature.hpp"

namespace noescape::memory {

class SignatureDatabase {
public:
    // Returns all active cheat signatures in the database
    static std::vector<CheatSignature> GetAllSignatures();

    // Returns signatures filtered by category
    static std::vector<CheatSignature> GetByCategory(SignatureCategory category);

    // Returns signatures filtered by target rule
    static std::vector<CheatSignature> GetByTargetRule(MemoryTargetRule rule);

    // Find signature by unique name
    static std::optional<CheatSignature> FindByName(std::string_view name);

    // Register a custom cheat signature at runtime
    static void RegisterCustomSignature(CheatSignature signature);

    // Reset database to default curated anti-cheat signatures
    static void Reset();

    // Total count of registered signatures
    static size_t Count();

    // Converts a collection of CheatSignatures to raw Patterns
    static std::vector<Pattern> ToPatterns(const std::vector<CheatSignature>& signatures);

    // Returns internal memory spans [start, end] of the signature database storage
    // to prevent self-detection false positives when scanning anonymous data / heap
    static std::vector<std::pair<uintptr_t, uintptr_t>> GetInternalSpans();

private:
    static std::vector<CheatSignature> CreateDefaultSignatures();
};

} // namespace noescape::memory
