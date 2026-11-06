#pragma once
#include <cstring>
#include <cctype>
#include <string>

namespace noescape::core {

// Portable, locale-independent ASCII case-insensitive equality (strcasecmp is not available on MSVC).
inline bool EqualsIgnoreCase(const char* a, const char* b) {
    if (!a || !b) return false;
    while (*a && *b) {
        if (std::tolower(static_cast<unsigned char>(*a)) != std::tolower(static_cast<unsigned char>(*b))) return false;
        ++a; ++b;
    }
    return *a == *b;
}

// True for "1" / "true" (any case). NULL -> false.
inline bool EnvFlagTrue(const char* v) {
    return v && (std::strcmp(v, "1") == 0 || EqualsIgnoreCase(v, "true"));
}

} // namespace noescape::core

namespace noescape::core {

// Matches a process/binary name against a blacklist entry without raw substring matching:
// exact match, or the entry followed by a non-letter (so "gdb-multiarch" and "ida64" match
// but "gdbus", "validator" or "tidal" do not).
inline bool NameMatchesEntry(const std::string& lowerName, const std::string& lowerEntry) {
    if (lowerEntry.empty() || lowerName.size() < lowerEntry.size()) return false;
    if (lowerName.compare(0, lowerEntry.size(), lowerEntry) != 0) return false;
    if (lowerName.size() == lowerEntry.size()) return true;
    return !std::isalpha(static_cast<unsigned char>(lowerName[lowerEntry.size()]));
}

inline std::string BaseName(const std::string& path) {
    size_t p = path.find_last_of("/\\");
    return p == std::string::npos ? path : path.substr(p + 1);
}

} // namespace noescape::core
