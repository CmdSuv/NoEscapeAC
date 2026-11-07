#pragma once
#include <cstring>
#include <cctype>
#include <mutex>
#include <string>

#if !defined(_WIN32)
#include <cerrno>
#include <fcntl.h>
#include <sys/prctl.h>
#endif

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

#if !defined(_WIN32)
// Process-wide mutex serializing temporary PR_SET_DUMPABLE transitions across threads.
inline std::mutex& ProcSelfDumpableMutex() {
    static std::mutex m;
    return m;
}

// Opens a /proc/self/* file. When PR_SET_DUMPABLE is 0, the kernel denies opening mode-0400/0600
// /proc/self entries with EACCES; this helper serializes a minimal temporary toggle across just the
// open() syscall and immediately restores PR_SET_DUMPABLE = 0 before releasing the lock.
inline int OpenProcSelfWithDumpableFallback(const char* path, int flags) {
    int fd = ::open(path, flags);
    if (fd >= 0 || errno != EACCES) {
        return fd;
    }
    std::lock_guard<std::mutex> lock(ProcSelfDumpableMutex());
    const int dumpable = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
    if (dumpable == 0) {
        prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
    }
    fd = ::open(path, flags);
    const int savedErrno = errno;
    if (dumpable == 0) {
        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
    errno = savedErrno;
    return fd;
}
#endif

} // namespace noescape::core

