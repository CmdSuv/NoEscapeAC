#include "tests/test_framework.hpp"
#include "noescape/core/obfuscation.hpp"

using namespace noescape::core;

TEST(Obfuscation, CompileTimeFnv1a) {
    constexpr uint64_t hash1 = NOESCAPE_HASH("ntdll.dll");
    constexpr uint64_t hash2 = NOESCAPE_HASH("kernel32.dll");
    constexpr uint64_t hashEmpty = NOESCAPE_HASH("");

    ASSERT_NE(hash1, 0ULL);
    ASSERT_NE(hash2, 0ULL);
    ASSERT_NE(hash1, hash2);
    ASSERT_EQ(hashEmpty, FNV1A_OFFSET);

    // Verify consistency
    uint64_t runtimeHash = HashFnv1a("ntdll.dll");
    ASSERT_EQ(hash1, runtimeHash);
}

TEST(Obfuscation, CompileTimeXorStrings) {
    const char* str1 = NOESCAPE_XOR("/proc/self/status");
    ASSERT_EQ(std::string(str1), "/proc/self/status");

    const char* str2 = NOESCAPE_XOR("SeDebugPrivilege");
    ASSERT_EQ(std::string(str2), "SeDebugPrivilege");

    const char* str3 = NOESCAPE_XOR("dbk64.sys");
    ASSERT_EQ(std::string(str3), "dbk64.sys");
}
