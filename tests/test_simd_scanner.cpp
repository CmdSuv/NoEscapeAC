#include "tests/test_framework.hpp"
#include "noescape/memory/pattern_scanner.hpp"
#include <vector>

using namespace noescape::memory;

TEST(PatternScanner, ExactMatch) {
    std::vector<uint8_t> buffer = {0x90, 0x90, 0x48, 0x89, 0x5C, 0x24, 0x08, 0xC3};
    Pattern pat("48 89 5C 24 08", "ExactJmp");

    auto res = PatternScanner::Scan(buffer.data(), buffer.size(), pat);
    ASSERT_TRUE(res.has_value());
    ASSERT_EQ(*res, 2);
}

TEST(PatternScanner, WildcardMatch) {
    std::vector<uint8_t> buffer = {
        0x55, 0x48, 0x89, 0xE5, 0x48, 0xB8, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0
    };
    // Pattern with wildcards for imm64
    Pattern pat("48 B8 ? ? ? ? ? ? ? ? FF E0", "X64JmpTrampoline");

    auto res = PatternScanner::Scan(buffer.data(), buffer.size(), pat);
    ASSERT_TRUE(res.has_value());
    ASSERT_EQ(*res, 4);
}

TEST(PatternScanner, BoundaryCases) {
    std::vector<uint8_t> buffer = {0xAA, 0xBB, 0xCC, 0xDD};

    // Pattern at offset 0
    Pattern patStart("AA BB");
    auto resStart = PatternScanner::Scan(buffer.data(), buffer.size(), patStart);
    ASSERT_TRUE(resStart.has_value());
    ASSERT_EQ(*resStart, 0);

    // Pattern at the very end
    Pattern patEnd("CC DD");
    auto resEnd = PatternScanner::Scan(buffer.data(), buffer.size(), patEnd);
    ASSERT_TRUE(resEnd.has_value());
    ASSERT_EQ(*resEnd, 2);

    // Pattern longer than buffer
    Pattern patLong("AA BB CC DD EE");
    auto resLong = PatternScanner::Scan(buffer.data(), buffer.size(), patLong);
    ASSERT_FALSE(resLong.has_value());

    // Pattern not found
    Pattern patMissing("FF EE");
    auto resMissing = PatternScanner::Scan(buffer.data(), buffer.size(), patMissing);
    ASSERT_FALSE(resMissing.has_value());

    // Empty buffer
    auto resEmpty = PatternScanner::Scan(nullptr, 0, patStart);
    ASSERT_FALSE(resEmpty.has_value());
}

TEST(PatternScanner, MultipleOccurrences) {
    std::vector<uint8_t> buffer = {
        0x11, 0x22, 0x33, 0x00, 0x11, 0x22, 0x44, 0x00, 0x11, 0x22, 0x55
    };
    Pattern pat("11 22 ?");

    auto matches = PatternScanner::ScanAll(buffer.data(), buffer.size(), pat);
    ASSERT_EQ(matches.size(), 3);
    ASSERT_EQ(matches[0], 0);
    ASSERT_EQ(matches[1], 4);
    ASSERT_EQ(matches[2], 8);
}

TEST(PatternScanner, LargeSimdBuffer) {
    // Allocate 128KB buffer, insert pattern at arbitrary unaligned SIMD offset
    std::vector<uint8_t> largeBuf(128 * 1024, 0x90);
    size_t targetOffset = 65536 + 17; // Crosses 32-byte and 16-byte SIMD boundaries

    largeBuf[targetOffset]     = 0x4C;
    largeBuf[targetOffset + 1] = 0x43;
    largeBuf[targetOffset + 2] = 0x5F;
    largeBuf[targetOffset + 3] = 0x4D;
    largeBuf[targetOffset + 4] = 0x45;
    largeBuf[targetOffset + 5] = 0x4D;

    Pattern leechPat("4C 43 5F 4D 45 4D", "LeechSig");
    auto res = PatternScanner::Scan(largeBuf.data(), largeBuf.size(), leechPat);

    ASSERT_TRUE(res.has_value());
    ASSERT_EQ(*res, targetOffset);
}

TEST(PatternScanner, BatchScanning) {
    std::vector<uint8_t> buffer(1024, 0x00);
    buffer[100] = 0xAA; buffer[101] = 0xBB;
    buffer[500] = 0xCC; buffer[501] = 0xDD;

    std::vector<Pattern> patterns = {
        Pattern("AA BB", "SigA"),
        Pattern("CC DD", "SigB"),
        Pattern("EE FF", "SigC")
    };

    auto matches = PatternScanner::ScanBatch(buffer.data(), buffer.size(), patterns);
    ASSERT_EQ(matches.size(), 2);
    ASSERT_EQ(matches[0].pattern_name, "SigA");
    ASSERT_EQ(matches[0].address, 100);
    ASSERT_EQ(matches[1].pattern_name, "SigB");
    ASSERT_EQ(matches[1].address, 500);
}

TEST(PatternScanner, AllWildcardsAndLeadingWildcards) {
    // 1. All wildcards on non-zero buffer
    std::vector<uint8_t> nonZeroBuf = {0x11, 0x22, 0x33, 0x44};
    Pattern allWild("? ? ? ?");
    auto resAll = PatternScanner::Scan(nonZeroBuf.data(), nonZeroBuf.size(), allWild);
    ASSERT_TRUE(resAll.has_value());
    ASSERT_EQ(*resAll, 0);

    // 2. Leading wildcards
    std::vector<uint8_t> leadingBuf = {0x90, 0x90, 0x41, 0x42};
    Pattern leadWild("? ? 41 42");
    auto resLead = PatternScanner::Scan(leadingBuf.data(), leadingBuf.size(), leadWild);
    ASSERT_TRUE(resLead.has_value());
    ASSERT_EQ(*resLead, 0);

    // 3. Trailing wildcards
    std::vector<uint8_t> trailBuf = {0x41, 0x42, 0x88, 0x99};
    Pattern trailWild("41 42 ? ?");
    auto resTrail = PatternScanner::Scan(trailBuf.data(), trailBuf.size(), trailWild);
    ASSERT_TRUE(resTrail.has_value());
    ASSERT_EQ(*resTrail, 0);
}

TEST(PatternScanner, CacheBlockBoundaryCrossScan) {
    constexpr size_t kTotalSize = 128 * 1024; // 128 KiB buffer
    std::vector<uint8_t> buf(kTotalSize, 0x90);

    // Signature spanning across the 32 KiB (32768) block boundary:
    // Starts at 32764: 32764, 32765, 32766, 32767 | 32768, 32769, 32770, 32771
    size_t boundaryTarget = 32764;
    buf[boundaryTarget + 0] = 0xDE;
    buf[boundaryTarget + 1] = 0xAD;
    buf[boundaryTarget + 2] = 0xBE;
    buf[boundaryTarget + 3] = 0xEF;
    buf[boundaryTarget + 4] = 0xCA;
    buf[boundaryTarget + 5] = 0xFE;
    buf[boundaryTarget + 6] = 0xBA;
    buf[boundaryTarget + 7] = 0xBE;

    std::vector<Pattern> patterns = {
        Pattern("DE AD BE EF CA FE BA BE", "BoundarySig")
    };

    auto matches = PatternScanner::ScanBatch(buf.data(), buf.size(), patterns);
    ASSERT_EQ(matches.size(), 1);
    ASSERT_EQ(matches[0].pattern_name, "BoundarySig");
    ASSERT_EQ(matches[0].address, boundaryTarget);
}

