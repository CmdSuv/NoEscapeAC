#include "tests/test_framework.hpp"
#include "noescape/network/crypto_util.hpp"

using namespace noescape::network;

TEST(Crypto, Sha256StandardVectors) {
    // NIST Standard Test Vectors
    std::string hEmpty = CryptoUtil::Sha256("");
    ASSERT_EQ(hEmpty, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    std::string hAbc = CryptoUtil::Sha256("abc");
    ASSERT_EQ(hAbc, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    std::string longInput = "abcdbcdecdefdefgefghfghighijhijkiklklmlmnmnonopnopq";
    std::string hLong = CryptoUtil::Sha256(longInput);
    ASSERT_EQ(hLong, "4aed8ec5b3cbe72badd60bce25faf91b6928fc2cc0dd1c190a218c1a952151dc");
}

TEST(Crypto, HmacSha256StandardVectors) {
    // RFC 4231 / Standard HMAC Vector
    std::string key = "key";
    std::string data = "The quick brown fox jumps over the lazy dog";
    std::string expected = "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8";

    std::string actual = CryptoUtil::HmacSha256(key, data);
    ASSERT_EQ(actual, expected);

    // Empty Key
    std::string emptyKeyHmac = CryptoUtil::HmacSha256("", "data");
    ASSERT_EQ(emptyKeyHmac.length(), 64);
    ASSERT_NE(emptyKeyHmac, actual);

    // Long Key (>64 bytes, verifies key hashing path)
    std::string longKey(100, 'K');
    std::string longKeyHmac = CryptoUtil::HmacSha256(longKey, data);
    ASSERT_EQ(longKeyHmac.length(), 64);
}

TEST(Crypto, MachineHwidGeneration) {
    std::string hwid1 = CryptoUtil::GetMachineHWID();
    std::string hwid2 = CryptoUtil::GetMachineHWID();

    // HWID should be a deterministic 64-character SHA-256 hex digest
    ASSERT_EQ(hwid1.length(), 64);
    ASSERT_EQ(hwid1, hwid2);
}
