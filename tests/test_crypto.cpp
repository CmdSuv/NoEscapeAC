#include "tests/test_framework.hpp"
#include "noescape/network/crypto_util.hpp"
#include "noescape/network/ed25519.hpp"
#include "noescape/core/blackbox.hpp"

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

TEST(Crypto, Ed25519OfficialRfc8032Vectors) {
    // RFC 8032 Section 7.1 Test Vector 1 (Empty message)
    std::string priv1 = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    std::string expectedPub1 = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    std::string msg1 = "";
    std::string expectedSig1 = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

    std::string sig1 = CryptoUtil::SignAsymmetric(priv1, msg1);
    ASSERT_EQ(sig1, expectedSig1);
    ASSERT_TRUE(CryptoUtil::VerifyAsymmetric(expectedPub1, msg1, sig1));

    // RFC 8032 Section 7.1 Test Vector 2 (1-byte message: 0x72)
    std::string priv2 = "4ccd089b28ff96da9db6c346ec114e0f9b8a319f35aba624da8cf6ed4fb8a6fb";
    std::string expectedPub2 = "dee9b74d69fac31bbbf8e3cc317ab5e1d6e8fda98ed31bb52c23881ce4198dcd";
    std::string msg2 = "\x72";
    std::string expectedSig2 = "55278ef4887a7bd31043dcab71a8c9a2c83531be997024e12955e34989202d0b415cfaedfba299f7c2cc677bd57602cd113820ead58101f48a0dd09372a27703";

    std::string sig2 = CryptoUtil::SignAsymmetric(priv2, msg2);
    ASSERT_EQ(sig2, expectedSig2);
    ASSERT_TRUE(CryptoUtil::VerifyAsymmetric(expectedPub2, msg2, sig2));

    // RFC 8032 Section 7.1 Test Vector 3 (2-byte message: 0xaf 0x82)
    std::string priv3 = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7";
    std::string expectedPub3 = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";
    std::string msg3 = "\xaf\x82";
    std::string expectedSig3 = "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a";

    std::string sig3 = CryptoUtil::SignAsymmetric(priv3, msg3);
    ASSERT_EQ(sig3, expectedSig3);
    ASSERT_TRUE(CryptoUtil::VerifyAsymmetric(expectedPub3, msg3, sig3));
}

TEST(Crypto, Ed25519NegativeTestsAndTamperDetection) {
    auto kp = CryptoUtil::GenerateAsymmetricKeyPair();
    ASSERT_EQ(kp.private_key_hex.length(), 64);
    ASSERT_EQ(kp.public_key_hex.length(), 64);

    std::string msg = "PlayerScore:100;Session:Valid";
    std::string sig = CryptoUtil::SignAsymmetric(kp.private_key_hex, msg);
    ASSERT_EQ(sig.length(), 128); // 64 bytes = 128 hex chars
    ASSERT_TRUE(CryptoUtil::VerifyAsymmetric(kp.public_key_hex, msg, sig));

    // 1. Modified message must fail verification
    std::string tamperedMsg = "PlayerScore:999;Session:Valid";
    ASSERT_FALSE(CryptoUtil::VerifyAsymmetric(kp.public_key_hex, tamperedMsg, sig));

    // 2. Wrong public key must fail verification
    auto kp2 = CryptoUtil::GenerateAsymmetricKeyPair();
    ASSERT_FALSE(CryptoUtil::VerifyAsymmetric(kp2.public_key_hex, msg, sig));

    // 3. Mutated signature byte must fail verification
    std::string mutatedSig = sig;
    mutatedSig[0] = (mutatedSig[0] == 'a') ? 'b' : 'a';
    ASSERT_FALSE(CryptoUtil::VerifyAsymmetric(kp.public_key_hex, msg, mutatedSig));

    // 4. Truncated signature must fail verification
    ASSERT_FALSE(CryptoUtil::VerifyAsymmetric(kp.public_key_hex, msg, sig.substr(0, 64)));

    // 5. Invalid public key length must fail verification
    ASSERT_FALSE(CryptoUtil::VerifyAsymmetric(kp.public_key_hex.substr(0, 32), msg, sig));

    // 6. CRITICAL NEGATIVE TEST: Possessing only the public key MUST NOT allow creating a valid signature
    // An attacker tries to pass public key as private key:
    std::string attackerSig = CryptoUtil::SignAsymmetric(kp.public_key_hex, msg);
    // Even if something was produced or empty, verifying it against the genuine public key MUST FAIL!
    if (!attackerSig.empty()) {
        ASSERT_FALSE(CryptoUtil::VerifyAsymmetric(kp.public_key_hex, msg, attackerSig));
    }
}

TEST(Crypto, Ed25519KeyRotationScenario) {
    auto keyV1 = CryptoUtil::GenerateAsymmetricKeyPair();
    auto keyV2 = CryptoUtil::GenerateAsymmetricKeyPair();

    std::string payload = "ServerVerdict:CLEAN;Nonce:49fa81bc";
    std::string sigV1 = CryptoUtil::SignAsymmetric(keyV1.private_key_hex, payload);
    std::string sigV2 = CryptoUtil::SignAsymmetric(keyV2.private_key_hex, payload);

    // V1 payload verifies against V1 key, but not V2 key
    ASSERT_TRUE(CryptoUtil::VerifyAsymmetric(keyV1.public_key_hex, payload, sigV1));
    ASSERT_FALSE(CryptoUtil::VerifyAsymmetric(keyV2.public_key_hex, payload, sigV1));

    // Rotated V2 payload verifies against V2 key, but not V1 key
    ASSERT_TRUE(CryptoUtil::VerifyAsymmetric(keyV2.public_key_hex, payload, sigV2));
    ASSERT_FALSE(CryptoUtil::VerifyAsymmetric(keyV1.public_key_hex, payload, sigV2));
}

TEST(Crypto, Rfc8439ChaCha20Poly1305OfficialTestVector) {
    // Official test vector from RFC 8439 Section 2.8.2
    std::string keyHex = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
    std::string nonceHex = "070000004041424344454647";
    std::string aadHex = "50515253c0c1c2c3c4c5c6c7";
    std::string plaintextStr = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    std::string expectedCipherHex = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116";
    std::string expectedTagHex = "1ae10b594f09e26a7e902ecbd0600691";

    auto key = CryptoUtil::FromHex(keyHex);
    auto nonce = CryptoUtil::FromHex(nonceHex);
    auto aad = CryptoUtil::FromHex(aadHex);
    std::vector<uint8_t> pt(plaintextStr.begin(), plaintextStr.end());
    std::vector<uint8_t> ct;
    uint8_t tag[16]{};

    bool encOk = CryptoUtil::AeadChaCha20Poly1305Encrypt(pt, aad, key.data(), nonce.data(), ct, tag);
    ASSERT_TRUE(encOk);
    ASSERT_EQ(CryptoUtil::ToHex(ct.data(), ct.size()), expectedCipherHex);
    ASSERT_EQ(CryptoUtil::ToHex(tag, 16), expectedTagHex);

    std::vector<uint8_t> decrypted;
    bool decOk = CryptoUtil::AeadChaCha20Poly1305Decrypt(ct, aad, tag, key.data(), nonce.data(), decrypted);
    ASSERT_TRUE(decOk);
    ASSERT_EQ(std::string(decrypted.begin(), decrypted.end()), plaintextStr);
}

TEST(Crypto, Rfc8439ChaCha20Poly1305NegativeAndTamperTests) {
    std::string keyHex = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
    std::string nonceHex = "070000004041424344454647";
    std::string aadHex = "50515253c0c1c2c3c4c5c6c7";
    std::string plaintextStr = "Authentic Payload For AntiCheat Verification";

    auto key = CryptoUtil::FromHex(keyHex);
    auto nonce = CryptoUtil::FromHex(nonceHex);
    auto aad = CryptoUtil::FromHex(aadHex);
    std::vector<uint8_t> pt(plaintextStr.begin(), plaintextStr.end());
    std::vector<uint8_t> ct;
    uint8_t tag[16]{};

    ASSERT_TRUE(CryptoUtil::AeadChaCha20Poly1305Encrypt(pt, aad, key.data(), nonce.data(), ct, tag));

    std::vector<uint8_t> decrypted;

    // 1. Mutated ciphertext bit must fail tag authentication
    ct[0] ^= 0x01;
    ASSERT_FALSE(CryptoUtil::AeadChaCha20Poly1305Decrypt(ct, aad, tag, key.data(), nonce.data(), decrypted));
    ct[0] ^= 0x01;

    // 2. Mutated tag must fail
    tag[0] ^= 0x01;
    ASSERT_FALSE(CryptoUtil::AeadChaCha20Poly1305Decrypt(ct, aad, tag, key.data(), nonce.data(), decrypted));
    tag[0] ^= 0x01;

    // 3. Mutated AAD must fail
    aad[0] ^= 0x01;
    ASSERT_FALSE(CryptoUtil::AeadChaCha20Poly1305Decrypt(ct, aad, tag, key.data(), nonce.data(), decrypted));
    aad[0] ^= 0x01;

    // 4. Wrong key must fail
    key[0] ^= 0x01;
    ASSERT_FALSE(CryptoUtil::AeadChaCha20Poly1305Decrypt(ct, aad, tag, key.data(), nonce.data(), decrypted));
    key[0] ^= 0x01;

    // 5. Wrong nonce must fail
    nonce[0] ^= 0x01;
    ASSERT_FALSE(CryptoUtil::AeadChaCha20Poly1305Decrypt(ct, aad, tag, key.data(), nonce.data(), decrypted));
    nonce[0] ^= 0x01;

    // Original recovers cleanly
    ASSERT_TRUE(CryptoUtil::AeadChaCha20Poly1305Decrypt(ct, aad, tag, key.data(), nonce.data(), decrypted));
    ASSERT_EQ(std::string(decrypted.begin(), decrypted.end()), plaintextStr);
}

TEST(Crypto, PureEd25519DirectSoftwareVerification) {
    // Calling ed25519 namespace directly to guarantee software curve path passes
    std::string priv1Hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    auto priv1 = CryptoUtil::FromHex(priv1Hex);
    uint8_t pubKey[32]{};
    uint8_t privKey[64]{};
    ASSERT_TRUE(noescape::network::ed25519::CreateKeyPair(priv1.data(), pubKey, privKey));

    std::string msg = "";
    uint8_t sig[64]{};
    ASSERT_TRUE(noescape::network::ed25519::Sign(priv1.data(), 32,
        reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), sig));

    ASSERT_TRUE(noescape::network::ed25519::Verify(pubKey,
        reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), sig));

    // Direct negative test: altered message fails
    std::string altered = "tampered";
    ASSERT_FALSE(noescape::network::ed25519::Verify(pubKey,
        reinterpret_cast<const uint8_t*>(altered.data()), altered.size(), sig));
}

TEST(Blackbox, AeadV2FlightRecorderRoundtrip) {
    using namespace noescape::core;
    BlackboxRecord recIn;
    recIn.timestamp = 1730000000;
    recIn.threat_score = 95;
    recIn.violation_type = 4;
    recIn.hwid = "test-hwid-abc123xyz";
    recIn.violating_component = "MemoryScanner";
    recIn.violation_reason = "Unbacked executable memory at 0x7fff12340000";
    recIn.backtrace_addrs = {0x401000, 0x402500, 0x7fff0000};
    recIn.recent_input_trail = {{1.5f, 2.5f, 1000}, {1.6f, 2.6f, 1016}};
    recIn.loaded_modules_sample = {"game.exe", "ntdll.dll"};

    std::string secretKey = "ProductionDeploymentMasterSecretKey!";
    auto encrypted = BlackboxDumper::Instance().SerializeAndEncrypt(recIn, secretKey);
    ASSERT_GT(encrypted.size(), 60);

    BlackboxRecord recOut;
    ASSERT_TRUE(BlackboxDumper::Instance().DecryptAndDeserialize(encrypted, secretKey, recOut));
    ASSERT_EQ(recOut.timestamp, recIn.timestamp);
    ASSERT_EQ(recOut.threat_score, recIn.threat_score);
    ASSERT_EQ(recOut.violation_type, recIn.violation_type);
    ASSERT_EQ(recOut.hwid, recIn.hwid);
    ASSERT_EQ(recOut.violating_component, recIn.violating_component);
    ASSERT_EQ(recOut.violation_reason, recIn.violation_reason);
    ASSERT_EQ(recOut.backtrace_addrs.size(), recIn.backtrace_addrs.size());
    ASSERT_EQ(recOut.recent_input_trail.size(), recIn.recent_input_trail.size());

    // Tampered payload must fail decryption
    auto tampered = encrypted;
    tampered[tampered.size() - 1] ^= 0xFF;
    BlackboxRecord failRec;
    ASSERT_FALSE(BlackboxDumper::Instance().DecryptAndDeserialize(tampered, secretKey, failRec));

    // Wrong secret key must fail decryption
    ASSERT_FALSE(BlackboxDumper::Instance().DecryptAndDeserialize(encrypted, "WrongKey", failRec));
}

