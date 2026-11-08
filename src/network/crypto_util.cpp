#include "noescape/network/crypto_util.hpp"
#include "noescape/network/ed25519.hpp"
#include "noescape/network/chacha20poly1305.hpp"
#include "noescape/core/obfuscation.hpp"
#include <cstring>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <array>
#include <random>
#include <chrono>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/random.h>
#include <sys/statvfs.h>
#include <cpuid.h>
#include <fcntl.h>
#include <cerrno>
#endif

#if defined(NOESCAPE_HAS_OPENSSL)
#include <openssl/evp.h>
#endif

namespace noescape::network {

namespace {

// ============================================================================
// Standard SHA-256 Implementation (FIPS 180-4)
// ============================================================================

constexpr uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

inline uint32_t ROR(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

inline uint32_t Sigma0(uint32_t x) {
    return ROR(x, 2) ^ ROR(x, 13) ^ ROR(x, 22);
}

inline uint32_t Sigma1(uint32_t x) {
    return ROR(x, 6) ^ ROR(x, 11) ^ ROR(x, 25);
}

inline uint32_t Gamma0(uint32_t x) {
    return ROR(x, 7) ^ ROR(x, 18) ^ (x >> 3);
}

inline uint32_t Gamma1(uint32_t x) {
    return ROR(x, 17) ^ ROR(x, 19) ^ (x >> 10);
}

struct Sha256Context {
    uint32_t state[8]{
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    uint64_t count{0};
    uint8_t buffer[64]{};

    void Transform(const uint8_t chunk[64]) {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<uint32_t>(chunk[i * 4]) << 24) |
                   (static_cast<uint32_t>(chunk[i * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(chunk[i * 4 + 2]) << 8) |
                   (static_cast<uint32_t>(chunk[i * 4 + 3]));
        }
        for (int i = 16; i < 64; ++i) {
            w[i] = Gamma1(w[i - 2]) + w[i - 7] + Gamma0(w[i - 15]) + w[i - 16];
        }

        uint32_t a = state[0];
        uint32_t b = state[1];
        uint32_t c = state[2];
        uint32_t d = state[3];
        uint32_t e = state[4];
        uint32_t f = state[5];
        uint32_t g = state[6];
        uint32_t h = state[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t t1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + w[i];
            uint32_t t2 = Sigma0(a) + Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }

    void Update(const uint8_t* data, size_t len) {
        size_t bufferIndex = count % 64;
        count += len;
        size_t partLen = 64 - bufferIndex;
        size_t i = 0;

        if (len >= partLen) {
            std::memcpy(&buffer[bufferIndex], data, partLen);
            Transform(buffer);
            for (i = partLen; i + 63 < len; i += 64) {
                Transform(&data[i]);
            }
            bufferIndex = 0;
        }
        std::memcpy(&buffer[bufferIndex], &data[i], len - i);
    }

    void Finalize(uint8_t digest[32]) {
        uint8_t finalCount[8];
        for (int i = 0; i < 8; ++i) {
            finalCount[i] = static_cast<uint8_t>((count * 8) >> ((7 - i) * 8));
        }

        size_t bufferIndex = count % 64;
        size_t padLen = (bufferIndex < 56) ? (56 - bufferIndex) : (120 - bufferIndex);
        uint8_t padding[64]{0x80};
        Update(padding, padLen);
        Update(finalCount, 8);

        for (int i = 0; i < 8; ++i) {
            digest[i * 4]     = static_cast<uint8_t>(state[i] >> 24);
            digest[i * 4 + 1] = static_cast<uint8_t>(state[i] >> 16);
            digest[i * 4 + 2] = static_cast<uint8_t>(state[i] >> 8);
            digest[i * 4 + 3] = static_cast<uint8_t>(state[i]);
        }
    }
};

} // namespace

std::string CryptoUtil::ToHex(const uint8_t* data, size_t length) {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; ++i) {
        ss << std::setw(2) << static_cast<int>(data[i]);
    }
    return ss.str();
}

std::string CryptoUtil::Sha256(const uint8_t* data, size_t length) {
    Sha256Context ctx;
    ctx.Update(data, length);
    uint8_t digest[32];
    ctx.Finalize(digest);
    return ToHex(digest, 32);
}

std::string CryptoUtil::Sha256(const std::string& input) {
    return Sha256(reinterpret_cast<const uint8_t*>(input.data()), input.size());
}

std::string CryptoUtil::HmacSha256(const std::string& key, const std::string& data) {
    uint8_t keyPad[64]{};
    if (key.length() > 64) {
        Sha256Context keyCtx;
        keyCtx.Update(reinterpret_cast<const uint8_t*>(key.data()), key.length());
        keyCtx.Finalize(keyPad);
    } else {
        std::memcpy(keyPad, key.data(), key.length());
    }

    uint8_t iPad[64];
    uint8_t oPad[64];
    for (int i = 0; i < 64; ++i) {
        iPad[i] = keyPad[i] ^ 0x36;
        oPad[i] = keyPad[i] ^ 0x5c;
    }

    Sha256Context inner;
    inner.Update(iPad, 64);
    inner.Update(reinterpret_cast<const uint8_t*>(data.data()), data.length());
    uint8_t innerHash[32];
    inner.Finalize(innerHash);

    Sha256Context outer;
    outer.Update(oPad, 64);
    outer.Update(innerHash, 32);
    uint8_t finalDigest[32];
    outer.Finalize(finalDigest);

    return ToHex(finalDigest, 32);
}

bool CryptoUtil::ConstantTimeEquals(const std::string& a, const std::string& b) {
    unsigned char diff = (a.size() != b.size()) ? 1 : 0;
    const size_t n = a.size() < b.size() ? a.size() : b.size();
    for (size_t i = 0; i < n; ++i) {
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    }
    return diff == 0;
}

std::string CryptoUtil::GetMachineHWID() {
    static const std::string cachedHwid = []() -> std::string {
#if defined(_WIN32)
#pragma pack(push, 1)
    struct RawSMBIOSData {
        BYTE Used20CallingMethod;
        BYTE SMBIOSMajorVersion;
        BYTE SMBIOSMinorVersion;
        BYTE DmiRevision;
        DWORD Length;
        BYTE SMBIOSTableData[1];
    };
    struct SMBIOSHeader {
        BYTE Type;
        BYTE Length;
        WORD Handle;
    };
#pragma pack(pop)

    std::string smbiosUuid, boardSerial, chassisSerial, tpmStatus;
    const DWORD sig = 'RSMB';
    DWORD bufSize = GetSystemFirmwareTable(sig, 0, nullptr, 0);
    if (bufSize > 0 && bufSize <= 64 * 1024 * 1024) {
        std::vector<BYTE> buf(bufSize);
        if (GetSystemFirmwareTable(sig, 0, buf.data(), bufSize) == bufSize) {
            const auto* smb = reinterpret_cast<const RawSMBIOSData*>(buf.data());
            const BYTE* data = smb->SMBIOSTableData;
            const BYTE* end = data + smb->Length;
            while (data + sizeof(SMBIOSHeader) <= end) {
                const auto* hdr = reinterpret_cast<const SMBIOSHeader*>(data);
                if (hdr->Length < sizeof(SMBIOSHeader) || data + hdr->Length > end) break;
                const BYTE* strSection = data + hdr->Length;
                auto getSmbiosStr = [strSection, end](BYTE idx) -> std::string {
                    if (idx == 0) return "";
                    const BYTE* cur = strSection;
                    BYTE count = 1;
                    while (cur < end && *cur) {
                        const void* nullPos = std::memchr(cur, '\0', static_cast<size_t>(end - cur));
                        if (!nullPos) return "";
                        size_t strLen = static_cast<const BYTE*>(nullPos) - cur;
                        if (count == idx) return std::string(reinterpret_cast<const char*>(cur), strLen);
                        cur += strLen + 1;
                        count++;
                    }
                    return "";
                };
                if (hdr->Type == 1 && hdr->Length >= 0x18) { // System Info UUID
                    char uuidBuf[64];
                    const BYTE* u = data + 8;
                    std::snprintf(uuidBuf, sizeof(uuidBuf),
                        "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                        u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7],
                        u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]);
                    smbiosUuid = uuidBuf;
                } else if (hdr->Type == 2 && hdr->Length >= 8) { // Base Board Serial
                    boardSerial = getSmbiosStr(data[7]);
                } else if (hdr->Type == 3 && hdr->Length >= 8) { // Chassis Serial
                    chassisSerial = getSmbiosStr(data[7]);
                }
                const BYTE* next = strSection;
                while (next + 1 < end && !(next[0] == 0 && next[1] == 0)) next++;
                data = next + 2;
            }
        }
    }
    // Win32 CNG TPM 2.0 Check (MS_PLATFORM_CRYPTO_PROVIDER)
    NCRYPT_PROV_HANDLE hProv = 0;
    if (NCryptOpenStorageProvider(&hProv, MS_PLATFORM_CRYPTO_PROVIDER, 0) == ERROR_SUCCESS) {
        tpmStatus = "TPM2:SUPPORTED;";
        NCryptFreeObject(hProv);
    }
    // MachineGuid fallback
    char szHwid[256] = {0};
    DWORD dwSize = sizeof(szHwid);
    HKEY hKey = nullptr;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "MachineGuid", nullptr, nullptr, reinterpret_cast<LPBYTE>(szHwid), &dwSize);
        RegCloseKey(hKey);
    }
    std::ostringstream oss;
    oss << "WIN32-HWID-V2:UUID:" << smbiosUuid << ":BOARD:" << boardSerial
        << ":CHASSIS:" << chassisSerial << ":TPM:" << tpmStatus
        << ":MGUID:" << szHwid;
    return HmacSha256("NoEscape-Ring3-HardwareIdentity-v2", oss.str());
#else
    // 1. Unprivileged CPUID topology
    std::string cpuidInfo;
    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        char buf[64];
        std::snprintf(buf, sizeof(buf), "CPUID1:%08x-%08x-%08x-%08x;", eax, ebx, ecx, edx);
        cpuidInfo += buf;
    }
    char brand[49] = {0};
    if (__get_cpuid(0x80000002, &eax, &ebx, &ecx, &edx)) {
        std::memcpy(brand, &eax, 4); std::memcpy(brand + 4, &ebx, 4);
        std::memcpy(brand + 8, &ecx, 4); std::memcpy(brand + 12, &edx, 4);
    }
    if (__get_cpuid(0x80000003, &eax, &ebx, &ecx, &edx)) {
        std::memcpy(brand + 16, &eax, 4); std::memcpy(brand + 20, &ebx, 4);
        std::memcpy(brand + 24, &ecx, 4); std::memcpy(brand + 28, &edx, 4);
    }
    if (__get_cpuid(0x80000004, &eax, &ebx, &ecx, &edx)) {
        std::memcpy(brand + 32, &eax, 4); std::memcpy(brand + 36, &ebx, 4);
        std::memcpy(brand + 40, &ecx, 4); std::memcpy(brand + 44, &edx, 4);
    }
    cpuidInfo += "BRAND:" + std::string(brand) + ";";

    // 2. Unprivileged statvfs root filesystem superblock ID
    std::string fsInfo;
    struct statvfs sv{};
    if (statvfs("/", &sv) == 0) {
        char buf[64];
        std::snprintf(buf, sizeof(buf), "FSID:%lx-%lx;", static_cast<unsigned long>(sv.f_fsid), static_cast<unsigned long>(sv.f_type));
        fsInfo = buf;
    }

    // 3. DMI sysfs identifiers
    auto readDmiFile = [](const char* path) -> std::string {
        std::ifstream f(path);
        std::string s;
        if (f.is_open() && std::getline(f, s)) {
            while (!s.empty() && (s.back() == '\r' || s.back() == '\n' || s.back() == ' ')) s.pop_back();
            return s;
        }
        return "";
    };
    std::string prodUuid = readDmiFile("/sys/class/dmi/id/product_uuid");
    std::string boardSerial = readDmiFile("/sys/class/dmi/id/board_serial");
    std::string chassisSerial = readDmiFile("/sys/class/dmi/id/chassis_serial");
    std::string prodSerial = readDmiFile("/sys/class/dmi/id/product_serial");
    std::string modalias = readDmiFile("/sys/class/dmi/id/modalias");

    // 4. Linux machine-id fallbacks
    std::string mid;
    std::ifstream midF(NOESCAPE_XOR("/etc/machine-id"));
    if (midF.is_open()) std::getline(midF, mid);
    if (mid.empty()) {
        std::ifstream dbusMid(NOESCAPE_XOR("/var/lib/dbus/machine-id"));
        if (dbusMid.is_open()) std::getline(dbusMid, mid);
    }

    std::ostringstream oss;
    oss << "LINUX-HWID-V2:" << cpuidInfo << fsInfo
        << "DMI:[" << prodUuid << ":" << boardSerial << ":" << chassisSerial << ":" << prodSerial << ":" << modalias << "]"
        << ":MID:" << mid;

    return HmacSha256("NoEscape-Ring3-HardwareIdentity-v2", oss.str());
#endif
    }();
    return cachedHwid;
}

std::vector<uint8_t> CryptoUtil::FromHex(const std::string& hex) {
    std::vector<uint8_t> out;
    if (hex.size() % 2 != 0) return out;
    out.reserve(hex.size() / 2);
    auto hexVal = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = hexVal(hex[i]);
        int lo = hexVal(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            out.clear();
            return out;
        }
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

std::string CryptoUtil::Sha256File(const std::string& file_path) {
    if (file_path.empty()) return "";
    std::ifstream ifs(file_path, std::ios::binary);
    if (!ifs.is_open()) return "";

    Sha256Context ctx;
    std::array<uint8_t, 65536> buf{};
    while (ifs.good()) {
        ifs.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
        std::streamsize n = ifs.gcount();
        if (n > 0) {
            ctx.Update(buf.data(), static_cast<size_t>(n));
        }
    }
    uint8_t digest[32];
    ctx.Finalize(digest);
    return ToHex(digest, 32);
}

bool CryptoUtil::GenerateRandomBytes(uint8_t* out, size_t length) {
    if (!out) return false;
    if (length == 0) return true;

#if defined(_WIN32)
    NTSTATUS status = BCryptGenRandom(
        nullptr,
        out,
        static_cast<ULONG>(length),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );
    return status == 0;
#else
    size_t total = 0;
    // 1. Explicit getrandom(2) syscall (Linux CSPRNG)
    while (total < length) {
        ssize_t ret = getrandom(out + total, length - total, 0);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break; // Failed or unsupported, fallback to /dev/urandom
        }
        total += static_cast<size_t>(ret);
    }
    if (total == length) {
        return true;
    }

    // 2. Direct POSIX /dev/urandom fallback (no timestamp fallback)
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        while (total < length) {
            ssize_t ret = read(fd, out + total, length - total);
            if (ret < 0) {
                if (errno == EINTR) continue;
                close(fd);
                return false;
            }
            if (ret == 0) {
                close(fd);
                return false;
            }
            total += static_cast<size_t>(ret);
        }
        close(fd);
        return total == length;
    }
    return false;
#endif
}

std::string CryptoUtil::GenerateRandomHex(size_t byte_length) {
    if (byte_length == 0) return "";
    std::vector<uint8_t> bytes(byte_length);
    if (!GenerateRandomBytes(bytes.data(), byte_length)) {
        return "";
    }
    return ToHex(bytes.data(), bytes.size());
}

std::string CryptoUtil::DeriveKeyHkdf(
    const std::string& input_key_material,
    const std::string& salt,
    const std::string& info
) {
    std::string effectiveSalt = salt.empty() ? std::string(32, '\0') : salt;
    std::string prk = HmacSha256(effectiveSalt, input_key_material);
    std::string expandInput = info + std::string(1, '\x01');
    return HmacSha256(prk, expandInput);
}

CryptoUtil::AsymmetricKeyPair CryptoUtil::GenerateAsymmetricKeyPair() {
    AsymmetricKeyPair kp{};
#if defined(NOESCAPE_HAS_OPENSSL)
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    if (pctx) {
        if (EVP_PKEY_keygen_init(pctx) == 1 && EVP_PKEY_keygen(pctx, &pkey) == 1 && pkey) {
            uint8_t privBuf[32]{};
            uint8_t pubBuf[32]{};
            size_t privLen = sizeof(privBuf);
            size_t pubLen = sizeof(pubBuf);
            if (EVP_PKEY_get_raw_private_key(pkey, privBuf, &privLen) == 1 &&
                EVP_PKEY_get_raw_public_key(pkey, pubBuf, &pubLen) == 1) {
                kp.private_key_hex = ToHex(privBuf, privLen);
                kp.public_key_hex = ToHex(pubBuf, pubLen);
            }
        }
        if (pkey) EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
    }
    if (!kp.private_key_hex.empty() && !kp.public_key_hex.empty()) {
        return kp;
    }
#endif
    // Genuine RFC 8032 Ed25519 portable provider
    uint8_t seed[32]{};
    if (!GenerateRandomBytes(seed, sizeof(seed))) {
        return kp;
    }
    uint8_t pubKey[32]{};
    uint8_t privKey[64]{};
    if (ed25519::CreateKeyPair(seed, pubKey, privKey)) {
        kp.private_key_hex = ToHex(seed, 32);
        kp.public_key_hex = ToHex(pubKey, 32);
    }
    return kp;
}

std::string CryptoUtil::SignAsymmetric(const std::string& private_key_hex, const std::string& message) {
    auto privBytes = FromHex(private_key_hex);
    if (privBytes.size() != 32 && privBytes.size() != 64) return "";
#if defined(NOESCAPE_HAS_OPENSSL)
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, privBytes.data(), 32);
    if (pkey) {
        EVP_MD_CTX* mctx = EVP_MD_CTX_new();
        std::string sigHex;
        if (mctx) {
            uint8_t sig[64]{};
            size_t sigLen = sizeof(sig);
            if (EVP_DigestSignInit(mctx, nullptr, nullptr, nullptr, pkey) == 1 &&
                EVP_DigestSign(mctx, sig, &sigLen,
                               reinterpret_cast<const uint8_t*>(message.data()), message.size()) == 1) {
                sigHex = ToHex(sig, sigLen);
            }
            EVP_MD_CTX_free(mctx);
        }
        EVP_PKEY_free(pkey);
        if (!sigHex.empty()) return sigHex;
    }
#endif
    // Genuine RFC 8032 Ed25519 portable provider
    uint8_t sig[64]{};
    if (ed25519::Sign(privBytes.data(), privBytes.size(),
                      reinterpret_cast<const uint8_t*>(message.data()), message.size(), sig)) {
        return ToHex(sig, 64);
    }
    return "";
}

bool CryptoUtil::VerifyAsymmetric(
    const std::string& public_key_hex,
    const std::string& message,
    const std::string& signature_hex
) {
    auto pubBytes = FromHex(public_key_hex);
    auto sigBytes = FromHex(signature_hex);
    if (pubBytes.size() != 32 || sigBytes.size() != 64) return false;
#if defined(NOESCAPE_HAS_OPENSSL)
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pubBytes.data(), pubBytes.size());
    if (pkey) {
        EVP_MD_CTX* mctx = EVP_MD_CTX_new();
        bool ok = false;
        if (mctx) {
            if (EVP_DigestVerifyInit(mctx, nullptr, nullptr, nullptr, pkey) == 1 &&
                EVP_DigestVerify(mctx, sigBytes.data(), sigBytes.size(),
                                 reinterpret_cast<const uint8_t*>(message.data()), message.size()) == 1) {
                ok = true;
            }
            EVP_MD_CTX_free(mctx);
        }
        EVP_PKEY_free(pkey);
        if (ok) return true;
    }
#endif
    // Genuine RFC 8032 Ed25519 portable provider
    return ed25519::Verify(pubBytes.data(),
                           reinterpret_cast<const uint8_t*>(message.data()), message.size(),
                           sigBytes.data());
}

CryptoUtil::AsymmetricKeyPair CryptoUtil::GenerateX25519KeyPair() {
    AsymmetricKeyPair kp{};
    uint8_t seed[32]{};
    if (!GenerateRandomBytes(seed, sizeof(seed))) {
        return kp;
    }
    uint8_t pubKey[32]{};
    uint8_t privKey[32]{};
    if (x25519::CreateKeyPair(seed, pubKey, privKey)) {
        kp.private_key_hex = ToHex(privKey, 32);
        kp.public_key_hex = ToHex(pubKey, 32);
    }
    return kp;
}

std::string CryptoUtil::DiffieHellmanX25519(
    const std::string& private_key_hex,
    const std::string& peer_public_key_hex
) {
    auto privBytes = FromHex(private_key_hex);
    auto pubBytes = FromHex(peer_public_key_hex);
    if (privBytes.size() != 32 || pubBytes.size() != 32) return "";
    uint8_t secret[32]{};
    if (x25519::DiffieHellman(privBytes.data(), pubBytes.data(), secret)) {
        return ToHex(secret, 32);
    }
    return "";
}

bool CryptoUtil::AeadChaCha20Poly1305Encrypt(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& aad,
    const uint8_t key[32],
    const uint8_t nonce[12],
    std::vector<uint8_t>& out_ciphertext,
    uint8_t out_tag[16]
) {
#if defined(NOESCAPE_HAS_OPENSSL)
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx) {
        int len = 0;
        if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) == 1 &&
            EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce) == 1) {
            bool ok = true;
            if (!aad.empty()) {
                if (EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1) {
                    ok = false;
                }
            }
            out_ciphertext.resize(plaintext.size());
            if (ok && !plaintext.empty()) {
                if (EVP_EncryptUpdate(ctx, out_ciphertext.data(), &len, plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
                    ok = false;
                }
            }
            int finalLen = 0;
            if (ok && EVP_EncryptFinal_ex(ctx, out_ciphertext.data() + len, &finalLen) == 1 &&
                EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, out_tag) == 1) {
                EVP_CIPHER_CTX_free(ctx);
                return true;
            }
        }
        EVP_CIPHER_CTX_free(ctx);
    }
#endif
    // Genuine RFC 8439 pure ChaCha20-Poly1305 provider (portable fallback / non-OpenSSL builds / Windows)
    return chacha20poly1305::AeadEncrypt(key, nonce, aad.data(), aad.size(),
                                         plaintext.data(), plaintext.size(),
                                         out_ciphertext, out_tag);
}

bool CryptoUtil::AeadChaCha20Poly1305Decrypt(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& aad,
    const uint8_t tag[16],
    const uint8_t key[32],
    const uint8_t nonce[12],
    std::vector<uint8_t>& out_plaintext
) {
#if defined(NOESCAPE_HAS_OPENSSL)
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx) {
        int len = 0;
        if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, const_cast<uint8_t*>(tag)) == 1 &&
            EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce) == 1) {
            bool ok = true;
            if (!aad.empty()) {
                if (EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1) {
                    ok = false;
                }
            }
            out_plaintext.resize(ciphertext.size());
            if (ok && !ciphertext.empty()) {
                if (EVP_DecryptUpdate(ctx, out_plaintext.data(), &len, ciphertext.data(), static_cast<int>(ciphertext.size())) != 1) {
                    ok = false;
                }
            }
            int finalLen = 0;
            if (ok && EVP_DecryptFinal_ex(ctx, out_plaintext.data() + len, &finalLen) == 1) {
                EVP_CIPHER_CTX_free(ctx);
                return true;
            }
        }
        EVP_CIPHER_CTX_free(ctx);
    }
#endif
    // Genuine RFC 8439 pure ChaCha20-Poly1305 provider (portable fallback / non-OpenSSL builds / Windows)
    return chacha20poly1305::AeadDecrypt(key, nonce, aad.data(), aad.size(),
                                         ciphertext.data(), ciphertext.size(),
                                         tag, out_plaintext);
}

bool CryptoUtil::IsVersionAtLeast(const std::string& actual_version, const std::string& minimum_required) {
    if (minimum_required.empty()) return true;
    if (actual_version.empty()) return false;

    auto parseVer = [](const std::string& v) -> std::array<int, 3> {
        std::array<int, 3> parts{0, 0, 0};
        std::istringstream ss(v);
        std::string token;
        size_t idx = 0;
        while (idx < 3 && std::getline(ss, token, '.')) {
            try {
                parts[idx++] = std::stoi(token);
            } catch (...) {
                parts[idx++] = 0;
            }
        }
        return parts;
    };

    auto act = parseVer(actual_version);
    auto req = parseVer(minimum_required);
    for (size_t i = 0; i < 3; ++i) {
        if (act[i] > req[i]) return true;
        if (act[i] < req[i]) return false;
    }
    return true;
}

} // namespace noescape::network
