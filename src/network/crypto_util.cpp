#include "noescape/network/crypto_util.hpp"
#include "noescape/core/obfuscation.hpp"
#include <cstring>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <array>

#if defined(_WIN32)
#include <windows.h>
#else
#include <unistd.h>
#include <sys/types.h>
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
#if defined(_WIN32)
    HKEY hKey = nullptr;
    char szHwid[256] = {0};
    DWORD dwSize = sizeof(szHwid);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "MachineGuid", nullptr, nullptr, reinterpret_cast<LPBYTE>(szHwid), &dwSize);
        RegCloseKey(hKey);
    }
    if (strlen(szHwid) > 0) {
        return Sha256(szHwid);
    }
    char compName[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD compLen = sizeof(compName);
    GetComputerNameA(compName, &compLen);
    DWORD volSerial = 0;
    GetVolumeInformationA("C:\\", nullptr, 0, &volSerial, nullptr, nullptr, nullptr, 0);
    return Sha256(std::string("WIN32-FALLBACK-") + compName + ":" + std::to_string(volSerial));
#else
    // Linux HWID: Read /etc/machine-id or fallback to /var/lib/dbus/machine-id
    std::ifstream mid(NOESCAPE_XOR("/etc/machine-id"));
    std::string id;
    if (mid.is_open() && std::getline(mid, id) && !id.empty()) {
        return Sha256(id);
    }
    std::ifstream dbusMid(NOESCAPE_XOR("/var/lib/dbus/machine-id"));
    if (dbusMid.is_open() && std::getline(dbusMid, id) && !id.empty()) {
        return Sha256(id);
    }
    // Fallback: hostname
    char hostname[256]{};
    gethostname(hostname, sizeof(hostname) - 1);
    return Sha256(std::string("LINUX-HWID-") + hostname);
#endif
}

} // namespace noescape::network
