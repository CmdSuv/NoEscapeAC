#include "noescape/core/blackbox.hpp"
#include "noescape/network/crypto_util.hpp"
#include "noescape/core/logger.hpp"

#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <ctime>
#include <chrono>
#include <set>
#include <atomic>

#if defined(_WIN32)
#include <windows.h>
#include <psapi.h>
#else
#include <execinfo.h>
#include <unistd.h>
#include <sys/stat.h>
#endif

namespace noescape::core {

namespace {

void PutU16(std::vector<uint8_t>& buf, uint16_t v) {
    buf.push_back(static_cast<uint8_t>(v & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
}

void PutU32(std::vector<uint8_t>& buf, uint32_t v) {
    for (int i = 0; i < 4; ++i) {
        buf.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
    }
}

void PutU64(std::vector<uint8_t>& buf, uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        buf.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
    }
}

void PutFloat(std::vector<uint8_t>& buf, float f) {
    uint32_t v = 0;
    std::memcpy(&v, &f, sizeof(v));
    PutU32(buf, v);
}

void PutString(std::vector<uint8_t>& buf, const std::string& str) {
    uint16_t len = static_cast<uint16_t>(std::min<size_t>(str.size(), 65535));
    PutU16(buf, len);
    buf.insert(buf.end(), str.data(), str.data() + len);
}

bool GetU16(const uint8_t*& ptr, size_t& remain, uint16_t& v) {
    if (remain < 2) return false;
    v = static_cast<uint16_t>(ptr[0]) | (static_cast<uint16_t>(ptr[1]) << 8);
    ptr += 2; remain -= 2;
    return true;
}

bool GetU32(const uint8_t*& ptr, size_t& remain, uint32_t& v) {
    if (remain < 4) return false;
    v = static_cast<uint32_t>(ptr[0]) |
        (static_cast<uint32_t>(ptr[1]) << 8) |
        (static_cast<uint32_t>(ptr[2]) << 16) |
        (static_cast<uint32_t>(ptr[3]) << 24);
    ptr += 4; remain -= 4;
    return true;
}

bool GetU64(const uint8_t*& ptr, size_t& remain, uint64_t& v) {
    if (remain < 8) return false;
    v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= (static_cast<uint64_t>(ptr[i]) << (i * 8));
    }
    ptr += 8; remain -= 8;
    return true;
}

bool GetFloat(const uint8_t*& ptr, size_t& remain, float& f) {
    uint32_t v = 0;
    if (!GetU32(ptr, remain, v)) return false;
    std::memcpy(&f, &v, sizeof(f));
    return true;
}

bool GetString(const uint8_t*& ptr, size_t& remain, std::string& str) {
    uint16_t len = 0;
    if (!GetU16(ptr, remain, len)) return false;
    if (remain < len) return false;
    str.assign(reinterpret_cast<const char*>(ptr), len);
    ptr += len; remain -= len;
    return true;
}

std::vector<uint8_t> HexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        std::string byteStr = hex.substr(i, 2);
        uint8_t b = static_cast<uint8_t>(std::strtoul(byteStr.c_str(), nullptr, 16));
        bytes.push_back(b);
    }
    return bytes;
}

} // namespace

BlackboxDumper& BlackboxDumper::Instance() {
    static BlackboxDumper* instance = new BlackboxDumper();
    return *instance;
}

BlackboxDumper::BlackboxDumper() : trail_capacity_(64) {}

void BlackboxDumper::RecordInputSample(float pitch, float yaw, uint64_t timestamp_ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (input_trail_.size() >= trail_capacity_) {
        input_trail_.pop_front();
    }
    input_trail_.push_back({pitch, yaw, timestamp_ms});
}

void BlackboxDumper::RecordInputSample(const kinematics::AngleSample& sample) {
    RecordInputSample(sample.pitch, sample.yaw, sample.timestamp_ms);
}

void BlackboxDumper::ClearInputTrail() {
    std::lock_guard<std::mutex> lock(mutex_);
    input_trail_.clear();
}

size_t BlackboxDumper::GetInputTrailCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return input_trail_.size();
}

std::vector<uintptr_t> BlackboxDumper::CaptureBacktrace(size_t max_depth) {
    std::vector<uintptr_t> addrs;
    if (max_depth == 0) return addrs;

#if defined(_WIN32)
    std::vector<void*> buffer(max_depth);
    USHORT frames = CaptureStackBackTrace(0, static_cast<DWORD>(max_depth), buffer.data(), nullptr);
    for (USHORT i = 0; i < frames; ++i) {
        addrs.push_back(reinterpret_cast<uintptr_t>(buffer[i]));
    }
#else
    std::vector<void*> buffer(max_depth);
    int frames = backtrace(buffer.data(), static_cast<int>(max_depth));
    for (int i = 0; i < frames; ++i) {
        addrs.push_back(reinterpret_cast<uintptr_t>(buffer[i]));
    }
#endif

    return addrs;
}

std::vector<std::string> BlackboxDumper::SampleLoadedModules(size_t max_count) {
    std::vector<std::string> modules;
    std::set<std::string> uniquePaths;

#if defined(_WIN32)
    HMODULE hMods[1024];
    HANDLE hProcess = GetCurrentProcess();
    DWORD cbNeeded = 0;
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        size_t count = cbNeeded / sizeof(HMODULE);
        for (size_t i = 0; i < count && modules.size() < max_count; ++i) {
            char szModName[MAX_PATH];
            if (GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName))) {
                if (uniquePaths.insert(szModName).second) {
                    modules.emplace_back(szModName);
                }
            }
        }
    }
#else
    std::ifstream maps("/proc/self/maps");
    if (maps.is_open()) {
        std::string line;
        while (std::getline(maps, line) && modules.size() < max_count) {
            size_t slashPos = line.find('/');
            if (slashPos != std::string::npos) {
                std::string path = line.substr(slashPos);
                if (uniquePaths.insert(path).second) {
                    modules.push_back(path);
                }
            }
        }
    }
#endif

    return modules;
}

BlackboxRecord BlackboxDumper::CaptureSnapshot(
    const std::string& component,
    const std::string& reason,
    uint32_t score,
    uint32_t violation_type
) {
    BlackboxRecord rec;
    rec.timestamp = static_cast<uint64_t>(std::time(nullptr));
    rec.hwid = network::CryptoUtil::GetMachineHWID();
    rec.violating_component = component;
    rec.violation_reason = reason;
    rec.threat_score = score;
    rec.violation_type = violation_type;

    rec.backtrace_addrs = CaptureBacktrace(32);
    rec.loaded_modules_sample = SampleLoadedModules(16);

    {
        std::lock_guard<std::mutex> lock(mutex_);
        rec.recent_input_trail.assign(input_trail_.begin(), input_trail_.end());
    }

    return rec;
}

std::vector<uint8_t> BlackboxDumper::SerializeAndEncrypt(
    const BlackboxRecord& record,
    const std::string& secret_key
) {
    // 1. Serialize plaintext payload
    std::vector<uint8_t> plaintext;
    PutU64(plaintext, record.timestamp);
    PutU32(plaintext, record.threat_score);
    PutU32(plaintext, record.violation_type);
    PutString(plaintext, record.hwid);
    PutString(plaintext, record.violating_component);
    PutString(plaintext, record.violation_reason);

    // Backtrace addresses
    PutU16(plaintext, static_cast<uint16_t>(record.backtrace_addrs.size()));
    for (uintptr_t addr : record.backtrace_addrs) {
        PutU64(plaintext, static_cast<uint64_t>(addr));
    }

    // Recent input trail
    PutU16(plaintext, static_cast<uint16_t>(record.recent_input_trail.size()));
    for (const auto& sample : record.recent_input_trail) {
        PutFloat(plaintext, sample.pitch);
        PutFloat(plaintext, sample.yaw);
        PutU64(plaintext, sample.timestamp_ms);
    }

    // Loaded modules sample
    PutU16(plaintext, static_cast<uint16_t>(record.loaded_modules_sample.size()));
    for (const auto& mod : record.loaded_modules_sample) {
        PutString(plaintext, mod);
    }

    // 2. Generate 16-byte IV
    uint64_t nowNs = static_cast<uint64_t>(std::chrono::high_resolution_clock::now().time_since_epoch().count());
    std::string ivSeed = network::CryptoUtil::Sha256(secret_key + ":" + std::to_string(nowNs) + ":" + record.hwid);
    std::vector<uint8_t> iv = HexToBytes(ivSeed.substr(0, 32));
    if (iv.size() < 16) {
        iv.resize(16, 0xA5);
    }

    // 3. Keystream CTR encryption using SHA-256 blocks
    std::string ivStr(reinterpret_cast<const char*>(iv.data()), 16);
    std::string derivedKey = network::CryptoUtil::Sha256(secret_key + ivStr);

    std::vector<uint8_t> ciphertext = plaintext;
    size_t offset = 0;
    uint32_t blockCounter = 0;

    while (offset < ciphertext.size()) {
        std::string blockHashHex = network::CryptoUtil::Sha256(derivedKey + ":" + std::to_string(blockCounter++));
        std::vector<uint8_t> blockKey = HexToBytes(blockHashHex);

        for (size_t b = 0; b < blockKey.size() && offset < ciphertext.size(); ++b, ++offset) {
            ciphertext[offset] ^= blockKey[b];
        }
    }

    // 4. Compute HMAC tag over (IV + ciphertext)
    std::string signPayload = ivStr;
    signPayload.append(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
    std::string hmacTag = network::CryptoUtil::HmacSha256(secret_key, signPayload);

    // 5. Build final packet:
    // [Magic: 4B "NEBB"] [Version: 2B (1)] [IV: 16B] [CipherLen: 4B] [Ciphertext: N] [HMAC Tag: 64B hex]
    std::vector<uint8_t> packet;
    packet.push_back('N');
    packet.push_back('E');
    packet.push_back('B');
    packet.push_back('B');

    PutU16(packet, 1); // version
    packet.insert(packet.end(), iv.begin(), iv.end());
    PutU32(packet, static_cast<uint32_t>(ciphertext.size()));
    packet.insert(packet.end(), ciphertext.begin(), ciphertext.end());
    packet.insert(packet.end(), hmacTag.begin(), hmacTag.end());

    return packet;
}

bool BlackboxDumper::DecryptAndDeserialize(
    const std::vector<uint8_t>& encrypted_data,
    const std::string& secret_key,
    BlackboxRecord& out_record
) {
    // Header checks: 4 (Magic) + 2 (Version) + 16 (IV) + 4 (CipherLen) + 64 (HMAC) = 90 bytes minimum
    constexpr size_t kMinHeader = 4 + 2 + 16 + 4 + 64;
    if (encrypted_data.size() < kMinHeader) {
        return false;
    }

    if (encrypted_data[0] != 'N' || encrypted_data[1] != 'E' ||
        encrypted_data[2] != 'B' || encrypted_data[3] != 'B') {
        return false;
    }

    const uint8_t* ptr = encrypted_data.data() + 4;
    size_t remain = encrypted_data.size() - 4;

    uint16_t version = 0;
    if (!GetU16(ptr, remain, version) || version != 1) {
        return false;
    }

    if (remain < 16 + 4 + 64) return false;
    std::vector<uint8_t> iv(ptr, ptr + 16);
    ptr += 16; remain -= 16;

    uint32_t cipherLen = 0;
    if (!GetU32(ptr, remain, cipherLen)) return false;

    // widen before adding: a uint32 sum wraps for cipherLen close to 4 GiB
    if (remain < static_cast<size_t>(cipherLen) + 64) return false;
    std::vector<uint8_t> ciphertext(ptr, ptr + cipherLen);
    ptr += cipherLen; remain -= cipherLen;

    std::string providedTag(reinterpret_cast<const char*>(ptr), 64);
    ptr += 64; remain -= 64;

    // Verify HMAC-SHA256 signature
    std::string signPayload(reinterpret_cast<const char*>(iv.data()), 16);
    signPayload.append(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
    std::string expectedTag = network::CryptoUtil::HmacSha256(secret_key, signPayload);

    if (!network::CryptoUtil::ConstantTimeEquals(providedTag, expectedTag)) {
        Logger::Instance().Error("Blackbox decryption failed: HMAC signature mismatch (Tampered or Wrong Key)");
        return false;
    }

    // Decrypt ciphertext using stream keystream
    std::string ivStr(reinterpret_cast<const char*>(iv.data()), 16);
    std::string derivedKey = network::CryptoUtil::Sha256(secret_key + ivStr);

    std::vector<uint8_t> plaintext = ciphertext;
    size_t offset = 0;
    uint32_t blockCounter = 0;

    while (offset < plaintext.size()) {
        std::string blockHashHex = network::CryptoUtil::Sha256(derivedKey + ":" + std::to_string(blockCounter++));
        std::vector<uint8_t> blockKey = HexToBytes(blockHashHex);

        for (size_t b = 0; b < blockKey.size() && offset < plaintext.size(); ++b, ++offset) {
            plaintext[offset] ^= blockKey[b];
        }
    }

    // Deserialize plaintext fields
    const uint8_t* pPlain = plaintext.data();
    size_t pRemain = plaintext.size();

    if (!GetU64(pPlain, pRemain, out_record.timestamp)) return false;
    if (!GetU32(pPlain, pRemain, out_record.threat_score)) return false;
    if (!GetU32(pPlain, pRemain, out_record.violation_type)) return false;
    if (!GetString(pPlain, pRemain, out_record.hwid)) return false;
    if (!GetString(pPlain, pRemain, out_record.violating_component)) return false;
    if (!GetString(pPlain, pRemain, out_record.violation_reason)) return false;

    // Backtrace
    uint16_t btCount = 0;
    if (!GetU16(pPlain, pRemain, btCount)) return false;
    out_record.backtrace_addrs.clear();
    for (uint16_t i = 0; i < btCount; ++i) {
        uint64_t addr = 0;
        if (!GetU64(pPlain, pRemain, addr)) return false;
        out_record.backtrace_addrs.push_back(static_cast<uintptr_t>(addr));
    }

    // Input trail
    uint16_t trailCount = 0;
    if (!GetU16(pPlain, pRemain, trailCount)) return false;
    out_record.recent_input_trail.clear();
    for (uint16_t i = 0; i < trailCount; ++i) {
        kinematics::AngleSample s;
        if (!GetFloat(pPlain, pRemain, s.pitch)) return false;
        if (!GetFloat(pPlain, pRemain, s.yaw)) return false;
        if (!GetU64(pPlain, pRemain, s.timestamp_ms)) return false;
        out_record.recent_input_trail.push_back(s);
    }

    // Loaded modules
    uint16_t modCount = 0;
    if (!GetU16(pPlain, pRemain, modCount)) return false;
    out_record.loaded_modules_sample.clear();
    for (uint16_t i = 0; i < modCount; ++i) {
        std::string mod;
        if (!GetString(pPlain, pRemain, mod)) return false;
        out_record.loaded_modules_sample.push_back(mod);
    }

    return true;
}

bool BlackboxDumper::SaveDumpToFile(const std::string& file_path, const std::vector<uint8_t>& encrypted_data) {
    std::ofstream ofs(file_path, std::ios::binary | std::ios::trunc);
    if (!ofs.is_open()) return false;
#if !defined(_WIN32)
    ::chmod(file_path.c_str(), 0600);
#endif
    ofs.write(reinterpret_cast<const char*>(encrypted_data.data()), encrypted_data.size());
    return ofs.good();
}

void BlackboxDumper::SetDumpDirectory(const std::string& dir) {
    std::lock_guard<std::mutex> lock(mutex_);
    dump_dir_ = dir;
}

std::string BlackboxDumper::GetDumpDirectory() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return dump_dir_;
}

std::string BlackboxDumper::GenerateDumpFilename() const {
    uint64_t now = static_cast<uint64_t>(std::time(nullptr));
    std::lock_guard<std::mutex> lock(mutex_);
    static std::atomic<uint32_t> seq{0};
    std::string base = "noescape_blackbox_" + std::to_string(now) + "_" + std::to_string(seq.fetch_add(1)) + ".dmp";
    if (dump_dir_.empty()) {
        return base;
    }
    if (dump_dir_.back() == '/' || dump_dir_.back() == '\\') {
        return dump_dir_ + base;
    }
    return dump_dir_ + "/" + base;
}

} // namespace noescape::core
