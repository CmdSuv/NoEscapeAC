#pragma once

#include <string>
#include <vector>
#include <deque>
#include <cstdint>
#include <mutex>
#include "noescape/core/types.hpp"
#include "noescape/kinematics/aim_analyzer.hpp"

namespace noescape::core {

struct BlackboxRecord {
    uint64_t timestamp{0};
    std::string hwid;
    std::string violating_component;
    std::string violation_reason;
    uint32_t threat_score{0};
    uint32_t violation_type{0};
    std::vector<uintptr_t> backtrace_addrs;
    std::vector<kinematics::AngleSample> recent_input_trail;
    std::vector<std::string> loaded_modules_sample;
};

class BlackboxDumper {
public:
    static BlackboxDumper& Instance();

    // Feeds an input sample into the circular blackbox buffer
    void RecordInputSample(float pitch, float yaw, uint64_t timestamp_ms);
    void RecordInputSample(const kinematics::AngleSample& sample);

    // Captures a full diagnostic snapshot
    BlackboxRecord CaptureSnapshot(
        const std::string& component,
        const std::string& reason,
        uint32_t score,
        uint32_t violation_type = 0
    );

    // Serializes snapshot and encrypts with HMAC authentication
    std::vector<uint8_t> SerializeAndEncrypt(
        const BlackboxRecord& record,
        const std::string& secret_key
    );

    // Decrypts and deserializes snapshot; verifies HMAC signature
    bool DecryptAndDeserialize(
        const std::vector<uint8_t>& encrypted_data,
        const std::string& secret_key,
        BlackboxRecord& out_record
    );

    // Writes encrypted dump payload to disk
    bool SaveDumpToFile(const std::string& file_path, const std::vector<uint8_t>& encrypted_data);

    // Dump directory configuration
    void SetDumpDirectory(const std::string& dir);
    std::string GetDumpDirectory() const;

    // Generates a standard blackbox filename with timestamp
    std::string GenerateDumpFilename() const;

    // Platform-specific stack backtrace capture
    static std::vector<uintptr_t> CaptureBacktrace(size_t max_depth = 32);

    // Platform-specific sample of loaded module paths
    static std::vector<std::string> SampleLoadedModules(size_t max_count = 16);

    // Privacy helper: redacts OS usernames from file paths (/home/<user>/ -> /home/<REDACTED>/)
    static std::string RedactSensitivePaths(const std::string& input);

    // Clears the input trail buffer
    void ClearInputTrail();

    // Gets the current trail count
    size_t GetInputTrailCount() const;

private:
    BlackboxDumper();

    mutable std::mutex mutex_;
    std::string dump_dir_{""};
    std::deque<kinematics::AngleSample> input_trail_;
    size_t trail_capacity_{64};
};

} // namespace noescape::core
