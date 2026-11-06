#include "noescape/dma/dma_detector.hpp"
#include "noescape/core/obfuscation.hpp"
#include <cmath>
#include <algorithm>
#include <chrono>
#include <numeric>
#include <fstream>
#include <sstream>
#include <ctime>
#include <cstring>

#if defined(_WIN32)
#include <windows.h>
#include <setupapi.h>
#else
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#endif

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#include <immintrin.h>
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <x86intrin.h>
#endif
#endif

namespace noescape::dma {

namespace {

inline uint64_t ReadTsc() {
#if defined(_MSC_VER) || defined(__x86_64__) || defined(__i386__)
    return __rdtsc();
#else
    auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(now).count());
#endif
}

inline void FullFence() {
#if defined(__x86_64__) || defined(_M_X64)
    _mm_mfence();
#elif defined(__GNUC__)
    __sync_synchronize();
#endif
}

} // namespace

DmaDetector::DmaDetector() {
    // 4MB cache-aligned probe buffer
    probe_buffer_.resize(4 * 1024 * 1024, 0xAA);
}

DmaDetector::~DmaDetector() = default;

DmaDetector& DmaDetector::Instance() {
    static DmaDetector* instance = new DmaDetector();
    return *instance;
}

uint64_t DmaDetector::MeasureBufferTraversal() {
    if (probe_buffer_.empty()) return 0;

    volatile uint8_t* ptr = probe_buffer_.data();
    size_t size = probe_buffer_.size();
    size_t stride = 64; // Stride by standard cache-line size (64 bytes)
    volatile uint64_t sink = 0;

    // Flush cache lines so traversal hits DRAM bus and evaluates physical PCIe contention
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    for (size_t i = 0; i < size; i += stride) {
        _mm_clflush(const_cast<uint8_t*>(ptr + i));
    }
#endif

    FullFence();
    uint64_t t0 = ReadTsc();
    FullFence();

    for (size_t i = 0; i < size; i += stride) {
        sink += ptr[i];
    }

    FullFence();
    uint64_t t1 = ReadTsc();
    FullFence();

    (void)sink;
    return (t1 > t0) ? (t1 - t0) : 0;
}

bool DmaDetector::Calibrate(size_t probe_size_kb, size_t iterations) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (iterations == 0) iterations = 15;
    probe_buffer_.resize(probe_size_kb * 1024, 0x55);

    std::vector<double> samples;
    samples.reserve(iterations);

    for (size_t i = 0; i < iterations; ++i) {
        uint64_t cycles = MeasureBufferTraversal();
        if (cycles > 0) {
            samples.push_back(static_cast<double>(cycles));
        }
    }

    if (samples.size() < 4) return false;

    double sum = std::accumulate(samples.begin(), samples.end(), 0.0);
    baseline_mean_cycles_ = sum / samples.size();

    double varSum = 0.0;
    for (double s : samples) {
        double diff = s - baseline_mean_cycles_;
        varSum += diff * diff;
    }
    baseline_variance_ = varSum / samples.size();
    calibrated_ = true;

    return true;
}

DmaProfile DmaDetector::ProfileMemoryBusJitter(size_t iterations) {
    DmaProfile profile;
    if (!calibrated_) {
        if (!Calibrate()) return profile;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (iterations == 0) iterations = 30;
    std::vector<double> samples;
    samples.reserve(iterations);

    for (size_t i = 0; i < iterations; ++i) {
        uint64_t cycles = MeasureBufferTraversal();
        if (cycles > 0) {
            samples.push_back(static_cast<double>(cycles));
        }
    }

    if (samples.empty()) return profile;

    // Reject outliers caused by OS scheduler interrupts
    if (samples.size() >= 5) {
        std::vector<double> sorted = samples;
        std::sort(sorted.begin(), sorted.end());
        double median = sorted[sorted.size() / 2];
        std::vector<double> filtered;
        for (double s : samples) {
            if (s <= median * 3.5) {
                filtered.push_back(s);
            }
        }
        if (filtered.size() >= 5) {
            samples = std::move(filtered);
        }
    }

    double sum = std::accumulate(samples.begin(), samples.end(), 0.0);
    profile.current_mean_cycles = sum / samples.size();
    profile.baseline_mean_cycles = baseline_mean_cycles_;

    double varSum = 0.0;
    for (double s : samples) {
        double diff = s - profile.current_mean_cycles;
        varSum += diff * diff;
    }
    double currentVar = varSum / samples.size();
    profile.jitter_stddev = std::sqrt(currentVar);

    double baselineStdDev = std::sqrt(baseline_variance_ > 0 ? baseline_variance_ : 1.0);

    // Count spikes exceeding threshold (incorporating a minimum relative noise floor to avoid false alarms on idle baselines)
    double minDeviation = std::max(anomaly_multiplier_ * baselineStdDev, baseline_mean_cycles_ * 0.35);
    double spikeCutoff = baseline_mean_cycles_ + minDeviation;
    for (double s : samples) {
        if (s > spikeCutoff) {
            profile.spike_count++;
        }
    }

    // If more than 30% of reads suffer massive bus contention and average latency shifted, or stddev is wildly anomalous
    if ((profile.spike_count > (iterations / 3) && profile.current_mean_cycles > baseline_mean_cycles_ * 1.25) || 
        (profile.jitter_stddev > baselineStdDev * anomaly_multiplier_ && profile.current_mean_cycles > baseline_mean_cycles_ * 1.5)) {
        profile.anomalous = true;
    }

    return profile;
}

std::vector<PciDeviceInfo> DmaDetector::ScanHardwareDevices() {
    std::vector<PciDeviceInfo> detected;

#if defined(_WIN32)
    // Windows: Check known FTDI USB3 FIFO bridges via registry
    HKEY hUsbKey = nullptr;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Enum\\USB", 0, KEY_READ, &hUsbKey) == ERROR_SUCCESS) {
        char subKeyName[256]{};
        DWORD index = 0;
        DWORD nameLen = sizeof(subKeyName);

        while (RegEnumKeyExA(hUsbKey, index++, subKeyName, &nameLen, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            nameLen = sizeof(subKeyName);
            std::string keyUpper = subKeyName;
            for (auto& c : keyUpper) c = static_cast<char>(std::toupper(c));

            // Check for FTDI FT601 (VID_0403&PID_601F) or standard LeechCore bridges
            if (keyUpper.find("VID_0403&PID_601F") != std::string::npos ||
                keyUpper.find("VID_0403&PID_601E") != std::string::npos) {
                PciDeviceInfo info;
                info.device_id = subKeyName;
                info.vendor_id = "0403";
                info.description = "FTDI SuperSpeed USB3 DMA Bridge (PCIeLeech hardware carrier)";
                info.is_suspicious = true;
                detected.push_back(info);
            }
        }
        RegCloseKey(hUsbKey);
    }

    // Windows: Check PCIe Bus for Xilinx Artix-7 (VEN_10EE) or Altera (VEN_1172) FPGA endpoints
    HKEY hPciKey = nullptr;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Enum\\PCI", 0, KEY_READ, &hPciKey) == ERROR_SUCCESS) {
        char subKeyName[256]{};
        DWORD index = 0;
        DWORD nameLen = sizeof(subKeyName);

        while (RegEnumKeyExA(hPciKey, index++, subKeyName, &nameLen, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            nameLen = sizeof(subKeyName);
            std::string keyUpper = subKeyName;
            for (auto& c : keyUpper) c = static_cast<char>(std::toupper(c));

            if (keyUpper.find("VEN_10EE") != std::string::npos) {
                PciDeviceInfo info;
                info.device_id = subKeyName;
                info.vendor_id = "10EE";
                info.description = "Xilinx FPGA PCIe Endpoint (PCIeLeech DMA Hardware Card)";
                info.is_suspicious = true;
                detected.push_back(info);
            } else if (keyUpper.find("VEN_1172") != std::string::npos) {
                PciDeviceInfo info;
                info.device_id = subKeyName;
                info.vendor_id = "1172";
                info.description = "Altera FPGA PCIe Endpoint (DMA Hardware Carrier)";
                info.is_suspicious = true;
                detected.push_back(info);
            }
        }
        RegCloseKey(hPciKey);
    }

#else
    // Linux: Inspect /sys/bus/pci/devices
    DIR* pciDir = opendir(NOESCAPE_XOR("/sys/bus/pci/devices"));
    if (pciDir) {
        struct dirent* entry = nullptr;
        while ((entry = readdir(pciDir)) != nullptr) {
            if (entry->d_name[0] == '.') continue;

            std::string pciPath = std::string("/sys/bus/pci/devices/") + entry->d_name;
            std::ifstream vendorFile(pciPath + "/vendor");
            std::ifstream deviceFile(pciPath + "/device");

            std::string vid, did;
            if (vendorFile >> vid && deviceFile >> did) {
                // Xilinx Artix-7 / Spartan FPGA default PCIe vendor ID is 0x10ee
                if (vid == "0x10ee") {
                    PciDeviceInfo dev;
                    dev.device_id = did;
                    dev.vendor_id = vid;
                    dev.description = "Xilinx FPGA PCIe Endpoint (Known LeechCore DMA hardware)";
                    dev.is_suspicious = true;
                    detected.push_back(dev);
                }
            }
        }
        closedir(pciDir);
    }

    // Inspect /sys/bus/usb/devices for FTDI FT601 bridge
    DIR* usbDir = opendir(NOESCAPE_XOR("/sys/bus/usb/devices"));
    if (usbDir) {
        struct dirent* entry = nullptr;
        while ((entry = readdir(usbDir)) != nullptr) {
            if (entry->d_name[0] == '.') continue;

            std::string usbPath = std::string("/sys/bus/usb/devices/") + entry->d_name;
            std::ifstream vendorFile(usbPath + "/idVendor");
            std::ifstream prodFile(usbPath + "/idProduct");

            std::string vid, pid;
            if (vendorFile >> vid && prodFile >> pid) {
                // FTDI FT601 USB 3.0 bridge VID: 0403, PID: 601f
                // Only FT600/FT601 (601e/601f). 6010/6014 are FT2232H/FT232H, ubiquitous USB-serial adapters.
                if (vid == "0403" && (pid == "601f" || pid == "601e")) {
                    PciDeviceInfo dev;
                    dev.device_id = pid;
                    dev.vendor_id = vid;
                    dev.description = "FTDI SuperSpeed FIFO Bridge (PCIeLeech DMA interface)";
                    dev.is_suspicious = true;
                    detected.push_back(dev);
                }
            }
        }
        closedir(usbDir);
    }
#endif

    return detected;
}

bool DmaDetector::CheckLeechCoreArtifacts() {
#if defined(_WIN32)
    // Check for LeechCore named pipe or driver symlink
    HANDLE hPipe = CreateFileA("\\\\.\\LeechCore", GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(hPipe);
        return true;
    }
    HANDLE hMem = CreateFileA("\\\\.\\PhysicalMemory", GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hMem != INVALID_HANDLE_VALUE) {
        CloseHandle(hMem);
        return true;
    }
    return false;
#else
    // Check for /dev/pcileech or /dev/fpgamem or open access to /dev/mem
    std::ifstream dev1(NOESCAPE_XOR("/dev/pcileech"));
    if (dev1.is_open()) return true;

    std::ifstream dev2(NOESCAPE_XOR("/dev/fpgamem"));
    if (dev2.is_open()) return true;

    return false;
#endif
}

std::vector<core::DetectionEvent> DmaDetector::PerformAudit() {
    std::vector<core::DetectionEvent> events;

    // 1. Check for LeechCore interface presence
    if (CheckLeechCoreArtifacts()) {
        core::DetectionEvent ev;
        ev.type = core::DetectionType::DMA_PCIE_LEECH_DEVICE;
        ev.severity = core::Severity::FATAL_BAN;
        ev.component = "DmaDetector::LeechCoreDriver";
        ev.details = "Active Direct Memory Access (DMA) LeechCore device handle identified";
        ev.timestamp = static_cast<uint64_t>(std::time(nullptr));
        ev.threat_score = 100;
        events.push_back(ev);
    }

    // 2. Hardware device scan (PCIe / USB)
    auto devices = ScanHardwareDevices();
    for (const auto& dev : devices) {
        if (dev.is_suspicious) {
            core::DetectionEvent ev;
            ev.type = core::DetectionType::DMA_PCIE_LEECH_DEVICE;
            ev.severity = core::Severity::FATAL_BAN;
            ev.component = "DmaDetector::PciScan";
            ev.details = "DMA Hardware device discovered on bus: " + dev.description +
                         " [VID: " + dev.vendor_id + " PID: " + dev.device_id + "]";
            ev.timestamp = static_cast<uint64_t>(std::time(nullptr));
            ev.severity = core::Severity::HIGH; // vendor ID alone is not proof of a DMA card
            ev.threat_score = 60;
            events.push_back(ev);
        }
    }

    // 3. Memory bus contention / latency jitter profile
    auto profile = ProfileMemoryBusJitter(30);
    if (profile.anomalous) {
        core::DetectionEvent ev;
        ev.type = core::DetectionType::DMA_LATENCY_JITTER_ANOMALY;
        ev.severity = core::Severity::MEDIUM;
        ev.component = "DmaDetector::LatencyJitter";

        std::ostringstream ss;
        ss << "Memory bus contention anomaly detected: current_mean=" << profile.current_mean_cycles
           << " baseline=" << profile.baseline_mean_cycles
           << " jitter_stddev=" << profile.jitter_stddev
           << " spikes=" << profile.spike_count;
        ev.details = ss.str();
        ev.timestamp = static_cast<uint64_t>(std::time(nullptr));
        ev.threat_score = 30;
        events.push_back(ev);
    }

    return events;
}

} // namespace noescape::dma
