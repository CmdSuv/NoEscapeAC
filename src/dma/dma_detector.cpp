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

            // Check for FTDI FT601 (VID_0403&PID_601F), standard LeechCore bridges, or KMBox hardware aimbot bridges
            if (keyUpper.find("VID_0403&PID_601F") != std::string::npos ||
                keyUpper.find("VID_0403&PID_601E") != std::string::npos) {
                PciDeviceInfo info;
                info.device_id = subKeyName;
                info.vendor_id = "0403";
                info.description = "FTDI SuperSpeed USB3 DMA Bridge (PCIeLeech hardware carrier)";
                info.is_suspicious = true;
                detected.push_back(info);
            } else if (keyUpper.find("VID_1A86&PID_55D3") != std::string::npos ||
                       keyUpper.find("VID_8888&PID_") != std::string::npos) {
                PciDeviceInfo info;
                info.device_id = subKeyName;
                info.vendor_id = "KMBOX";
                info.description = "Hardware KMBox / HID Aimbot Injection Controller";
                info.is_suspicious = true;
                detected.push_back(info);
            }
        }
        RegCloseKey(hUsbKey);
    }

    // Windows: Check PCIe Bus for Xilinx Artix-7 (VEN_10EE), Altera (VEN_1172) FPGA endpoints,
    // or Spoofed DMA firmware that forged VEN_xxxx but leaked SUBSYS_xxxx10EE / SUBSYS_xxxx1172
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
            } else {
                size_t subPos = keyUpper.find("SUBSYS_");
                if (subPos != std::string::npos && keyUpper.size() >= subPos + 15) {
                    std::string subsysVendor = keyUpper.substr(subPos + 11, 4);
                    if (subsysVendor == "10EE" || subsysVendor == "1172") {
                        PciDeviceInfo info;
                        info.device_id = subKeyName;
                        info.vendor_id = subsysVendor;
                        info.description = "Spoofed PCIe DMA Card (Forged Vendor ID with Xilinx/Altera FPGA Subsystem ID)";
                        info.is_suspicious = true;
                        detected.push_back(info);
                    }
                }
            }
        }
        RegCloseKey(hPciKey);
    }

#else
    // Linux: Inspect /sys/bus/pci/devices for stock FPGA VIDs and Spoofed DMA firmware anomalies
    DIR* pciDir = opendir(NOESCAPE_XOR("/sys/bus/pci/devices"));
    if (pciDir) {
        struct dirent* entry = nullptr;
        while ((entry = readdir(pciDir)) != nullptr) {
            if (entry->d_name[0] == '.') continue;

            std::string pciPath = std::string("/sys/bus/pci/devices/") + entry->d_name;
            std::ifstream vendorFile(pciPath + "/vendor");
            std::ifstream deviceFile(pciPath + "/device");
            std::ifstream subVendorFile(pciPath + "/subsystem_vendor");

            std::string vid, did, subVid;
            if (vendorFile >> vid && deviceFile >> did) {
                subVendorFile >> subVid;
                // 1. Stock Xilinx (0x10ee) or Altera (0x1172) FPGA PCIe endpoint
                if (vid == "0x10ee" || vid == "0x1172") {
                    PciDeviceInfo dev;
                    dev.device_id = did;
                    dev.vendor_id = vid;
                    dev.description = "FPGA PCIe Endpoint (Known LeechCore DMA hardware)";
                    dev.is_suspicious = true;
                    detected.push_back(dev);
                }
                // 2. Spoofed DMA Firmware: Cloned primary Vendor ID (e.g. Realtek/Intel) but leaked
                //    Xilinx (0x10ee) or Altera (0x1172) Subsystem Vendor ID in PCI config space
                else if (subVid == "0x10ee" || subVid == "0x1172") {
                    PciDeviceInfo dev;
                    dev.device_id = did;
                    dev.vendor_id = vid + "/sub:" + subVid;
                    dev.description = "Spoofed PCIe DMA Card (Forged Vendor ID with FPGA Subsystem ID)";
                    dev.is_suspicious = true;
                    detected.push_back(dev);
                }
            }
        }
        closedir(pciDir);
    }

    // Inspect /sys/bus/usb/devices for FTDI FT601 bridge and KMBox / MAKCU hardware aimbot controllers
    DIR* usbDir = opendir(NOESCAPE_XOR("/sys/bus/usb/devices"));
    if (usbDir) {
        struct dirent* entry = nullptr;
        while ((entry = readdir(usbDir)) != nullptr) {
            if (entry->d_name[0] == '.') continue;

            std::string usbPath = std::string("/sys/bus/usb/devices/") + entry->d_name;
            std::ifstream vendorFile(usbPath + "/idVendor");
            std::ifstream prodFile(usbPath + "/idProduct");
            std::ifstream prodStrFile(usbPath + "/product");

            std::string vid, pid, prodName;
            if (vendorFile >> vid && prodFile >> pid) {
                std::getline(prodStrFile, prodName);
                std::string lowerProd = prodName;
                std::transform(lowerProd.begin(), lowerProd.end(), lowerProd.begin(), [](unsigned char c) {
                    return static_cast<char>(std::tolower(c));
                });

                // FTDI FT601 USB 3.0 bridge VID: 0403, PID: 601f/601e
                if (vid == "0403" && (pid == "601f" || pid == "601e")) {
                    PciDeviceInfo dev;
                    dev.device_id = pid;
                    dev.vendor_id = vid;
                    dev.description = "FTDI SuperSpeed FIFO Bridge (PCIeLeech DMA interface)";
                    dev.is_suspicious = true;
                    detected.push_back(dev);
                } else if ((vid == "1a86" && pid == "55d3") ||
                           lowerProd.find("kmbox") != std::string::npos ||
                           lowerProd.find("makcu") != std::string::npos ||
                           lowerProd.find("pcileech") != std::string::npos) {
                    PciDeviceInfo dev;
                    dev.device_id = pid;
                    dev.vendor_id = vid;
                    dev.description = "Hardware Aimbot / DMA Controller (" + (prodName.empty() ? "KMBox" : prodName) + ")";
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

IommuStatusInfo DmaDetector::CheckIommuStatus() {
    IommuStatusInfo status;
#if defined(_WIN32)
    status.source = "Windows Registry (DMAGuardPolicy / DeviceGuard)";
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SYSTEM\\CurrentControlSet\\Control\\DmaSecurity\\AllowedBuses",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        status.iommu_present = true;
        status.dma_remapping_enabled = true;
        RegCloseKey(hKey);
    }
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\Policies\\Microsoft\\Windows\\Kernel DMA Protection",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD policy = 0, size = sizeof(DWORD);
        if (RegQueryValueExA(hKey, "DeviceEnumerationPolicy", nullptr, nullptr,
                             reinterpret_cast<LPBYTE>(&policy), &size) == ERROR_SUCCESS) {
            status.iommu_present = true;
            status.dma_remapping_enabled = (policy == 0 || policy == 1);
            status.dma_remapping_active = status.dma_remapping_enabled;
            status.strict_mode = (policy == 0);
        }
        RegCloseKey(hKey);
    }
#else
    status.source = "/sys/class/iommu & /sys/kernel/iommu_groups";
    DIR* iommu_dir = opendir("/sys/class/iommu");
    if (iommu_dir) {
        struct dirent* entry;
        while ((entry = readdir(iommu_dir)) != nullptr) {
            if (entry->d_name[0] != '.') {
                status.iommu_present = true;
                break;
            }
        }
        closedir(iommu_dir);
    }
    DIR* groups_dir = opendir("/sys/kernel/iommu_groups");
    if (groups_dir) {
        struct dirent* entry;
        while ((entry = readdir(groups_dir)) != nullptr) {
            if (entry->d_name[0] != '.') {
                status.dma_remapping_enabled = true;
                status.dma_remapping_active = true;
                break;
            }
        }
        closedir(groups_dir);
    }
    std::ifstream cmdline("/proc/cmdline");
    if (cmdline.is_open()) {
        std::string line;
        std::getline(cmdline, line);
        if (line.find("iommu.strict=1") != std::string::npos ||
            line.find("intel_iommu=on") != std::string::npos ||
            line.find("amd_iommu=on") != std::string::npos) {
            status.strict_mode = (line.find("iommu.passthrough=1") == std::string::npos &&
                                  line.find("iommu=pt") == std::string::npos);
        }
    }
#endif
    return status;
}

HardwareConfidenceLevel DmaDetector::EvaluateHardwareConfidence(
    const PciDeviceInfo& dev,
    bool has_leechcore_artifact,
    bool has_bus_jitter_anomaly) const {
    if (has_leechcore_artifact) {
        return HardwareConfidenceLevel::CONFIRMED_TOOL_ARTIFACT;
    }
    // Check if the description explicitly names PCILeech / Screamer
    std::string lower_desc = dev.description;
    std::transform(lower_desc.begin(), lower_desc.end(), lower_desc.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (lower_desc.find("pcileech") != std::string::npos ||
        lower_desc.find("screamer") != std::string::npos) {
        return HardwareConfidenceLevel::KNOWN_CHEAT_HARDWARE;
    }
    if (dev.is_suspicious) {
        if (has_bus_jitter_anomaly) {
            return HardwareConfidenceLevel::KNOWN_CHEAT_HARDWARE;
        }
        return HardwareConfidenceLevel::SUSPICIOUS_BRIDGE_OR_FPGA;
    }
    return HardwareConfidenceLevel::BENIGN_DEV_HARDWARE;
}

HardwareConfidenceLevel DmaDetector::EvaluateHardwareConfidence(
    const DmaProfile& jitter_profile,
    const std::vector<PciDeviceInfo>& devices,
    bool leechcore_present,
    const IommuStatusInfo& /*iommu_status*/
) const {
    if (leechcore_present) {
        return HardwareConfidenceLevel::CONFIRMED_TOOL_ARTIFACT;
    }
    bool any_known_cheat = false;
    bool any_suspicious = false;
    for (const auto& dev : devices) {
        auto conf = EvaluateHardwareConfidence(dev, false, jitter_profile.anomalous);
        if (conf == HardwareConfidenceLevel::KNOWN_CHEAT_HARDWARE) {
            any_known_cheat = true;
        } else if (conf == HardwareConfidenceLevel::SUSPICIOUS_BRIDGE_OR_FPGA) {
            any_suspicious = true;
        }
    }
    if (any_known_cheat) return HardwareConfidenceLevel::KNOWN_CHEAT_HARDWARE;
    if (any_suspicious && jitter_profile.anomalous) return HardwareConfidenceLevel::CORROBORATED_DMA_EVIDENCE;
    if (any_suspicious) return HardwareConfidenceLevel::SUSPICIOUS_CHARACTERISTICS;
    if (jitter_profile.anomalous) return HardwareConfidenceLevel::TIMING_ANOMALY_ONLY;
    return HardwareConfidenceLevel::KNOWN_LEGITIMATE;
}

const char* DmaDetector::ConfidenceLevelToString(HardwareConfidenceLevel level) {
    switch (level) {
        case HardwareConfidenceLevel::BENIGN_DEV_HARDWARE:
            return "BENIGN_DEV_HARDWARE";
        case HardwareConfidenceLevel::TIMING_ANOMALY_ONLY:
            return "TIMING_ANOMALY_ONLY";
        case HardwareConfidenceLevel::SUSPICIOUS_BRIDGE_OR_FPGA:
            return "SUSPICIOUS_BRIDGE_OR_FPGA";
        case HardwareConfidenceLevel::KNOWN_CHEAT_HARDWARE:
            return "KNOWN_CHEAT_HARDWARE";
        case HardwareConfidenceLevel::CONFIRMED_TOOL_ARTIFACT:
            return "CONFIRMED_TOOL_ARTIFACT";
        default:
            return "UNKNOWN";
    }
}

std::vector<core::DetectionEvent> DmaDetector::PerformAudit() {
    std::vector<core::DetectionEvent> events;

    // 1. Check for LeechCore interface presence
    bool leechcore_found = CheckLeechCoreArtifacts();
    if (leechcore_found) {
        core::DetectionEvent ev;
        ev.type = core::DetectionType::DMA_PCIE_LEECH_DEVICE;
        ev.severity = core::Severity::CRITICAL;
        ev.component = "DmaDetector::LeechCoreDriver";
        ev.details = "Active Direct Memory Access (DMA) LeechCore device handle identified";
        ev.timestamp = core::DetectionEvent::NowMonotonicMs();
        ev.timestamp_utc_ms = core::DetectionEvent::NowUtcMs();
        ev.threat_score = 90;
        ev.confidence = core::ConfidenceLevel::CONFIRMED;
        events.push_back(ev);
    }

    // 2. Memory bus contention / latency jitter profile
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
        ev.timestamp = core::DetectionEvent::NowMonotonicMs();
        ev.timestamp_utc_ms = core::DetectionEvent::NowUtcMs();
        ev.threat_score = 30;
        ev.confidence = core::ConfidenceLevel::LOW;
        events.push_back(ev);
    }

    // 3. Hardware device scan (PCIe / USB) with explicit confidence classification
    auto iommu = CheckIommuStatus();
    auto devices = ScanHardwareDevices();
    for (const auto& dev : devices) {
        if (dev.is_suspicious) {
            auto hw_conf = EvaluateHardwareConfidence(dev, leechcore_found, profile.anomalous);
            core::DetectionEvent ev;
            ev.type = core::DetectionType::DMA_PCIE_LEECH_DEVICE;
            ev.component = "DmaDetector::PciScan";
            ev.details = std::string("DMA/FPGA hardware discovered on bus (") +
                         ConfidenceLevelToString(hw_conf) + ", IOMMU=" +
                         (iommu.dma_remapping_enabled ? "ON" : "OFF") + "): " + dev.description +
                         " [VID: " + dev.vendor_id + " PID: " + dev.device_id + "]";
            ev.timestamp = core::DetectionEvent::NowMonotonicMs();
            ev.timestamp_utc_ms = core::DetectionEvent::NowUtcMs();
            if (hw_conf == HardwareConfidenceLevel::CONFIRMED_TOOL_ARTIFACT ||
                hw_conf == HardwareConfidenceLevel::KNOWN_CHEAT_HARDWARE) {
                ev.severity = core::Severity::HIGH;
                ev.threat_score = 75;
                ev.confidence = core::ConfidenceLevel::HIGH;
            } else {
                // Vendor ID alone (e.g., Xilinx FPGA / FTDI FIFO dev board) is never standalone proof of cheating
                ev.severity = core::Severity::MEDIUM;
                ev.threat_score = 40;
                ev.confidence = core::ConfidenceLevel::MEDIUM;
            }
            events.push_back(ev);
        }
    }

    return events;
}

} // namespace noescape::dma

