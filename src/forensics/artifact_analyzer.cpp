#include "noescape/forensics/artifact_analyzer.hpp"
#include "noescape/core/obfuscation.hpp"
#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <sstream>
#include <ctime>

#if defined(_WIN32)
#include <windows.h>
#include <psapi.h>
#else
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#endif

namespace noescape::forensics {

namespace {

std::string ToLower(const std::string& str) {
    std::string s = str;
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

} // namespace

ArtifactAnalyzer& ArtifactAnalyzer::Instance() {
    static ArtifactAnalyzer* instance = new ArtifactAnalyzer();
    return *instance;
}

bool ArtifactAnalyzer::CheckSystemWidePreload() {
#if defined(_WIN32)
    HKEY hKey = nullptr;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
                      NOESCAPE_XOR("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows"), 
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char buffer[512]{};
        DWORD size = sizeof(buffer);
        DWORD type = 0;
        if (RegQueryValueExA(hKey, NOESCAPE_XOR("AppInit_DLLs"), nullptr, &type, reinterpret_cast<LPBYTE>(buffer), &size) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return std::strlen(buffer) > 0;
        }
        RegCloseKey(hKey);
    }
    return false;
#else
    std::ifstream preload(NOESCAPE_XOR("/etc/ld.so.preload"));
    if (preload.is_open()) {
        std::string line;
        while (std::getline(preload, line)) {
            // If there is any non-whitespace, non-comment line, it's active
            size_t first = line.find_first_not_of(" \t\r\n");
            if (first != std::string::npos && line[first] != '#') {
                return true;
            }
        }
    }
    return false;
#endif
}

std::vector<ArtifactRecord> ArtifactAnalyzer::ScanFilesystemArtifacts(const std::vector<std::string>& blacklisted_names) {
    std::vector<ArtifactRecord> findings;
    if (blacklisted_names.empty()) return findings;

#if defined(_WIN32)
    std::vector<std::string> searchDirs;
    char tempPath[MAX_PATH]{};
    if (GetTempPathA(MAX_PATH, tempPath) > 0) {
        searchDirs.push_back(tempPath);
    }
    searchDirs.push_back("C:\\Windows\\Temp");

    for (const auto& dir : searchDirs) {
        WIN32_FIND_DATAA fd{};
        std::string query = dir + "\\*";
        HANDLE hFind = FindFirstFileA(query.c_str(), &fd);
        if (hFind == INVALID_HANDLE_VALUE) continue;

        do {
            if (std::strcmp(fd.cFileName, ".") == 0 || std::strcmp(fd.cFileName, "..") == 0) continue;
            std::string fileName = ToLower(fd.cFileName);

            for (const auto& target : blacklisted_names) {
                if (fileName.find(ToLower(target)) != std::string::npos) {
                    findings.push_back({dir + "\\" + fd.cFileName, target, "TempArtifact"});
                    break;
                }
            }
        } while (FindNextFileA(hFind, &fd));

        FindClose(hFind);
    }

#else
    std::vector<std::string> searchDirs = {"/dev/shm", "/tmp", "/var/tmp"};

    for (const auto& dirPath : searchDirs) {
        DIR* dir = opendir(dirPath.c_str());
        if (!dir) continue;

        struct dirent* entry = nullptr;
        while ((entry = readdir(dir)) != nullptr) {
            if (std::strcmp(entry->d_name, ".") == 0 || std::strcmp(entry->d_name, "..") == 0) continue;

            std::string fileName = ToLower(entry->d_name);
            for (const auto& target : blacklisted_names) {
                if (fileName.find(ToLower(target)) != std::string::npos) {
                    findings.push_back({dirPath + "/" + entry->d_name, target, "TransientSharedMemoryArtifact"});
                    break;
                }
            }
        }

        closedir(dir);
    }
#endif

    return findings;
}

std::vector<ArtifactRecord> ArtifactAnalyzer::ScanKernelDrivers(const std::vector<std::string>& blacklisted_drivers) {
    std::vector<ArtifactRecord> findings;
    if (blacklisted_drivers.empty()) return findings;

#if defined(_WIN32)
    LPVOID drivers[1024];
    DWORD cbNeeded = 0;
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) {
        int count = cbNeeded / sizeof(drivers[0]);
        for (int i = 0; i < count; ++i) {
            char baseName[MAX_PATH]{};
            if (GetDeviceDriverBaseNameA(drivers[i], baseName, MAX_PATH)) {
                std::string lowerDriver = ToLower(baseName);
                for (const auto& bl : blacklisted_drivers) {
                    if (lowerDriver.find(ToLower(bl)) != std::string::npos) {
                        findings.push_back({baseName, bl, "VulnerableKernelDriver"});
                        break;
                    }
                }
            }
        }
    }

#else
    std::ifstream modules(NOESCAPE_XOR("/proc/modules"));
    if (modules.is_open()) {
        std::string line;
        while (std::getline(modules, line)) {
            std::istringstream iss(line);
            std::string modName;
            if (iss >> modName) {
                std::string lowerMod = ToLower(modName);
                for (const auto& bl : blacklisted_drivers) {
                    if (lowerMod.find(ToLower(bl)) != std::string::npos) {
                        findings.push_back({modName, bl, "BlacklistedKernelModule"});
                        break;
                    }
                }
            }
        }
    }
#endif

    return findings;
}

std::vector<core::DetectionEvent> ArtifactAnalyzer::PerformAudit(
    const std::vector<std::string>& blacklisted_names,
    const std::vector<std::string>& blacklisted_drivers
) {
    std::vector<core::DetectionEvent> events;

    // Check system-wide linker hook
    if (CheckSystemWidePreload()) {
        core::DetectionEvent ev;
        ev.type = core::DetectionType::ENVIRONMENT_TAMPERING;
        ev.severity = core::Severity::FATAL_BAN;
        ev.component = "ArtifactAnalyzer::SystemHook";
        ev.details = "System-wide persistent dynamic hook installed (/etc/ld.so.preload or AppInit_DLLs)";
        ev.timestamp = static_cast<uint64_t>(std::time(nullptr));
        ev.threat_score = 100;
        events.push_back(ev);
    }

    // Scan filesystem artifacts
    auto fsArtifacts = ScanFilesystemArtifacts(blacklisted_names);
    for (const auto& art : fsArtifacts) {
        core::DetectionEvent ev;
        ev.type = core::DetectionType::FORENSICS_ARTIFACT_DETECTED;
        ev.severity = core::Severity::HIGH;
        ev.component = "ArtifactAnalyzer::Filesystem";
        ev.details = "Cheat binary or payload artifact found on disk: " + art.path + " (matched: " + art.matched_signature + ")";
        ev.timestamp = static_cast<uint64_t>(std::time(nullptr));
        ev.threat_score = 70;
        events.push_back(ev);
    }

    // Scan kernel drivers
    auto driverArtifacts = ScanKernelDrivers(blacklisted_drivers);
    for (const auto& drv : driverArtifacts) {
        core::DetectionEvent ev;
        ev.type = core::DetectionType::FORENSICS_ARTIFACT_DETECTED;
        ev.severity = core::Severity::FATAL_BAN;
        ev.component = "ArtifactAnalyzer::DriverWatch";
        ev.details = "Dangerous/vulnerable kernel driver active: " + drv.path + " (matched: " + drv.matched_signature + ")";
        ev.timestamp = static_cast<uint64_t>(std::time(nullptr));
        ev.threat_score = 100;
        events.push_back(ev);
    }

    return events;
}

} // namespace noescape::forensics
