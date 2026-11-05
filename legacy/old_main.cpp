// ============================================================================
// NoEscape Anti-Cheat Engine - Standalone Open Source Edition (v7.0)
// GitHub: https://github.com/KULLANICI_ADIN/NoEscape-AntiCheat
// ============================================================================

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <wininet.h>
#include <wintrust.h>
#include <softpub.h>
#include <string>
#include <vector>
#include <deque>
#include <fstream>
#include <mutex>
#include <sstream>
#include <chrono>
#include <thread>
#include <atomic>
#include <cmath>
#include <optional>
#include <numeric>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

// ============================================================================
// RAII Handle Wrapper for Safe OS Handle Management
// ============================================================================
class ScopedHandle {
    HANDLE h = nullptr;
public:
    ScopedHandle() = default;
    explicit ScopedHandle(HANDLE handle) : h(handle) {}
    ~ScopedHandle() { reset(); }
    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;
    ScopedHandle(ScopedHandle&& o) noexcept : h(o.h) { o.h = nullptr; }
    ScopedHandle& operator=(ScopedHandle&& o) noexcept {
        if (this != &o) { reset(); h = o.h; o.h = nullptr; }
        return *this;
    }
    void reset(HANDLE n = nullptr) {
        if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
        h = n;
    }
    HANDLE get() const { return h; }
    bool valid() const { return h != nullptr && h != INVALID_HANDLE_VALUE; }
    explicit operator bool() const { return valid(); }
};

static std::string ToLower(const std::string& s) {
    std::string out = s;
    for (auto& c : out) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    return out;
}

static std::string UrlEncode(const std::string& str) {
    std::string strTemp = "";
    size_t length = str.length();
    for (size_t i = 0; i < length; i++) {
        INT ihn = (INT)str[i];
        if (isalnum((unsigned char)str[i]) || str[i] == '-' || str[i] == '_' || str[i] == '.' || str[i] == '~')
            strTemp += str[i];
        else if (str[i] == ' ')
            strTemp += "+";
        else {
            char hex[4]{};
            sprintf_s(hex, sizeof(hex), "%%%02X", ihn);
            strTemp += hex;
        }
    }
    return strTemp;
}

// ============================================================================
// HWID & Network Fingerprint Utilities
// ============================================================================
class HwidUtil {
public:
    static std::string GetMachineHWID() {
        HKEY hKey = nullptr;
        char szHwid[256] = { 0 };
        DWORD dwSize = sizeof(szHwid);
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
            RegQueryValueExA(hKey, "MachineGuid", nullptr, nullptr, (LPBYTE)szHwid, &dwSize);
            RegCloseKey(hKey);
        }
        return strlen(szHwid) == 0 ? "UNKNOWN-HWID-DEVICE" : std::string(szHwid);
    }
};

class NetworkUtil {
public:
    static std::string GetPublicIP() {
        HINTERNET hInternet = InternetOpenA("NoEscapeAntiCheat", INTERNET_OPEN_TYPE_DIRECT, nullptr, nullptr, 0);
        if (!hInternet) return "UNKNOWN_IP";

        HINTERNET hConnect = InternetOpenUrlA(hInternet, "https://api.ipify.org", nullptr, 0, INTERNET_FLAG_RELOAD, 0);
        std::string ip = "UNKNOWN_IP";
        
        if (hConnect) {
            char buffer[128]{};
            DWORD bytesRead = 0;
            if (InternetReadFile(hConnect, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) {
                buffer[bytesRead] = '\0';
                ip = buffer;
            }
            InternetCloseHandle(hConnect);
        }
        InternetCloseHandle(hInternet);
        return ip;
    }
};

// ============================================================================
// Panel REST API Client (HWID & IP Banning System)
// ============================================================================
class PanelClient {
    std::string baseUrl;
public:
    explicit PanelClient(std::string url) : baseUrl(std::move(url)) {}

    bool SendBanRequest(const std::string& hwid, const std::string& ip, const std::string& reason) const {
        HINTERNET hInternet = InternetOpenA("NoEscapeAntiCheat", INTERNET_OPEN_TYPE_DIRECT, nullptr, nullptr, 0);
        if (!hInternet) return false;

        std::string encodedReason = UrlEncode(reason);
        std::string fullUrl = baseUrl + "/api/ban-hwid.php?hwid=" + hwid + "&ip=" + ip + "&reason=" + encodedReason;

        HINTERNET hConnect = InternetOpenUrlA(hInternet, fullUrl.c_str(), nullptr, 0, INTERNET_FLAG_RELOAD, 0);
        if (hConnect) {
            InternetCloseHandle(hConnect);
        }
        InternetCloseHandle(hInternet);
        return true;
    }

    bool CheckIfBanned(const std::string& hwid, const std::string& ip, std::string& outDetails) const {
        HINTERNET hInternet = InternetOpenA("NoEscapeAntiCheat", INTERNET_OPEN_TYPE_DIRECT, nullptr, nullptr, 0);
        if (!hInternet) return false;

        std::string fullUrl = baseUrl + "/api/check-hwid.php?hwid=" + hwid + "&ip=" + ip;
        HINTERNET hConnect = InternetOpenUrlA(hInternet, fullUrl.c_str(), nullptr, 0, INTERNET_FLAG_RELOAD, 0);

        bool isBanned = false;
        if (hConnect) {
            char buffer[1024]{};
            DWORD bytesRead = 0;
            if (InternetReadFile(hConnect, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) {
                buffer[bytesRead] = '\0';
                std::string response(buffer);
                if (response.find("banned:1") != std::string::npos) {
                    isBanned = true;
                    outDetails = response;
                }
            }
            InternetCloseHandle(hConnect);
        }
        InternetCloseHandle(hInternet);
        return isBanned;
    }
};

// ============================================================================
// Anti-Cheat Configuration Signatures & Thresholds
// ============================================================================
struct Config {
    std::vector<std::string> processSignatures;
    std::vector<std::string> moduleSignatures;
    std::vector<std::string> driverSignatures;

    std::string panelApiUrl = "http://localhost/noescape_panel";

    static Config Default() {
        Config cfg;
        cfg.processSignatures = {
            "vape", "wurst", "meteor", "raven", "astolfo", "liquidbounce", "impact", "aristois",
            "cheatengine", "x64dbg", "ollydbg", "wireshark", "processhacker", "killaura", "aimbot"
        };
        cfg.moduleSignatures = {
            "vape", "wurst", "meteor", "impact", "aristois", "liquidbounce", "killaura", "aimbot", "xray"
        };
        cfg.driverSignatures = { "dbk64.sys", "ksdumper.sys", "winring0x64.sys" };
        return cfg;
    }
};

// ============================================================================
// Privilege Escalation & Scanners (Process, Module, Driver)
// ============================================================================
static bool EnableDebugPrivilege() {
    HANDLE tokenRaw = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tokenRaw)) return false;
    ScopedHandle token(tokenRaw);
    LUID luid{};
    if (!LookupPrivilegeValueA(nullptr, "SeDebugPrivilege", &luid)) return false;
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(token.get(), FALSE, &tp, sizeof(tp), nullptr, nullptr)) return false;
    return true;
}

class ProcessUtil {
public:
    static std::string GetProcessPath(DWORD pid) {
        char path[MAX_PATH]{};
        ScopedHandle hProc(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
        if (hProc) {
            DWORD size = MAX_PATH;
            if (QueryFullProcessImageNameA(hProc.get(), 0, path, &size)) {
                return std::string(path);
            }
        }
        return "";
    }

    static bool IsFileDigitallySigned(const std::string& filePath) {
        if (filePath.empty()) return false;
        int len = MultiByteToWideChar(CP_UTF8, 0, filePath.c_str(), -1, NULL, 0);
        std::wstring wPath(len, 0);
        MultiByteToWideChar(CP_UTF8, 0, filePath.c_str(), -1, &wPath[0], len);

        WINTRUST_FILE_INFO fileInfo{};
        fileInfo.cbStruct = sizeof(fileInfo);
        fileInfo.pcwszFilePath = wPath.c_str();

        WINTRUST_DATA trustData{};
        trustData.cbStruct = sizeof(trustData);
        trustData.dwUIChoice = WTD_UI_NONE;
        trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        trustData.dwUnionChoice = WTD_CHOICE_FILE;
        trustData.dwStateAction = WTD_STATEACTION_VERIFY;
        trustData.pFile = &fileInfo;

        GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        LONG lStatus = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &policyGUID, &trustData);

        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &policyGUID, &trustData);

        return (lStatus == ERROR_SUCCESS);
    }

    static bool FindSuspiciousProcess(const std::vector<std::string>& sigs, std::string& outMatch, DWORD& outPid) {
        ScopedHandle snap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (!snap) return false;
        PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap.get(), &pe)) {
            do {
                char narrow[MAX_PATH]{};
                if (WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, narrow, MAX_PATH, nullptr, nullptr) <= 0) continue;
                std::string name = ToLower(narrow);

                bool matchesSig = false;
                for (const auto& sig : sigs) {
                    if (!sig.empty() && name.find(ToLower(sig)) != std::string::npos) {
                        matchesSig = true;
                        break;
                    }
                }

                if (matchesSig) {
                    std::string processPath = GetProcessPath(pe.th32ProcessID);
                    std::string lowerPath = ToLower(processPath);

                    if (processPath.empty()) continue;
                    if (lowerPath.find("\\windows\\") != std::string::npos || 
                        lowerPath.find("discord") != std::string::npos || 
                        lowerPath.find("steam") != std::string::npos) {
                        continue;
                    }

                    if (IsFileDigitallySigned(processPath)) continue;

                    outMatch = narrow;
                    outPid = pe.th32ProcessID;
                    return true;
                }
            } while (Process32NextW(snap.get(), &pe));
        }
        return false;
    }
};

// ============================================================================
// Core Standalone Anti-Cheat Engine Controller
// ============================================================================
class AntiCheatEngine {
    Config cfg;
    PanelClient panel;
    std::string hwid;
    std::string publicIp;
public:
    explicit AntiCheatEngine(Config c) : cfg(c), panel(c.panelApiUrl), 
                                         hwid(HwidUtil::GetMachineHWID()), publicIp(NetworkUtil::GetPublicIP()) {}

    [[noreturn]] void BanAndTerminate(const std::string& reason) const {
        panel.SendBanRequest(hwid, publicIp, reason);

        MessageBoxA(nullptr, ("NoEscape Security Violation\n\nReason: " + reason + "\nDevice and IP have been banned.").c_str(), "NoEscape Anti-Cheat - Standalone", MB_OK | MB_ICONERROR | MB_TOPMOST);
        ExitProcess(1);
    }

    void RunLoop() {
        auto lastApiCheck = std::chrono::steady_clock::now() - std::chrono::seconds(10);

        while (true) {
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - lastApiCheck).count() >= 10) {
                std::string banDetails;
                if (panel.CheckIfBanned(hwid, publicIp, banDetails)) {
                    BanAndTerminate("Global Ban List Match (HWID/IP)");
                }
                lastApiCheck = now;
            }

            std::string detail; DWORD pid = 0;
            if (ProcessUtil::FindSuspiciousProcess(cfg.processSignatures, detail, pid)) {
                BanAndTerminate("Blacklisted Process Signature: " + detail);
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    }
};

int main() {
    if (HWND hwnd = GetConsoleWindow()) ShowWindow(hwnd, SW_HIDE);
    EnableDebugPrivilege();

    Config cfg = Config::Default();
    AntiCheatEngine engine(cfg);
    engine.RunLoop();

    return 0;
}
