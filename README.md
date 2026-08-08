# 🛡️ NoEscape Anti-Cheat

**NoEscape** is a lightweight, high-performance security and anti-cheat framework written in C++. Designed for modern applications and game environments, it features real-time process signature scanning, hardware fingerprinting, and automated global ban enforcement.

---

### ✨ Key Features

* **Dual-Layer Identification:** Combines Windows MachineGuid (`HWID`) and real-time Public IP tracking (`ipify API`) to prevent hardware spoofing bypasses.
* **Smart Digital Whitelisting:** Integrates native Windows trust verification (`WinVerifyTrust`) to automatically whitelist signed system processes and trusted applications (e.g., Discord, Steam), minimizing false positives.
* **Process Signature Scanner:** Actively scans running system processes against a predefined blacklisted signature array (debugters, memory editors, and known injection tools).
* **REST API Panel Integration:** Communicates seamlessly with a backend panel to check global ban statuses and issue automated HWID/IP bans upon security violations.
* **Privilege Escalation:** Automatically attempts to acquire `SeDebugPrivilege` for comprehensive process monitoring capabilities.

---

### ⚙️ Architecture & Modules

* `ScopedHandle`: RAII wrapper ensuring safe, leak-free Win32 handle management.
* `HwidUtil & NetworkUtil`: Hardware and network fingerprint generators.
* `PanelClient`: HTTP communication interface using WinINet for secure API requests.
* `ProcessUtil`: Toolhelp32 snapshot engine combined with digital signature validation.

---

### 🚀 Getting Started

#### Prerequisites
* Windows 10 / 11 (x64)
* Visual Studio (MSVC compiler with C++17 support)

#### Compilation & Build
1. Clone or download the repository.
2. Open the project in Visual Studio.
3. Configure your backend API endpoint in the `Config` struct (`panelApiUrl`).
4. Build the solution as **Release / x64**.

---

### ⚠️ Disclaimer
*This project is open-source and provided for educational and developmental purposes. Use it responsibly to secure your own applications.*
