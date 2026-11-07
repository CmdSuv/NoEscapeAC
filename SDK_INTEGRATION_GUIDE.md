# NoEscapeAC Developer SDK Integration Guide

**Project:** NoEscapeAC — Unified Ring-3 Anti-Cheat Architecture  
**Target Audience:** Game Engine Programmers & Systems Engineers  
**Supported Languages:** Modern C++20, C99/C11, C#, and Engine Scripting FFI  
**Compatible Engines:** Unreal Engine 4/5, Unity, Godot 4, Custom C++ Game Engines  

---

## 1. Architecture & Linking Overview

NoEscapeAC is designed as a modular, lightweight, zero-dependency Ring-3 dynamic or static library:
- **Header:** `include/noescape_sdk.h`
- **Linux Library:** `libnoescape.so` / `libnoescape.a`
- **Windows Library:** `noescape.dll` / `noescape.lib`

All public interfaces are exported with standard C linkage (`extern "C"`) to guarantee ABI stability across compiler revisions, along with high-level header-only C++ wrappers in namespace `noescape::sdk`.

---

## 2. Initialization Lifecycle & Profile Selection

### 2.1 Configuration Profiles
NoEscapeAC provides five formal operational profiles matching each stage of game production:

| Profile Enum | Purpose | Enforcement Mode | Multi-Signal Required | Anti-Debug |
| :--- | :--- | :--- | :--- | :--- |
| `NOESCAPE_PROFILE_DEVELOPMENT` | Local game development & debugging | `REPORT_ONLY` | False | Disabled |
| `NOESCAPE_PROFILE_TESTING` | CI/CD automation & deterministic integration tests | `ENFORCE` | False | Enabled |
| `NOESCAPE_PROFILE_SHADOW_PRODUCTION` | Production soft-launch; silent violation telemetry | `SHADOW` | True | Enabled |
| `NOESCAPE_PROFILE_PRODUCTION` | Live competitive multiplayer deployment | `SERVER_SESSION_REJECT` | True | Enabled |
| `NOESCAPE_PROFILE_OFFLINE_DIAGNOSTICS` | Single-player / offline diagnostic audit passes | `REPORT_ONLY` | False | Enabled |

### 2.2 Integration Code (C++ Example)

```cpp
#include "noescape_sdk.h"
#include <iostream>

void OnSecurityViolation(int violation_type, int score, const char* details) {
    std::cout << "[ANTI-CHEAT] Violation Type: " << violation_type 
              << " | Score: +" << score 
              << " | Details: " << (details ? details : "N/A") << std::endl;
}

int main() {
    // 1. Declare special environment features before initialization (if applicable)
    // E.g., if the game embeds LuaJIT, Mono, or V8:
    noescape::sdk::Client::SetHostUsesJit(true);

    // Pin the backend panel's TLS SubjectPublicKeyInfo hash (if HTTPS is used)
    noescape::sdk::Client::SetPanelPin("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    // 2. Obtain recommended production profile configuration
    NoEscapeConfig config = noescape::sdk::Client::GetProfileConfig(NOESCAPE_PROFILE_PRODUCTION);
    
    // Customise backend credentials for your game deployment
    config.panel_url = "https://anticheat.yourgame.com/api/v2";
    config.secret_key = "YourSecureProductionDeploymentSecret";
    config.server_public_key = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";

    // 3. Register violation callback
    noescape::sdk::Client::SetViolationCallback(OnSecurityViolation);

    // 4. Initialize the anti-cheat engine
    if (!noescape::sdk::Client::Init(&config)) {
        std::cerr << "Failed to initialize NoEscape Anti-Cheat!" << std::endl;
        return 1;
    }

    // 5. Start background continuous audit threads
    noescape::sdk::Client::Start();

    // 6. Set game viewport for overlay matching
    noescape::sdk::Client::SetViewport(0, 0, 1920, 1080);

    // Run game loop...
    while (GameIsRunning()) {
        // Feed mouse motion, weapon actions, and camera transforms (see Section 3)
        noescape::sdk::Client::Tick();
    }

    // 7. Clean shutdown on game exit
    noescape::sdk::Client::Shutdown();
    return 0;
}
```

---

## 3. High-Frequency Telemetry Ingestion

To enable behavioral aimbot, triggerbot, and recoil compensation detection, feed player input events into the SDK:

### 3.1 View Angle Deltas
Call whenever the local player updates their camera orientation:
```cpp
// Pitch and Yaw delta in degrees
noescape::sdk::Client::PushMouseEvent(delta_yaw, delta_pitch, current_timestamp_ms);
```

### 3.2 Raw HID Polling Telemetry
Call inside your raw input receiver (e.g. `WM_INPUT` on Windows or `evdev` on Linux) to catch synthetic macro automation:
```cpp
// interval_us: microseconds elapsed since last raw input event
// dx, dy: raw mouse counts
noescape::sdk::Client::PushRawInput(interval_us, dx, dy);
```

### 3.3 Triggerbot Engagement Timers
Call when the crosshair acquires a target, and when the trigger is pressed:
```cpp
// 1. Crosshair raycast intersects an enemy hitbox
noescape::sdk::Client::RecordTargetAcquire(current_timestamp_ms);

// 2. Player presses fire button
noescape::sdk::Client::PushWeaponFire(current_timestamp_ms);
```

### 3.4 Recoil Compensation Analysis
Call per weapon shot to compare physical weapon recoil kick against player counter-movement:
```cpp
// weapon_pitch, weapon_yaw: recoil kick angle applied by game physics
// player_pitch, player_yaw: player's counter-pull angle during compensation window
noescape::sdk::Client::PushRecoilEvent(recoil_kick_pitch, recoil_kick_yaw, player_counter_pitch, player_counter_yaw);
```

### 3.5 Resetting Kinematics on Teleport / Respawn
Always call when player respawns, teleports, or transitions between rounds to prevent false snap detections:
```cpp
noescape::sdk::Client::ResetInput();
```

---

## 4. Decoy Phantom Entity Integration

To catch memory-reading ESP wallhacks and aimbots that scan the game's replicated actor list:

1. Spawn dummy player entities in your game engine that are **never rendered**, **have no collision**, and **make no sound**.
2. Register their positions with the SDK:
```cpp
// Register decoy #101 placed behind a solid occluder
noescape::sdk::Client::AddPhantom(101, 1500.0f, 320.0f, 100.0f);

// Update position if decoy is mobile
noescape::sdk::Client::UpdatePhantom(101, 1520.0f, 320.0f, 100.0f);

// Feed local camera position and angles per frame
noescape::sdk::Client::PushView(cam_x, cam_y, cam_z, cam_pitch, cam_yaw, current_timestamp_ms);
```
If a player's crosshair locks onto or tracks the invisible decoy entity, `PHANTOM_ENTITY_TARGETED` is triggered immediately.

---

## 5. Host JIT Compatibility (Unreal Lua, Unity Mono, V8/CEF)

Game engines embedding runtime JIT compilers (e.g. LuaJIT, Mono runtime, Unreal Engine CEF web views) allocate dynamic executable memory segments (`RWX` or unbacked `RX` pages).
- **Declaration:** Call `noescape::sdk::Client::SetHostUsesJit(true)` *before* `Init()`.
- **Behavior:** The memory scanner suppresses false positive unbacked memory alerts for valid JIT heaps while continuing to enforce Authenticode signatures, system DLL unhooking, and thread call stack provenance.
