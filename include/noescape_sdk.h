#ifndef NOESCAPE_SDK_H
#define NOESCAPE_SDK_H

#include <stdint.h>
#include <stdbool.h>

#if defined(NOESCAPE_STATIC)
    #define NOESCAPE_API
#elif defined(_WIN32)
    #if defined(NOESCAPE_EXPORTS)
        #define NOESCAPE_API __declspec(dllexport)
    #else
        #define NOESCAPE_API __declspec(dllimport)
    #endif
#else
    #define NOESCAPE_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Profile presets for multi-tier deployment
typedef enum NoEscapeProfile {
    NOESCAPE_PROFILE_DEVELOPMENT = 0,
    NOESCAPE_PROFILE_TESTING = 1,
    NOESCAPE_PROFILE_SHADOW_PRODUCTION = 2,
    NOESCAPE_PROFILE_PRODUCTION = 3,
    NOESCAPE_PROFILE_OFFLINE_DIAGNOSTICS = 4
} NoEscapeProfile;

typedef enum NoEscapeEnforcementMode {
    NOESCAPE_ENFORCEMENT_REPORT_ONLY = 0,
    NOESCAPE_ENFORCEMENT_SHADOW = 1,
    NOESCAPE_ENFORCEMENT_MATCH_RESTRICTION = 2,
    NOESCAPE_ENFORCEMENT_SERVER_SESSION_REJECT = 3,
    NOESCAPE_ENFORCEMENT_ENFORCE = 4
} NoEscapeEnforcementMode;

// Callback signature for violation notifications
typedef void (*NoEscapeViolationCallback)(int violation_type, int score, const char* details);

// C-compatible configuration structure
typedef struct NoEscapeConfig {
    const char* panel_url;
    const char* secret_key;
    const char* blackbox_dump_dir;
    uint32_t ban_threshold;
    bool enforce_ban;
    bool enable_anti_debug;
    bool enable_integrity_scan;
    bool enable_speedhack_detection;
    bool enable_memory_scan;
    bool enable_unhooker;
    bool enable_forensics;
    bool enable_dma_detection;
    bool enable_kinematics;
    bool enable_overlay_detection;
    bool enable_blackbox_dump;
    bool enable_heartbeat;
    bool terminate_on_ban;
    bool show_ban_ui;
    const char* ban_ui_path;

    // Extended v2.0 fields
    uint32_t struct_size;
    uint32_t config_version;
    const char* server_public_key;
    const char* key_id;
    const char* client_build_version;
    int enforcement_mode;
    bool require_multi_signal_corroboration;
    uint64_t memory_scan_budget_ms;
} NoEscapeConfig;

// Returns the default recommended anti-cheat configuration
NOESCAPE_API NoEscapeConfig NoEscape_GetDefaultConfig(void);

// Returns the configuration corresponding to a specific architectural profile
NOESCAPE_API NoEscapeConfig NoEscape_GetProfileConfig(NoEscapeProfile profile);

// Initializes the anti-cheat engine. Pass NULL to use defaults. Returns 0 on success.
NOESCAPE_API int NoEscape_Init(const NoEscapeConfig* config);

// Stops all background threads and frees resources
NOESCAPE_API void NoEscape_Shutdown(void);

// Starts background continuous audit monitoring workers
NOESCAPE_API void NoEscape_Start(void);

// Stops background continuous audit monitoring workers
NOESCAPE_API void NoEscape_Stop(void);

// Runs a single synchronous audit tick (e.g. called inside game loop)
NOESCAPE_API void NoEscape_Tick(void);

// Feeds mouse/view angle motion delta into the kinematics aimbot detector
NOESCAPE_API void NoEscape_PushMouseEvent(float delta_yaw, float delta_pitch, uint64_t timestamp_ms);

// Feeds raw mouse input timing & deltas for HID macro and quantization analysis
NOESCAPE_API void NoEscape_PushRawInput(uint64_t interval_us, int32_t dx, int32_t dy);

// Feeds crosshair target acquisition timestamp for triggerbot reaction timing
NOESCAPE_API void NoEscape_RecordTargetAcquire(uint64_t timestamp_ms);

// Feeds weapon fire timestamp for triggerbot evaluation
NOESCAPE_API void NoEscape_PushWeaponFire(uint64_t timestamp_ms);

// Feeds recoil compensation observation (weapon kick vs player counter-movement)
NOESCAPE_API void NoEscape_PushRecoilEvent(float weapon_pitch, float weapon_yaw, float player_pitch, float player_yaw);

// Resets accumulated mouse delta orientation and kinematics history (e.g. teleport/respawn)
NOESCAPE_API void NoEscape_ResetInput(void);

// Returns current cumulative threat score
NOESCAPE_API uint32_t NoEscape_GetThreatScore(void);

// Returns true if the session/client has been banned
NOESCAPE_API bool NoEscape_IsBanned(void);

// Registers a callback for security violations and ban enforcement
NOESCAPE_API void NoEscape_SetViolationCallback(NoEscapeViolationCallback callback);

// Sets the game viewport rectangle for overlay matching
NOESCAPE_API void NoEscape_SetViewport(int x, int y, int width, int height);

// Pins the panel's TLS public key (hex SHA-256 of the certificate's SubjectPublicKeyInfo).
// Call before NoEscape_Init(). Obtain it with:
//   openssl x509 -in panel.crt -pubkey -noout | openssl pkey -pubin -outform der | sha256sum
NOESCAPE_API void NoEscape_SetPanelPin(const char* spki_sha256_hex);

// Declares that the host embeds a JIT (LuaJIT, V8/CEF, Mono...). Call before NoEscape_Init().
NOESCAPE_API void NoEscape_SetHostUsesJit(bool uses_jit);

// Registers an invisible decoy entity (never render or network it). Sustained precise aim at
// it is reported as PHANTOM_ENTITY_TARGETED.
NOESCAPE_API void NoEscape_AddPhantom(uint32_t id, float x, float y, float z);
NOESCAPE_API void NoEscape_UpdatePhantom(uint32_t id, float x, float y, float z);

// Feeds camera position and view angles (degrees) for phantom analysis
NOESCAPE_API void NoEscape_PushView(float x, float y, float z, float pitch, float yaw, uint64_t timestamp_ms);

#ifdef __cplusplus
} // extern "C"

#include <string>

namespace noescape::sdk {

class Client {
public:
    static bool Init(const NoEscapeConfig* config = nullptr) {
        return NoEscape_Init(config) == 0;
    }

    static void Shutdown() {
        NoEscape_Shutdown();
    }

    static void Start() {
        NoEscape_Start();
    }

    static void Stop() {
        NoEscape_Stop();
    }

    static void Tick() {
        NoEscape_Tick();
    }

    static void PushMouseEvent(float delta_yaw, float delta_pitch, uint64_t timestamp_ms) {
        NoEscape_PushMouseEvent(delta_yaw, delta_pitch, timestamp_ms);
    }

    static void ResetInput() {
        NoEscape_ResetInput();
    }

    static uint32_t GetThreatScore() {
        return NoEscape_GetThreatScore();
    }

    static bool IsBanned() {
        return NoEscape_IsBanned();
    }

    static void SetViolationCallback(NoEscapeViolationCallback cb) {
        NoEscape_SetViolationCallback(cb);
    }

    static void SetViewport(int x, int y, int width, int height) {
        NoEscape_SetViewport(x, y, width, height);
    }

    static void SetPanelPin(const char* spki_sha256_hex) {
        NoEscape_SetPanelPin(spki_sha256_hex);
    }

    static void SetHostUsesJit(bool uses_jit) {
        NoEscape_SetHostUsesJit(uses_jit);
    }

    static void AddPhantom(uint32_t id, float x, float y, float z) {
        NoEscape_AddPhantom(id, x, y, z);
    }

    static void UpdatePhantom(uint32_t id, float x, float y, float z) {
        NoEscape_UpdatePhantom(id, x, y, z);
    }

    static NoEscapeConfig GetProfileConfig(NoEscapeProfile profile) {
        return NoEscape_GetProfileConfig(profile);
    }

    static void PushRawInput(uint64_t interval_us, int32_t dx, int32_t dy) {
        NoEscape_PushRawInput(interval_us, dx, dy);
    }

    static void RecordTargetAcquire(uint64_t timestamp_ms) {
        NoEscape_RecordTargetAcquire(timestamp_ms);
    }

    static void PushWeaponFire(uint64_t timestamp_ms) {
        NoEscape_PushWeaponFire(timestamp_ms);
    }

    static void PushRecoilEvent(float weapon_pitch, float weapon_yaw, float player_pitch, float player_yaw) {
        NoEscape_PushRecoilEvent(weapon_pitch, weapon_yaw, player_pitch, player_yaw);
    }

    static void PushView(float x, float y, float z, float pitch, float yaw, uint64_t timestamp_ms) {
        NoEscape_PushView(x, y, z, pitch, yaw, timestamp_ms);
    }
};

} // namespace noescape::sdk
#endif

#endif // NOESCAPE_SDK_H
