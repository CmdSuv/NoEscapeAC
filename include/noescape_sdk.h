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
} NoEscapeConfig;

// Returns the default recommended anti-cheat configuration
NOESCAPE_API NoEscapeConfig NoEscape_GetDefaultConfig(void);

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

    static void PushView(float x, float y, float z, float pitch, float yaw, uint64_t timestamp_ms) {
        NoEscape_PushView(x, y, z, pitch, yaw, timestamp_ms);
    }
};

} // namespace noescape::sdk
#endif

#endif // NOESCAPE_SDK_H
