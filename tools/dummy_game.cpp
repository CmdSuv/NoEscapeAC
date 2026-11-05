#include <iostream>
#include <chrono>
#include <thread>
#include <vector>
#include <cmath>
#include <cstdlib>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <unistd.h>
#endif

// ============================================================================
// Dummy Game Binary (Unmodified Host Process)
// Scenario B: ZERO Anti-Cheat Code, ZERO Anti-Cheat Includes, ZERO Modifications.
// The anti-cheat is loaded entirely dynamically via LD_PRELOAD (Linux) or DLL injection (Windows).
// ============================================================================

struct DummyEntity {
    float x{0.0f};
    float y{0.0f};
    float z{0.0f};
    float vx{1.0f};
    float vy{0.5f};
    float vz{0.0f};
    int health{100};
};

int main(int argc, char* argv[]) {
    int duration_sec = 2;
    if (argc > 1) {
        int parsed = std::atoi(argv[1]);
        if (parsed > 0) duration_sec = parsed;
    }

    std::cout << "[DummyGame] Game binary started successfully (PID: " << 
#if defined(_WIN32)
        GetCurrentProcessId()
#else
        getpid()
#endif
        << ")" << std::endl;
    std::cout << "[DummyGame] Initializing 3D game world and dummy entities..." << std::endl;

    std::vector<DummyEntity> entities(100);
    for (size_t i = 0; i < entities.size(); ++i) {
        entities[i].x = static_cast<float>(i * 5);
        entities[i].y = static_cast<float>(i * 3);
        entities[i].z = 0.0f;
    }

    std::cout << "[DummyGame] Game loop started. Running for " << duration_sec << " seconds..." << std::endl;

    auto startTime = std::chrono::steady_clock::now();
    auto runDuration = std::chrono::seconds(duration_sec);
    uint64_t totalFrames = 0;

    while (std::chrono::steady_clock::now() - startTime < runDuration) {
        totalFrames++;

        // Simulate game loop entity updates
        for (auto& entity : entities) {
            entity.x += entity.vx * 0.016f;
            entity.y += entity.vy * 0.016f;
            entity.z = std::sin(entity.x * 0.1f);
        }

        // Simulate 60 FPS tick rate (~16 ms per frame)
        std::this_thread::sleep_for(std::chrono::milliseconds(16));
    }

    std::cout << "[DummyGame] Game loop finished cleanly (" << totalFrames << " frames rendered)." << std::endl;
    std::cout << "[DummyGame] Host process shutting down cleanly with exit code 0." << std::endl;
    return 0;
}
