cmake_minimum_required(VERSION 3.20)
project(NoEscapeAC VERSION 7.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Optimization & Compiler Flags
if(MSVC)
    add_compile_options(/W4 /arch:AVX2 /permissive- /utf-8 /EHsc /WX)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
else()
    add_compile_options(-O3 -Wall -Wextra -Werror -Wno-unused-parameter -mavx2 -msse2 -pthread)
endif()

# Strict Production Build Flag (strips environment overrides)
option(NOESCAPE_SECURE_BUILD "Enable strict production build disabling development environment overrides" ON)
if(NOESCAPE_SECURE_BUILD)
    add_compile_definitions(NOESCAPE_SECURE_BUILD)
endif()

# Core Include Directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Core Library Sources
set(CORE_SOURCES
    src/core/logger.cpp
    src/core/thread_pool.cpp
    src/core/engine.cpp
    src/core/blackbox.cpp
    src/network/crypto_util.cpp
    src/network/panel_client.cpp
    src/security/anti_debug_linux.cpp
    src/security/anti_debug_windows.cpp
    src/security/integrity.cpp
    src/security/timing.cpp
    src/memory/pattern_scanner.cpp
    src/memory/memory_scanner.cpp
    src/memory/signature_database.cpp
    src/memory/unhooker.cpp
    src/memory/canary_monitor.cpp
    src/forensics/process_analyzer.cpp
    src/forensics/artifact_analyzer.cpp
    src/dma/dma_detector.cpp
    src/kinematics/aim_analyzer.cpp
    src/kinematics/phantom_monitor.cpp
    src/overlay/overlay_detector.cpp
    src/sdk/noescape_sdk.cpp
    src/sdk/auto_init.cpp
)

# Static Library Target (libnoescape.a / noescape_static.lib)
add_library(noescape_core STATIC ${CORE_SOURCES})
if(WIN32)
    set_target_properties(noescape_core PROPERTIES OUTPUT_NAME "noescape_static")
    target_link_libraries(noescape_core PUBLIC ws2_32 psapi advapi32 wintrust crypt32)
else()
    set_target_properties(noescape_core PROPERTIES OUTPUT_NAME "noescape")
    target_link_libraries(noescape_core PUBLIC pthread dl)
endif()

# Shared Library Target (libnoescape.so / noescape.dll)
add_library(noescape_shared SHARED ${CORE_SOURCES})
set_target_properties(noescape_shared PROPERTIES OUTPUT_NAME "noescape")
target_compile_definitions(noescape_shared PRIVATE NOESCAPE_EXPORTS NOESCAPE_BUILD_SHARED)
if(WIN32)
    target_link_libraries(noescape_shared PUBLIC ws2_32 psapi advapi32 wintrust crypt32)
else()
    target_link_libraries(noescape_shared PUBLIC pthread dl)
endif()

# Standalone Client Application
add_executable(noescape_app main.cpp)
target_link_libraries(noescape_app PRIVATE noescape_core)

# Interactive Subsystem Demo
add_executable(noescape_demo demo/demo_main.cpp)
target_link_libraries(noescape_demo PRIVATE noescape_core)

# Standalone Dummy Game Executable (Zero AC code, used for Scenario B / LD_PRELOAD verification)
add_executable(dummy_game tools/dummy_game.cpp)
if(NOT MSVC)
    target_link_libraries(dummy_game PRIVATE pthread)
endif()

# Vanguard Ban UI Helper executable
add_custom_target(noescape_ban_ui ALL
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/tools/noescape_ban_ui.py ${CMAKE_CURRENT_BINARY_DIR}/noescape_ban_ui
    COMMAND chmod +x ${CMAKE_CURRENT_BINARY_DIR}/noescape_ban_ui
    COMMENT "Installing Vanguard Ban UI executable into build tree"
)

# Comprehensive Unit Test Suite
set(TEST_SOURCES
    tests/test_main.cpp
    tests/test_crypto.cpp
    tests/test_obfuscation.cpp
    tests/test_simd_scanner.cpp
    tests/test_kinematics.cpp
    tests/test_memory.cpp
    tests/test_forensics.cpp
    tests/test_dma.cpp
    tests/test_timing.cpp
    tests/test_thread_pool.cpp
    tests/test_engine.cpp
    tests/test_overlay.cpp
    tests/test_sdk.cpp
    tests/test_blackbox.cpp
    tests/test_audit_remediation.cpp
    tests/test_signatures.cpp
)

add_executable(noescape_tests ${TEST_SOURCES})
target_link_libraries(noescape_tests PRIVATE noescape_core)
target_compile_definitions(noescape_tests PRIVATE NOESCAPE_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")

enable_testing()
add_test(NAME UnifiedNoEscapeTests COMMAND noescape_tests)
