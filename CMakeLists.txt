cmake_minimum_required(VERSION 3.20)
project(NoEscapeAC VERSION 7.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(NOESCAPE_WERROR "Treat warnings as errors (CI only; breaks on newer toolchains)" OFF)
# Optimization & Compiler Flags
if(WIN32)
    add_compile_definitions(_WIN32_WINNT=0x0A00 WINVER=0x0A00)
endif()

if(MSVC)
    # AVX2 is selected at runtime inside the pattern scanner via __cpuidex + _xgetbv;
    # never compile the whole library with /arch:AVX2 or it faults on CPUs without AVX2.
    add_compile_options(/W4 /permissive- /utf-8 /EHsc)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
else()
    # AVX2 is selected at runtime inside the pattern scanner (target attribute + cpu check);
    # never compile the whole library with -mavx2 or it faults on CPUs without AVX2.
    add_compile_options(-O3 -Wall -Wextra -Wno-unused-parameter -pthread)
endif()

if(NOESCAPE_WERROR)
    if(MSVC)
        add_compile_options(/WX)
    else()
        add_compile_options(-Werror)
    endif()
endif()

# Strict Production Build Flag (strips environment overrides)
option(NOESCAPE_SECURE_BUILD "Enable strict production build disabling development environment overrides" ON)
if(NOESCAPE_SECURE_BUILD)
    add_compile_definitions(NOESCAPE_SECURE_BUILD)
endif()

# TLS for the panel client: OpenSSL on POSIX (optional), WinHTTP on Windows (always available).
option(NOESCAPE_WITH_TLS "Enable https:// panel transport (OpenSSL on POSIX)" ON)
set(NOESCAPE_TLS_LIBS "")
if(NOESCAPE_WITH_TLS AND NOT WIN32)
    find_package(OpenSSL)
    if(OPENSSL_FOUND)
        set(NOESCAPE_TLS_LIBS OpenSSL::SSL OpenSSL::Crypto)
        add_compile_definitions(NOESCAPE_HAS_OPENSSL)
        message(STATUS "NoEscape: TLS panel transport enabled (OpenSSL ${OPENSSL_VERSION})")
    else()
        message(WARNING "NoEscape: OpenSSL not found - https:// panel URLs will be refused")
    endif()
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
    src/core/evidence_correlator.cpp
    src/core/engine.cpp
    src/core/blackbox.cpp
    src/network/crypto_util.cpp
    src/network/ed25519.cpp
    src/network/chacha20poly1305.cpp
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
    src/server/server_integration.cpp
    src/sdk/noescape_sdk.cpp
    src/sdk/auto_init.cpp
)

# Static Library Target (libnoescape.a / noescape_static.lib)
add_library(noescape_core STATIC ${CORE_SOURCES})
# Consumers of the static library must not see __declspec(dllimport) on the C API
target_compile_definitions(noescape_core PUBLIC NOESCAPE_STATIC)
if(WIN32)
    set_target_properties(noescape_core PROPERTIES OUTPUT_NAME "noescape_static")
    target_link_libraries(noescape_core PUBLIC ws2_32 psapi advapi32 wintrust crypt32 winhttp bcrypt ncrypt)
else()
    set_target_properties(noescape_core PROPERTIES OUTPUT_NAME "noescape")
    target_link_libraries(noescape_core PUBLIC pthread dl ${NOESCAPE_TLS_LIBS})
endif()

# Shared Library Target (libnoescape.so / noescape.dll)
add_library(noescape_shared SHARED ${CORE_SOURCES})
set_target_properties(noescape_shared PROPERTIES OUTPUT_NAME "noescape")
target_compile_definitions(noescape_shared PRIVATE NOESCAPE_EXPORTS NOESCAPE_BUILD_SHARED)
if(WIN32)
    target_link_libraries(noescape_shared PUBLIC ws2_32 psapi advapi32 wintrust crypt32 winhttp bcrypt ncrypt)
else()
    target_link_libraries(noescape_shared PUBLIC pthread dl ${NOESCAPE_TLS_LIBS})
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
    COMMENT "Installing ban UI helper into build tree"
)
if(NOT WIN32)
    add_custom_command(TARGET noescape_ban_ui POST_BUILD
        COMMAND chmod +x ${CMAKE_CURRENT_BINARY_DIR}/noescape_ban_ui)
endif()

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
    tests/test_regressions.cpp
    tests/test_server_and_correlation.cpp
    tests/test_audit_v2_reengineering.cpp
    tests/test_remediation_v1_4.cpp
)

add_executable(noescape_tests ${TEST_SOURCES})
target_link_libraries(noescape_tests PRIVATE noescape_core)
target_compile_definitions(noescape_tests PRIVATE NOESCAPE_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")

enable_testing()
add_test(NAME UnifiedNoEscapeTests COMMAND noescape_tests)
