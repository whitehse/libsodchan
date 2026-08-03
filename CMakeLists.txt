cmake_minimum_required(VERSION 3.20)
project(libsodchan LANGUAGES C VERSION 0.7.0)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(MSVC)
    add_compile_options(/W4 /WX)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()

# Optional: allow lab_mode cleartext (tests only; default OFF — K11).
option(SODCHAN_ALLOW_LAB_CLEARTEXT
    "Allow sodchan_config_t.lab_mode (never for field builds)" OFF)

# Optional prefix for libsodium (headers + lib). Empty → auto-detect.
set(SODIUM_ROOT "" CACHE PATH "libsodium install prefix (include/ + lib/)")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(Sodium REQUIRED)
message(STATUS "libsodium: ${Sodium_LIBRARY}")
message(STATUS "libsodium include: ${Sodium_INCLUDE_DIR}")

add_library(sodchan STATIC
    src/sodchan.c
    src/sodchan_crypto.c
    src/sodchan_wire.c
)

target_include_directories(sodchan PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_include_directories(sodchan PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(sodchan PUBLIC Sodium::Sodium)

if(SODCHAN_ALLOW_LAB_CLEARTEXT)
    target_compile_definitions(sodchan PUBLIC SODCHAN_ALLOW_LAB_CLEARTEXT=1)
endif()

include(GNUInstallDirs)
install(TARGETS sodchan EXPORT sodchan-targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT sodchan-targets FILE sodchan-config.cmake
    NAMESPACE sodchan:: DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/sodchan)
install(FILES cmake/FindSodium.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/sodchan)

enable_testing()

add_executable(sodchan_smoke_test tests/test_sodchan_smoke.c)
target_link_libraries(sodchan_smoke_test PRIVATE sodchan)
add_test(NAME sodchan_smoke COMMAND sodchan_smoke_test)

add_executable(sodchan_crypto_test tests/test_sodchan_crypto.c)
target_link_libraries(sodchan_crypto_test PRIVATE sodchan)
add_test(NAME sodchan_crypto COMMAND sodchan_crypto_test)

add_executable(sodchan_wire_test tests/test_sodchan_wire.c)
target_link_libraries(sodchan_wire_test PRIVATE sodchan)
target_include_directories(sodchan_wire_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
# Run from build dir; pass absolute path to golden vectors.
add_test(NAME sodchan_wire COMMAND sodchan_wire_test
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors/handshake_v1.hex")

add_executable(sodchan_dialectic_test tests/test_sodchan_dialectic.c)
target_link_libraries(sodchan_dialectic_test PRIVATE sodchan)
add_test(NAME sodchan_dialectic COMMAND sodchan_dialectic_test)

add_executable(sodchan_mitm_pin_test tests/test_sodchan_mitm_pin.c)
target_link_libraries(sodchan_mitm_pin_test PRIVATE sodchan)
target_include_directories(sodchan_mitm_pin_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
add_test(NAME sodchan_mitm_pin COMMAND sodchan_mitm_pin_test)

add_executable(sodchan_auth_test tests/test_sodchan_auth.c)
target_link_libraries(sodchan_auth_test PRIVATE sodchan)
add_test(NAME sodchan_auth COMMAND sodchan_auth_test)

add_executable(sodchan_channels_test tests/test_sodchan_channels.c)
target_link_libraries(sodchan_channels_test PRIVATE sodchan)
add_test(NAME sodchan_channels COMMAND sodchan_channels_test)

add_executable(sodchan_client_example examples/sodchan_client_example.c)
target_link_libraries(sodchan_client_example PRIVATE sodchan)

add_executable(sodchan_server_example examples/sodchan_server_example.c)
target_link_libraries(sodchan_server_example PRIVATE sodchan)

# Fuzz harness (libFuzzer) — PR-7. Prefer clang:
#   cmake -B build-fuzz -DENABLE_FUZZ=ON -DCMAKE_C_COMPILER=clang-19 ...
option(ENABLE_FUZZ "Build libFuzzer harness fuzz_sodchan" OFF)
if(ENABLE_FUZZ)
    add_executable(fuzz_sodchan fuzz/fuzz_sodchan.c)
    target_link_libraries(fuzz_sodchan PRIVATE sodchan)
    target_compile_options(fuzz_sodchan PRIVATE -fsanitize=fuzzer,address -g -O1)
    target_link_options(fuzz_sodchan PRIVATE -fsanitize=fuzzer,address)
endif()

# Standalone corpus runner (no libFuzzer) — always useful for CI smoke.
option(ENABLE_FUZZ_STANDALONE "Build fuzz_sodchan_standalone corpus replay" ON)
if(ENABLE_FUZZ_STANDALONE)
    add_executable(fuzz_sodchan_standalone fuzz/fuzz_sodchan.c)
    target_link_libraries(fuzz_sodchan_standalone PRIVATE sodchan)
    target_compile_definitions(fuzz_sodchan_standalone PRIVATE SODCHAN_FUZZ_STANDALONE=1)
    add_test(NAME sodchan_fuzz_corpus COMMAND fuzz_sodchan_standalone
        "${CMAKE_CURRENT_SOURCE_DIR}/fuzz/corpus/empty"
        "${CMAKE_CURRENT_SOURCE_DIR}/fuzz/corpus/mode0"
        "${CMAKE_CURRENT_SOURCE_DIR}/fuzz/corpus/mode1"
        "${CMAKE_CURRENT_SOURCE_DIR}/fuzz/corpus/mode2"
        "${CMAKE_CURRENT_SOURCE_DIR}/fuzz/corpus/hello_frame"
        "${CMAKE_CURRENT_SOURCE_DIR}/fuzz/corpus/garbage"
        "${CMAKE_CURRENT_SOURCE_DIR}/fuzz/corpus/big_len")
endif()
