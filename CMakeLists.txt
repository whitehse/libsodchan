cmake_minimum_required(VERSION 3.20)
project(libsodchan LANGUAGES C VERSION 0.1.0)

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

if(SODCHAN_ALLOW_LAB_CLEARTEXT)
    target_compile_definitions(sodchan PUBLIC SODCHAN_ALLOW_LAB_CLEARTEXT=1)
endif()

# PR-2: find_package(Sodium) / link sodium. Scaffold builds without sodium.

include(GNUInstallDirs)
install(TARGETS sodchan EXPORT sodchan-targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT sodchan-targets FILE sodchan-config.cmake
    NAMESPACE sodchan:: DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/sodchan)

enable_testing()

add_executable(sodchan_smoke_test tests/test_sodchan_smoke.c)
target_link_libraries(sodchan_smoke_test PRIVATE sodchan)
add_test(NAME sodchan_smoke COMMAND sodchan_smoke_test)

add_executable(sodchan_client_example examples/sodchan_client_example.c)
target_link_libraries(sodchan_client_example PRIVATE sodchan)

add_executable(sodchan_server_example examples/sodchan_server_example.c)
target_link_libraries(sodchan_server_example PRIVATE sodchan)

# Fuzz harness (optional — requires libFuzzer); body lands with PR-7.
option(ENABLE_FUZZ "Build fuzz harness (requires libFuzzer)" OFF)
if(ENABLE_FUZZ)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/fuzz/fuzz_sodchan.c")
        add_executable(fuzz_sodchan fuzz/fuzz_sodchan.c)
        target_link_libraries(fuzz_sodchan PRIVATE sodchan)
        target_compile_options(fuzz_sodchan PRIVATE -fsanitize=fuzzer,address -g -O1)
        target_link_options(fuzz_sodchan PRIVATE -fsanitize=fuzzer,address)
    endif()
endif()
