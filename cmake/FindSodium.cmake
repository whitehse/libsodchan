# FindSodium.cmake — locate libsodium (headers + library).
#
# Sets:
#   Sodium_FOUND
#   Sodium_INCLUDE_DIRS
#   Sodium_LIBRARIES
#   Sodium_VERSION (if known)
#
# Hints:
#   SODIUM_ROOT — prefix containing include/ and lib/ (or lib/<triplet>/)
#   Sodium_DIR  — unused (compatibility)
#
# Search order: SODIUM_ROOT, pkg-config, standard paths, libsodchan third_party prefix.

if(TARGET Sodium::Sodium)
    set(Sodium_FOUND TRUE)
    return()
endif()

set(_sodium_root_hints "")
if(SODIUM_ROOT)
    list(APPEND _sodium_root_hints "${SODIUM_ROOT}")
endif()
if(DEFINED ENV{SODIUM_ROOT})
    list(APPEND _sodium_root_hints "$ENV{SODIUM_ROOT}")
endif()
# Local extracted -dev prefix (not committed; see README)
list(APPEND _sodium_root_hints
    "${CMAKE_SOURCE_DIR}/third_party/sodium-prefix/usr"
    "${CMAKE_CURRENT_LIST_DIR}/../third_party/sodium-prefix/usr"
)

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND AND NOT Sodium_FOUND)
    pkg_check_modules(PC_SODIUM QUIET libsodium)
endif()

# When SODIUM_ROOT points at a host-side cross prefix (e.g. armv7 musl
# static install under third_party/), CMAKE_FIND_ROOT_PATH_MODE_*=ONLY
# would otherwise only search the toolchain sysroot. Prefer the explicit
# prefix with NO_CMAKE_FIND_ROOT_PATH.
set(_sodium_find_extra "")
if(_sodium_root_hints)
    set(_sodium_find_extra NO_CMAKE_FIND_ROOT_PATH)
endif()

find_path(Sodium_INCLUDE_DIR
    NAMES sodium.h
    HINTS ${_sodium_root_hints}
          ${PC_SODIUM_INCLUDE_DIRS}
    PATH_SUFFIXES include
    ${_sodium_find_extra}
)

find_library(Sodium_LIBRARY
    NAMES sodium libsodium
    HINTS ${_sodium_root_hints}
          ${PC_SODIUM_LIBRARY_DIRS}
    PATH_SUFFIXES
        lib
        lib64
        lib/x86_64-linux-gnu
        lib/aarch64-linux-gnu
        lib/arm-linux-gnueabihf
    ${_sodium_find_extra}
)

# Runtime-only systems often lack libsodium.so (unversioned); try soname.
if(NOT Sodium_LIBRARY)
    find_library(Sodium_LIBRARY
        NAMES libsodium.so.23 sodium.so.23
        HINTS /usr/lib /usr/lib/x86_64-linux-gnu /usr/lib64
    )
endif()

# Prefer static archive from a SODIUM_ROOT when dynamic not found
if(NOT Sodium_LIBRARY)
    find_library(Sodium_LIBRARY
        NAMES libsodium.a
        HINTS ${_sodium_root_hints}
        PATH_SUFFIXES lib lib/x86_64-linux-gnu lib/aarch64-linux-gnu lib64
        ${_sodium_find_extra}
    )
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Sodium
    REQUIRED_VARS Sodium_LIBRARY Sodium_INCLUDE_DIR
    VERSION_VAR PC_SODIUM_VERSION
)

if(Sodium_FOUND)
    set(Sodium_INCLUDE_DIRS "${Sodium_INCLUDE_DIR}")
    set(Sodium_LIBRARIES "${Sodium_LIBRARY}")
    if(PC_SODIUM_VERSION)
        set(Sodium_VERSION "${PC_SODIUM_VERSION}")
    endif()
    if(NOT TARGET Sodium::Sodium)
        add_library(Sodium::Sodium UNKNOWN IMPORTED)
        set_target_properties(Sodium::Sodium PROPERTIES
            IMPORTED_LOCATION "${Sodium_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${Sodium_INCLUDE_DIR}"
        )
        # Static libsodium may need pthread
        if(Sodium_LIBRARY MATCHES "\\.a$")
            set(THREADS_PREFER_PTHREAD_FLAG ON)
            find_package(Threads REQUIRED)
            set_property(TARGET Sodium::Sodium APPEND PROPERTY
                INTERFACE_LINK_LIBRARIES Threads::Threads)
        endif()
    endif()
endif()

mark_as_advanced(Sodium_INCLUDE_DIR Sodium_LIBRARY)
