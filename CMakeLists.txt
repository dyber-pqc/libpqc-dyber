cmake_minimum_required(VERSION 3.16)

# Read version from file
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" PQC_VERSION_STRING)
string(STRIP "${PQC_VERSION_STRING}" PQC_VERSION_STRING)

project(libpqc-dyber
    VERSION ${PQC_VERSION_STRING}
    DESCRIPTION "Post-Quantum Cryptography Library by Dyber, Inc."
    HOMEPAGE_URL "https://github.com/dyber-pqc/libpqc-dyber"
    LANGUAGES C
)

# C11 standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Build options
option(PQC_BUILD_SHARED "Build shared library" ON)
option(PQC_BUILD_STATIC "Build static library" ON)
option(PQC_BUILD_TESTS "Build test suite" ON)
option(PQC_BUILD_BENCHMARKS "Build benchmarks" ON)
option(PQC_BUILD_CLI "Build CLI tool" ON)
option(PQC_ENABLE_ASM "Enable assembly optimizations" ON)

# Algorithm toggles
option(PQC_ENABLE_KEM_MLKEM "Enable ML-KEM (FIPS 203)" ON)
option(PQC_ENABLE_KEM_HQC "Enable HQC" ON)
option(PQC_ENABLE_KEM_BIKE "Enable BIKE" ON)
option(PQC_ENABLE_KEM_MCELIECE "Enable Classic McEliece" ON)
option(PQC_ENABLE_KEM_FRODO "Enable FrodoKEM" ON)
option(PQC_ENABLE_KEM_NTRU "Enable NTRU" ON)
option(PQC_ENABLE_KEM_NTRUPRIME "Enable NTRU-Prime" ON)

option(PQC_ENABLE_SIG_MLDSA "Enable ML-DSA (FIPS 204)" ON)
option(PQC_ENABLE_SIG_SLHDSA "Enable SLH-DSA (FIPS 205)" ON)
option(PQC_ENABLE_SIG_FNDSA "Enable FN-DSA / Falcon (FIPS 206)" ON)
option(PQC_ENABLE_SIG_SPHINCSPLUS "Enable SPHINCS+" ON)
option(PQC_ENABLE_SIG_MAYO "Enable MAYO" ON)
option(PQC_ENABLE_SIG_UOV "Enable UOV" ON)
option(PQC_ENABLE_SIG_SNOVA "Enable SNOVA" ON)
option(PQC_ENABLE_SIG_CROSS "Enable CROSS" ON)
option(PQC_ENABLE_SIG_LMS "Enable LMS (RFC 8554)" ON)
option(PQC_ENABLE_SIG_XMSS "Enable XMSS (RFC 8391)" ON)

option(PQC_ENABLE_HYBRID "Enable hybrid schemes" ON)

# Include CMake modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(cmake/CompilerFlags.cmake)
include(cmake/FindPlatform.cmake)
include(cmake/FindSIMD.cmake)

# Generate config header
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/pqc_config.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/include/pqc/pqc_config.h"
)

# Core library sources
set(PQC_CORE_SOURCES
    src/core/common/ct_ops.c
    src/core/common/mem.c
    src/core/common/rand.c
    src/core/common/platform.c
    src/core/common/error.c
    src/core/common/hash/sha2.c
    src/core/common/hash/sha3.c
    src/core/common/hash/keccak.c
    src/dispatch/dispatch.c
)

# KEM sources
set(PQC_KEM_SOURCES src/core/kem/kem.c)
if(PQC_ENABLE_KEM_MLKEM)
    list(APPEND PQC_KEM_SOURCES
        src/core/kem/mlkem/mlkem.c
        src/core/kem/mlkem/ntt.c
        src/core/kem/mlkem/poly.c
        src/core/kem/mlkem/polyvec.c
        src/core/kem/mlkem/indcpa.c
        src/core/kem/mlkem/cbd.c
        src/core/kem/mlkem/reduce.c
        src/core/kem/mlkem/verify.c
    )
endif()
if(PQC_ENABLE_KEM_HQC)
    list(APPEND PQC_KEM_SOURCES
        src/core/kem/hqc/hqc.c
        src/core/kem/hqc/gf.c
        src/core/kem/hqc/reed_solomon.c
        src/core/kem/hqc/reed_muller.c
        src/core/kem/hqc/code.c
        src/core/kem/hqc/parsing.c
    )
endif()
if(PQC_ENABLE_KEM_BIKE)
    list(APPEND PQC_KEM_SOURCES
        src/core/kem/bike/bike.c
        src/core/kem/bike/gf2x.c
        src/core/kem/bike/decode.c
        src/core/kem/bike/sampling.c
    )
endif()
if(PQC_ENABLE_KEM_MCELIECE)
    list(APPEND PQC_KEM_SOURCES
        src/core/kem/mceliece/mceliece.c
        src/core/kem/mceliece/gf.c
        src/core/kem/mceliece/benes.c
        src/core/kem/mceliece/controlbits.c
        src/core/kem/mceliece/goppa.c
        src/core/kem/mceliece/root.c
        src/core/kem/mceliece/decrypt.c
        src/core/kem/mceliece/encrypt.c
    )
endif()
if(PQC_ENABLE_KEM_FRODO)
    list(APPEND PQC_KEM_SOURCES
        src/core/kem/frodo/frodo.c
        src/core/kem/frodo/matrix.c
        src/core/kem/frodo/noise.c
        src/core/kem/frodo/pack.c
    )
endif()
if(PQC_ENABLE_KEM_NTRU)
    list(APPEND PQC_KEM_SOURCES
        src/core/kem/ntru/ntru.c
        src/core/kem/ntru/owcpa.c
        src/core/kem/ntru/poly.c
        src/core/kem/ntru/pack.c
        src/core/kem/ntru/sample.c
    )
endif()
if(PQC_ENABLE_KEM_NTRUPRIME)
    list(APPEND PQC_KEM_SOURCES
        src/core/kem/ntruprime/ntruprime.c
        src/core/kem/ntruprime/rq.c
        src/core/kem/ntruprime/r3.c
        src/core/kem/ntruprime/encode.c
    )
endif()

# Signature sources
set(PQC_SIG_SOURCES src/core/sig/sig.c)
if(PQC_ENABLE_SIG_MLDSA)
    list(APPEND PQC_SIG_SOURCES
        src/core/sig/mldsa/mldsa.c
        src/core/sig/mldsa/ntt.c
        src/core/sig/mldsa/poly.c
        src/core/sig/mldsa/polyvec.c
        src/core/sig/mldsa/packing.c
        src/core/sig/mldsa/rounding.c
        src/core/sig/mldsa/expand.c
        src/core/sig/mldsa/hint.c
    )
endif()
if(PQC_ENABLE_SIG_SLHDSA)
    list(APPEND PQC_SIG_SOURCES
        src/core/sig/slhdsa/slhdsa.c
        src/core/sig/slhdsa/address.c
        src/core/sig/slhdsa/wots.c
        src/core/sig/slhdsa/xmss_core.c
        src/core/sig/slhdsa/fors.c
        src/core/sig/slhdsa/hypertree.c
        src/core/sig/slhdsa/thash_sha2.c
        src/core/sig/slhdsa/thash_shake.c
    )
endif()
if(PQC_ENABLE_SIG_FNDSA)
    list(APPEND PQC_SIG_SOURCES
        src/core/sig/fndsa/fndsa.c
        src/core/sig/fndsa/fft.c
        src/core/sig/fndsa/sampler.c
        src/core/sig/fndsa/ntru_solve.c
        src/core/sig/fndsa/codec.c
        src/core/sig/fndsa/keygen.c
        src/core/sig/fndsa/sign.c
        src/core/sig/fndsa/vrfy.c
    )
endif()
if(PQC_ENABLE_SIG_SPHINCSPLUS)
    list(APPEND PQC_SIG_SOURCES
        src/core/sig/sphincsplus/sphincsplus.c
    )
endif()
if(PQC_ENABLE_SIG_MAYO)
    list(APPEND PQC_SIG_SOURCES
        src/core/sig/mayo/mayo.c
        src/core/sig/mayo/gf16.c
        src/core/sig/mayo/oil.c
        src/core/sig/mayo/vinegar.c
        src/core/sig/mayo/matrix_gf16.c
    )
endif()
if(PQC_ENABLE_SIG_UOV)
    list(APPEND PQC_SIG_SOURCES
        src/core/sig/uov/uov.c
        src/core/sig/uov/gf256.c
        src/core/sig/uov/mq.c
        src/core/sig/uov/keygen.c
    )
endif()
if(PQC_ENABLE_SIG_SNOVA)
    list(APPEND PQC_SIG_SOURCES
        src/core/sig/snova/snova.c
        src/core/sig/snova/ring.c
        src/core/sig/snova/matrix.c
    )
endif()
if(PQC_ENABLE_SIG_CROSS)
    list(APPEND PQC_SIG_SOURCES
        src/core/sig/cross/cross.c
        src/core/sig/cross/rsdp.c
        src/core/sig/cross/merkle.c
        src/core/sig/cross/seed_tree.c
    )
endif()
if(PQC_ENABLE_SIG_LMS)
    list(APPEND PQC_SIG_SOURCES
        src/core/sig/lms/lms.c
        src/core/sig/lms/lmots.c
        src/core/sig/lms/hss.c
    )
endif()
if(PQC_ENABLE_SIG_XMSS)
    list(APPEND PQC_SIG_SOURCES
        src/core/sig/xmss/xmss.c
        src/core/sig/xmss/wots.c
        src/core/sig/xmss/hash_address.c
    )
endif()

# Hybrid sources
set(PQC_HYBRID_SOURCES "")
if(PQC_ENABLE_HYBRID)
    set(PQC_HYBRID_SOURCES
        src/core/hybrid/hybrid_kem.c
        src/core/hybrid/hybrid_sig.c
        src/core/hybrid/x25519.c
        src/core/hybrid/ed25519.c
        src/core/hybrid/ecdh_p256.c
        src/core/hybrid/ecdsa_p256.c
        src/core/hybrid/field25519.c
        src/core/hybrid/field_p256.c
    )
endif()

# All sources
set(PQC_ALL_SOURCES
    ${PQC_CORE_SOURCES}
    ${PQC_KEM_SOURCES}
    ${PQC_SIG_SOURCES}
    ${PQC_HYBRID_SOURCES}
)

# Include directories
set(PQC_INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_BINARY_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Static library
if(PQC_BUILD_STATIC)
    add_library(pqc_static STATIC ${PQC_ALL_SOURCES})
    target_include_directories(pqc_static PUBLIC ${PQC_INCLUDE_DIRS})
    set_target_properties(pqc_static PROPERTIES OUTPUT_NAME pqc)
    target_compile_definitions(pqc_static PRIVATE PQC_BUILD)
endif()

# Shared library
if(PQC_BUILD_SHARED)
    add_library(pqc_shared SHARED ${PQC_ALL_SOURCES})
    target_include_directories(pqc_shared PUBLIC ${PQC_INCLUDE_DIRS})
    set_target_properties(pqc_shared PROPERTIES
        OUTPUT_NAME pqc
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
    )
    target_compile_definitions(pqc_shared PRIVATE PQC_BUILD PQC_SHARED)
    if(WIN32)
        target_compile_definitions(pqc_shared PRIVATE PQC_DLL_EXPORT)
    endif()
endif()

# Platform-specific libraries
if(WIN32)
    if(PQC_BUILD_STATIC)
        target_link_libraries(pqc_static PRIVATE bcrypt)
    endif()
    if(PQC_BUILD_SHARED)
        target_link_libraries(pqc_shared PRIVATE bcrypt)
    endif()
else()
    # Link math library on non-Windows platforms (for floor, cos, sin, sqrt in FN-DSA)
    if(PQC_BUILD_STATIC)
        target_link_libraries(pqc_static PRIVATE m)
    endif()
    if(PQC_BUILD_SHARED)
        target_link_libraries(pqc_shared PRIVATE m)
    endif()
endif()

# Tests
if(PQC_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# CLI tool
if(PQC_BUILD_CLI)
    add_executable(pqc-cli bindings/shell/pqc_cli.c)
    target_link_libraries(pqc-cli PRIVATE pqc_static)
    target_include_directories(pqc-cli PRIVATE ${PQC_INCLUDE_DIRS})
endif()

# Install
include(GNUInstallDirs)
if(PQC_BUILD_STATIC)
    install(TARGETS pqc_static ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()
if(PQC_BUILD_SHARED)
    install(TARGETS pqc_shared
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
endif()
install(DIRECTORY include/pqc DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/include/pqc/pqc_config.h"
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/pqc
)
if(PQC_BUILD_CLI)
    install(TARGETS pqc-cli RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

# Summary
message(STATUS "")
message(STATUS "libpqc-dyber v${PROJECT_VERSION} - Dyber, Inc.")
message(STATUS "  Platform:   ${PQC_PLATFORM}")
message(STATUS "  Arch:       ${PQC_ARCH}")
message(STATUS "  Compiler:   ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}")
message(STATUS "  Shared:     ${PQC_BUILD_SHARED}")
message(STATUS "  Static:     ${PQC_BUILD_STATIC}")
message(STATUS "  Tests:      ${PQC_BUILD_TESTS}")
message(STATUS "  ASM:        ${PQC_ENABLE_ASM}")
message(STATUS "")
