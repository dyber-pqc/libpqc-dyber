# Compiler warning and hardening flags for libpqc-dyber

if(MSVC)
    add_compile_options(/W4 /WX- /wd4200 /wd4204 /wd4221)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
else()
    # Ensure POSIX + GNU/BSD definitions are available
    if(NOT APPLE)
        add_compile_definitions(_POSIX_C_SOURCE=200809L _DEFAULT_SOURCE)
    endif()

    add_compile_options(
        -Wall -Wextra -Wpedantic
        -Wshadow -Wundef
        -Wformat=2 -Wformat-security
        -Wnull-dereference
        -Wstack-protector
        -fstack-protector-strong
        -fno-strict-aliasing
    )
    # Note: -Wconversion and -Wsign-conversion are intentionally omitted.
    # The PQC reference implementations (Kyber, Dilithium, etc.) use
    # idiomatic C patterns (int16_t arithmetic, bitwise ops) that produce
    # hundreds of benign conversion warnings under these flags.

    # Position-independent code for shared libs
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)

    # Hardening flags
    if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(-D_FORTIFY_SOURCE=2)
    endif()

    # Link-time hardening
    if(NOT APPLE)
        add_link_options(-Wl,-z,relro,-z,now)
    endif()
endif()

# Debug/Release flags
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_definitions(PQC_DEBUG=1)
endif()
