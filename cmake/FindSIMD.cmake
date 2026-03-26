# SIMD feature detection for libpqc-dyber

include(CheckCSourceCompiles)

set(PQC_HAS_AVX2 OFF)
set(PQC_HAS_AVX512 OFF)
set(PQC_HAS_NEON OFF)
set(PQC_HAS_SVE OFF)
set(PQC_HAS_SHA_NI OFF)
set(PQC_HAS_PCLMUL OFF)
set(PQC_HAS_BMI2 OFF)

if(PQC_ARCH_X86_64 AND PQC_ENABLE_ASM)
    # Check AVX2
    set(CMAKE_REQUIRED_FLAGS "-mavx2")
    check_c_source_compiles("
        #include <immintrin.h>
        int main() { __m256i a = _mm256_setzero_si256(); return 0; }
    " PQC_COMPILER_HAS_AVX2)
    if(PQC_COMPILER_HAS_AVX2)
        set(PQC_HAS_AVX2 ON)
    endif()

    # Check AVX-512
    set(CMAKE_REQUIRED_FLAGS "-mavx512f")
    check_c_source_compiles("
        #include <immintrin.h>
        int main() { __m512i a = _mm512_setzero_si512(); return 0; }
    " PQC_COMPILER_HAS_AVX512)
    if(PQC_COMPILER_HAS_AVX512)
        set(PQC_HAS_AVX512 ON)
    endif()

    # Check SHA-NI
    set(CMAKE_REQUIRED_FLAGS "-msha")
    check_c_source_compiles("
        #include <immintrin.h>
        int main() { __m128i a = _mm_setzero_si128(); a = _mm_sha256rnds2_epu32(a, a, a); return 0; }
    " PQC_COMPILER_HAS_SHA_NI)
    if(PQC_COMPILER_HAS_SHA_NI)
        set(PQC_HAS_SHA_NI ON)
    endif()

    # Check PCLMULQDQ
    set(CMAKE_REQUIRED_FLAGS "-mpclmul")
    check_c_source_compiles("
        #include <wmmintrin.h>
        int main() { __m128i a = _mm_setzero_si128(); a = _mm_clmulepi64_si128(a, a, 0); return 0; }
    " PQC_COMPILER_HAS_PCLMUL)
    if(PQC_COMPILER_HAS_PCLMUL)
        set(PQC_HAS_PCLMUL ON)
    endif()

    # Check BMI2
    set(CMAKE_REQUIRED_FLAGS "-mbmi2")
    check_c_source_compiles("
        #include <immintrin.h>
        int main() { unsigned long long a = _mulx_u64(1, 2, &a); return 0; }
    " PQC_COMPILER_HAS_BMI2)
    if(PQC_COMPILER_HAS_BMI2)
        set(PQC_HAS_BMI2 ON)
    endif()

    set(CMAKE_REQUIRED_FLAGS "")
endif()

if(PQC_ARCH_AARCH64 AND PQC_ENABLE_ASM)
    # NEON is always available on AArch64
    set(PQC_HAS_NEON ON)

    # Check SVE
    set(CMAKE_REQUIRED_FLAGS "-march=armv8.2-a+sve")
    check_c_source_compiles("
        #include <arm_sve.h>
        int main() { svint32_t a = svdup_s32(0); return 0; }
    " PQC_COMPILER_HAS_SVE)
    if(PQC_COMPILER_HAS_SVE)
        set(PQC_HAS_SVE ON)
    endif()
    set(CMAKE_REQUIRED_FLAGS "")
endif()

message(STATUS "SIMD: AVX2=${PQC_HAS_AVX2} AVX512=${PQC_HAS_AVX512} NEON=${PQC_HAS_NEON} SVE=${PQC_HAS_SVE} SHA-NI=${PQC_HAS_SHA_NI}")
