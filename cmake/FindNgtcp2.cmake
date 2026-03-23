find_path(NGTCP2_INCLUDE_DIR NAMES ngtcp2/ngtcp2.h
    HINTS
        "${NGTCP2_ROOT}/lib/includes"
        /workspace/group/ngtcp2/lib/includes
        /workspace/group/ngtcp2/build/lib/includes
)

# Build includes dir for version.h (generated at build time)
find_path(NGTCP2_BUILD_INCLUDE_DIR NAMES ngtcp2/version.h
    HINTS
        "${NGTCP2_ROOT}/build/lib/includes"
        /workspace/group/ngtcp2/build/lib/includes
)

# Crypto includes dir for ngtcp2_crypto.h and ngtcp2_crypto_boringssl.h
find_path(NGTCP2_CRYPTO_INCLUDE_DIR NAMES ngtcp2/ngtcp2_crypto.h
    HINTS
        "${NGTCP2_ROOT}/crypto/includes"
        /workspace/group/ngtcp2/crypto/includes
)

find_library(NGTCP2_LIBRARY NAMES ngtcp2 libngtcp2.a
    HINTS
        "${NGTCP2_ROOT}/lib"
        /workspace/group/ngtcp2/build/lib
)
find_library(NGTCP2_CRYPTO_LIBRARY NAMES ngtcp2_crypto_boringssl ngtcp2_crypto_openssl
    HINTS
        "${NGTCP2_ROOT}/crypto/boringssl"
        /workspace/group/ngtcp2/build/crypto/boringssl
)
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Ngtcp2 DEFAULT_MSG NGTCP2_LIBRARY NGTCP2_INCLUDE_DIR)
set(NGTCP2_LIBRARIES    ${NGTCP2_LIBRARY} ${NGTCP2_CRYPTO_LIBRARY})
set(NGTCP2_INCLUDE_DIRS ${NGTCP2_INCLUDE_DIR})
if(NGTCP2_BUILD_INCLUDE_DIR)
    list(APPEND NGTCP2_INCLUDE_DIRS ${NGTCP2_BUILD_INCLUDE_DIR})
endif()
if(NGTCP2_CRYPTO_INCLUDE_DIR)
    list(APPEND NGTCP2_INCLUDE_DIRS ${NGTCP2_CRYPTO_INCLUDE_DIR})
endif()
mark_as_advanced(NGTCP2_INCLUDE_DIR NGTCP2_BUILD_INCLUDE_DIR NGTCP2_CRYPTO_INCLUDE_DIR NGTCP2_LIBRARY NGTCP2_CRYPTO_LIBRARY)
