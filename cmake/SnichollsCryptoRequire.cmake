# snicholls-crypto - the diamond rules, as CMake functions.
#
# Included by the in-tree CMakeLists.txt and by the installed
# snicholls_cryptoConfig.cmake, so a consumer gets the same functions whichever
# way it reached crypto. See CLAUDE.md "Versioning and the diamond".
#
#   snicholls_crypto_require(<minimum>)          rule 2: fail configure if the
#                                              winning copy is older
#   snicholls_crypto_assert_single_version()     rule 3: fail configure if more
#                                              than one version was reached
#   snicholls_crypto_record_version(<v> <where>) called by crypto itself, once per
#                                              copy reached; not for consumers
#
# Global properties, readable by any project in the build:
#
#   SNICHOLLS_CRYPTO_VERSION         the version of the copy that won (rule 1)
#   SNICHOLLS_CRYPTO_SOURCE_DIR      where that copy lives
#   SNICHOLLS_CRYPTO_VERSIONS_SEEN   every distinct version reached, winner or not
#   SNICHOLLS_CRYPTO_COPIES_SEEN     every copy reached, as "<version> at <path>"

include_guard(GLOBAL)

function(snicholls_crypto_record_version version where)
    get_property(_seen GLOBAL PROPERTY SNICHOLLS_CRYPTO_VERSIONS_SEEN)
    list(APPEND _seen "${version}")
    list(REMOVE_DUPLICATES _seen)
    set_property(GLOBAL PROPERTY SNICHOLLS_CRYPTO_VERSIONS_SEEN "${_seen}")

    get_property(_copies GLOBAL PROPERTY SNICHOLLS_CRYPTO_COPIES_SEEN)
    list(APPEND _copies "${version} at ${where}")
    set_property(GLOBAL PROPERTY SNICHOLLS_CRYPTO_COPIES_SEEN "${_copies}")
endfunction()

function(snicholls_crypto_require minimum)
    get_property(_winner GLOBAL PROPERTY SNICHOLLS_CRYPTO_VERSION)
    if(NOT _winner)
        message(FATAL_ERROR
            "snicholls_crypto_require(${minimum}) was called before snicholls::crypto was added. "
            "add_subdirectory() the crypto checkout, or find_package(snicholls_crypto), first.")
    endif()
    if(_winner VERSION_LESS minimum)
        get_property(_where GLOBAL PROPERTY SNICHOLLS_CRYPTO_SOURCE_DIR)
        message(FATAL_ERROR
            "${PROJECT_NAME} needs snicholls::crypto ${minimum} or newer, but the copy that won is ${_winner} "
            "(${_where}). The first copy added to the build wins, so bump the top-level project's pin.")
    endif()
    message(STATUS "${PROJECT_NAME}: snicholls::crypto ${_winner} satisfies the required minimum ${minimum}")
endfunction()

function(snicholls_crypto_assert_single_version)
    get_property(_seen GLOBAL PROPERTY SNICHOLLS_CRYPTO_VERSIONS_SEEN)
    list(LENGTH _seen _n)
    if(_n GREATER 1)
        get_property(_copies GLOBAL PROPERTY SNICHOLLS_CRYPTO_COPIES_SEEN)
        string(REPLACE ";" "\n  " _copies "${_copies}")
        message(FATAL_ERROR
            "More than one snicholls::crypto version was reached in this build:\n  ${_copies}\n"
            "Pin every dependency that carries core to the same release tag.")
    endif()
    if(_n EQUAL 1)
        message(STATUS "${PROJECT_NAME}: one snicholls::crypto version in the build (${_seen})")
    endif()
endfunction()
