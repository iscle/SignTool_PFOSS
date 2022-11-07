cmake_minimum_required(VERSION 3.16)
project(SignTool_PFOSS C)

set(CMAKE_C_STANDARD 99)

include_directories(inc asf/inc)

add_executable(SignTool_PFOSS
        asf/core/alg_sha1.c
        asf/crypto/bgn_core.c
        asf/crypto/bgn_io.c
        asf/crypto/bgn_util.c
        asf/crypto/rsa_core.c
        asf/crypto/rsa_lib.c
        asf/crypto/rsa_util.c
        lib_sign.c
        sec_auth.c
        sign_util.c
        main.c)
