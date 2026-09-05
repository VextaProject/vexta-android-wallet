cmake_minimum_required(VERSION 3.22.1)

project(vextapq LANGUAGES C CXX)

add_library(
    vextapq
    SHARED

    vexta_pq_jni.cpp
    vexta_pq_randombytes.cpp
    pq/pq.cpp

    pq/mldsa65/fips202.c
    pq/mldsa65/ntt.c
    pq/mldsa65/packing.c
    pq/mldsa65/poly.c
    pq/mldsa65/polyvec.c
    pq/mldsa65/reduce.c
    pq/mldsa65/rounding.c
    pq/mldsa65/sign.c
    pq/mldsa65/symmetric-shake.c

    pq/sphincsplus/address.c
    pq/sphincsplus/fips202.c
    pq/sphincsplus/fors.c
    pq/sphincsplus/hash_sha2.c
    pq/sphincsplus/merkle.c
    pq/sphincsplus/sha2.c
    pq/sphincsplus/sign.c
    pq/sphincsplus/thash_sha2_simple.c
    pq/sphincsplus/utils.c
    pq/sphincsplus/utilsx1.c
    pq/sphincsplus/wots.c
    pq/sphincsplus/wotsx1.c
)

target_include_directories(
    vextapq
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/pq
    ${CMAKE_CURRENT_SOURCE_DIR}/pq/mldsa65
    ${CMAKE_CURRENT_SOURCE_DIR}/pq/sphincsplus
)

target_compile_definitions(
    vextapq
    PRIVATE
    DILITHIUM_MODE=3
    PARAMS=sphincs-sha2-128s
)

find_library(log-lib log)

target_link_libraries(
    vextapq
    ${log-lib}
)
