#ifndef VEXTA_PQ_RANDOMBYTES_H
#define VEXTA_PQ_RANDOMBYTES_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* VEXTA: unified prototype. Definition lives in pq_randombytes.cpp and is
   backed by Bitcoin's CSPRNG (GetStrongRandBytes). The upstream test-only
   randombytes.c files were deleted — they must never ship in a wallet. */
void randombytes(uint8_t *out, size_t outlen);
#ifdef __cplusplus
}
#endif
#endif
