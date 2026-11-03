/*
 * Compact interface based on Igor Pavlov's public-domain LZMA SDK decoder.
 * https://www.7-zip.org/sdk.html
 */

#pragma once

typedef unsigned char lz_u8;
typedef unsigned short lz_u16;
typedef unsigned int lz_u32;

#define LZMA_DICTIONARY_SIZE 0x200000U
#define LZMA_WORKSPACE_REQUIRED 0x3F80U

enum {
    LZMA_OK = 0,
    LZMA_INPUT = 1,
    LZMA_OUTPUT = 2,
    LZMA_DISTANCE = 3,
    LZMA_WORKSPACE = 4,
};

unsigned int lzma_workspace_size(void);
int lzma_decode(void *output, lz_u32 output_size,
                const void *input, lz_u32 input_size,
                void *workspace, lz_u32 workspace_size);
