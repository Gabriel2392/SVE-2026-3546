/*
 * Compact LZMA1 decoder based on the public-domain 7-Zip LZMA SDK:
 * LzmaDec.c -- LZMA Decoder
 * 2023-04-07 : Igor Pavlov : Public domain
 * https://www.7-zip.org/sdk.html
 */

#include "lzma_dec.h"

#define TOP (1U << 24)
#define TOTAL_BITS 11
#define TOTAL (1U << TOTAL_BITS)
#define MOVE_BITS 5
#define START 1664
#define SPEC_POS (-START)
#define IS_REP0_LONG (SPEC_POS + 128)
#define REP_LEN (IS_REP0_LONG + 256)
#define LEN_CODER (REP_LEN + 512)
#define IS_MATCH (LEN_CODER + 512)
#define ALIGN (IS_MATCH + 256)
#define IS_REP (ALIGN + 16)
#define IS_REP0 (IS_REP + 12)
#define IS_REP1 (IS_REP0 + 12)
#define IS_REP2 (IS_REP1 + 12)
#define POS_SLOT (IS_REP2 + 12)
#define LITERAL (POS_SLOT + 256)
#define PROB_COUNT (1984 + 0x300 * 8)
#define DICT_SIZE LZMA_DICTIONARY_SIZE

struct rc {
    const lz_u8 *ptr;
    const lz_u8 *end;
    lz_u32 range;
    lz_u32 code;
    int error;
};

static lz_u32 get_byte(struct rc *rc)
{
    if (rc->ptr == rc->end) {
        rc->error = 1;
        return 0;
    }
    return *rc->ptr++;
}

static void normalize(struct rc *rc)
{
    if (rc->range < TOP) {
        rc->range <<= 8;
        rc->code = rc->code << 8 | get_byte(rc);
    }
}

static lz_u32 bit(struct rc *rc, lz_u16 *prob)
{
    normalize(rc);
    lz_u32 value = *prob;
    lz_u32 bound = (rc->range >> TOTAL_BITS) * value;
    if (rc->code < bound) {
        rc->range = bound;
        *prob = (lz_u16)(value + ((TOTAL - value) >> MOVE_BITS));
        return 0;
    }
    rc->range -= bound;
    rc->code -= bound;
    *prob = (lz_u16)(value - (value >> MOVE_BITS));
    return 1;
}

static lz_u32 tree(struct rc *rc, lz_u16 *prob, lz_u32 bits)
{
    lz_u32 value = 1;
    while (bits--)
        value = value << 1 | bit(rc, prob + value);
    return value;
}

static lz_u32 reverse_tree(struct rc *rc, lz_u16 *prob, lz_u32 bits)
{
    lz_u32 value = 1;
    lz_u32 result = 0;
    for (lz_u32 index = 0; index != bits; ++index) {
        lz_u32 current = bit(rc, prob + value);
        value = value << 1 | current;
        result |= current << index;
    }
    return result;
}

static lz_u32 direct(struct rc *rc, lz_u32 bits)
{
    lz_u32 value = 0;
    while (bits--) {
        normalize(rc);
        rc->range >>= 1;
        lz_u32 current = 0;
        if (rc->code >= rc->range) {
            rc->code -= rc->range;
            current = 1;
        }
        value = value << 1 | current;
    }
    return value;
}

static lz_u32 length(struct rc *rc, lz_u16 *prob, lz_u32 pos_state)
{
    if (!bit(rc, prob))
        return tree(rc, prob + pos_state, 3) - 8;
    if (!bit(rc, prob + 8))
        return tree(rc, prob + pos_state + 8, 3);
    return tree(rc, prob + 256, 8) - 256 + 16;
}

unsigned int lzma_workspace_size(void)
{
    return LZMA_WORKSPACE_REQUIRED;
}

int lzma_decode(void *output, lz_u32 output_size,
                const void *input, lz_u32 input_size,
                void *workspace, lz_u32 workspace_size)
{
    lz_u8 *out = output;
    const lz_u8 *in = input;
    lz_u16 *base = workspace;
    lz_u16 *prob = base + START;
    struct rc rc;
    lz_u32 reps[4] = {1, 1, 1, 1};
    lz_u32 state = 0;
    lz_u32 pos = 0;

    if (workspace_size < LZMA_WORKSPACE_REQUIRED)
        return LZMA_WORKSPACE;
    if (input_size < 5 || in[0])
        return LZMA_INPUT;
    for (lz_u32 index = 0; index != PROB_COUNT; ++index)
        base[index] = TOTAL >> 1;
    rc.ptr = in + 1;
    rc.end = in + input_size;
    rc.range = 0xFFFFFFFF;
    rc.code = 0;
    rc.error = 0;
    for (lz_u32 index = 0; index != 4; ++index)
        rc.code = rc.code << 8 | get_byte(&rc);

    while (pos < output_size && !rc.error) {
        lz_u32 pos_state = (pos & 3) << 4;
        if (!bit(&rc, prob + IS_MATCH + pos_state + state)) {
            lz_u16 *literal = prob + LITERAL +
                0x300 * (pos ? out[pos - 1] >> 5 : 0);
            lz_u32 symbol = 1;
            if (state < 7) {
                state -= state < 4 ? state : 3;
#define LIT_BIT() symbol = symbol << 1 | bit(&rc, literal + symbol)
                LIT_BIT(); LIT_BIT(); LIT_BIT(); LIT_BIT();
                LIT_BIT(); LIT_BIT(); LIT_BIT(); LIT_BIT();
#undef LIT_BIT
            } else {
                if (reps[0] > pos)
                    return LZMA_DISTANCE;
                lz_u32 match = out[pos - reps[0]];
                lz_u32 offset = 0x100;
                state -= state < 10 ? 3 : 6;
                while (symbol < 0x100) {
                    match += match;
                    lz_u32 selector = offset;
                    offset &= match;
                    lz_u32 current = bit(
                        &rc, literal + offset + selector + symbol);
                    symbol = symbol << 1 | current;
                    if (selector)
                        offset = ((offset != 0) == (current != 0)) ? 0x100 : 0;
                }
            }
            out[pos++] = (lz_u8)symbol;
            continue;
        }

        lz_u16 *len_prob;
        if (!bit(&rc, prob + IS_REP + state)) {
            state += 12;
            len_prob = prob + LEN_CODER;
        } else {
            if (!bit(&rc, prob + IS_REP0 + state)) {
                if (!bit(&rc, prob + IS_REP0_LONG + pos_state + state)) {
                    if (reps[0] > pos)
                        return LZMA_DISTANCE;
                    out[pos] = out[pos - reps[0]];
                    ++pos;
                    state = state < 7 ? 9 : 11;
                    continue;
                }
            } else {
                lz_u32 distance;
                if (!bit(&rc, prob + IS_REP1 + state)) {
                    distance = reps[1];
                } else {
                    if (!bit(&rc, prob + IS_REP2 + state)) {
                        distance = reps[2];
                    } else {
                        distance = reps[3];
                        reps[3] = reps[2];
                    }
                    reps[2] = reps[1];
                }
                reps[1] = reps[0];
                reps[0] = distance;
            }
            state = state < 7 ? 8 : 11;
            len_prob = prob + REP_LEN;
        }

        lz_u32 len = length(&rc, len_prob, pos_state);
        if (state >= 12) {
            lz_u32 slot = tree(
                &rc, prob + POS_SLOT + (len < 4 ? len : 3) * 64, 6) - 64;
            lz_u32 distance = slot;
            if (slot >= 4) {
                lz_u32 bits = (slot >> 1) - 1;
                distance = 2 | (slot & 1);
                if (slot < 14) {
                    distance <<= bits;
                    distance += reverse_tree(
                        &rc, prob + SPEC_POS + distance - slot - 1, bits);
                } else {
                    distance <<= bits;
                    distance += direct(&rc, bits - 4) << 4;
                    distance += reverse_tree(&rc, prob + ALIGN, 4);
                }
            }
            reps[3] = reps[2];
            reps[2] = reps[1];
            reps[1] = reps[0];
            reps[0] = distance + 1;
            state = state < 19 ? 7 : 10;
        }
        len += 2;
        if (!reps[0] || reps[0] > pos || reps[0] > DICT_SIZE)
            return LZMA_DISTANCE;
        if (len > output_size - pos)
            return LZMA_OUTPUT;
        lz_u32 source = pos - reps[0];
        while (len--)
            out[pos++] = out[source++];
    }
    return rc.error || pos != output_size ? LZMA_INPUT : LZMA_OK;
}

_Static_assert(PROB_COUNT * sizeof(lz_u16) == LZMA_WORKSPACE_REQUIRED,
               "LZMA workspace size");
