#include "bundle_expected.h"
#include "lzma_dec.h"
#include "../loader_profile.h"

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;

#define MAGIC 0x42333541U
#define PIT_MAGIC 0x12349876U
#define PIT_HEADER 0x1CU
#define PIT_ENTRY 0x84U
#define PIT_TRAILER 0x310U
#define PIT_SHIFT 12U
#define CHUNK 0x100000U
#define SMC_OTP_CONTROL 0xC2001014U
#define OTP_WRITE_KEY2 0x16U
#define OTP_USE_KEY2 0x17U
#define OTP_KEY2_CRC 0x8C53BDC3U
#define WHITE 0xFFFFFFU
#define GREEN 0x40FF40U
#define RED 0xFF3030U

#define bread ((int (*)(void *, int, u32, u32))BLK_BREAD)
#define bwrite ((int (*)(const void *, int, u32, u32))BLK_BWRITE)
#define sha256 ((int (*)(const void *, u32, void *))SHA256)
#define send_response ((u32 (*)(void *, u32))SEND_CALLBACK_DEFAULT)
#define screen_cursor ((u32 (*)(void))SCREEN_CURSOR)
#define screen_printf ((void (*)(u32, u32, u32, u32, const char *, ...))SCREEN_PRINTF)
#define display_update ((void (*)(void))DISPLAY_UPDATE)

#define bundle_start ((const u8 *)BUNDLE_ADDRESS)

struct header {
    u32 magic;
    u16 version;
    u16 header_size;
    u32 total_size;
    u32 count;
    u32 entry_size;
    u32 data_offset;
    u32 pit_index;
    u32 dictionary_size;
    u8 hash[32];
} __attribute__((packed));

struct entry {
    char file[32];
    u32 offset;
    u32 packed_size;
    u32 raw_size;
    u32 flags;
    u8 hash[32];
    u8 reserved[48];
} __attribute__((packed));

struct pit_entry {
    u32 binary_type;
    u32 device_type;
    u32 identifier;
    u32 attributes;
    u32 update_attributes;
    u32 block_start;
    u32 block_count;
    u32 lun;
    u32 reserved;
    char name[32];
    char flash_file[32];
    char fota_file[32];
} __attribute__((packed));

struct otp_data {
    u8 key[128];
    u32 key_len;
    u32 checksum;
    u64 reserved[3];
} __attribute__((packed, aligned(64)));

static int same32(const void *left, const void *right)
{
    const volatile u8 *a = left;
    const volatile u8 *b = right;
    u8 value = 0;
    for (u32 index = 0; index != 32; ++index)
        value |= a[index] ^ b[index];
    return !value;
}

static void cache(void *pointer, u32 size)
{
    u64 ctr;
    __asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
    u64 line = 4ULL << ((ctr >> 16) & 15);
    u64 end = (u64)pointer + size;
    u64 address = (u64)pointer & -line;
    while (address < end) {
        __asm__ volatile("dc civac, %0" : : "r"(address) : "memory");
        address += line;
    }
    __asm__ volatile("dsb sy\nisb" : : : "memory");
}

static void show(u32 *line, u32 color, const char *text)
{
    screen_printf(20, *line, color, 0, text);
    display_update();
    *line += 32;
}

__attribute__((used, noinline, section(".text.keep")))
static u64 otp_smc(u64 selector, u64 argument)
{
    register u64 x0 __asm__("x0") = SMC_OTP_CONTROL;
    register u64 x1 __asm__("x1") = selector;
    register u64 x2 __asm__("x2") = argument;
    register u64 x3 __asm__("x3") = 0;
    __asm__ volatile("smc 0" : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3)
                     : : "memory");
    return x0;
}

static u32 fuse_key2(u32 *line)
{
    static const u8 key[32] __attribute__((aligned(64))) = {
        0x43, 0xC8, 0x8A, 0xB6, 0xAA, 0x58, 0x35, 0xC0,
        0x03, 0x72, 0xEA, 0x35, 0x15, 0x47, 0x8B, 0x06,
        0x55, 0x85, 0x4B, 0x69, 0x38, 0xC9, 0x82, 0x61,
        0x02, 0xE3, 0x31, 0x39, 0xD5, 0x15, 0xB6, 0x12,
    };
    struct otp_data data;
    u8 *bytes = (void *)&data;
    for (u32 index = 0; index != sizeof(data); ++index)
        bytes[index] = 0;
    for (u32 index = 0; index != sizeof(key); ++index)
        data.key[index] = key[index];
    data.key_len = sizeof(key);
    data.checksum = OTP_KEY2_CRC;
    cache(&data, sizeof(data));
    u64 result = otp_smc(OTP_WRITE_KEY2, (u64)&data);
    if (result)
        return result;
    show(line, GREEN, "KEY FUSED");
    result = otp_smc(OTP_USE_KEY2, 0);
    if (!result)
        show(line, GREEN, "USE KEY FUSED");
    return result;
}

static int hash_ok(const void *data, u32 size, const u8 expected[32])
{
    u8 digest[32];
    return !sha256(data, size, digest) && same32(digest, expected);
}

static const struct entry *entry(const struct header *header, u32 index)
{
    return (const void *)(bundle_start + sizeof(*header) +
                          index * sizeof(struct entry));
}

static int check_bundle(const struct header *header)
{
    if (header->magic != MAGIC || header->version != 1 ||
        header->header_size != sizeof(*header) ||
        header->total_size != BUNDLE_SIZE ||
        header->count != BUNDLE_EXPECTED_COUNT ||
        header->entry_size != sizeof(struct entry) ||
        header->pit_index != BUNDLE_PIT_INDEX ||
        header->dictionary_size != BUNDLE_DICTIONARY_SIZE ||
        !hash_ok(bundle_start + sizeof(*header),
                 header->total_size - sizeof(*header), header->hash))
        return 1;
    return 0;
}

static int decode(const struct header *header, u32 index, void *output)
{
    const struct entry *item = entry(header, index);
    return lzma_decode(output, item->raw_size,
                       bundle_start + item->offset, item->packed_size,
                       (void *)LZMA_WORKSPACE_ADDRESS,
                       LZMA_WORKSPACE_CAPACITY) ||
           !hash_ok(output, item->raw_size, item->hash);
}

static const struct pit_entry *partition(const u8 *pit, u32 size,
                                         const char file[32], int pit_target)
{
    if (size < PIT_HEADER + PIT_TRAILER || *(const u32 *)pit != PIT_MAGIC)
        return 0;
    u32 count = *(const u32 *)(pit + 4);
    if (!count || count > 128 || PIT_HEADER + count * PIT_ENTRY + PIT_TRAILER != size)
        return 0;
    const struct pit_entry *found = 0;
    for (u32 index = 0; index != count; ++index) {
        const struct pit_entry *item = (const void *)(pit + PIT_HEADER + index * PIT_ENTRY);
        int match = pit_target ? *(const u32 *)item->name == 0x00544950U
                               : same32(item->flash_file, file);
        if (match) {
            if (found)
                return 0;
            found = item;
        }
    }
    return found;
}

static int valid_partition(const struct pit_entry *part, u32 size)
{
    return part && !part->binary_type && part->device_type == 8 &&
           part->lun <= 7 && part->block_count &&
           (u64)part->block_count * 0x1000 >= size;
}

static int flash(const struct pit_entry *part, const void *data,
                 u32 size, const u8 hash[32])
{
    u8 *readback = (void *)READBACK_ADDRESS;
    u32 done = 0;
    while (done != size) {
        u32 count = size - done;
        if (count > CHUNK)
            count = CHUNK;
        cache((u8 *)data + done, count);
        if (bwrite((const u8 *)data + done, part->lun,
                   (part->block_start << (PIT_SHIFT - BLK_SHIFT)) +
                       (done >> BLK_SHIFT), count))
            return 1;
        cache(readback + done, count);
        if (bread(readback + done, part->lun,
                  (part->block_start << (PIT_SHIFT - BLK_SHIFT)) +
                      (done >> BLK_SHIFT), count))
            return 1;
        cache(readback + done, count);
        done += count;
    }
    return !hash_ok(readback, size, hash);
}

static int flash_all(u32 *line)
{
    const struct header *header = (const void *)bundle_start;
    int result = 1;
    if (check_bundle(header))
        goto integrity_fail;
    const struct entry *pit_item = entry(header, header->pit_index);
    if (decode(header, header->pit_index, (void *)PIT_ADDRESS)) {
        result = 2;
        goto integrity_fail;
    }
    const u8 *pit = (const void *)PIT_ADDRESS;

    for (u32 index = 0; index != header->count; ++index) {
        const struct entry *item = entry(header, index);
        void *output = index == header->pit_index ? (void *)PIT_ADDRESS
                                                  : (void *)DECOMPRESS_ADDRESS;
        if (decode(header, index, output) ||
            !valid_partition(partition(pit, pit_item->raw_size, item->file,
                                       index == header->pit_index),
                             item->raw_size)) {
            result = 3;
            goto integrity_fail;
        }
    }

    show(line, GREEN, "ALL HASH MATCH");
    result = fuse_key2(line);
    if (result)
        return result;
    show(line, WHITE, "FLASH BEGIN");
    for (u32 index = 0; index != header->count; ++index) {
        const struct entry *item = entry(header, index);
        if (index == header->pit_index)
            continue;
        if (decode(header, index, (void *)DECOMPRESS_ADDRESS) ||
            flash(partition(pit, pit_item->raw_size, item->file, 0),
                  (const void *)DECOMPRESS_ADDRESS, item->raw_size, item->hash)) {
            show(line, RED, "FLASH FAIL");
            return 4;
        }
    }

    result = flash(partition(pit, pit_item->raw_size, pit_item->file, 1),
                   pit, pit_item->raw_size, pit_item->hash);
    show(line, result ? RED : GREEN, result ? "FLASH FAIL" : "FLASH DONE");
    return result ? 5 : 0;

integrity_fail:
    show(line, RED, "PAYLOAD INTEGRITY FAIL");
    return result;
}

__attribute__((used)) u32 start_impl(void *response, u32 response_size)
{
    *(volatile u64 *)SEND_CALLBACK = SEND_CALLBACK_DEFAULT;
    u32 line = screen_cursor();
    u32 result = flash_all(&line);
    ((u32 *)response)[1] = result ? 0xE0000000U | result : RESULT_OK;
    cache(response, response_size);
    return send_response(response, response_size);
}

_Static_assert(sizeof(struct header) == 64, "bundle header");
_Static_assert(sizeof(struct entry) == 128, "bundle entry");
_Static_assert(sizeof(struct pit_entry) == PIT_ENTRY, "PIT entry");
_Static_assert(sizeof(struct otp_data) == 192, "OTP data");
_Static_assert(LOADER_SOC_ID == BUNDLE_SOC_ID, "SoC mismatch");
_Static_assert(BUNDLE_DICTIONARY_SIZE == LZMA_DICTIONARY_SIZE,
               "LZMA dictionary");
_Static_assert(LZMA_WORKSPACE_CAPACITY >= LZMA_WORKSPACE_REQUIRED,
               "LZMA workspace");
_Static_assert(DECOMPRESS_CAPACITY >= LZMA_DICTIONARY_SIZE,
               "LZMA output history");
_Static_assert(READBACK_CAPACITY >= DECOMPRESS_CAPACITY,
               "readback capacity");
