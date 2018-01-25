/*
 *  Cyclic Redundancy Code (32-bit)
 *
 *  Based on code from http://www.w3.org/TR/PNG/#D-CRCAppendix
 */
#ifndef _CRC32_H
#define _CRC32_H

#include <stdint.h>

// Table of CRCs of all 8-bit messages.
static uint32_t crc_table[256];

static int crc_table_computed = 0;

// Make table for a fast CRC.
static void make_crc_table(void) {
    uint32_t c, n;
    int k;

    for (n = 0; n < 256; n++) {
        c = n;
        for (k = 0; k < 8; k++) {
            c = c & 1 ? 0xedb88320L ^ (c >> 1) : c >> 1;
        }
        crc_table[n] = c;
    }
    crc_table_computed = 1;
}

static uint32_t crc32(const uint8_t *buf, int len) {
    uint32_t c = -1;  // 0xffffffff
    if (!crc_table_computed)
        make_crc_table();
    for (int n = 0; n < len; n++)
        c = crc_table[(c ^ buf[n]) & 0xff] ^ (c >> 8);
    return ~c;
}

static int check_fcs(const uint8_t *buf, int len) {
    return crc32(buf, len - 4) == *(uint32_t *)(buf + len - 4);
}

#endif /* _CRC32_H */
