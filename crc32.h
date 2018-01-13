/*
 *  Cyclic Redundancy Code (32-bit)
 *
 *  Based on code from http://www.w3.org/TR/PNG/#D-CRCAppendix
 *  TODO: cleanup!
 */

/* Table of CRCs of all 8-bit messages. */
static u_long crc_table[256];

/* Flag: has the table been computed? Initially false. */
static int crc_table_computed = 0;

/* Make the table for a fast CRC. */
static void make_crc_table(void) {
    u_long c;
    int n, k;

    for (n = 0; n < 256; n++) {
        c = (u_long)n;
        for (k = 0; k < 8; k++) {
            if (c & 1)
                c = 0xedb88320L ^ (c >> 1);
            else
                c = c >> 1;
        }
        crc_table[n] = c;
    }
    crc_table_computed = 1;
}

// Return the CRC of the bytes buf[0..len-1].
// static unsigned long crc32_x(unsigned char *buf, int len) {
//     unsigned long c = 0xffffffffL;
//     int n;
//     for (n = 0; n < len; n++)
//         c = crc_table[(c ^ buf[n]) & 0xff] ^ (c >> 8);
//     return c ^ 0xffffffffL;
// }

#define XF 0xffffffffL

static u_long crc32_xsx(const u_char *buf, int len) {
    u_long c = XF;
    int n;
    if (!crc_table_computed)
        make_crc_table();
    for (n = 0; n < len; n++)
        c = crc_table[(c ^ buf[n]) & 0xff] ^ (c >> 8);
    return c ^ XF;
}

/* CRC checksum verification routine from aircrack-ng */

static int check_fcs(const u_char *buf, int len) {
    u_long crc;
    crc = crc32_xsx(buf, len);
    buf += len;
    return  ( (crc      ) & 0xFF ) == buf[0] &&
            ( (crc >>  8) & 0xFF ) == buf[1] &&
            ( (crc >> 16) & 0xFF ) == buf[2] &&
            ( (crc >> 24) & 0xFF ) == buf[3];
}

// static int check_fcs2(const u_char *buf, int len) {
//     return crc32_xsx(buf, len) == (*((u_long *)(buf + len)) & XF);
// }
