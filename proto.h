#ifndef _PROTO_H
#define _PROTO_H

struct ieee80211_radiotap_header {
    u_int8_t version;  // set to 0
    u_int8_t pad;
    u_int16_t length;   // entire length
    u_int32_t present;  // fields present
} __attribute__((__packed__));

// TODO: currently for data frames (not control and management)
struct ieee80211_header {
    u_int16_t fc;  // frame control
    u_int16_t duration;
    // depending on fc flags
    u_int8_t addr1[6];
    u_int8_t addr2[6];
    u_int8_t addr3[6];
    u_int16_t seq_ctrl;  // sequence number & fragment number
} __attribute__((__packed__));

// frame types
#define MGMT_FRAME 0x00     // management
#define CONTROL_FRAME 0x01  // control
#define DATA_FRAME 0x02     // data

// extract values from the frame control field
#define FC_TYPE(x) ((x->fc >> 2) & 0x03)
#define FC_SUBTYPE(x) ((x->fc >> 4) & 0x0F)
#define FC_TO_DS(x) (x->fc & 0x0100)
#define FC_FROM_DS(x) (x->fc & 0x0200)

#define FC_DS_STATUS(x) ((x->fc >> 8) & 0x03)

#define ADHOC 0x00
#define TO_DS 0x01
#define FROM_DS 0x02
#define WDS 0x03

#endif /* _PROTO_H */
