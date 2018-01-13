/*
 * WLAN Activity Monitoring
 *
 * Outputs source MAC addresses for all captured WLAN data packets
 * 
 * Compile: gcc -std=c99 -O3 -lpcap macmon.c   
 */

#include <pcap.h>

#include "crc32.h"
#include "proto.h"

// callback function invoked for every incoming packet
void packet_handler(u_char *param, const struct pcap_pkthdr *pkt_hdr, const u_char *pkt) {
    // unused parameters
    (void)(param);

    u_int len = pkt_hdr->caplen;

    struct ieee80211_radiotap_header *radiotap;
    struct ieee80211_header *wlan;

    if (len < sizeof(struct ieee80211_radiotap_header)) {
        // fprintf(stderr, "Error: Packet too small for radiotap header!\n");
        return;
    }
    radiotap = (struct ieee80211_radiotap_header *)pkt;

    pkt += radiotap->length;
    len -= radiotap->length;

    if (len < sizeof(struct ieee80211_header)) {
        // fprintf(stderr, "Packet too short for ieee802.11 header\n");
        return;
    }
    wlan = (struct ieee80211_header *)pkt;

    // only consider data frames (already checked by bpf filter)
    // if(FC_TYPE(wlan) != DATA_FRAME) return;

    // verify frame check sequence (FCS),
    // frames without FCS will be discarded as well
    if (!check_fcs(pkt, len - 4)) {
        // fprintf(stderr, "Incorrect FCS\n");
        return;
    }

    // source address
    u_char *sa;

    switch (FC_DS_STATUS(wlan)) {
        case ADHOC: sa = wlan->addr2; break;
        case TO_DS: sa = wlan->addr2; break;
        case FROM_DS: sa = wlan->addr3; break;
        case WDS:  // TODO: ignore wds?
        default:
            return;
    }

    printf("%02X:%02X:%02X:%02X:%02X:%02X", sa[0], sa[1], sa[2], sa[3], sa[4], sa[5]);
    // printf(" -> ");
    // printf("%02X:%02X:%02X:%02X:%02X:%02X", da[0], da[1], da[2], da[3], da[4], da[5]);
    printf("\n");
}

int install_data_frame_filter(pcap_t *handle) {
    // filter wlan data frames
    char filter[] = "type data";

    // compiled filter expression
    struct bpf_program fp;

    // compile the filter with optimization (1) and any netmask (0)
    if (pcap_compile(handle, &fp, filter, 1, 0) == -1) {
        return 1;
    }

    // activate the filter
    if (pcap_setfilter(handle, &fp) == -1) {
        return 1;
    }

    return 0;
}

void print_adapter_list() {
    pcap_if_t *dev_list;
    char err_buf[PCAP_ERRBUF_SIZE];

    // retrieve device list
    if (pcap_findalldevs(&dev_list, err_buf) == -1) {
        fprintf(stderr, "Error retrieving device list: %s\n", err_buf);
        return;
    }

    // print list of devices (adapters)
    if (!dev_list) {
        printf("No devices found. Be sure to run as root!");
    } else {
        printf("Select one of the following adapters:\n\n");
        printf("Adapter name    Description\n");
        for (pcap_if_t *dev = dev_list; dev; dev = dev->next) {
            printf("%-16s", dev->name);
            printf("%s\n", dev->description ? dev->description : "N/A");
        }
    }

    pcap_freealldevs(dev_list);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: macmon <adapter>\n\n");
        print_adapter_list();
        return 1;
    }

    char *dev_name = argv[1];
    char err_buf[PCAP_ERRBUF_SIZE];

    pcap_t *ad_handle = pcap_create(dev_name, err_buf);
    if (ad_handle == NULL) {
        fprintf(stderr, "Unable to open the adapter '%s': %s\n", dev_name, err_buf);
        return 1;
    }

    if (pcap_set_rfmon(ad_handle, 1) == PCAP_ERROR_ACTIVATED) {
        fprintf(stderr, "Unable to put the adapter '%s' into monitor mode!\n", dev_name);
        // return 1;
    }

    pcap_set_snaplen(ad_handle, 2048);  // set snapshot length in bytes (65536 is whole)
    pcap_set_timeout(ad_handle, 512);   // set timeout in milliseconds (tcpdump uses 1000)
    // pcap_set_promisc(ad_handle, 0);  // turn promiscuous mode off

    // open the adapter
    if (pcap_activate(ad_handle) != 0) {
        pcap_perror(ad_handle, "Unable to start the capture");
        printf("\n");
        print_adapter_list();
        return 1;
    }

    // TODO: it's probably not even possible to get here if not in monitor mode.
    // check link layer
    if (pcap_datalink(ad_handle) != DLT_IEEE802_11_RADIO) {
        if (pcap_datalink(ad_handle) == DLT_EN10MB) {
            fprintf(stderr, "\nPlease put the adapter in monitor mode!\n");
        } else {
            fprintf(stderr, "\nThis program only supports ethernet adapters!\n");
        }
        return 1;
    }

    // only capture wlan data frames
    if (install_data_frame_filter(ad_handle) != 0) {
        pcap_perror(ad_handle, "Could not install capture filter");
        return 1;
    }

    // printf("Scanning incomming packets on %s (Ctrl+C to exit)\n\n", dev_name);

    // start capture
    if (pcap_loop(ad_handle, 0, packet_handler, 0) == -1) {
        pcap_perror(ad_handle, "An error ocurred during capture");
    }

    pcap_close(ad_handle);
    return 0;
}
