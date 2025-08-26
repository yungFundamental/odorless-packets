
#include <dlfcn.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

static u_char *(*og_pacp_next)(pcap_t *, struct pcap_pkthdr *) = NULL;

const u_char *pcap_next(pcap_t *p, struct pcap_pkthdr *h)
{
    u_char *packet;
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


    return packet;

}


