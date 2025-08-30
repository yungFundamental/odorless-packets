#include "../analysis/frame_analysis.h"
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <string.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */


int main()
{
    char *payload;
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    const u_char *packet;
    struct pcap_pkthdr hdr;     /* pcap.h */
    pcap_if_t *all_devices;
    pcap_if_t *dev_i;
    struct tcphdr *tcp_hdr;



    if(pcap_findalldevs(&all_devices, errbuf))
    {
        printf("%s\n",errbuf);
        exit(1);
    }

    // Find loopback
    for (dev_i = all_devices; dev_i && strcmp(dev_i->name, "lo"); dev_i = dev_i->next);
    if (!dev_i)
    {
      fprintf(stderr, "Loopback device not found!\n");
      exit(1);
    }
    dev = dev_i->name;

    printf("DEV: %s\n",dev);
    printf("Description: %s\n", dev_i->description);

    descr = pcap_open_live(dev,BUFSIZ, 0, 2000, errbuf);

    if(descr == NULL)
    {
        printf("pcap_open_live(): %s\n",errbuf);
        exit(1);
    }


    for (packet = pcap_next(descr,&hdr); packet != NULL; packet = pcap_next(descr,&hdr))
    {
        tcp_hdr = find_tcp_segment(packet, hdr.len);
        // TODO Add timestamp print
        if (tcp_hdr == NULL)
        {
            printf("Not a TCP Segment.\n");
        }
        else {
            payload = (char *)get_tcp_payload(tcp_hdr);
            printf("Payload: %s\n", payload);
        }
    }

    printf("Closing capture...\n");
    pcap_close(descr);
    pcap_freealldevs(all_devices);
    return 0;
}

