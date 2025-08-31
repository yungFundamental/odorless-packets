#include "frame_analysis.h"
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
    u_char *payload;
    u_int payload_len;
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    const u_char *packet;
    struct pcap_pkthdr hdr;     /* pcap.h */
    pcap_if_t *all_devices;
    pcap_if_t *dev_i;
    struct tcphdr *tcp_hdr;
    u_int i;



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
        if (tcp_hdr != NULL)
        {
            printf("%ld.%06ld: ", hdr.ts.tv_sec, hdr.ts.tv_usec);
            printf("TCP SEGMENT\n");

            printf("\tPorts: %d->%d\n", ntohs(tcp_hdr->th_sport), ntohs(tcp_hdr->th_dport));
            printf("\tSequence Number: %u, Acknowledgement Number: %u\n", ntohl(tcp_hdr->seq), ntohl(tcp_hdr->ack_seq));
            printf("\tFlags: %s%s%s%s%s%s", 
                   (tcp_hdr->syn) ? "SYN " : "",
                   (tcp_hdr->ack) ? "ACK " : "",
                   (tcp_hdr->psh) ? "PSH " : "",
                   (tcp_hdr->urg) ? "URG " : "",
                   (tcp_hdr->rst) ? "RST " : "",
                   (tcp_hdr->fin) ? "FIN " : ""
                   );
            printf("\n");
            payload = get_tcp_payload(tcp_hdr);
            payload_len = (packet + hdr.len) - payload;
            if (payload_len > 0)
            {
                printf("\tPayload:\n");
                printf("\t\tLength: %u\n", payload_len);
                printf("\t\tHexadecimal:");
                for (i = 0; i < payload_len; i++)
                    printf(" %02X", payload[i]);

                printf("\n\t\tASCII: ");
                for (i = 0; i < payload_len; i++)
                    printf("%c", payload[i]);
            }
        }
    }

    printf("Closing capture...\n");
    pcap_close(descr);
    pcap_freealldevs(all_devices);
    return 0;
}

