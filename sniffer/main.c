#include "frame_analysis.h"
#include <net/ethernet.h>
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

// char *get_packet_data(const u_char *packet)
// {
// }
//
// void parse_ip_packet(const u_char *packet)
// {
//     struct in_addr src, dst;
//     struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));
//
//     src.s_addr = ip_hdr->ip_src.s_addr;
//     dst.s_addr = ip_hdr->ip_dst.s_addr;
//
//     printf("\t\tFrom: %s\n", inet_ntoa(src));
//     printf("\t\tTo: %s\n", inet_ntoa(dst));
//     printf("\tVersion: %d\n", (unsigned int)ip_hdr->ip_v);
//     printf("\tHeader Length: %d bytes\n",((unsigned int)(ip_hdr->ip_hl))*4);
//     printf("\tType of Service: %d\n", (unsigned int)ip_hdr->ip_tos);
//     printf("\tTotal Length: %d  bytes\n", ntohs(ip_hdr->ip_len));
//     printf("\tIdentification: %d\n", ntohs(ip_hdr->ip_id));
//     printf("\tTime to live: %d\n", (unsigned int)ip_hdr->ip_ttl);
//     printf("\tProtocol: %d\n", (unsigned int)ip_hdr->ip_p);
//     printf("\tChecksum: %d\n", ntohs(ip_hdr->ip_sum));
// }
//
// void parse_ethernet_packet(const u_char *packet, struct pcap_pkthdr *hdr)
// {
//     int i;
//     struct ether_header *eptr;  /* net/ethernet.h */
//     u_char *ptr; /* printing out hardware header info */
//
//     printf("Grabbed packet of length %d\n",hdr->len);
//     printf("Recieved at ..... %s\n",ctime((const time_t*)&hdr->ts.tv_sec)); 
//     printf("Ethernet address length is %d\n",ETHER_HDR_LEN);
//
//     /* lets start with the ether header... */
//     eptr = (struct ether_header *) packet;
//
//     /* check to see if we have an ip packet */
//     if (ntohs (eptr->ether_type) == ETHERTYPE_IP)
//     {
//         printf("Ethernet type hex:%x dec:%d is an IP packet\n",
//                 ntohs(eptr->ether_type),
//                 ntohs(eptr->ether_type));
//         parse_ip_packet(packet);
//     }else  if (ntohs (eptr->ether_type) == ETHERTYPE_ARP)
//     {
//         printf("Ethernet type hex:%x dec:%d is an ARP packet\n",
//                 ntohs(eptr->ether_type),
//                 ntohs(eptr->ether_type));
//     }else {
//         printf("Ethernet type %x not IP", ntohs(eptr->ether_type));
//         exit(1);
//     }
//
//     ptr = eptr->ether_dhost;
//     i = ETHER_ADDR_LEN;
//     printf(" Destination Address:  ");
//     do{
//         printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
//     }while(--i>0);
//     printf("\n");
//
//     ptr = eptr->ether_shost;
//     i = ETHER_ADDR_LEN;
//     printf(" Source Address:  ");
//     do{
//         printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
//     }while(--i>0);
//     printf("\n");
// }

int main(int argc, char **argv)
{
    int i;
    char *payload;
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    const u_char *packet;
    struct pcap_pkthdr hdr;     /* pcap.h */
    pcap_if_t *all_devices;
    pcap_if_t *dev_i;



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

    /* open the device for sniffing.

       pcap_t *pcap_open_live(char *device,int snaplen, int prmisc,int to_ms,
       char *ebuf)

       snaplen - maximum size of packets to capture in bytes
       promisc - set card in promiscuous mode?
       to_ms   - time to wait for packets in miliseconds before read
       times out
       errbuf  - if something happens, place error string here
     */

    /* get packet capture descriptor from capture.  Note if you change
       "prmisc" param to anything other than zero, you will get all
       packets your device sees, whether they are intendeed for you or 
       not!! Be sure you know the rules of the network you are running
       on before you set your card in promiscuous mode or you could get
       yourself in serious doo doo!!! (also need to be root to run in
       promisuous mode)                                               */
    descr = pcap_open_live(dev,BUFSIZ, 0, 2000, errbuf);

    if(descr == NULL)
    {
        printf("pcap_open_live(): %s\n",errbuf);
        exit(1);
    }


    /* grab a packet from descr (yay!)                    */
    /* const u_char *pcap_next(pcap_t *p,struct pcap_pkthdr *h) */
    /* so just pass in the descriptor we got from         */
    /* our call to pcap_open_live and an allocated        */ 
    /* struct pcap_pkthdr                                 */
    packet = pcap_next(descr,&hdr);

    if(packet == NULL)
    {
        printf("Didn't grab packet\n");
        exit(1);
    }

    payload = (char *)find_tcp_payload(packet, hdr.len);
    if (payload)
        printf("Payload: %s\n", payload);
    else 
        printf("No payload found!\n");

    pcap_close(descr);
    pcap_freealldevs(all_devices);
    return 0;
}

