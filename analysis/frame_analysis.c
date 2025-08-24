#include "frame_analysis.h"
#include <stdlib.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <sys/types.h>

struct ip *get_ip_header(struct ether_header *frame)
{
    u_char *frame_p = (u_char *)frame;
    if (frame == NULL)
    {
        return NULL;
    }
    if (ntohs(frame->ether_type) == ETHERTYPE_IP)
    {
        return (struct ip *)(frame_p + sizeof(struct ether_header));
    }
    return NULL;
}

struct tcphdr *get_tcp_header(struct ip *packet)
{
    u_char *packet_p = (u_char *)packet;
    if (packet == NULL)
    {
        return NULL;
    }
    if (packet->ip_p == IPPROTO_TCP)
    {
        return (struct tcphdr *)(packet_p + (packet->ip_hl * 4));
    }
    return NULL;
}

u_char *get_tcp_payload(struct tcphdr *segment)
{
    if (segment == NULL)
    {
        return NULL;
    }
    u_char *segment_p = (u_char *)segment;
    return segment_p + (segment->th_off * 4);
}

u_char *find_tcp_payload(u_char *frame, size_t len)
{
    u_char *eof, *ip, *tcp;
    if (len < MIN_TCP_SEGMENT_LEN)
    {
        return NULL;
    }
    eof = frame + len;
    ip = (u_char *)get_ip_header((struct ether_header *)frame);
    if (ip == NULL || ip >= eof)
    {
        return NULL;
    }
    tcp = (u_char *)get_tcp_header((struct ip *)ip);
    if (tcp == NULL || tcp >= eof)
    {
        return NULL;
    }
    
    return get_tcp_payload((struct tcphdr *)tcp);
}

