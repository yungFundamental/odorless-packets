#ifndef FRAME_ANALYSIS_H
#define FRAME_ANALYSIS_H

#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */

#define MIN_TCP_SEGMENT_LEN 20

/*
 * Return the pointer to the IP header portion of the ethernet frame.
 * If there is no such portion - return NULL
 */
struct ip *get_ip_header(struct ether_header *frame);

/*
 * Return the pointer to the TCP header portion of the IP packet.
 * If there is no such portion - return NULL
 */
struct tcphdr *get_tcp_header(struct ip *packet);

/*
 * Return the pointer to the TCP header portion of the IP packet.
 * If there is no such portion - return NULL
 */
u_char *get_tcp_payload(struct tcphdr *segment);

/*
 * Return the pointer to the TCP payload portion of the network frame.
 * If there is no such portion - return NULL
 */
u_char *find_tcp_payload(u_char *frame, size_t len);

#endif // FRAME_ANALYSIS_H

