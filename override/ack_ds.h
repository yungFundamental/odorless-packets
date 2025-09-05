#ifndef ACK_KEEPING_H
#define ACK_KEEPING_H

#include <sys/types.h>

// Which data structure implementation to use can be altered in the following line:
typedef struct ack_node *ack_ds;

typedef struct ack {
    unsigned int sport;     /* Source port number */
    unsigned int dport;     /* Destination port number */  
    unsigned int ack_seq;   /* Acknowledgement sequence number */
}tcp_ack;


/*
 * Return empty ack datastructure
 */
ack_ds create_ack_ds();

void destroy_ack_ds(ack_ds *);

/*
* Return 1 if the ack is kept in the data structure, 0 if not.
*/
u_char is_ack_kept(ack_ds, unsigned int src_port, unsigned int dst_port, unsigned int ack_seq);

/*
* Add ack to the data structure. Return 1 if successfully added, 0 if not.
*/
u_char add_ack(ack_ds *, unsigned int src_port, unsigned int dst_port, unsigned int ack_seq);

/*
* Remove ack from the datastructure.
* return 1 if found and successfully removed, return 0 if the ack wasn't found and removed successfully.
*/
u_char remove_ack(ack_ds *, unsigned int src_port, unsigned int dst_port, unsigned int ack_seq);


#endif // !ACK_KEEPING_H
