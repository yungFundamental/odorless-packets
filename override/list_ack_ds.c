#include "ack_ds.h"
#include <stdlib.h>

typedef struct ack_node {
    tcp_ack ack;
    struct ack_node *next;
} ack_node, ack_list;

// ASSUMES THAT ack_ds == ack_node *

u_char ack_cmp(tcp_ack ack1, tcp_ack ack2)
{
    return ack1.ack_seq == ack2.ack_seq && ack1.dport == ack2.dport && ack1.sport == ack2.sport;
}

ack_node *get_node_before(ack_ds head, tcp_ack ack)
{
    ack_node *i;
    if (head == NULL)
        return NULL;
    
    if (ack_cmp(ack, head->ack))
        return head;
    
    for (i = head; i->next != NULL; i = i->next)
         if (ack_cmp(i->ack, ack))
            return i;
    return NULL;
}

void destroy_next_ack_node(ack_node *an)
{
    ack_node *new_next; 
    if (an->next == NULL)
        return;
    new_next = an->next->next;
    free(an->next);
    an->next = new_next;
}

ack_ds create_ack_ds()
{
    return NULL;
}

void destroy_ack_ds(ack_ds *head)
{
    ack_node *i;
    ack_node *next;
    if (head == NULL)
        return;

    for (i = *head; i != NULL; i = next)
    {
        next = i->next;
        free(i);
    }
}

u_char is_ack_kept(ack_ds head, unsigned int src_port, unsigned int dst_port, unsigned int ack_seq)
{
    tcp_ack ack = {src_port, dst_port, ack_seq};
    return get_node_before(head, ack) != NULL;
}

/*
* Add ack to the data structure. Return 1 if successfully added, 0 if not.
*/
u_char add_ack(ack_ds *, unsigned int src_port, unsigned int dst_port, unsigned int ack_seq);

u_char remove_ack(ack_ds *head, unsigned int src_port, unsigned int dst_port, unsigned int ack_seq)
{
    ack_node *prev;
    tcp_ack ack = {src_port, dst_port, ack_seq};
    if (head == NULL || *head == NULL)
        return 0;
    if (ack_cmp((*head)->ack, ack))
    {
        prev = *head;
        *head = prev->next;
        free(prev);
        return 1;
    }
    prev = get_node_before(*head, ack);
    if (prev == NULL)
        return 0;
    destroy_next_ack_node(prev);
    return 1;
}
