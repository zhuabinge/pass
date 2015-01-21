#ifndef SPO_SPOOFER_H
#define SPO_SPOOFER_H

#include <sys/types.h>

#define SPO_HTTP_SEND_MSG_TYPE  (1)
#define SPO_MSG_HP      (0)
#define SPO_MSG_DNS     (1)

/**
 *  when we catch a http get request packet, we record the request's info.
 *
 *  we use these info to build the response packet, and send it to client.
 *
 **/

struct spo_http_hijack_info_s {
    u_char src_mac[ETHER_ADDR_LEN];                  /* 6 bytes mac src address */
    u_char dst_mac[ETHER_ADDR_LEN];                  /* 6 bytes mac dst address */

    u_long ip_src_addr;                 /* ip's src address */
    u_long ip_dst_addr;                 /* ip's dst address */

    /**
     *  tcp_next_seq = ip->total_len - tcp->head_len - ip->head_len
     *  so we can compute it by follow :
     *  int len = (u_int)ntohs(ip->ip_len) - ((u_int)(tcp->tcp_offx2 >> 2) + LIBNET_IPV4_H)
     **/

    u_int tcp_next_seq;                 /* is the tcp ack seq for response, we have to compute it */

    u_int tcp_resp_seq;                 /* tcp response's seq, we compute and save it here */
    u_int tcp_resp_Ack;                 /* tcp response's Ack, we compute and save it here  */

    u_int tcp_rst_resp_seq;             /* when we send rst response packet, we have to compute the rst resp seq */
    u_int tcp_rst_resp_Ack;             /* when we send rst response packet, we have to compute the rst resp Ack */

    int tcp_op_len;                     /* if this tcp packet has option, we save it len */

    u_short vlan_id;

    u_short tcp_src_port;               /* tcp's src port  */
    u_short tcp_dst_port;               /* tcp's dst port  */

    u_short ip_len;                     /* ip's total len */
    u_short ip_off;                     /* ip offset */

    uint8_t tcp_resp_flg;               /* tcp's flage, we save it, and used in response packet */
    char vlan_targe;                    /* running in vlan ? */
    uint8_t tcp_op[40];                 /* tcp option the largest is 40 byte */
};


/* Storage for Packet Generation */
struct spo_dns_hijack_info_s  {
    u_char src_mac[ETHER_ADDR_LEN];
    u_char dst_mac[ETHER_ADDR_LEN];

    u_short vlan_id;

    u_long  src_address;                /* source address               */
    u_long  dst_address;                /* destination address          */

    u_short src_port;                   /* source port                  */
    u_short dst_port;                   /* destination port             */
    u_short ip_off;

    u_short dns_id;
    u_short dns_flag;
    u_short dns_ques;
    u_short dns_ans;
    u_short dns_auth;
    u_short dns_add;
    char vlan_targe;
};

void spo_http_spoofer(void *proc_infos);
void spo_dns_spoofer(void *proc_infos);

#endif // SPO_SPOOFER_H
