#ifndef SPO_SNIFFER_H
#define SPO_SNIFFER_H

#include <sys/types.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <libnet.h>

#define SPO_VLAN_LEN (4)

#define SPO_IP_OFFSET   (LIBNET_ETH_H)  /* 14 */
#define SPO_TCP_OFFSET  (LIBNET_ETH_H + LIBNET_IPV4_H)  /* 34 */
#define SPO_UDP_OFFSET  (LIBNET_ETH_H + LIBNET_IPV4_H)  /* 34 */
#define SPO_DNS_OFFSET  (LIBNET_ETH_H + LIBNET_IPV4_H + LIBNET_UDP_H)   /* 42 */

#define SPO_VLAN_OFFSET (LIBNET_ETH_H)  /* 14 */

#define SPO_IP_OFFSET_VLAN   (LIBNET_ETH_H + SPO_VLAN_LEN)  /* 18 */
#define SPO_TCP_OFFSET_VLAN  (LIBNET_ETH_H + SPO_VLAN_LEN + LIBNET_IPV4_H)  /* 38 */
#define SPO_UDP_OFFSET_VLAN  (LIBNET_ETH_H + SPO_VLAN_LEN + LIBNET_IPV4_H)  /* 38 */
#define SPO_DNS_OFFSET_VLAN  (LIBNET_ETH_H + SPO_VLAN_LEN + LIBNET_IPV4_H + LIBNET_UDP_H)   /* 46 */


#define SPO_VLAN_PROT_MASK  0xe000  /* prot is 3 bit */
#define SPO_VLAN_CFI_MASK   0x1000  /* vlan cfi is 1 bit */
#define SPO_VLAN_ID_MASK    0x0fff  /* vlan id is 12 bit */

#define SPO_PKT_MSG_TYPE (1)                     /* the msg type of packet */

#define SPO_PROTOCOL_OFFSET (SPO_IP_OFFSET + 10)
#define SPO_PROTOCOL_OFFSET_VLAN (SPO_IP_OFFSET_VLAN + 10)


#define SPO_SPACE   (0x20)  /* the char ' ' is 0x20 */

#define SPO_LF     (u_char) '\n'    /* 0x0a */
#define SPO_CR     (u_char) '\r'    /* 0x0d */
#define SPO_CRLF   "\r\n"


/* get the string len */

#define SPO_REFERER_STR_LEN ((strlen("referer")) + 2)   /* the string len */
#define SPO_REFERER_VAR_LEN (9)

#define SPO_COOKIE_STR_LEN  ((strlen("cookie")) + 2)    /*  */
#define SPO_COOKIE_VAR_LEN  (8)

#define SPO_HOST_STR_LEN    ((strlen("host")) + 2)
#define SPO_HOST_VAR_LEN    (6)

#define SPO_RUNNING_IN_VLAN (1)

#define SPO_MAX_QUE_METHOD (10)


/**
 *
 * The following struct is for the tcp/ip net level.
 *
 **/

typedef struct spo_sniff_ether_s {
    u_char ether_dhost[ETHER_ADDR_LEN];                 /* dst mac address */
    u_char ether_shost[ETHER_ADDR_LEN];                 /* src mac address */
    u_short ether_type;                                 /* ether type */
}spo_sniff_ether_t;


typedef struct spo_sniff_ip_s {
    u_char ip_vhl;
    #define IP_V(ip) (((ip)->ip_vhl & 0xf0) >> 4)       /* ip version */
    #define IP_HL(ip) ((ip)->ip_vhl & 0x0f)             /* ip header length */

    u_char ip_tos;
    u_short ip_len;                                     /* ip total len */
    u_short ip_id;                                      /* ip's id */
    u_short ip_off;                                     /* ip fragment offset */


    #define IP_RF 0x8000
    #define IP_DF 0x4000
    #define IP_MF 0x2000
    #define IP_OFFMASK 0x1fff

    u_char ip_ttl;                                      /* ip's ttl */
    u_char ip_p;                                        /*ip protocol*/
    u_short ip_sum;                                     /*ip check sum*/

    struct in_addr ip_src;                              /* ip src address */
    struct in_addr ip_dst;                              /* ip dst address */
}spo_sniff_ip_t;


typedef u_int tcp_seq_t;

typedef struct spo_sniff_tcp_s {
    u_short tcp_sport;                                  /* tcp src port */
    u_short tcp_dport;                                  /* tcp dst port */
    tcp_seq_t tcp_seq;                                  /* tcp current seq */
    tcp_seq_t tcp_ack;                                  /* tcp ack */

    u_char tcp_offx2;                                   /* tcp header len, just 6 bit */
    u_char tcp_flags;                                   /* tcp flag */

    u_short tcp_win;                                    /* tcp win size */
    u_short tcp_sum;                                    /* tcp sum check */
    u_short tcp_urp;                                    /* Urgent Pointer */
}spo_sniff_tcp_t;


typedef struct spo_sniff_udp_s {
    u_short udp_sport;                                  /* udp src port */
    u_short udp_dport;                                  /* udp dst port */
    u_short udp_len;                                    /* udp total length */
    u_short udp_sum;                                    /* udp check sum */
}spo_sniff_udp_t;


typedef struct spo_sniff_dns_s {
    u_short dns_id;                                     /* dns id */
    u_short dns_flag;                                   /* dns flg */
    u_short dns_ques;                                   /* question amount */
    u_short dns_ans;                                    /* answer amount */
    u_short dns_auth;                                   /*  */
    u_short dns_add;
}spo_sniff_dns_t;


/* update log */
void spo_updata_log(int type, char *log_info);

inline SPO_RET_BOOLEN spo_is_802_1q_vlan(const u_char *packet);
inline size_t spo_packet_size(const u_char *packet);
inline short spo_get_tcp_options_len(const u_char *packet);
inline const u_char *spo_http_start(const u_char *packet);


void spo_http_spoofer(void *proc_infos);
void spo_dns_spoofer(void *proc_infos);


void spo_sniffers(void *info_blk);

#endif // SPO_SNIFFER_H
