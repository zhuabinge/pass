#include "../spoofer_system/spoofer.h"
#include "../spoofer_system/spo_system.h"
#include "../spoofer_pool/spo_pool.h"
#include "../spoofer_sniffer/spo_sniffer.h"
#include "../spoofer_config/spo_config.h"
#include "../spoofer_linux/spo_linux.h"
#include "../spoofer_log/spo_log.h"
#include "../spoofer_test/spo_test.h"

#include <pcap.h>
#include <pfring.h>

#include <sys/shm.h>

#define SPO_CATCHED_PKT_LEN 65535
#define SPO_SNIF_POOL_S (8192 * 8)

#define SPO_PF_WATERMARK    (1)

static int pkt_len_ = sizeof(spo_msg_t) + sizeof(spo_packet_t);


/* - - - - - -- - - - -- - - - update - - -- - - - -- - - -- -- - - - --  */

static SPO_RET_STATUS spo_snif_init_sig();
static void spo_rld_hp_data_tmp(int sig, siginfo_t *info, void *p);
static void spo_rld_dns_cfg_tmp(int sig, siginfo_t *info, void *p);
static void spo_rld_hp_cfg_tmp(int sig, siginfo_t *info, void *p);
static void spo_rld_hp_data(int sig, siginfo_t *info, void *p);
static void spo_rld_dns_cfg(int sig, siginfo_t *info, void *p);
static void spo_rld_hp_cfg(int sig, siginfo_t *info, void *p);
static void spo_to_update(spo_proc_node_t *node);

/* -- - - - -  - - - - - -- - -- analysis - - -- -- -- - - - - - - - - --*/


static void spo_http_sniffer_callback_fp_ring(
        const struct pfring_pkthdr *header, const u_char *packet, const u_char *user_bytes);
static void spo_http_sniffer_callback_pcap(u_char *user, const struct pcap_pkthdr *pcap_head, const u_char *packet);
static void spo_sniffer_callback(const u_char *packet, size_t caplen);
static SPO_RET_STATUS spo_protocol_type(const u_char *packet);
static SPO_RET_STATUS
spo_do_dns_sniffer_callback(spo_proc_node_t *p_node, const u_char *packet, size_t caplen, int msgid);
static SPO_RET_STATUS spo_do_http_sniffer_callback(const u_char *packet, size_t caplen, int msgid);
static SPO_RET_STATUS spo_sniff_analy_http_request(spo_packet_t *pkt, const u_char *packet);
static SPO_RET_STATUS spo_http_method_filter(spo_tree_header_t *mtd_header, spo_str_t *mtd);
static SPO_RET_STATUS spo_http_request_method(const u_char *http_start, spo_str_t *mtd, int mtd_off);
static SPO_RET_STATUS spo_http_host(const u_char *packet, spo_packet_t *pkt);


/* -- - - - -  - - - -- - -- - -- init - - -- -- -- - - - - -- - - - --*/

static SPO_RET_STATUS spo_snif_init_pool(spo_proc_node_t *node);
static void spo_sniffer_fp_ring(void *info_blk);
static SPO_RET_STATUS spo_set_pf_dircte(pfring *pd, int driect);
static void spo_sniffer_pcap(void *info_blk);
static SPO_RET_STATUS spo_set_filter(pcap_t *p, const char *filter_exp);


#if SPO_SEE_TIME
static void spo_snif_used_time();
#endif


/**
 *
 *  for test used time
 *
 * */

#if SPO_SEE_TIME
static void spo_snif_used_time()
{
    struct timeval start, *p;
    gettimeofday(&start, 0);
    p = shmat(sys_shmid, NULL, 0);
    p->tv_sec = start.tv_sec;
    p->tv_usec = start.tv_usec;
}
#endif


/**
 *
 *  the packet is in 802.3 -1q vlan ?
 *
 *  @param packet, the packet we catch.
 *
 *  @return the judgment result.
 *
 *  status finished, tested.
 *
 *  ok
 *
 **/

inline SPO_RET_BOOLEN spo_is_802_1q_vlan(const u_char *packet)
{
    spo_sniff_ether_t *eth = (spo_sniff_ether_t *) packet;

    if (ntohs(eth->ether_type) == 0x8100)   return SPO_TRUE;

    return SPO_FALSE;
}


/**
 *
 *  when we catch the http packet, we get the http packets's size in here.
 *
 *  @param packet, is the http packet we catched.
 *
 *  @return size, is the packet total size.
 *
 **/

inline size_t spo_packet_size(const u_char *packet)
{
    size_t packet_size = 0;

    if (spo_is_802_1q_vlan(packet) == SPO_TRUE) {   /* is running vlan env */

        spo_sniff_ip_t *ip =  (spo_sniff_ip_t *) (packet + SPO_IP_OFFSET_VLAN);

        /* packet size eq ip len + vlan header len + eth header len */
        packet_size = ntohs(ip->ip_len) + SPO_IP_OFFSET_VLAN;

        return packet_size;
    }else {

        spo_sniff_ip_t *ip =  (spo_sniff_ip_t *) (packet + LIBNET_ETH_H);

        packet_size = ntohs(ip->ip_len) + LIBNET_ETH_H;

        return packet_size;
    }
}


/**
 *
 *  get the http packet's tcp level options's length.
 *
 *  the option length < 40 byte.
 *
 *  @param packet, is the http request packet we catched.
 *
 *  @return op_len, is the options's length.
 *
 *  ok
 *
 **/

inline short spo_get_tcp_options_len(const u_char *packet)
{
    short op_len = -1;
    spo_sniff_tcp_t *tcp = NULL;

    if (spo_is_802_1q_vlan(packet) == SPO_TRUE) {
        tcp = (spo_sniff_tcp_t *) (packet + SPO_TCP_OFFSET_VLAN);
    }else {
        tcp = (spo_sniff_tcp_t *) (packet + SPO_TCP_OFFSET);
    }

    op_len = (short) ((short)(tcp->tcp_offx2 >> 2) - LIBNET_TCP_H);

    return op_len;
}


/**
 *
 *  get the http request packet start pointer.
 *
 *  @param packet, is the http request packet we catched.
 *
 *  @return http_start, is the http start pointer.
 *
 **/

inline const u_char *spo_http_start(const u_char *packet)
{
    u_char *http_start = NULL;

    if (spo_is_802_1q_vlan(packet) == SPO_TRUE) {
        http_start = (u_char *) (packet + SPO_TCP_OFFSET_VLAN
                                 + LIBNET_TCP_H + spo_get_tcp_options_len(packet));
    }else {
        http_start = (u_char *) (packet + SPO_TCP_OFFSET
                                 + LIBNET_TCP_H + spo_get_tcp_options_len(packet));
    }

    if ((long)spo_packet_size(packet) == (long)(http_start - packet)) return NULL;

    return http_start;
}


/**
 *
 *  when we catched a packet packet, we analysis it.
 *
 *  if this packet is we need, we get it's info that we need and save the info at hjk_info.
 *
 *  after save the info, we send the hjk_info to msg queue.
 *
 *  @param packet, is the packet we catched.
 *
 *  @return exec status.
 *
 **/

static SPO_RET_STATUS spo_http_host(const u_char *packet, spo_packet_t *pkt)
{
    u_char *field = NULL;
    u_char *http_start = NULL;
    size_t i = 0;
    size_t len = ((size_t) pkt->pkt_s - (size_t) pkt->http_s + 3);
    spo_str_t *host = &((spo_str_t *) pkt->pkt_info)[1];

    http_start = (u_char *) (packet + pkt->http_s);
    field = http_start;

    for (i = 0; i <= len; i += 2) {
        if (*(http_start) == SPO_CR) {      //'\r'
            if (*(http_start + 1) == SPO_LF) {
                if (memcmp(field, "Host", 4) == 0) {
                    host->data = field + SPO_HOST_VAR_LEN;
                    host->len = (size_t) (http_start - host->data);
                    return SPO_OK;
                }
            }
            http_start += 2;
            field = http_start;
            continue;
        }

        if (*(http_start) == SPO_LF) {      //'\n
            if (*(http_start - 1) == SPO_CR) {
                if (memcmp(field, "Host", 4) == 0) {
                    host->data = field + SPO_HOST_VAR_LEN;
                    host->len = (size_t) (http_start - host->data -1);
                    return SPO_OK;
                }
            }
            http_start += 1;
            field = http_start;
            continue;
        }

        http_start += 2;
    }

    if (i > len) return SPO_FAILURE;

    return SPO_OK;
}


/**
 *
 *  get the http request packet method.
 *
 *  @param packet, is the packet we catched.
 *
 *  @param method, used to save the method name and name's len.
 *
 *  @return int, is the exec status.
 *
 **/

static SPO_RET_STATUS spo_http_request_method(const u_char *http_start, spo_str_t *mtd, int mtd_off)
{
    u_char *ch = NULL;
    int i = SPO_MAX_QUE_METHOD;

    ch = (u_char *) (((u_char *)http_start) + mtd_off);

    if (*ch == SPO_CR || *ch == SPO_LF) return SPO_FAILURE;

    while (*ch == 0x20 && i >= 0) {    //skip the ' ', hex is 0x20
        ch++;
        i--;
    }

    mtd->data = ch;
    i = SPO_MAX_QUE_METHOD;

    while (*ch != 0x20 && i >= 0) {
        ch++;
        i--;
    }

    if (i < 0) return SPO_FAILURE;

    if ((mtd->len = (size_t)(ch - mtd->data)) == 0) return SPO_FAILURE;

    return SPO_OK;
}


/**
 *
 *  filter the http request method. we need the 'GET'.
 *
 * */

static SPO_RET_STATUS spo_http_method_filter(spo_tree_header_t *mtd_header, spo_str_t *mtd)
{
    if (mtd == NULL || mtd->data == NULL) return SPO_FAILURE;

    if (spo_tree_match(mtd_header, mtd, spo_comp_hp_mtd) == NULL) return SPO_FAILURE;

    return SPO_OK;

    //return spo_comp_string(mtd, (const char *)"GET");
}


/**
 *
 *  analysis the http packet, get the http request host and method.
 *
 * */

static SPO_RET_STATUS spo_sniff_analy_http_request(spo_packet_t *pkt, const u_char *packet)
{
    const u_char *http_start = NULL;
    spo_str_t *info = NULL;

    pkt->op_len = spo_get_tcp_options_len(packet);

    info = (spo_str_t *) pkt->pkt_info;

    if ((http_start = spo_http_start(packet)) == NULL) return SPO_FAILURE;  /* get http start */

    pkt->http_s = http_start - packet;  /* record the offset */

    /* get the request method */
    if (spo_http_request_method(http_start, &info[0], 0) == SPO_FAILURE) return SPO_FAILURE;

    /* filter the http query method */
    if (spo_http_method_filter(hp_mtd, &info[0]) == SPO_FAILURE) return SPO_FAILURE;

    if (spo_http_host(packet, pkt) == SPO_FAILURE) return SPO_FAILURE;  /* geth the host */

    return SPO_OK;
}


/**
 *
 *  analysis http packet.
 *
 *  is domain is we need, send this packet to http spoofer.
 *
 * */

static SPO_RET_STATUS spo_do_http_sniffer_callback(const u_char *packet, size_t caplen, int msgid)
{
#if SPO_SHUTDOWN_HP_SPOF
    return SPO_OK;
#endif

    register spo_proc_node_t *node = current;
    spo_msg_t *msg = node->hp_pkt;
    register spo_packet_t *pkt = (spo_packet_t *) (msg->data);
    spo_tree_header_t *header = node->http_dmn_header->dmn;
    spo_str_t *infos = (spo_str_t *) pkt->pkt_info;

#if SPO_SEE_TIME
    spo_use_time(SPO_TIME_START, "sniffer");
#endif

    /* judge the msg queue status */

    spo_rst_packet(pkt);    /* reset the pkt, and reset the info */

    if ((pkt->pkt_s = caplen) >= pkt->max_pkts - pkt_len_)
        return SPO_FAILURE;

    if (spo_sniff_analy_http_request(pkt, packet) == SPO_FAILURE) goto spo_bad_call_bak;

#if SPO_SEE_TIME
    spo_snif_used_time();
#endif

    if (spo_tree_match(header, &(infos[1]), spo_comp_http_dmn) == NULL) return SPO_FAILURE;

    memcpy(pkt->packet, packet, pkt->pkt_s);

    if (spo_msgsnd(msgid, msg, pkt->pkt_s + pkt_len_, IPC_NOWAIT) == SPO_FAILURE) {
#if SPO_DEBUG
            printf("fail to send\n");
#endif
        return SPO_FAILURE;
    }

#if SPO_SEE_TIME
    spo_use_time(SPO_TIME_END, "sniffer");
#endif
    return SPO_OK;

spo_bad_call_bak:

    return SPO_FAILURE;
}


/**
 *
 *  send the packet to spoofer by msg queue.
 *
 *  @param packet, is the dns packet we catched.
 *
 *  @param msgid , is the dns msg queue id.
 *
 *  @return int, is the exec status.
 *
 **/

static SPO_RET_STATUS
spo_do_dns_sniffer_callback(spo_proc_node_t *p_node, const u_char *packet, size_t caplen, int msgid)
{
#if SPO_SHUTDOWN_DNS_SPOF
        return SPO_OK;
#endif

    spo_msg_t *msg = p_node->dns_pkt;
    u_char *pkt = (u_char *) (msg->data);
    register size_t size = p_node->cfg->global->max_dns_pkt_s - sizeof(spo_msg_t);

    if (caplen > size) return SPO_FAILURE;

    memcpy(pkt, packet, caplen);

    if (spo_msgsnd(msgid, msg, p_node->cfg->global->max_dns_pkt_s, IPC_NOWAIT) == SPO_FAILURE) {
#if SPO_DEBUG
        printf("dns sniffer snd err\n");
        perror("err \n");
#endif
        return SPO_FAILURE;
    }

    return SPO_OK;
}


/**
 *
 *  get the packet protocol, we need http or dns.
 *
 *  @param packet, is the packet we catched.
 *
 *  @return int, is the exec status.
 *
 **/

static SPO_RET_STATUS spo_protocol_type(const u_char *packet)
{

    spo_sniff_ip_t *ip = NULL;
    spo_sniff_tcp_t *tcp = NULL;
    spo_sniff_udp_t *udp = NULL;

    if (spo_is_802_1q_vlan(packet) == SPO_TRUE) {       /* running in vlan */
        ip = (spo_sniff_ip_t *) (packet + SPO_IP_OFFSET_VLAN);

        if (ip->ip_p == IPPROTO_TCP) {
            tcp = (spo_sniff_tcp_t *) (packet + SPO_TCP_OFFSET_VLAN);
            if (tcp->tcp_dport == 0x5000) return IPPROTO_TCP;          /* is http */

            return SPO_FAILURE;
        }

        if (ip->ip_p == IPPROTO_UDP) {
            udp = (spo_sniff_udp_t *) (packet + SPO_UDP_OFFSET_VLAN);
            if (udp->udp_dport == 0x3500) return IPPROTO_UDP;         /* is dns */

            return SPO_FAILURE;
        }

    }else {
        ip = (spo_sniff_ip_t *) (packet + SPO_IP_OFFSET);

        if (ip->ip_p == IPPROTO_TCP) {
            tcp = (spo_sniff_tcp_t *) (packet + SPO_TCP_OFFSET);
            if (tcp->tcp_dport == 0x5000) return IPPROTO_TCP;          /* is http */

            return SPO_FAILURE;
        }

        if (ip->ip_p == IPPROTO_UDP) {
            udp = (spo_sniff_udp_t *) (packet + SPO_UDP_OFFSET);
            if (udp->udp_dport == 0x3500) {
                return IPPROTO_UDP;         /* is dns */
            }

            return SPO_FAILURE;
        }
    }

    return SPO_FAILURE;
}


void spo_updata_log(int type, char *log_info)
{
    switch (type) {
    case SPO_UP_HP_CFG:
        memcpy(log_info, "updata http cfg fail", strlen("updata http cfg fail"));
        break;
    case SPO_UP_HP_DATA:
        memcpy(log_info, "updata http data fail", strlen("updata http data fail"));
        break;
    case SPO_UP_DNS_CFG:
        memcpy(log_info, "updata dns data fail", strlen("updata dns data fail"));
        break;
    default :
        memcpy(log_info, "updata fail", strlen("updata fail"));
    }
}


static void spo_to_update(spo_proc_node_t *node)
{
    if (node->security == 1) {
        int ret = 0;
        int type = 0;

        if (node->hp_cfg_security == 1) {
            ret = spo_reload_http_config(node->cfg, node);
            node->security = 0;
            node->hp_cfg_security = 0;
            type = SPO_UP_HP_CFG;
            goto spo_snif_update_fial;
        }

        if (node->hp_data_security == 1) {
            ret = spo_reload_http_data(node->cfg, node);
            node->security = 0;
            node->hp_data_security = 0;
            type = SPO_UP_HP_DATA;
            goto spo_snif_update_fial;
        }

        if (node->dns_cfg_security == 1) {
            ret = spo_reload_dns_data(node->cfg, node);
            node->security = 0;
            node->dns_cfg_security = 0;
            type = SPO_UP_DNS_CFG;
            goto spo_snif_update_fial;
        }

spo_snif_update_fial:

        if (ret == SPO_FAILURE) {
            char log_info[256] = {'\0'};
            spo_updata_log(type, log_info);
            spo_do_snd_log_msg(current->log, log_info, SPO_LOG_LEVEL_ERR);
        }
    }
}


static void spo_sniffer_callback(const u_char *packet, size_t caplen)
{
    int ret = 0;

    static int hp_counter = 0;
    static int dns_counter = 0;

    ret = spo_protocol_type(packet);

    if (ret == IPPROTO_TCP) {
        if (++hp_counter > current->hp_msgid[0]) hp_counter = 1;
        spo_do_http_sniffer_callback(packet, caplen, current->hp_msgid[hp_counter]);
        goto spo_rld_pcap;
    }

    if (ret == IPPROTO_UDP) {
        if (++dns_counter > current->dns_msgid[0]) dns_counter = 1;
        spo_do_dns_sniffer_callback(current, packet, caplen, current->dns_msgid[dns_counter]);
    }

spo_rld_pcap:

    spo_to_update(current);
}


/**
 *
 *  when we catch a packet we callback here.
 *
 **/

static void spo_http_sniffer_callback_pcap(u_char *user, const struct pcap_pkthdr *pcap_head, const u_char *packet)
{
    user = user;

    spo_sniffer_callback(packet, pcap_head->len);
}


/**
 *
 *  when we catch a packet we callback here.
 *
 *
 **/

static void spo_http_sniffer_callback_fp_ring(
        const struct pfring_pkthdr *header, const u_char *packet, const u_char *user_bytes)
{
    user_bytes = user_bytes;
    header = header;

    spo_sniffer_callback(packet, header->len);
}


/**
 *
 *  set the sniffer filter.
 *
 *  @param p, is the pcap handler.
 *
 *  @param filter_exp, is the exp to filte the packet.
 *
 *  @return exec status.
 *
 *  status finished, tested.
 *
 **/

static SPO_RET_STATUS spo_set_filter(pcap_t *p, const char *filter_exp)
{

    int ret = -1;
    struct bpf_program bpf;

    if (filter_exp == NULL) {
#if SPO_DEBUG
        printf("filter is null\n");
#endif
        return SPO_OK;
    }

    /*compile the filter exp*/
    ret = pcap_compile(p, &bpf, filter_exp, 0, 0);
    if (ret == SPO_FAILURE) {
        return SPO_FAILURE;
    }

    /*set the filter*/
    ret = pcap_setfilter(p, &bpf);
    if (ret == SPO_FAILURE) {
        return SPO_FAILURE;
    }

    return SPO_OK;
}


/**
 *
 *  we use the pcap lib catch the pcaket's here.
 *
 *  sniffer start here.
 *
 *  we catch the http request packet by libpcap.
 *
 *  @param filter, is the filter we filte the workers_logpacket.
 *
 *  @return nothing.
 *
 **/

static void spo_sniffer_pcap(void *info_blk)
{
    spo_info_t *info = (spo_info_t *) info_blk;

    char *dev_r = (char *) info->dev;
    const char *filter_exp = info->filter != NULL ? (const char *) info->filter : NULL;

    int ret = -1;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handler;

    handler = pcap_open_live(dev_r, SPO_CATCHED_PKT_LEN, 1, 0, errbuf);
    if (handler == NULL) {
        /* wirte log */
#if SPO_DEBUG
        printf("pcap_open_live err \n");
#endif
        spo_do_snd_log_msg(current->log, "pcap_open_live err \n", SPO_LOG_LEVEL_ERR);
        exit(EXIT_FAILURE);
    }

    ret = spo_set_filter(handler, filter_exp);
    if (ret == SPO_FAILURE) {
        /* wirte log */
        exit(EXIT_FAILURE);
    }

    pcap_loop(handler, -1, spo_http_sniffer_callback_pcap, NULL);
}


/**
 *
 *  set the packet's direc.
 *
 * */

static SPO_RET_STATUS spo_set_pf_dircte(pfring *pd, int driect)
{
    char *log_info = NULL;

    if (driect == 2) {
#if SPO_DEBUG
        printf("tx\n");
#endif
        if (pfring_set_direction(pd, tx_only_direction) != 0) {
            goto spo_bad_pf_driec;
        }
    }else {
        if (driect == 1) {
#if SPO_DEBUG
            printf("rx\n");
#endif
            if (pfring_set_direction(pd, rx_only_direction) != 0) {
                goto spo_bad_pf_driec;
            }
        }else {
            if (pfring_set_direction(pd, rx_and_tx_direction) != 0) {
                goto spo_bad_pf_driec;
            }
        }
    }

    return SPO_OK;

spo_bad_pf_driec:
#if SPO_DEBUG
    printf("pfring_set_direction is failure error [%s]\n", strerror(errno));
#endif
    log_info = "pfring_set_direction is failure error\n";
    spo_do_snd_log_msg(current->log, log_info, SPO_LOG_LEVEL_ERR);
    return SPO_FAILURE;
}


/**
 *
 *  we use the pf ring lib catch the pcaket's here.
 *
 *  open the dev, and set the filter use bpf.s
 *
 *  @param filter_exp, is the exp of the filter.
 *
 *  @return nothing.
 *
 **/

static void spo_sniffer_fp_ring(void *info_blk)
{
    pfring *pd;
    int rc = 0;
    u_int8_t wait_for_packet = 1;
    spo_info_t *info = (spo_info_t *) info_blk;

    const char *dev_r = (const char *) info->dev;
    char *filter_exp = (char *) info->filter;

#if SPO_DEBUG
    printf("pf dev --%s--\n", dev_r);
    printf("pf fileter --%s--\n", filter_exp);
#endif

    pd = pfring_open(dev_r, SPO_CATCHED_PKT_LEN, PF_RING_PROMISC);
    if (pd == NULL) {
#if SPO_DEBUG
        printf("init pd err\n");
#endif
        spo_do_snd_log_msg(current->log, "init pd err\n", SPO_LOG_LEVEL_ERR);
    }

#if SPO_TEST_PF
    rc = pfring_set_cluster(pd, 1, cluster_round_robin);
#if SPO_DEBUG
    printf("pfring_set_cluster returned %d\n", rc);
#endif

    if((rc = pfring_set_socket_mode(pd, recv_only_mode)) != 0) {
#if SPO_DEBUG
        fprintf(stderr, "pfring_set_socket_mode returned [rc=%d]\n", rc);
#endif
    }
#endif

    if((rc = pfring_set_poll_watermark(pd, SPO_PF_WATERMARK)) != 0) {
#if SPO_DEBUG
        fprintf(stderr, "pfring_set_poll_watermark returned [rc=%d][watermark=%d]\n", rc, 1);
#endif
    }

#if SPO_TEST_PF
    rc = pfring_set_reflector_device(pd, (char *) dev_r);
    if(rc == 0) {
        /* printf("pfring_set_reflector_device(%s) succeeded\n", reflector_device); */
    }else {
#if SPO_DEBUG
        fprintf(stderr, "pfring_set_reflector_device(%s) failed [rc: %d]\n", dev_r, rc);
#endif
    }
#endif

#if SPO_DEBUG
    u_int32_t version;
    /* 获取版本号 */
    pfring_version(pd, &version);
    printf("Using PF_RING v%u.%u.%u\n",
(version & 0xFFFF0000) >> 16, (version & 0x0000FF00) >> 8, version & 0x000000FF);
#endif

    if (spo_set_pf_dircte(pd, info->driection) == SPO_FAILURE) exit(EXIT_FAILURE);

    if (filter_exp != NULL) {
        if (pfring_set_bpf_filter(pd, filter_exp) != 0) {
#if SPO_DEBUG
            printf("set_BPF is failure!\n");
#endif
            spo_do_snd_log_msg(current->log, "set_BPF is failure!\n", SPO_LOG_LEVEL_ERR);
            exit(EXIT_FAILURE);
        }
    }

    /* 开启pfring */
    if (pfring_enable_ring(pd) != 0) {
#if SPO_DEBUG
        printf("pfring_enable is failure error [%s]\n", strerror(errno));
#endif
        spo_do_snd_log_msg(current->log, "pfring_enable is failure error\n", SPO_LOG_LEVEL_ERR);
        exit(EXIT_FAILURE);
    }

    pfring_loop(pd, spo_http_sniffer_callback_fp_ring, (u_char*) NULL, wait_for_packet);

#if SPO_DEBUG
    perror("pfring loop err\n");
#endif
    pfring_close(pd);
}



/**
 *
 *  sniffers init pool.
 *
 * */

static SPO_RET_STATUS spo_snif_init_pool(spo_proc_node_t *node)
{
    spo_pool_t *pool = NULL;
    spo_packet_t *pkt = NULL;
    spo_str_t *infos = NULL;
    size_t size = 0;
    spo_log_t *log = NULL;
    int i = 0;

    /* create snif pool */
    if ((pool = spo_create_pool(SPO_SNIF_POOL_S)) == NULL) return SPO_FAILURE;
    node->pool = pool;

    /* init snif's http pkt */
    if ((node->hp_pkt = spo_palloc(pool, node->cfg->global->max_http_pkt_s)) == NULL) return SPO_FAILURE;
    node->hp_pkt->type = SPO_PKT_MSG_TYPE;  /* init the hp msg type */

    pkt = (spo_packet_t *) ((char *) (node->hp_pkt->data));
    pkt->len = node->cfg->global->max_http_pkt_s;
    pkt->max_pkts = pkt->len - (sizeof(spo_packet_t) + sizeof(spo_msg_t));

    if ((pkt->pkt_info = spo_palloc(pool, 2 * sizeof(spo_str_t))) == NULL) return SPO_FAILURE;
    pkt->info_amt = 2;

    /* init infos */
    infos = (spo_str_t *) pkt->pkt_info;
    for (i = 0; i < pkt->info_amt; i++) spo_init_str(&infos[i]);

    /* init snif dns pkt */
    if ((node->dns_pkt = spo_palloc(pool, node->cfg->global->max_dns_pkt_s)) == NULL) return SPO_FAILURE;
    node->dns_pkt->type = SPO_PKT_MSG_TYPE; /* init the dns msg type */

    /* init log and statis */
    size = sizeof(spo_msg_t) + sizeof(spo_log_t) + node->cfg->global->max_log_len;
    if ((node->log = spo_palloc(pool, size)) == NULL) return SPO_FAILURE;
    log = (spo_log_t *) node->log->data;
    log->pid = node->pid;
    log->proc_type = SPO_SNIFFER;
    log->size = size;

    return SPO_OK;
}


/* -- - -- -- - -- -- - - -  - -  sniffers reload  cfg  - - -- - - -- - -- - - -- - -- - - */


static void spo_rld_hp_cfg(int sig, siginfo_t *info, void *p)
{
    info = info;
    p = p;

    if (sig == SIGUSR1) {
#if SPO_DEBUG
        printf("sniffer rld hp cfg\n");
#endif
        current->security = 1;
        current->hp_cfg_security = 1;
    }
}


static void spo_rld_dns_cfg(int sig, siginfo_t *info, void *p)
{
    info = info;
    p = p;

    if (sig == SIGUSR2) {
#if SPO_DEBUG
        printf("sniffer rld dns data\n");
#endif
        current->security = 1;
        current->dns_cfg_security = 1;
    }
}


static void spo_rld_hp_data(int sig, siginfo_t *info, void *p)
{
    info = info;
    p = p;

    if (sig == SIGINT) {
#if SPO_DEBUG
        printf("sniffer rld hp data\n");
#endif
        current->security = 1;
        current->hp_data_security = 1;
    }
}


static void spo_rld_hp_cfg_tmp(int sig, siginfo_t *info, void *p)
{
    info = info;
    p = p;

    if (sig == SIGIO) {
#if SPO_DEBUG
        printf("sniffer rld hp cfg tmp\n");
#endif
        current->security = 1;
        current->hp_cfg_tmp_security = 1;
    }
}


static void spo_rld_dns_cfg_tmp(int sig, siginfo_t *info, void *p)
{
    info = info;
    p = p;

    if (sig == SIGQUIT) {
#if SPO_DEBUG
        printf("sniffer rld dns cfg tmp\n");
#endif
        current->security = 1;
        current->dns_cfg_tmp_security = 1;
    }
}


static void spo_rld_hp_data_tmp(int sig, siginfo_t *info, void *p)
{
    info = info;
    p = p;

    if (sig == SIGTRAP) {
#if SPO_DEBUG
        printf("sniffer rld hp data tmp\n");
#endif
        current->security = 1;
        current->hp_data_tmp_security = 1;
    }
}


static SPO_RET_STATUS spo_snif_init_sig()
{
    sigset_t set;
    memset(&set, '\0', sizeof(sigset_t));

    spo_fill_sigmask(&set);

    spo_del_sig_in_set(SIGUSR1, &set);  //http cfg reload
    spo_del_sig_in_set(SIGUSR2, &set);  //dns cfg reload
    spo_del_sig_in_set(SIGINT, &set);   //http data
    spo_del_sig_in_set(SIGIO, &set);    //http cfg tmp
    spo_del_sig_in_set(SIGQUIT, &set);  //dns cfg tmp
    spo_del_sig_in_set(SIGTRAP, &set);  //http data tmp

    spo_signal_a_sigset(&set);

    spo_signal_a_sig(SIGUSR1, spo_rld_hp_cfg);
    spo_signal_a_sig(SIGUSR2, spo_rld_dns_cfg);
    spo_signal_a_sig(SIGINT, spo_rld_hp_data);
    spo_signal_a_sig(SIGIO, spo_rld_hp_cfg_tmp);
    spo_signal_a_sig(SIGQUIT, spo_rld_dns_cfg_tmp);
    spo_signal_a_sig(SIGTRAP, spo_rld_hp_data_tmp);

    return SPO_OK;
}


/**
 *
 *  sniffers working here.
 *
 * */

void spo_sniffers(void *info_blk)
{
    spo_info_t *info = (spo_info_t *) info_blk;

    spo_bind_cpu(info->cpuid, current->pid);

    spo_snif_init_sig();

    if (spo_snif_init_pool(current) == SPO_FAILURE) exit(EXIT_FAILURE);

    if (memcmp(info->lib, "pcap", 4) == 0) {    /* running pcap */
#if SPO_DEBUG
        printf("pcap  running  \n");
#endif
        spo_do_snd_log_msg(current->log, "pcap  running", SPO_LOG_LEVEL_MSG);
        spo_sniffer_pcap(info_blk);
    }else {
#if SPO_DEBUG
        printf("running pf\n");
#endif
        spo_do_snd_log_msg(current->log, "running pf", SPO_LOG_LEVEL_MSG);
        spo_sniffer_fp_ring(info_blk);
    }
}
