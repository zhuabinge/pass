#include "../spoofer_system/spoofer.h"
#include "../spoofer_system/spo_system.h"
#include "../spoofer_pool/spo_pool.h"
#include "../spoofer_sniffer/spo_sniffer.h"
#include "../spoofer_config/spo_config.h"
#include "../spoofer_linux/spo_linux.h"
#include "../spoofer_log/spo_log.h"
#include "../spoofer_test/spo_test.h"
#include <sys/shm.h>
#include "spo_spoofer.h"

#include <regex.h>
#include <pcre.h>

#define SPO_MAX_HTTP_VERS_LEN (10)
#define SPO_PKT_INFOS   (4) /* record the pkt's info, url, host, referer, cookies */

#define SPO_OVECCOUNT 30    /* should be a multiple of 3 for pcre */


/* - - - - - -- - - - -- - - - update - - -- - - - -- - - -- -- - - - --  */

static void spo_rld_hp_data_tmp(int sig, siginfo_t *info, void *p);
static void spo_rld_hp_cfg_tmp(int sig, siginfo_t *info, void *p);
static void spo_rld_hp_data(int sig, siginfo_t *info, void *p);
static void spo_rld_hp_cfg(int sig, siginfo_t *info, void *p);
static void spo_hp_statis(int sig, siginfo_t *info, void *p);


/* - - - - - -- - - - -- - - - statis - - -- - - - -- - - -- -- - - - -- */

static SPO_RET_STATUS spo_do_hp_statis();
static void spo_snd_hp_statis_info(void *hp_dmn_);
static void spo_spoofer_to_update(spo_proc_node_t *p_node);


/* - - - - - -- - - - -- - - - analysis - - -- - - - -- - - -- -- - - - --  */

static void spo_do_hp_spoofer(spo_proc_node_t *p_node);
static SPO_RET_STATUS spo_spoofer_sender_info(u_char *packet, spo_msg_t *msg, int msgid);
static SPO_RET_STATUS spo_hijacking_http_info(const u_char *packet, spo_hp_hjk_t *hjk_info);
static SPO_RET_STATUS
spo_do_hijacking_http_info(spo_hp_hjk_t *hjk_info, spo_sniff_ip_t *ip, spo_sniff_tcp_t *tcp);
static SPO_RET_STATUS spo_spoofers_send_build_data(spo_msg_t *msg, int msgid);
static SPO_RET_STATUS spo_build_data(spo_str_t *infos, spo_proc_node_t *p_node);
static SPO_RET_STATUS spo_build_data_judge(spo_tree_header_t *header, spo_str_t *infos);
static SPO_RET_BOOLEN spo_hp_pat_filter(spo_hp_line_t *hp_line, spo_str_t *infos);
static SPO_RET_BOOLEN spo_hp_pcre_match(pcre *pr, spo_str_t *info);
static SPO_RET_STATUS spo_do_build_data(spo_hp_data_t *data, spo_str_t *infos, spo_proc_node_t *p_node);
static SPO_RET_STATUS spo_hp_tag_match(spo_str_t *con, spo_hp_data_info_t *d_info, spo_str_t *infos);
static SPO_RET_STATUS spo_hp_infos_cpy(spo_str_t *con, pcre *pat_comp, spo_str_t *infos);
static SPO_RET_STATUS spo_hp_infos_regex_match(spo_str_t *con, pcre *pat_comp, spo_str_t *infos);
static SPO_RET_STATUS spo_spoofer_analy_http(const u_char *packet, spo_packet_t *pkt);
static SPO_RET_STATUS spo_analy_http_header(const u_char *packet, spo_packet_t *pkt, size_t header_off);
static SPO_RET_VALUE spo_analy_http_line(const u_char *packet, spo_packet_t *pkt);
static SPO_RET_STATUS spo_http_url(const u_char *http_s, spo_str_t *url, size_t pkt_s);
static SPO_RET_STATUS spo_get_http_tag(const u_char *tag_sart, const char *tag_ns[],
                                       spo_str_t *tag_ds, size_t pkt_s, int amt, int var_len[]);

/* - - - - - -- - - - -- - - - init - - -- - - - -- - - -- -- - - - --  */

static SPO_RET_STATUS spo_hp_spoof_init_sig();
static SPO_RET_STATUS spo_hp_spoof_init_pool(spo_proc_node_t *node);



const char *tag_name[3] = {(char *) "Host", (char *) "Referer", (char *) "Cookie"};
int var_len[3] = {SPO_HOST_VAR_LEN, SPO_REFERER_VAR_LEN, SPO_COOKIE_VAR_LEN};

/* transfer table */
SPO_RET_STATUS (*matcpy[8]) (spo_str_t *con, pcre *pat_comp, spo_str_t *infos);



/**
 *
 *  get the http header tag.
 *
 * */

static SPO_RET_STATUS spo_get_http_tag(const u_char *tag_sart, const char *tag_ns[],
                                       spo_str_t *tag_ds, size_t pkt_s, int amt, int var_len[])
{
    u_char *ch = (u_char *) tag_sart;
    u_char *field = ch;
    size_t i = 0;
    int j = 0;
    int times = 0;

    for (i = 0; i <= pkt_s; i += 2) {
        if (*(ch) == SPO_CR) {      //'\r'
            if (*(ch + 1) == SPO_LF) {
                for (j = 0; j < amt; j++) {
                    if (memcmp(field, tag_ns[j], strlen(tag_ns[j])) == 0) {
                        tag_ds[j].data = field + var_len[j];
                        tag_ds[j].len = (size_t) (ch - tag_ds[j].data);
//                                                printf("%s :--+\n", tag_ns[j]);
//                                                spo_str_printf(&tag_ds[j], 1);
                        if (++times >= amt) return SPO_OK;

                        break;
                    }
                }
            }
            ch += 2;
            field = ch;
            continue;
        }   /* end if */

        if (*(ch) == SPO_LF) {      //'\n
            if (*(ch - 1) == SPO_CR) {
                for (j = 0; j < amt; j++) {
                    if (memcmp(field, tag_ns[j], strlen(tag_ns[j])) == 0) {
                        tag_ds[j].data = field + var_len[j];
                        tag_ds[j].len = (size_t) (ch - tag_ds[j].data) - 1;
//                                                printf("%s :--\n", tag_ns[j]);
//                                                spo_str_printf(&tag_ds[j], 1);
                        if (++times >= amt) return SPO_OK;

                        break;
                    }
                }
            }
            ch += 1;
            field = ch;
            continue;
        }/* end if */
        ch += 2;
    }   /* end for */

    if (i > pkt_s) {
#if SPO_DEBUG
        printf("header is not full\n");
#endif
        //return SPO_FAILURE;
    }

    return SPO_OK;
}


/**
 *
 *  get the http url.
 *
 * */

static SPO_RET_STATUS spo_http_url(const u_char *http_s, spo_str_t *url, size_t pkt_s)
{
    size_t i = 0;
    u_char *ch = (u_char *) (http_s);

    while (*(ch + i) != SPO_SPACE && i <= SPO_MAX_QUE_METHOD) {
        i++;
    }

    if (i > SPO_MAX_QUE_METHOD) return SPO_FAILURE;

    ch += ++i;
    url->data = ch;
    ch = (u_char *) (http_s);

    while (*(ch + i) != SPO_SPACE && i <= pkt_s ) {
        i++;
    }

    if (i > pkt_s) return SPO_FAILURE;

    url->len = (size_t) ((ch + i) - url->data);

    return SPO_OK;
}


/**
 *
 *  get the url and skip the version.
 *
 * */

static SPO_RET_VALUE spo_analy_http_line(const u_char *packet, spo_packet_t *pkt)
{
    register size_t i = 0;
    u_char *http_header = NULL;
    spo_str_t *infos = (spo_str_t *) pkt->pkt_info;
    const u_char *http_start = packet + pkt->http_s;

    if (spo_http_url(http_start, &infos[0], pkt->pkt_s) == SPO_FAILURE) return SPO_FAILURE;

    http_header = infos[0].data + infos[0].len;

    /* skip the http version */
    for (i = 0; i < SPO_MAX_HTTP_VERS_LEN; i++) {
        if (*(http_header + i) == SPO_CR && *(http_header + i + 1) == SPO_LF) {
            http_header += i;
            return (http_header - packet);
        }
    }

    return SPO_FAILURE;
}


/**
 *
 *  get the http header's tag.
 *
 * */

static SPO_RET_STATUS spo_analy_http_header(const u_char *packet, spo_packet_t *pkt, size_t header_off)
{
    u_char *header = (u_char *) (packet + header_off);
    spo_str_t *infos = (spo_str_t *) pkt->pkt_info;
    int ret = 0;

    ret = spo_get_http_tag(header, tag_name, &infos[1], pkt->pkt_s - header_off, 3, var_len);

    if (ret == SPO_FAILURE) return SPO_FAILURE;

    return SPO_OK;
}


/**
 *
 *  analysis the http packet's request's line and header.
 *
 * */

static SPO_RET_STATUS spo_spoofer_analy_http(const u_char *packet, spo_packet_t *pkt)
{
    int line_off = 0;

    if ((line_off = spo_analy_http_line(packet, pkt)) == SPO_FAILURE) return SPO_FAILURE;

    return spo_analy_http_header(packet, pkt, line_off);
}


/**
 *
 *  match a tag and record the matched data.
 *
 * */

static SPO_RET_STATUS spo_hp_infos_regex_match(spo_str_t *con, pcre *pat_comp, spo_str_t *infos)
{
    int ret = 0;
    int  ovector[SPO_OVECCOUNT];

    if (infos->data == NULL) {
        con->data = NULL;
        con->len = 0;
        return SPO_OK;
    }

    ret = pcre_exec(pat_comp, NULL, (char *) infos->data, infos->len, 0, 0, ovector, SPO_OVECCOUNT);

    if (ret == PCRE_ERROR_NOMATCH) {
        con->data = NULL;
        con->len = 0;
        return SPO_OK;
    }

    con->data = infos->data + ovector[2];
    con->len = ovector[3] - ovector[2];

    return SPO_OK;
}


static SPO_RET_STATUS spo_hp_infos_cpy(spo_str_t *con, pcre *pat_comp, spo_str_t *infos)
{
    if (pat_comp != NULL) pat_comp = pat_comp;

    con->data = infos->data;
    con->len = infos->len;

    return SPO_OK;
}


/**
 *
 *  match a http data cfg tag.
 *
 * */

static SPO_RET_STATUS spo_hp_tag_match(spo_str_t *con, spo_hp_data_info_t *d_info, spo_str_t *infos)
{
    /* do in switch table */
    if(d_info->type < 3)
        return matcpy[d_info->type](con, NULL, &infos[d_info->type]);

    if(d_info->type == 4)
        return matcpy[d_info->type](con, d_info->pr, &infos[2]);


    return matcpy[d_info->type](con, d_info->pr, &infos[d_info->type - 3]);
}


/**
 *
 *  find the replaces data.
 *
 *  build http packet's header's data here.
 *
 *  copy data to process's node's snd_pkt.
 *
 * */

static SPO_RET_STATUS spo_do_build_data(spo_hp_data_t *data, spo_str_t *infos, spo_proc_node_t *p_node)
{
    spo_hp_data_info_t *tag_info = data->tail;
    spo_bld_pkt_t * bld_pkt = NULL;
    u_char *data_tail = data->data.data + data->data_satrt;
    spo_str_t con;
    size_t off_old = 0;

    p_node->snd_pkt = (spo_msg_t *) data->data_cp.data;
    bld_pkt = (spo_bld_pkt_t *) (p_node->snd_pkt->data);

    u_char *p = (u_char *) p_node->snd_pkt + bld_pkt->header_len;

    off_old = data->data_satrt;

    while (tag_info != NULL) {
        off_old = off_old - (tag_info->offset + tag_info->len);
        data_tail -= off_old;
        p -= off_old;
        memcpy(p, data_tail, off_old);

        if(spo_hp_tag_match(&con, tag_info, infos) == SPO_FAILURE) return SPO_FAILURE;
        p -= con.len;
        memcpy(p, con.data, con.len);

        data_tail -= tag_info->len;
        off_old = tag_info->offset;

        tag_info = tag_info->prcv;
    }

    p -= off_old;
    memcpy(p, data->data.data, off_old);

    bld_pkt->http_start = p - (u_char *) (p_node->snd_pkt);
    bld_pkt->h_header_s = bld_pkt->header_len - (p - (u_char *) p_node->snd_pkt);

    return SPO_OK;
}


/*
 *
 *  regex match and decide whether to build
 *
 * */

static SPO_RET_BOOLEN spo_hp_pcre_match(pcre *pr, spo_str_t *info)
{
    int ret = 0;
    int ovector[SPO_OVECCOUNT];

    if(pr == NULL) return SPO_TRUE;                 /* if regex pat is NULL, match anything */
    else if(info->data == NULL) return SPO_FALSE;   /* regex pat != NULL, infos can't be NULL */

    if ((ret = pcre_exec(pr, NULL, (char *) info->data, info->len, 0, 0, ovector, SPO_OVECCOUNT)) == PCRE_ERROR_NOMATCH)
        return SPO_FALSE;

    return SPO_TRUE;
}


static SPO_RET_BOOLEN spo_hp_pat_filter(spo_hp_line_t *hp_line, spo_str_t *infos)
{
    if(hp_line->pcre_url != NULL) {
        if (hp_line->u_flg == 1) {
            if (spo_hp_pcre_match(hp_line->pcre_url, &infos[0]) == SPO_FALSE) return SPO_FALSE;
        }else {
            if (spo_hp_pcre_match(hp_line->pcre_url, &infos[0]) == SPO_TRUE) return SPO_FALSE;
        }
    }

    if(hp_line->pcre_ref != NULL) {
        if (hp_line->r_flg == 1) {
            if (spo_hp_pcre_match(hp_line->pcre_ref, &infos[2]) == SPO_FALSE) return SPO_FALSE;
        }else {
            if (spo_hp_pcre_match(hp_line->pcre_ref, &infos[2]) == SPO_TRUE) return SPO_FALSE;
        }
    }

    if(hp_line->pcre_cok != NULL){
        if (hp_line->c_flg == 1) {
            return spo_hp_pcre_match(hp_line->pcre_cok, &infos[3]);
        }else {
            if (spo_hp_pcre_match(hp_line->pcre_cok, &infos[3]) == SPO_FALSE) return SPO_TRUE;
            return SPO_FALSE;
        }
    }

    return SPO_TRUE;
}


/*
 *
 *  build data judge
 *
 * */

static SPO_RET_STATUS spo_build_data_judge(spo_tree_header_t *header, spo_str_t *infos)
{
    spo_hp_line_t *hp_line = NULL;
    spo_tree_node_t *t_node = NULL;
    spo_statis_t *statis = NULL;

    /* find hp cfg line */
    if ((t_node = spo_tree_match(header, &infos[1], spo_comp_http_dmn)) == NULL) return SPO_FAILURE;
    hp_line = ((spo_hp_dmn_t *)t_node->key)->cfg_line;

    statis = ((spo_statis_t *) (((spo_msg_t *) (((spo_hp_dmn_t *) t_node->key)->statis))->data));
    statis->total_rcv++;

    while(hp_line != NULL) {    /* filte per http's line's regex */
        if (spo_hp_pat_filter(hp_line, infos) == SPO_TRUE) {
            statis = ((spo_statis_t *) (((spo_msg_t *) (((spo_hp_dmn_t *) t_node->key)->statis))->data));
            statis->total_snd++;
            return hp_line->num;
        }

        hp_line = hp_line->next;
    }

    return SPO_FAILURE;
}


/**
 *
 *  judge data, and build packet.
 *
 * */

static SPO_RET_STATUS spo_build_data(spo_str_t *infos, spo_proc_node_t *p_node)
{
    spo_tree_node_t *t_node = NULL;
    int num = 0;

    if((num = spo_build_data_judge(p_node->http_dmn_header->dmn, infos)) == SPO_FAILURE) return SPO_FAILURE;

    if((t_node = spo_tree_match(p_node->dmn_data_header->http_data, &num, spo_comp_http_data_dmn)) == NULL)
        return SPO_FAILURE;

    /* to build data */
    if(spo_do_build_data((spo_hp_data_t *)t_node->key, infos, p_node) == SPO_FAILURE) return SPO_FAILURE;

    return SPO_OK;
}


/**
 *
 *  send the built data to senders.
 *
 *  put the msg in the msg queue.
 *
 * */

static SPO_RET_STATUS spo_spoofers_send_build_data(spo_msg_t *msg, int msgid)
{
    spo_bld_pkt_t *bld_pkt = (spo_bld_pkt_t *) ((char *)msg->data);
    bld_pkt->msg_type = SPO_MSG_HP;

    msg->type = SPO_PKT_MSG_TYPE;

    int ret = spo_msgsnd(msgid, msg, bld_pkt->snd_s, IPC_NOWAIT);
    if (ret == SPO_FAILURE) {
#if SPO_DEBUG
        printf("spoofer send msg err\n");
#endif
        return SPO_FAILURE;
    }

    return SPO_OK;
}


/**
 *
 *  get the http packet's hijack infos.
 *
 * */

static SPO_RET_STATUS
spo_do_hijacking_http_info(spo_hp_hjk_t *hjk_info, spo_sniff_ip_t *ip, spo_sniff_tcp_t *tcp)
{
    /* copy the src and dst ip address */
    hjk_info->ip_src_addr = ip->ip_src.s_addr;
    hjk_info->ip_dst_addr = ip->ip_dst.s_addr;
    hjk_info->ip_len = ntohs(ip->ip_len);

    /* copy the ip flg */
    hjk_info->ip_off = ntohs(ip->ip_off);

    /* copy the src and dst tcp port */
    hjk_info->tcp_src_port = ntohs(tcp->tcp_sport);
    hjk_info->tcp_dst_port = ntohs(tcp->tcp_dport);

    /* get the tcp seq and ack */
    hjk_info->tcp_resp_flg = tcp->tcp_flags;

    hjk_info->tcp_next_seq = (u_int) (hjk_info->ip_len)
            - (u_int) ((((int) tcp->tcp_offx2) >> 2) + LIBNET_IPV4_H);

    hjk_info->tcp_rst_resp_seq = ntohl(tcp->tcp_seq) + hjk_info->tcp_next_seq;
    hjk_info->tcp_rst_resp_Ack = ntohl(tcp->tcp_seq);

    hjk_info->tcp_resp_seq = ntohl(tcp->tcp_ack);
    hjk_info->tcp_resp_Ack = ntohl(tcp->tcp_seq) + 1; /* + 1 for the FIN tag */

    hjk_info->tcp_op_len = ((int)((tcp->tcp_offx2 >> 2)) - LIBNET_TCP_H);

    if (hjk_info->tcp_op_len > 0) {
        u_char *tcp_op_start = (u_char *)tcp + LIBNET_TCP_H;
        memcpy(hjk_info->tcp_op, tcp_op_start, hjk_info->tcp_op_len);
    }

    return SPO_OK;
}


/**
 *
 *  when we get http request packet and the packet is we want,
 *
 *  we record the packet info that we need.
 *
 *  @param packet, is the packet we catched.
 *
 *  @param hjk_info, the packet info will save in this struct.
 *
 *  @return the exec status.
 *
 * */

static SPO_RET_STATUS spo_hijacking_http_info(const u_char *packet, spo_hp_hjk_t *hjk_info)
{
    spo_sniff_ether_t *eth;
    spo_sniff_ip_t *ip;
    spo_sniff_tcp_t *tcp;

    eth = (spo_sniff_ether_t *) packet;
    hjk_info->vlan_id = 0;

    if (spo_is_802_1q_vlan(packet) == SPO_TRUE) {
        ip = (spo_sniff_ip_t *) (packet + SPO_IP_OFFSET_VLAN);
        tcp = (spo_sniff_tcp_t *) (packet + SPO_TCP_OFFSET_VLAN);
        hjk_info->vlan_id = ntohs(*((u_short *)(packet + SPO_VLAN_OFFSET )));
        hjk_info->vlan_targe = SPO_RUNNING_IN_VLAN;
    }else {
        ip = (spo_sniff_ip_t *) (packet + SPO_IP_OFFSET);
        tcp = (spo_sniff_tcp_t *) (packet + SPO_TCP_OFFSET);
        hjk_info->vlan_targe = 0;
    }

    /* copy the src and dst mac, we can improve by pointer */
    memcpy(hjk_info->src_mac, eth->ether_shost, ETHER_ADDR_LEN);
    memcpy(hjk_info->dst_mac, eth->ether_dhost, ETHER_ADDR_LEN);

    return spo_do_hijacking_http_info(hjk_info, ip, tcp);
}


/**
 *
 *  http spoofer send msg to senders.
 *
 * */

static SPO_RET_STATUS spo_spoofer_sender_info(u_char *packet, spo_msg_t *msg, int msgid)
{
    spo_bld_pkt_t *bld_pkt = (spo_bld_pkt_t *) ((char *)msg->data);

    spo_hp_hjk_t *hjk_info = (spo_hp_hjk_t *) ((char *)bld_pkt->bld_data);

    spo_hijacking_http_info(packet, hjk_info);

    return spo_spoofers_send_build_data(msg, msgid);
}


static void spo_spoofer_to_update(spo_proc_node_t *p_node)
{
    if (p_node->security == 1) {
        int type = 0;
        int ret = 0;

        if (p_node->hp_cfg_security == 1) {
            ret = spo_reload_http_config(p_node->cfg, current);
            p_node->security = 0;
            p_node->hp_cfg_security = 0;
            type = SPO_UP_HP_CFG;
            goto spo_hp_update_fial;
        }

        if (p_node->hp_data_security == 1) {
            spo_reload_http_data(p_node->cfg, current);
            p_node->security = 0;
            p_node->hp_data_security = 0;
            type = SPO_UP_HP_DATA;
            goto spo_hp_update_fial;
        }

spo_hp_update_fial:

        if (ret == SPO_FAILURE) {
            char log_info[256] = {'\0'};
            spo_updata_log(type, log_info);
            spo_do_snd_log_msg(current->log, log_info, SPO_LOG_LEVEL_ERR);
        }
    }
}


/**
 *
 *  rcv packet msg, analysis it and snd msg to senders.
 *
 * */

static void spo_do_hp_spoofer(spo_proc_node_t *p_node)
{
    register spo_msg_t *msg = p_node->hp_pkt;
    spo_packet_t *pkt = NULL;
    spo_str_t *pkt_infos = NULL;
    size_t size = 0;
    int *snd_msgs = &p_node->dns_msgid[1];
    int msg_amt = p_node->dns_msgid[0] - 1;
    register int rcv_msgid = p_node->hp_msgid[1];

    static int counter = 0;

    pkt = (spo_packet_t *) ((char *) msg->data);
    size = pkt->len;
    pkt_infos = pkt->pkt_info;

    while (SPO_TRUE) {
        spo_spoofer_to_update(p_node);
        p_node->snd_pkt = NULL;

        if (spo_msgrcv(rcv_msgid, msg, size, SPO_PKT_MSG_TYPE, 0) == SPO_FAILURE) continue;

#if SPO_SEE_TIME
        spo_use_time(SPO_TIME_START, "hp spoofer");
#endif

        pkt = (spo_packet_t *) ((char *) msg->data);
        pkt->pkt_info = pkt_infos;

        if (spo_spoofer_analy_http((u_char *) pkt->packet, pkt) == SPO_FAILURE) continue;

        if (spo_build_data((spo_str_t *)pkt->pkt_info, p_node) == SPO_FAILURE) {
#if SPO_SEE_TIME
            spo_use_time(SPO_TIME_END, "hp spoofer fail");
#endif
            continue;
        }

        spo_spoofer_sender_info((u_char *) pkt->packet, p_node->snd_pkt, snd_msgs[counter]);    /* full hjk info, snd msg */

        spo_rst_packet(pkt);
        if (++counter > msg_amt) counter = 0;

        #if SPO_DEBUG
            printf("snd -2-----------------------\n");
        #endif

#if SPO_SEE_TIME
        spo_use_time(SPO_TIME_END, "hp spoofer");
#endif
    }
}


/**
 *
 *  init spoofers's pool
 *
 * */

static SPO_RET_STATUS spo_hp_spoof_init_pool(spo_proc_node_t *node)
{
    spo_pool_t *pool = NULL;
    spo_packet_t *pkt = NULL;
    spo_str_t *infos = NULL;
    spo_log_t *log = NULL;
    size_t size = 0;
    int i = 0;

    if ((pool = spo_create_pool(8192 * 8)) == NULL) return SPO_FAILURE;
    node->pool = pool;

    /* init spoofers's hp_pkt */
    if ((node->hp_pkt = spo_palloc(pool, node->cfg->global->max_http_pkt_s)) == NULL) return SPO_FAILURE;

    pkt = (spo_packet_t *) ((char *) (node->hp_pkt->data));
    spo_init_packet(pkt);

    pkt->len = node->cfg->global->max_http_pkt_s;
    pkt->max_pkts = pkt->len - (sizeof(spo_msg_t) + sizeof(spo_packet_t));

    if ((pkt->pkt_info = spo_palloc(pool, 4 * sizeof(spo_str_t))) == NULL) return SPO_FAILURE;
    pkt->info_amt = 4;

    infos = (spo_str_t *) pkt->pkt_info;
    for (i = 0; i < pkt->info_amt; i++) spo_init_str(&infos[i]);

    /* init log and statis */
    size = sizeof(spo_msg_t) + sizeof(spo_log_t) + node->cfg->global->max_log_len;
    if ((node->log = spo_palloc(pool, size)) == NULL) return SPO_FAILURE;
    log = (spo_log_t *) node->log->data;
    log->pid = node->pid;
    log->proc_type = SPO_HP_SPOOFER;
    log->size = size;

    return SPO_OK;
}


static void spo_snd_hp_statis_info(void *hp_dmn_)
{
    spo_hp_dmn_t *hp_dmn = (spo_hp_dmn_t *) hp_dmn_;
    spo_msg_t *msg = hp_dmn->statis;
    spo_statis_t *statis = (spo_statis_t *) (msg->data);

    if (hp_dmn_ == NULL) return;

    statis->proc_type = SPO_HP_SPOOFER;
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


static SPO_RET_STATUS spo_do_hp_statis()
{
    InOrderTraverse(current->http_dmn_header->dmn->root, spo_snd_hp_statis_info);
    return SPO_OK;
}


static void spo_hp_statis(int sig, siginfo_t *info, void *p)
{
    info = info;
    p = p;

    if (sig == SIGALRM) {
        spo_do_hp_statis();
        alarm(600);
    }
}


static void spo_rld_hp_cfg(int sig, siginfo_t *info, void *p)
{
    info = info;
    p = p;

    if (sig == SIGUSR1) {
#if SPO_DEBUG
        printf("hp spoofer rld hp cfg\n");
#endif
        current->security = 1;
        current->hp_cfg_security = 1;

    }
}


static void spo_rld_hp_data(int sig, siginfo_t *info, void *p)
{
    info = info;
    p = p;

    if (sig == SIGUSR2) {
#if SPO_DEBUG
        printf("hp spoofer rld hp data\n");
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
        printf("hp spoofer rld hp cfg tmp\n");
#endif
        current->security = 1;
        current->hp_cfg_tmp_security = 1;

    }
}


static void spo_rld_hp_data_tmp(int sig, siginfo_t *info, void *p)
{
    info = info;
    p = p;

    if (sig == SIGTRAP) {
#if SPO_DEBUG
        printf("hp spoofer rld hp data tmp\n");
#endif
        current->security = 1;
        current->hp_data_tmp_security = 1;
    }
}


static SPO_RET_STATUS spo_hp_spoof_init_sig()
{
    sigset_t set;
    memset(&set, '\0', sizeof(sigset_t));

    spo_fill_sigmask(&set);

    spo_del_sig_in_set(SIGUSR1, &set);  //http cfg reload
    spo_del_sig_in_set(SIGUSR2, &set);  //dns cfg reload
    spo_del_sig_in_set(SIGIO, &set);    //http cfg tmp
    spo_del_sig_in_set(SIGTRAP, &set);  //http data tmp
    spo_del_sig_in_set(SIGALRM, &set);  //statis

    spo_signal_a_sigset(&set);

    spo_signal_a_sig(SIGUSR1, spo_rld_hp_cfg);
    spo_signal_a_sig(SIGUSR2, spo_rld_hp_data);
    spo_signal_a_sig(SIGIO, spo_rld_hp_cfg_tmp);
    spo_signal_a_sig(SIGTRAP, spo_rld_hp_data_tmp);
    spo_signal_a_sig(SIGALRM, spo_hp_statis);

    return SPO_OK;
}


/**
 *
 *  http spoofers working here
 *
 * */

void spo_http_spoofer(void *proc_infos)
{
    int i = 0;
#if SPO_SHUTDOWN_HP_SPOF
    while (1) sleep(10);
#endif

    if (proc_infos != NULL) proc_infos = proc_infos;

    spo_bind_cpu(current->info->cpuid, current->pid);
    spo_hp_spoof_init_sig();
    alarm(600);

    /* init transfer table */
    for(i = 0; i < 3; i++) matcpy[i] = spo_hp_infos_cpy;
    for(i = 3; i < 7 ; i++) matcpy[i] = spo_hp_infos_regex_match;

    if (spo_hp_spoof_init_pool(current) == SPO_FAILURE) return;

    spo_do_hp_spoofer(current);
}
