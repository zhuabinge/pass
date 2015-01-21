#include "../spoofer_system/spoofer.h"
#include "../spoofer_system/spo_system.h"
#include "../spoofer_pool/spo_pool.h"
#include "../spoofer_sniffer/spo_sniffer.h"
#include "../spoofer_config/spo_config.h"
#include "../spoofer_linux/spo_linux.h"
#include "../spoofer_kernel/spo_kernel.h"
#include "../spoofer_sniffer/spo_spoofer.h"
#include "../spoofer_log/spo_log.h"
#include "../spoofer_test/spo_test.h"
#include <sys/shm.h>


#define SPO_NO_SUM_CHECK 0          /* no ip sum check, libnet create for us */
#define SPO_IP_TOL  0               /* ip tol */
#define SPO_VOID_PALYLOAD_SIZE  0   /* is the palyload is NULL, the size is 0 */
#define SPO_NEW_PACKET_TARGE  0     /* when we create a new packet we use this targe. */
#define SPO_NO_WIN_SIZE     0

#define SPO_TCP_WIN_SIZE  192       /* this is the tcp win size just for test */
#define SPO_NO_TCP_URG  0           /* no tcp usg */
#define SPO_RST_NO_ACK  0x00

#define SPO_VLAN_CFI_MASK   0x1000  /* the mask for vlan cfi, 1 bit */
#define SPO_VLAN_ID_MASK    0x0fff  /* the mask for vlan id, 12 bit */

#define SPO_VLAN_TARGE        1     /* if we not running not vlan */

#define SPO_DNS_PORT	(53)


#define SPO_UDP_HEAD_TOTAL_LEN	(LIBNET_UDP_H + LIBNET_DNS_H)
#define SPO_IP_HEAD_TOTAL_LEN	(LIBNET_IPV4_H + LIBNET_UDP_H + LIBNET_DNS_H)


static SPO_RET_STATUS spo_sender_init_sig();
static void spo_snd_statis(int sig, siginfo_t *info, void *p);
static SPO_RET_STATUS spo_do_snd_sender_statis();

static SPO_RET_STATUS spo_sender_init_pool(spo_proc_node_t *node);
static void spo_do_http_sender(spo_proc_node_t *node, int msgid);
static SPO_RET_STATUS spo_snd_dns_pkt(spo_msg_t *msg);
static SPO_RET_STATUS spo_snd_http_pkt(spo_msg_t *msg);
static SPO_RET_STATUS
spo_send_http_rsp_pkt(spo_hp_hjk_t *hjk_info,
                                 libnet_t *handle, u_char  *playload, uint playload_size);
static SPO_RET_VALUE spo_send_http_rst_pkt(spo_hp_hjk_t *hjk_info, libnet_t *handle);
static SPO_RET_STATUS spo_send_dns_rsp(
        spo_dns_hjk_t *hjk_info, libnet_t *handle, u_char *payload, uint payload_size);
static SPO_RET_STATUS
spo_http_create_handle(char *dev_s, libnet_t **handle_lnk, libnet_t **handle_raw);


#if SPO_SEE_TIME
static void spo_snd_used_time();
#endif


typedef unsigned char uint8_t;

libnet_t *handle_lnk = NULL;
libnet_t *handle_raw = NULL;

spo_msg_t *statis_msg = NULL;



#if SPO_SEE_TIME
static void spo_snd_used_time()
{
    static struct timeval start, *p;

    spo_use_time(SPO_TIME_END, "sender");
    gettimeofday(&start, 0);

    p = shmat(sys_shmid, NULL, 0);
    if (p != NULL)  {
        float ff = 1000000 * (start.tv_sec - p->tv_sec) + (start.tv_usec - p->tv_usec);
        printf("total use time ----------- %f ms\n", ff / 1000);
    }
}
#endif


/**
 *
 *  init the handle for send packets.
 *
 * */

static SPO_RET_STATUS
spo_http_create_handle(char *dev_s, libnet_t **handle_lnk, libnet_t **handle_raw)
{
    char error_raw[LIBNET_ERRBUF_SIZE]; /* 出错信息 */
    char error_vlan[LIBNET_ERRBUF_SIZE]; /* 出错信息 */

    /* init handle */
    if (*handle_lnk == NULL) {
        *handle_lnk = libnet_init(LIBNET_LINK, dev_s, error_vlan);
        if (*handle_lnk == NULL) goto spo_bad_handle;
    }

    if (*handle_raw == NULL) {
        *handle_raw = libnet_init(LIBNET_RAW4, dev_s, error_raw);
        if (*handle_raw == NULL) goto spo_bad_handle;
    }

    return SPO_OK;

spo_bad_handle:

    if (*handle_lnk != NULL) libnet_destroy(*handle_lnk);
    if (*handle_raw != NULL) libnet_destroy(*handle_raw);

    return SPO_ERR;
}


/**
 *
 *  here we send the dns response packet.
 *
 *  @param hjk_info, is the info that in dns request packet and we need it to built the packet.
 *
 *  @param handle, is the libnet handle we send the packet.
 *
 *  @param payload, is the dns response contents.
 *
 *  @param payload_size, is the contents size.
 *
 *  @return int, is the exec status.
 *
 **/

static SPO_RET_STATUS spo_send_dns_rsp(
        spo_dns_hjk_t *hjk_info, libnet_t *handle, u_char *payload, uint payload_size)
{
    int ret = 0;
    libnet_ptag_t t;
    uint8_t ttl = 0;

    u_short proto = IPPROTO_UDP; /* 传输层协议 */

    t = libnet_build_dnsv4(
                LIBNET_DNS_H,
                hjk_info->dns_id,               /* dns id */
                hjk_info->dns_flag,             /* flsge */
                hjk_info->dns_ques,             /* question amount */
                hjk_info->dns_ans,              /* answers */
                hjk_info->dns_auth,             /* auth_rr */
                hjk_info->dns_add,              /* addi_rr */
                (uint8_t *)payload,             /* payload start */
                payload_size,                   /* dns payload size */
                handle,
                SPO_NEW_PACKET_TARGE
                );

    if (t == -1) {
#if SPO_DEBUG
        printf("build dns err\n");
#endif
        return SPO_FAILURE;
    };

    t = libnet_build_udp(
                SPO_DNS_PORT,                         			/* 源端口 */
                hjk_info->src_port,                             /* 目的端口 */
                SPO_UDP_HEAD_TOTAL_LEN + payload_size,          /* 长度 */
                SPO_NO_SUM_CHECK,                               /* 校验和,0为libnet自动计算 */
                NULL,                                           /* 负载内容 */
                SPO_VOID_PALYLOAD_SIZE,                     /* 负载内容长度 */
                handle,                                         /* libnet句柄 */
                SPO_NEW_PACKET_TARGE                        /* 新建包 */
                );

    if (t == -1) {
#if SPO_DEBUG
        printf("libnet_build_udp failure\n");
#endif
        return SPO_FAILURE;
    };

    ttl = (ttl = (uint8_t)libnet_get_prand(LIBNET_PR8)) < 64 ? ttl + 64 : ttl;

    /* 构造IP协议块，返回值是新生成的IP协议快的一个标记 */
    t = libnet_build_ipv4(
                SPO_IP_HEAD_TOTAL_LEN + payload_size,           /* IP协议块的总长,*/
                SPO_IP_TOL,                                     /* tos */
                (u_short) libnet_get_prand(LIBNET_PRu16),       /* id */
                hjk_info->ip_off,                      			/* frag 片偏移 */
                ttl,                                            /* ttl */
                proto,                                          /* 上层协议 */
                SPO_NO_SUM_CHECK,                               /* 校验和，此时为0，表示由Libnet自动计算 */
                hjk_info->dst_address,                          /* 源IP地址,网络序 */
                hjk_info->src_address,                          /* 目标IP地址,网络序 */
                NULL,                                           /* 负载内容或为NULL */
                0,                                              /* 负载内容的大小*/
                handle,                                         /* Libnet句柄 */
                SPO_NEW_PACKET_TARGE                            /* 协议块标记可修改或创建,0表示构造一个新的*/
                );

    if (t == -1) {
#if SPO_DEBUG
        perror("libnet_build_ipv4 failure\n");
#endif
        return SPO_FAILURE;
    };

    if (hjk_info->vlan_targe) {
        t = libnet_build_802_1q(
                    hjk_info->src_mac,                                                  /* dest mac */
                    hjk_info->dst_mac,                                                  /* source mac */
                    ETHERTYPE_VLAN,                                                     /* TPI */
                    (uint8_t) ((hjk_info->vlan_id & SPO_VLAN_PROT_MASK)  >> 13),        /* priority (0 - 7) */
                    (uint8_t) ((hjk_info->vlan_id & SPO_VLAN_CFI_MASK) >> 12),          /* CFI flag */
                    hjk_info->vlan_id & SPO_VLAN_ID_MASK,                               /* vid (0 - 4095) */
                    IPPROTO_IP,                                                         /*for ip*/
                    NULL,                                                               /* payload */
                    0,                                                                  /* payload size */
                    handle,                                                             /* libnet handle */
                    0);                                                                 /* libnet id */

        if (t == -1) {
#if SPO_DEBUG
            perror("803.1q err \n");
#endif
            return SPO_FAILURE;
        }
    }

    ret = libnet_write(handle); /* 发送已经构造的数据包*/

    libnet_clear_packet(handle);

#if SPO_DEBUG
        printf("dns send -- %d\n", ret);
#endif

    if (ret == SPO_FAILURE) return SPO_FAILURE;

    return SPO_OK;
}


/**
 *  here we send the rst packet in vlan env.
 *
 *  the rst packet discontinue the connection between server and client.
 *
 *  @param hjk_info, record the http packet's info.
 *
 *  @param handle, the handle where we send the packet.
 *
 * */

static SPO_RET_VALUE spo_send_http_rst_pkt(spo_hp_hjk_t *hjk_info, libnet_t *handle)
{
    libnet_ptag_t t;
    int ret = SPO_FAILURE;
    uint8_t ttl = 0;

    t = libnet_build_tcp(
                hjk_info->tcp_src_port,         /* tcp src port */
                hjk_info->tcp_dst_port,         /* tcp dst port */
                hjk_info->tcp_rst_resp_seq,     /* tcp seq */
                SPO_RST_NO_ACK,                 /* tcp Ack */
                TH_RST,
                SPO_NO_WIN_SIZE,                /* win size */
                SPO_NO_SUM_CHECK,               /* tcp sum check */
                SPO_NO_TCP_URG,                 /* tcp urg */
                LIBNET_TCP_H,                   /* tcp header length */
                NULL,                           /* tcp palyload */
                SPO_VOID_PALYLOAD_SIZE,         /* palload size */
                handle,
                SPO_NEW_PACKET_TARGE
                );

    if (t == SPO_FAILURE) goto spo_bad_build_pkt;

    ttl = (ttl = (uint8_t)libnet_get_prand(LIBNET_PR8)) < 64 ? ttl + 64 : ttl;
    t = libnet_build_ipv4(
                LIBNET_IPV4_H + LIBNET_TCP_H,                   /* ip length, is the palyload size and the header length */
                SPO_IP_TOL,                                     /* ip tol */
                (u_short) libnet_get_prand(LIBNET_PRu16),       /* ip id */
                hjk_info->ip_off,
                ttl,                                            /* ip ttl */
                IPPROTO_TCP,                                    /* tcp prot */
                SPO_NO_SUM_CHECK,                               /* ip check sum */
                hjk_info->ip_src_addr,                          /* ip src address */
                hjk_info->ip_dst_addr,                          /* ip dst address */
                NULL,                                           /* ip palyload */
                SPO_VOID_PALYLOAD_SIZE,                         /* ip palyload size */
                handle,
                SPO_NEW_PACKET_TARGE
                );

    if (t == SPO_FAILURE) goto spo_bad_build_pkt;

    if (hjk_info->vlan_targe == SPO_VLAN_TARGE) {                                   /*  running in vlan */
        t = libnet_build_802_1q(
                    hjk_info->dst_mac,                                              /* dest mac */
                    hjk_info->src_mac,                                              /* source mac */
                    ETHERTYPE_VLAN,                                                 /* TPI */
                    (uint8_t) (hjk_info->vlan_id >> 13),                            /* priority (0 - 7) */
                    (uint8_t) ((hjk_info->vlan_id & SPO_VLAN_CFI_MASK) >> 12),      /* CFI flag */
                    hjk_info->vlan_id & SPO_VLAN_ID_MASK,                           /* vid (0 - 4095) */
                    ETHERTYPE_IP,                                                   /* for ip */
                    NULL,                                                           /* payload */
                    SPO_VOID_PALYLOAD_SIZE,                                         /* payload size */
                    handle,                                                         /* libnet handle */
                    SPO_NEW_PACKET_TARGE
                    );

        if (t == SPO_FAILURE) goto spo_bad_build_pkt;
    }

    ret = libnet_write(handle);

spo_bad_build_pkt:

    libnet_clear_packet(handle);

    if (ret == SPO_FAILURE) return SPO_FAILURE;

    return SPO_OK;
}


/**
 *  here we send the http response packet to user in vlan env.
 *
 *  @param hjk_info, record the http packet's info.
 *
 *  @param handle, the handle we send the packet.
 *
 *  @param playload, the http packet content, we use it to spoofe the users.
 *
 *  @param playload_size, the http packet content size.
 *
 * */

static SPO_RET_STATUS
spo_send_http_rsp_pkt(spo_hp_hjk_t *hjk_info,
                                 libnet_t *handle, u_char  *playload, uint playload_size)
{
    libnet_ptag_t t;
    int ret = SPO_FAILURE;
    u_int8_t ttl = 0;

    t = libnet_build_tcp(
                hjk_info->tcp_dst_port,                                 /* tcp src port */
                hjk_info->tcp_src_port,                                 /* tcp dst port */
                hjk_info->tcp_resp_seq,                                 /* tcp seq */
                hjk_info->tcp_resp_Ack,                                 /* tcp ACK */
                hjk_info->tcp_resp_flg | TH_FIN,                        /* tcp flags */
                SPO_TCP_WIN_SIZE,                                       /* win size */
                SPO_NO_SUM_CHECK,                                       /* check sum */
                SPO_NO_TCP_URG,                                         /* tcp ueg targe */
                LIBNET_TCP_H + playload_size,                           /* tcp total size */
                (uint8_t *)playload,                                    /* tcp palyload */
                playload_size,                                          /* tcp palyload size, is the http packets size */
                handle,
                SPO_NEW_PACKET_TARGE
                );

    if (t == SPO_FAILURE) goto spo_bad_build_pkt;

    ttl = (ttl = (uint8_t)libnet_get_prand(LIBNET_PR8)) < 64 ? ttl + 64 : ttl;

    t = libnet_build_ipv4(
                LIBNET_IPV4_H + LIBNET_TCP_H + playload_size,           /* ip total size */
                SPO_IP_TOL,                                             /* ip tol */
                (u_short) libnet_get_prand(LIBNET_PRu16),               /* ip id */
                hjk_info->ip_off,                                       /* ip don't fragment */
                ttl,                                                    /* ip ttl */
                IPPROTO_TCP,                                            /* the prot is ip */
                SPO_NO_SUM_CHECK,                                       /* sum check is 0, libnet will create it for us */
                hjk_info->ip_dst_addr,                                  /* ip src addr */
                hjk_info->ip_src_addr,                                  /* ip dst addr */
                NULL,                                                   /* ip palyload */
                SPO_VOID_PALYLOAD_SIZE,                                 /* ip palyload size */
                handle,
                SPO_NEW_PACKET_TARGE
                );

    if (t == SPO_FAILURE) goto spo_bad_build_pkt;

    if (hjk_info->vlan_targe == SPO_VLAN_TARGE) {                               /* running in vlan */
        t = libnet_build_802_1q(
                    hjk_info->src_mac,                                          /* dest mac */
                    hjk_info->dst_mac,                                          /* source mac */
                    ETHERTYPE_VLAN,                                             /* TPI */
                    (uint8_t) (hjk_info->vlan_id >> 13),                        /* priority (0 - 7) */
                    (uint8_t) ((hjk_info->vlan_id & SPO_VLAN_CFI_MASK) >> 12),  /* CFI flag */
                    hjk_info->vlan_id & SPO_VLAN_ID_MASK,                       /* vid (0 - 4095) */
                    ETHERTYPE_IP,                                               /* for ip */
                    NULL,                                                       /* payload */
                    SPO_VOID_PALYLOAD_SIZE,                                     /* payload size */
                    handle,                                                     /* libnet handle */
                    SPO_NEW_PACKET_TARGE
                    );

        if (t == SPO_FAILURE) goto spo_bad_build_pkt;
    }


    ret = libnet_write(handle);

spo_bad_build_pkt:

    libnet_clear_packet(handle);
    if (ret == SPO_FAILURE) return SPO_FAILURE;

#if SPO_DEBUG
        printf("ret response   %d \n", ret);
#endif

    return SPO_OK;
}


/**
 *
 *  go to send the packets.
 *
 * */

static SPO_RET_STATUS spo_snd_http_pkt(spo_msg_t *msg)
{
    spo_bld_pkt_t *bld_pkt = (spo_bld_pkt_t *) ((char *) msg->data);
    spo_hp_hjk_t *hjk_info = NULL;
    u_char *p = (u_char *) msg;
    size_t p_size = 0;

    hjk_info = (spo_hp_hjk_t *) ((char *) bld_pkt->bld_data);

    p = p + bld_pkt->http_start;
    p_size = bld_pkt->h_header_s + bld_pkt->h_data_s;

    if (hjk_info->vlan_targe == SPO_RUNNING_IN_VLAN) {      /* running in the vlan env */
        if ((spo_send_http_rsp_pkt(hjk_info, handle_lnk, p, p_size)) == SPO_FAILURE) return SPO_FAILURE;
        //if ((spo_send_http_rst_pkt(hjk_info, handle_lnk)) == SPO_FAILURE) return SPO_FAILURE;
    }else {
        if ((spo_send_http_rsp_pkt(hjk_info, handle_raw, p, p_size)) == SPO_FAILURE) return SPO_FAILURE;
        //if ((spo_send_http_rst_pkt(hjk_info, handle_raw)) == SPO_FAILURE) return SPO_FAILURE;
    }

    return SPO_OK;
}


/**
 *
 *  to snd the dns packet.
 *
 * */

static SPO_RET_STATUS spo_snd_dns_pkt(spo_msg_t *msg)
{
    spo_bld_pkt_t *bld_pkt = (spo_bld_pkt_t *) ((char *) msg->data);
    spo_dns_hjk_t *hjk = (spo_dns_hjk_t *) (bld_pkt->bld_data);
    u_char *data = (((u_char *)(bld_pkt->bld_data)) + sizeof(spo_dns_hjk_t));

    if (hjk->vlan_targe == SPO_RUNNING_IN_VLAN) {
        spo_send_dns_rsp(hjk, handle_lnk, data, bld_pkt->h_data_s);
    }else {
        spo_send_dns_rsp(hjk, handle_raw, data, bld_pkt->h_data_s);
    }

    return SPO_OK;
}


static spo_msg_t *spo_init_senders_statis_info()
{
    spo_msg_t *msg = NULL;
    spo_statis_t *statis = NULL;
    size_t size = sizeof(spo_msg_t) + sizeof(spo_statis_t) + 129;

    if ((msg = spo_calloc(size)) == NULL) return NULL;
    msg->type = SPO_STATIS_MSG_TYPE;
    statis = (spo_statis_t *) ((char *) msg->data);

    statis->pid         = current->pid;
    statis->proc_type   = SPO_SENDER;
    statis->size        = size;
    statis->next        = NULL;
    statis->total_rcv   = 0;
    statis->total_snd   = 0;

    memcpy(statis->domain, "all", strlen("all"));

    return msg;
}


/**
 *
 *  http senders work here.
 *
 * */

static void spo_do_http_sender(spo_proc_node_t *node, int msgid)
{
    spo_msg_t *msg = node->hp_pkt;
    spo_bld_pkt_t *bld_pkt = (spo_bld_pkt_t *) ((char *) msg->data);
    size_t rcv_size = bld_pkt->len;
    spo_statis_t *statis = NULL;

    /* init handle */
    if ((spo_http_create_handle((char *) node->info->dev, &handle_lnk, &handle_raw)) == SPO_ERR) return;

    while (1) {
        if ((spo_msgrcv(msgid, msg, rcv_size, SPO_HTTP_SEND_MSG_TYPE, 0)) == SPO_FAILURE) {
            continue;
        }
#if SPO_SEE_TIME
        spo_use_time(SPO_TIME_START, "sender");
#endif

        statis = (spo_statis_t *) (statis_msg->data);
        statis->total_rcv++;

        bld_pkt = (spo_bld_pkt_t *) ((char *) msg->data);

        if (bld_pkt->msg_type == SPO_MSG_HP) {
            if (spo_snd_http_pkt(msg) != SPO_FAILURE) {
                statis = (spo_statis_t *) (statis_msg->data);
                statis->total_snd++;
            }
#if SPO_SEE_TIME
            spo_snd_used_time();
#endif
            continue;
        }

        if (bld_pkt->msg_type == SPO_MSG_DNS) {
            if (spo_snd_dns_pkt(msg) != SPO_FAILURE) {
                statis = (spo_statis_t *) (statis_msg->data);
                statis->total_snd++;
            }
        }
    }
}


/**
 *
 *  senders init pool.
 *
 * */

static SPO_RET_STATUS spo_sender_init_pool(spo_proc_node_t *node)
{
    spo_pool_t *pool = NULL;
    spo_bld_pkt_t *bld_pkt = NULL;

    if ((pool = spo_create_pool(8 * 8192)) == NULL) return SPO_FAILURE;
    node->pool = pool;

    if ((node->hp_pkt = spo_palloc(pool, node->cfg->global->max_send_size)) == NULL) return SPO_FAILURE;
    bld_pkt = (spo_bld_pkt_t *) (node->hp_pkt->data);

    bld_pkt->len = node->cfg->global->max_send_size;

    return SPO_OK;
}


static SPO_RET_STATUS spo_do_snd_sender_statis(spo_msg_t *msg)
{
    spo_statis_t *statis = NULL;
    size_t size = 0;

    if (msg == NULL) return SPO_FAILURE;

    statis = (spo_statis_t *) ((char *)msg->data);
    size = statis->size;

    if (spo_msgsnd(statis_msgid, msg, size, IPC_NOWAIT) == SPO_FAILURE) {
#if SPO_DEBUG
        printf("sender snd stati msg err\n");
        perror("err : \n");
#endif
    }

    statis->total_rcv = 0;
    statis->total_snd = 0;

    return SPO_OK;
}


static void spo_snd_statis(int sig, siginfo_t *info, void *p)
{
    info = info;
    p = p;

    if (sig == SIGALRM) {
        spo_do_snd_sender_statis(statis_msg);
        alarm(600);
    }
}


static SPO_RET_STATUS spo_sender_init_sig()
{
    sigset_t set;
    memset(&set, '\0', sizeof(sigset_t));

    spo_fill_sigmask(&set);

    spo_del_sig_in_set(SIGALRM, &set);  //http cfg reload

    spo_signal_a_sigset(&set);

    spo_signal_a_sig(SIGALRM, spo_snd_statis);

    return SPO_OK;
}


/**
 *
 *  http senders working here.
 *
 * */

void spo_http_sender(void *proc_infos)
{
    proc_infos = proc_infos;

    spo_sender_init_sig();

    if ((statis_msg = spo_init_senders_statis_info()) == NULL) return;

    spo_bind_cpu(current->info->cpuid, current->pid);

#if SPO_SHUTDOWN_SND
    while (1) sleep(10);
#endif

    alarm(600);

    if (spo_sender_init_pool(current) == SPO_FAILURE) exit(EXIT_FAILURE);

    spo_do_http_sender(current, current->hp_msgid[1]);
}
