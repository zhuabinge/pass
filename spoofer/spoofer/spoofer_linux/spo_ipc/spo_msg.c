#include "../../spoofer_system/spoofer.h"
#include "../spo_linux.h"
#include "../../spoofer_kernel/spo_kernel.h"


#define SPOOFER_MSQID_DS_SIZE (int)sizeof(struct msqid_ds)


SPO_RET_STATUS spo_init_packet(spo_packet_t *pkt)
{
    pkt->http_s = 0;
    pkt->len = 0;
    pkt->op_len = 0;
    pkt->pkt_s = 0;
    pkt->max_pkts = 0;
    pkt->pkt_info = NULL;
    pkt->info_amt = 0;

    return SPO_OK;
}


SPO_RET_STATUS spo_rst_packet(spo_packet_t *pkt)
{
    int i = 0;
    spo_str_t *info = (spo_str_t *) pkt->pkt_info;

    pkt->http_s = 0;

    pkt->pkt_s = 0;

    for (i = 0; i < pkt->info_amt; i++) {
        spo_init_str(&info[i]);
    }

    pkt->op_len = 0;

    return SPO_OK;
}


SPO_RET_STATUS spo_msgget(key_t key, int msgflg)
{
    int ret = -1;

    ret = msgget(key, msgflg);

    return ret;
}

SPO_RET_VALUE spo_msgrcv(int msgid, void *msg_buf, size_t msg_size, long msg_type, int msgflg)
{
    ssize_t size = 0;

    size = msgrcv(msgid, msg_buf, msg_size, msg_type, msgflg);

    return size;
}


SPO_RET_VALUE spo_msgsnd(int msgid, void *msg_buf, size_t msg_size, int msgflg)
{
    int size = -1;

    if (msg_buf == NULL || msg_size <= 0) {
        return SPO_FAILURE;
    }

    size = msgsnd(msgid, msg_buf, msg_size, msgflg);

    return size;
}



/**
 *
 *  create a msg queue.
 *
 *  @param msgid_p, is the msgid but no a key_t type.
 *
 *  @param msgflg_perm, is the perm of the queue we create.
 *
 *  @return msgid, is the queue id we create.
 *
 **/

SPO_RET_VALUE spo_create_msg_queue(int msgid_p, int msgflg_perm)
{
    int msgid = -1;

    msgid = spo_msgget((key_t) msgid_p, msgflg_perm | IPC_CREAT);

    if (msgid == -1) {
        /* wirte log */
        return SPO_FAILURE;
    }

    return msgid;
}


/**
 *
 *  get the msg queue status.
 *
 *  if more than 3 packets in msg queue, we discard the current packet.
 *
 *  @param msgid, is the msg queue id.
 *
 *  @return the queue status.
 *
 **/

inline SPO_RET_STATUS spo_msg_queue_stat(int msgid, ulong max_amt)
{
    static struct msqid_ds spo_msg_info;

    int ret = msgctl(msgid, IPC_STAT, &spo_msg_info);

    if (ret == SPO_FAILURE) return SPO_FAILURE;

    if (spo_msg_info.msg_qnum > max_amt) {
        memset(&spo_msg_info, '\0', SPOOFER_MSQID_DS_SIZE);
        return SPO_FAILURE;
    }

    memset(&spo_msg_info, '\0', SPOOFER_MSQID_DS_SIZE);

    return SPO_OK;
}
