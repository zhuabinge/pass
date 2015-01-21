#include "../spoofer_system/spoofer.h"
#include "../spoofer_pool/spo_pool.h"
#include "../spoofer_linux/spo_linux.h"
#include "../spoofer_config/spo_config.h"
#include "spo_log.h"

#include <pthread.h>
#include <sys/file.h>

#define SPO_MAX_STATIS_SIZE (1024)

spo_statis_head_t *statis_header = NULL;



SPO_RET_STATUS spo_init_log_info(spo_log_t *log)
{
    log->level = 0;
    log->pid = 0;
    log->proc_type = 0;

    return SPO_OK;
}


SPO_RET_STATUS spo_init_statis(spo_statis_t *statis)
{
    statis->pid         = 0;
    statis->size        = 0;
    statis->proc_type   = -1;
    statis->total_rcv   = 0;
    statis->total_snd   = 0;
    statis->next        = NULL;

    return SPO_OK;
}


struct spo_statis_s *spo_create_statis(size_t size)
{
    size = sizeof(spo_statis_t) + size;

    spo_statis_t *statis = spo_calloc(size);

    if (statis == NULL) return NULL;

    memset(statis, '\0', size);

    spo_init_statis(statis);

    return statis;
}


spo_statis_head_t *spo_create_statis_header()
{
    spo_statis_head_t *header = NULL;

    if ((header = spo_calloc(sizeof(spo_statis_head_t))) == NULL) return NULL;

    header->fd          = 0;

    header->hp_statis   = NULL;
    header->hp_tail     =NULL;

    header->dns_statis  = NULL;
    header->dns_tail    = NULL;

    header->snd_statis  = NULL;
    header->snd_tail    = NULL;

    return header;
}


SPO_RET_STATUS spo_do_destory_statis_header(spo_statis_t *statis)
{
    spo_statis_t *p = statis;

    if (statis == NULL) return SPO_OK;

    while (p != NULL) {
        statis = statis->next;
        spo_free(p);
        p = statis;
    }

    return SPO_OK;
}


SPO_RET_STATUS spo_destory_statis_header(spo_statis_head_t *header)
{
    if (header == NULL) return SPO_OK;

    spo_do_destory_statis_header(header->hp_statis);
    spo_do_destory_statis_header(header->dns_statis);
    spo_do_destory_statis_header(header->snd_statis);

    spo_free(header);

    return SPO_OK;
}


SPO_RET_STATUS spo_do_snd_log_msg(spo_msg_t *msg, const char *log_info, int level)
{
    spo_log_t *log = NULL;
    size_t size = 0;
    size_t len = strlen(log_info);

    size = strlen(log_info) + sizeof(spo_msg_t) + sizeof(spo_log_t);

    log = (spo_log_t *) msg->data;
    log->level = level;

    if (log->size < size) return SPO_FAILURE;

    memset(log->log_info, '\0', len);
    msg->type = SPO_LOG_MSG_TYPE;
    memcpy(log->log_info, log_info, len);

    if (spo_msgsnd(log_msgid, msg, size, IPC_NOWAIT) == SPO_FAILURE) {
#if SPO_DEBUG
        printf("sender log info err\n");
        perror("err : \n");
#endif
        return SPO_FAILURE;
    }

    return SPO_OK;
}


SPO_RET_STATUS spo_snd_log_msg(spo_msg_t *msg, const char *log_info, int proc_type, int level, pid_t pid)
{
    spo_log_t *log = NULL;

    log = (spo_log_t *) (msg->data);

    log->pid = pid;
    log->proc_type = proc_type;

    return spo_do_snd_log_msg(msg, log_info, level);
}


static void spo_do_write_statis_info(spo_statis_head_t *header)
{
    spo_statis_t *p = NULL;
    FILE *fp = NULL;

    if ((fp = spo_fopen(current->cfg->global->statis_file, "w")) == NULL) return;
    if ((header->fd = fileno(fp)) == -1) return;
    flock(header->fd, LOCK_EX | LOCK_NB);

    time(&header->now);

    p = header->hp_statis;
    while (p != NULL) {
        fprintf(fp, "http,%s,%ld,%ld,%ld,%ld\n", p->domain, p->total_rcv, p->total_snd, header->start, header->now);
        p = p->next;
    }

    p = header->dns_statis;
    while (p != NULL) {
        fprintf(fp, "dns,%s,%ld,%ld,%ld,%ld\n", p->domain, p->total_rcv, p->total_snd, header->start, header->now);
        p = p->next;
    }

    p = header->snd_statis;
    while (p != NULL) {
        fprintf(fp, "senders,%s,%ld,%ld,%ld,%ld\n", p->domain, p->total_rcv, p->total_snd, header->start, header->now);
        p = p->next;
    }

    fchmod(header->fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    flock(header->fd, LOCK_UN);
    spo_fclose(fp);
}


static void spo_write_statis_info(int sig, siginfo_t *info, void *p)
{
    info = info;
    p = p;

    if (sig == SIGALRM) {
        /* write to file */
        spo_do_write_statis_info(statis_header);
        alarm(5);
    }
}


static SPO_RET_STATUS spo_init_statis_sig()
{
    sigset_t set;
    memset(&set, '\0', sizeof(sigset_t));

    spo_fill_sigmask(&set);

    spo_del_sig_in_set(SIGALRM, &set);  //http cfg reload

    spo_signal_a_sigset(&set);

    spo_signal_a_sig(SIGALRM, spo_write_statis_info);

    return SPO_OK;
}


static spo_statis_t *spo_search_statis_info(spo_statis_t *header, spo_statis_t *statis)
{
    if (header == NULL) return NULL;

    spo_statis_t *p = NULL;
    p = header;

    while (p != NULL) {
        if (memcmp(p->domain, statis->domain, strlen(statis->domain)) == 0) {
            return p;
        }

        p = p->next;
    }

    return NULL;
}


static SPO_RET_STATUS spo_copy_statis_info(spo_statis_t *statis, spo_statis_t *rcv)
{
    statis->pid = rcv->pid;
    statis->proc_type = rcv->proc_type;
    statis->total_rcv = rcv->total_rcv;
    statis->total_snd = rcv->total_snd;

    memcpy(statis->domain, rcv->domain, strlen(rcv->domain));

    return SPO_OK;
}


static SPO_RET_STATUS spo_do_insert_statis_info(spo_statis_t **statis_header, spo_statis_t **statis_tail, spo_statis_t *statis)
{
    spo_statis_t *p = NULL;
    spo_statis_t *insert_point = NULL;

    insert_point = spo_search_statis_info((*statis_header), statis);

    if (insert_point == NULL) {
        if ((p = spo_create_statis(strlen(statis->domain))) == NULL) return SPO_FAILURE;

        if ((*statis_header) == NULL) {    /* insert queue header */
            (*statis_header) = p;
            (*statis_tail) = p;
        }else {
            /* insert statis into queue tail */
            (*statis_tail)->next = p;
            (*statis_tail) = p;
        }

        p->next = NULL;
        spo_copy_statis_info(p, statis);
    }else {     /* this statis info was exist */
        insert_point->total_rcv += statis->total_rcv;
        insert_point->total_snd += statis->total_snd;
    }

    return SPO_OK;
}


static SPO_RET_STATUS spo_insert_statis_info(spo_statis_head_t *header, spo_statis_t *statis)
{
    int type = 0;

    if (header == NULL || statis == NULL) return SPO_FAILURE;

    type = statis->proc_type;

    if (type == SPO_HP_SPOOFER) {
        return spo_do_insert_statis_info(&header->hp_statis, &header->hp_tail, statis);
    }

    if (type == SPO_DNS_SPOOFER) {
        return spo_do_insert_statis_info(&header->dns_statis, &header->dns_tail, statis);
    }

    if (type == SPO_SENDER) {
        return spo_do_insert_statis_info(&header->snd_statis, &header->snd_tail, statis);
    }

    return SPO_FAILURE;
}


static void spo_do_statiser(spo_proc_node_t *node, spo_statis_head_t *header, int msgid)
{
    node = node;
    spo_msg_t *msg = NULL;
    spo_statis_t *statis = NULL;
    size_t len = 0;

    len = SPO_MAX_STATIS_SIZE;

    if ((msg = spo_calloc(len)) == NULL) return;

    while (SPO_TRUE) {

        if (spo_msgrcv(msgid, msg, len, SPO_STATIS_MSG_TYPE, 0) == SPO_FAILURE) continue;

        statis = (spo_statis_t *) ((char *) msg->data);
        spo_insert_statis_info(header, statis);

        memset(msg, '\0', len);
    }
}


void spo_statiser(void *info_blk)
{
    if (info_blk != NULL) info_blk = info_blk;

    int msgid = spo_create_msg_queue(20152016, 0666);
    if (msgid == SPO_FAILURE) return;

    spo_init_statis_sig();

    alarm(5);

    if ((statis_header = spo_create_statis_header()) == NULL) return;

    time(&statis_header->start);

    spo_do_statiser(current, statis_header, msgid);
}


static SPO_RET_STATUS spo_log_proc_type(char *proc_type, spo_log_t *log)
{
    if (proc_type == NULL || log == NULL) return SPO_FAILURE;

    if (log->proc_type == SPO_SNIFFER) {
        memcpy(proc_type, "sniffer", strlen("sniffer"));
    }else {
        if (log->proc_type == SPO_HP_SPOOFER) {
            memcpy(proc_type, "http spoofer", strlen("http spoofer"));
        }else {
            if (log->proc_type == SPO_DNS_SPOOFER) {
                memcpy(proc_type, "dns spoofer", strlen("dns spoofer"));
            }else {
                if (log->proc_type == SPO_SENDER) {
                    memcpy(proc_type, "sender", strlen("sender"));
                }else {
                    memcpy(proc_type, "main", strlen("main"));
                }
            }
        }
    }

    return SPO_OK;
}


static SPO_RET_STATUS spo_log_level(char *level, spo_log_t *log)
{
    if (level == NULL || log == NULL) return SPO_FAILURE;

    switch (log->level) {
    case SPO_LOG_LEVEL_ERR:
        memcpy(level, "error", strlen("error"));
        break;
    case SPO_LOG_LEVEL_WARN:
        memcpy(level, "warning", strlen("warning"));
        break;
    case SPO_LOG_LEVEL_MSG:
        memcpy(level, "message", strlen("message"));
        break;
    default:
        memcpy(level, "error", strlen("error"));
    }

    return SPO_OK;
}


static SPO_RET_STATUS spo_write_log(spo_log_t *log, char *log_data, int fd)
{
    char proc_type[32] = {'\0'};
    char level[16] = {'\0'};
    time_t now;
    struct tm *timenow = NULL;
    char *str_time = NULL;

    if (log == NULL) return SPO_FAILURE;

    spo_log_proc_type(proc_type, log);
    spo_log_level(level, log);
    memset(log_data, '\0', 1024);

    time(&now);
    timenow = localtime(&now);
    str_time = asctime(timenow);
    str_time[strlen(str_time) - 1] = '\0';

    sprintf(log_data, "%s, %s pid %ld, %s, %s\n", level, proc_type, (long) log->pid, log->log_info, str_time);
    if (spo_write(fd, log_data, strlen(log_data)) == SPO_FAILURE) return SPO_FAILURE;

    return SPO_OK;
}


static void spo_do_loger()
{
    size_t size = 0;
    int fd = 0;
    spo_msg_t *log_msg = NULL;
    spo_log_t *log = NULL;
    char *log_data = NULL;

    size = sizeof(spo_msg_t) + sizeof(spo_log_t) + current->cfg->global->max_log_len + 1;

    if ((log_msg = spo_calloc(size)) == NULL) return;
    memset(log_msg, '\0', size);

    if ((log_data = spo_calloc(1024)) == NULL) return;

    log = (spo_log_t *) ((char *) log_msg->data);
    spo_init_log_info(log);

    if ((fd = spo_open(current->cfg->global->log_file, O_CREAT | O_WRONLY | O_APPEND, 0666)) == SPO_FAILURE) return;

    fchmod(fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

    while (SPO_TRUE) {
        if (spo_msgrcv(log_msgid, log_msg, size, SPO_LOG_MSG_TYPE, 0) == SPO_FAILURE) {
#if SPO_DEBUG
            printf("loger rcv msg err\n");
            perror("err : \n");
#endif
            continue;
        }

        log = (spo_log_t *) ((char *) log_msg->data);
        spo_write_log(log, log_data, fd);

        memset(log_msg, '\0', size);
        spo_init_log_info(log);

        //when file size too big, clear it.
    }
}


void *spo_loger(void *info_blk)
{
    printf("i am loger\n");

    if (info_blk != NULL) info_blk = info_blk;

    sigset_t set;
    memset(&set, '\0', sizeof(sigset_t));

    spo_fill_sigmask(&set);

    pthread_sigmask(SIG_SETMASK, &set, NULL);

    spo_do_loger();

    return NULL;
}


void spo_loger_statiser(void *info_blk)
{
    pthread_t loger_tid;

    if (info_blk != NULL) info_blk = info_blk;

    if (pthread_create(&loger_tid, NULL, spo_loger, info_blk) != 0) return;

    spo_statiser(info_blk);
}

