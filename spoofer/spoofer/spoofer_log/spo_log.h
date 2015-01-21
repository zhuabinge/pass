#ifndef SPO_LOG_H
#define SPO_LOG_H

#include <sys/types.h>
#include <time.h>

#define SPO_UP_HP_CFG   (1)
#define SPO_UP_DNS_CFG  (2)
#define SPO_UP_HP_DATA  (3)

#define SPO_STATIS_MSG_TYPE (12)
#define SPO_LOG_MSG_TYPE    (11)

#define SPO_LOG_LEVEL_ERR   (0)
#define SPO_LOG_LEVEL_WARN  (1)
#define SPO_LOG_LEVEL_MSG   (2)

struct spo_log_s {
    size_t size;            /* msg's size */
    pid_t pid;              /* 写日志的进程id */
    int proc_type;          /* process's type */
    int level;              /* 日志的级别, 0 (error), 1 (warning), 2 (message) */
    char log_info[0];       /* 日志信息 */
};


struct spo_statis_s {
    ulong total_rcv;        /* 总共接收的包 */
    ulong total_snd;        /* 总共发送的包 */
    size_t size;
    struct spo_statis_s *next;
    pid_t pid;              /* 统计的进程id */
    int proc_type;          /* 进程的类型 */
    char domain[0];         /* domain, max domain size is 128. */
};


/* header of all domain statis's info */

struct spo_statis_header_s {
    time_t start;                       /* the start time of this statis */
    time_t now;                         /* the time of now */

    struct spo_statis_s *hp_statis;     /* http spoofer's first statis info */
    struct spo_statis_s *hp_tail;       /* http spoofer's tail's statis info */

    struct spo_statis_s *dns_statis;    /* dns spoofer's first statis info */
    struct spo_statis_s *dns_tail;      /* dns spoofer's tail's statis info */

    struct spo_statis_s *snd_statis;    /* sender's first statis info */
    struct spo_statis_s *snd_tail;      /* sender's tail's statis info */

    int fd;                             /* the statis file fd */
};


/* statis */

SPO_RET_STATUS spo_init_statis(spo_statis_t *statis);
struct spo_statis_s *spo_create_statis(size_t size);

/* loger */
SPO_RET_STATUS spo_do_snd_log_msg(spo_msg_t *msg, const char *log_info, int level);
SPO_RET_STATUS spo_snd_log_msg(spo_msg_t *msg, const char *log_info, int proc_type, int level, pid_t pid);

void spo_loger_statiser(void *info_blk);

#endif // SPO_LOG_H
