#ifndef SPO_CONFIG_H
#define SPO_CONFIG_H

#include <sys/types.h>
#include <regex.h>
#include "../spoofer_kernel/spo_kernel.h"


typedef enum spo_cfg_stat_e {
    SPO_IN_START    = 0,
    SPO_IN_GLOBAL   = 1,
    SPO_IN_SNIFFER  = 2,
    SPO_IN_SPOOFER  = 4,
    SPO_IN_SENDER   = 8,
    SPO_IN_DOMAIN   = 16
}spo_cfg_stat;


struct spo_info_s {
    char type[16];                      /* 进程的类型，sniffer，http_spoofer, dns_spoofer */
    int *h_msgid;                       /* 处理http msg 的队列id数组 */
    int *d_msgid;                       /* 处理http msg 的队列id数组 */
    u_char *filter;                     /* 进程使用的包过滤规则 */
    u_char *dev;                        /* 接收包的驱动 */
    struct spo_info_s *next;            /* 下一个info */
    char lib[8];                        /* 进行使用的捉包库，pcap或者pf */
    pid_t pid;                          /* 使用这个info的进程的id */
    int cpuid;                          /* 这个进程绑定到那个cpu上 */
    int driection;                      /* pcaket driection, only 1(tx), 0(rx), 2(rx and tx ) */
};


struct spo_info_header_s {
    struct spo_info_s *infos;           /* 记录进程信息块 */
    struct spo_info_s *infos_tail;
    uint sniffers:8;                    /* sniffer进程的个数，使用位域，最大为255个 */
    uint h_spofs:8;                     /* http spoofer进程的个数 */
    uint d_spofs:8;                     /* dnd spoofer进程的个数 */
    uint sender:8;                      /* sender进程的个数 */
};

struct spo_cfg_g_s{
    ulong max_dns_pkt_s;                /* dns包的最大长度 */
    ulong max_http_pkt_s;               /* http包的最大长度 */
    ulong max_send_size;                /* the max size of built data. */
    ulong max_log_len;                  /* max log info len */
    char *h_dmn_cfg_file;               /* http 域名的配置文件路径 */
    char *h_data_path;                  /* http 伪造包数据路径 */
    char *d_data_path;                  /* dns 伪造包的数据路径 */
    char *log_file;                     /* log file path and name */
    char *statis_file;                  /* statis file path and name */
    spo_tree_header_t *hp_mtd;          /* http method's tree */
};

struct spo_cfg_s{
    struct spo_cfg_g_s *global;              /* 记录全局的指令 */
    struct spo_info_header_s inf_header;
};

/* for business */
struct spo_hp_data_info_s{
    size_t offset;
    void *pr;                           /* the pcre regex */
    struct spo_hp_data_info_s *next;
    struct spo_hp_data_info_s *prcv;
    u_char type;
    u_char len;
};


/* tree key */
struct spo_http_data_s{
    spo_str_t dmn;                          /* 伪造包数据对应的域名 */
    spo_str_t data;                         /* 伪造包的数据 */
    spo_str_t data_cp;                      /* use to send packet to senders. */
    struct spo_hp_data_info_s *data_info;   /* a data info */
    struct spo_hp_data_info_s *tail;        /* a data info */
    uint data_satrt;                        /* pointer to data.data's hp data's dtart*/
    int num;                                /* 伪造包的number，用于排序与搜索 */
};


struct spo_http_cfg_line_s {
    void *pcre_url;
    void *pcre_cok;
    void *pcre_ref;

    int u_flg;
    int c_flg;
    int r_flg;

    int num;                                    /* http data tree number */
    struct spo_http_cfg_line_s *next;           /* 下一条表达式 */
};


/* 域名信息块 */
struct spo_http_dmn_s {
    spo_str_t dmn;                                  /* domain */
    struct spo_http_cfg_line_s *cfg_line;           /* 域名的配置line */
    struct spo_http_cfg_line_s *cfg_line_tail;      /* 域名的配置line */
    void *statis;                                   /* statis info, is spo_msg_t, spo_msg_t->data is spo_statis_t */
};


/* tree key */
struct spo_dns_data_s {
    spo_str_t dmn;                                  /* dns配置域名 */
    spo_str_t data;                                 /* dns伪造包的数据 */
    spo_str_t data_cp;                              /* use to snd the packet to senders */
    void *statis;                               /* statis info, is spo_msg_t, spo_msg_t->data is spo_statis_t */
};


/* data tree headers */
struct spo_dmn_data_header_s {
    struct spo_tree_header_s *http_data;            /* http 数据树的入口 */
    struct spo_tree_header_s *dns_data;             /* dns 数据树的入口 */
};


/* http dmn tree header */
struct spo_dmn_s {
    struct spo_tree_header_s *dmn;                  /* http 域名配置树的入口 */
};


/* create the struct */
spo_dmn_data_header_t *spo_create_dmn_data_header();


/* load cfg */

/* load the program's cfg, return spo_cfg_s */
void *spo_load_prog_cfg(const char *f_name);

/* load the http domain's cfg, return spo_dmn_t */
spo_dmn_t *spo_load_http_dmn_cfg(const char *f_name);

/* load dns's domain and data */
spo_tree_header_t *spo_load_dns_data_cfg(const char *p_name);

/* load http's data cfg */
spo_tree_header_t *spo_load_http_data_cfg(const char *p_name);


/* destory struct */
SPO_RET_STATUS spo_destory_info(spo_info_t *info);
SPO_RET_STATUS spo_destory_cfg_g(spo_cfg_g_t *cfg_g);
SPO_RET_STATUS spo_destory_cfg(spo_cfg_t *cfg);

SPO_RET_STATUS spo_destory_http_data(void *data_);
SPO_RET_STATUS spo_destory_dns_data(void *data_);

SPO_RET_STATUS spo_destory_http_line(spo_hp_line_t *line);
SPO_RET_STATUS spo_destory_http_dmn(void *http_dmn);

SPO_RET_STATUS spo_destory_dmn(spo_dmn_t *dmn);
SPO_RET_STATUS spo_destory_hp_mtd(void *mtd_);

/* reload cfg */

SPO_RET_STATUS spo_reload_http_config(spo_cfg_t *cfg, spo_proc_node_t *node);
SPO_RET_STATUS spo_reload_http_data(spo_cfg_t *cfg, spo_proc_node_t *node);
SPO_RET_STATUS spo_reload_dns_data(spo_cfg_t *cfg, spo_proc_node_t *node);

#endif // SPO_CONFIG_H
