#ifndef SPO_LIINUX_H
#define SPO_LIINUX_H

#include <sys/types.h>
#include <sys/msg.h>


#define SPO_MAX_FILE_NAME_LEN   (512)

#define SPO_UPEXEC_MSGTYPE  (11)

#define SPO_INSTR_SIZE  (1024)


typedef void (*spo_sa_sigaction)(int, siginfo_t *, void *);


struct spo_msg_s {
    long type;
    char data[0];
};

struct spo_packet_s {
    void *pkt_info;         //record http packet's host, url, referer, cookie
    size_t pkt_s;           //packet size
    size_t max_pkts;        //max packet size, max_http_packet_len - sizeof(spo_packet_s) - sizeof(spo_msg_s)
    size_t len;             //max_http_packet_len, malloc size
    int info_amt;           //the amount ofpkt_info
    int http_s;             //http start point offset
    uint8_t op_len;
    u_char packet[0];
};


struct spo_build_packet_s {
    size_t msg_type;        /* 0 is http, 1 is dns */
    size_t len;             /* msg's size, is malloc size */
    size_t snd_s;           /* snd msg size, == h_header_s +  h_data_s + szieof(hjk) + sizeof(bld_pkt) + sizeof(msg)*/
    size_t header_len;      /* malloced header's len */
    size_t h_header_s;      /* pkt's header's size */
    size_t h_data_s;        /* pkt data size */
    size_t http_start;      /* pkt's start pointer */
    u_char bld_data[0];
};


/**
 *
 *  for manage msg.
 *
 * */

typedef struct spo_mge_instr_s {
    int id;
    char data[SPO_INSTR_SIZE];      /* save the instr and the exec status */
}spo_instr_t;


typedef struct spo_manage_buf_s {
    long type;
    spo_instr_t instr;
}spo_mge_buf_t;


/* linux file */
SPO_RET_VALUE spo_open(const char *file, int file_flg, int perm);
size_t spo_read(int fd, void *buf, size_t n_size);
ssize_t spo_write(int fd, const void *buf, size_t size);
SPO_RET_VALUE spo_close(int fd);
FILE *spo_fopen(const char *file_name, const char *modes);
SPO_RET_VALUE spo_fclose(FILE *fp);
size_t spo_file_size(const char *file_path);
size_t spo_read_file_data(const char *file_path, void *buf);
SPO_RET_STATUS spo_merg_absol_path_name(const char *path, const char *name, char *absol_name);

/* pkt */
SPO_RET_STATUS spo_init_packet(spo_packet_t *pkt);
SPO_RET_STATUS spo_rst_packet(spo_packet_t *pkt);

/* linucx msg queue */
SPO_RET_STATUS spo_msgget(key_t key, int msgflg);
SPO_RET_VALUE spo_msgrcv(int msgid, void *msg_buf, size_t msg_size, long msg_type, int msgflg);
SPO_RET_VALUE spo_msgsnd(int msgid, void *msg_buf, size_t msg_size, int msgflg);
SPO_RET_VALUE spo_create_msg_queue(int msgid_p, int msgflg_perm);
inline SPO_RET_STATUS spo_msg_queue_stat(int msgid, ulong max_amt);


/* linux signal */
/* sig mod */

__sighandler_t spo_signal(int sig, __sighandler_t handler);
SPO_RET_VALUE spo_sigaction(int sig, const struct sigaction *act, struct sigaction *oact);
SPO_RET_STATUS spo_signal_a_sig(int sig, spo_sa_sigaction func);
SPO_RET_STATUS spo_del_sig_in_set(int sig, sigset_t *set);
SPO_RET_STATUS spo_fill_sigmask(sigset_t *set);
SPO_RET_STATUS spo_mask_all_sig();
SPO_RET_STATUS spo_signal_a_sigset(sigset_t *set);


/* linux others */
void spo_bind_cpu(int cpu_id, pid_t pid);
char *spo_strtok(char *str, const char *delim);

#endif // SPO_LIINUX_H
