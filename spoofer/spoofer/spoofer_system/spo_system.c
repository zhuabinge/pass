#include<stdio.h>
#include<stdlib.h>
#define __USE_GNU
#define _GNU_SOURCE
#include <sched.h>
#include <sys/wait.h>
#include <sys/shm.h>

#include "spoofer.h"
#include "spo_system.h"
#include "../spoofer_config/spo_config.h"
#include "../spoofer_pool/spo_pool.h"
#include "../spoofer_test/spo_test.h"
#include "../spoofer_sniffer/spo_sniffer.h"
#include "../spoofer_linux/spo_linux.h"
#include "../spoofer_sender/spo_sender.h"
#include "../spoofer_log/spo_log.h"
#include "spo_verification.h"

#define SPO_NOFILE  (256)
#define SPO_MAX_PROG_NAME   (512)


/* -- - - - - -- - - - - -  init  -- - - - - - - - - - --- - - -- */

static SPO_RET_STATUS spo_init_loger_msg();
static SPO_RET_STATUS spo_running_path(const char *name);
static void spo_init_inst_func();


/* -- - - - - -- - - - - -  manage  -- - - - -- - - - - - -- - - - */

static SPO_RET_STATUS spo_snd_manage_reply(int msgid, spo_mge_buf_t *buf, int status);
static void spo_manager();
static SPO_RET_STATUS spo_analysis_instructions(const char *inst);
static SPO_RET_STATUS spo_do_help();
static SPO_RET_STATUS spo_do_rst_def_cfg();
static SPO_RET_STATUS spo_do_rld_hp_data_tmp();
static SPO_RET_STATUS spo_do_rld_dns_cfg_tmp();
static SPO_RET_STATUS spo_do_rld_hp_cfg_tmp();
static SPO_RET_STATUS spo_do_rld_hp_data();
static SPO_RET_STATUS spo_do_rld_dns_cfg();
static SPO_RET_STATUS spo_do_rld_hp_cfg();
static SPO_RET_STATUS spo_do_restart_spof();
static SPO_RET_STATUS spo_do_shutdown_spof();
static SPO_RET_STATUS spo_do_restart_os();
static SPO_RET_STATUS spo_do_shutdown_os();
static SPO_RET_STATUS spo_do_nothing();


/* --- - - -- - - -- -  restart and exit  - -- --- - - - -- - - -- - - */

static void spo_prog_restart(int sig, siginfo_t *info, void *p);
static void spo_prog_exit(int sig, siginfo_t *info, void *p);
static SPO_RET_STATUS spo_kill_subprocs(spo_proc_header_t *header);
static void spo_subproc_dead(int sig, siginfo_t *info, void *p);
static SPO_RET_STATUS spo_rebuild_sub(spo_proc_node_t *node);
static spo_proc_node_t *spo_search_dead(spo_proc_header_t *header, pid_t pid);


/* - - - -- - - -- - - - -- -  init system  - - -- - - -- - - -- - - - */

static SPO_RET_STATUS spo_init_system();
static SPO_RET_STATUS spo_init_daemon();
static SPO_RET_STATUS spo_set_main_sig();
static SPO_RET_STATUS spo_init_sub_proc(spo_proc_header_t *header);
static void spo_sub_start();
static SPO_RET_STATUS spo_sub_init_self_msg(spo_proc_node_t *self);
static SPO_RET_VALUE spo_create_sub_proc(spo_proc_node_t *nodes, uint n);
static SPO_RET_STATUS spo_init_proc_node(spo_proc_header_t *p_header);
static SPO_RET_STATUS spo_proc_load_cfg(spo_proc_header_t *p_header);
static SPO_RET_STATUS spo_do_proc_load_cfg(spo_proc_node_t *nodes, uint n);
static SPO_RET_STATUS spo_proc_find_info(spo_proc_node_t *nodes, spo_cfg_t *cfg, const char *type, uint n);
static SPO_RET_STATUS spo_init_working_func(spo_proc_header_t *p_header);
static void spo_do_init_working_func(spo_proc_node_t *nodes, void (*func) (void *), uint n);
static SPO_RET_STATUS spo_init_load_cfg();
static SPO_RET_STATUS spo_init_proc_hehader(spo_cfg_t *cfg, spo_proc_header_t *header);
static SPO_RET_STATUS spo_do_create_proc_node(spo_proc_node_t *node);



char prog_abso_path[SPO_MAX_PROG_NAME] = {'\0'};
char prog_abso_name[SPO_MAX_PROG_NAME] = {'\0'};

SPO_RET_STATUS (*inst_func[13]) (void);

/* for system */
int proc_idx;
spo_proc_node_t *current        = NULL;

spo_proc_header_t *proc_queue   = NULL;
spo_tree_header_t *dns_data     = NULL;
spo_tree_header_t *hp_data      = NULL;
spo_tree_header_t *hp_mtd       = NULL;
spo_dmn_t *hp_dmn               = NULL;
spo_cfg_t *prog_cfg             = NULL;


int log_msgid           = 0;
int statis_msgid        = 0;
int sys_shmid           = 0;        /* used to see the total time */

spo_msg_t *sys_log      = NULL;


#if SPO_SEE_TIME
SPO_RET_STATUS spo_use_time(int when, const char *who)
{
    static struct timeval start, stop;

    if (when == SPO_TIME_START) {
        memset(&start, '\0', sizeof(struct timeval));
        gettimeofday(&start,0);
    }

    if (when == SPO_TIME_END) {
        float timer = 0;
        memset(&stop, '\0', sizeof(struct timeval));
        gettimeofday(&stop,0);

        timer = 1000000 * (stop.tv_sec - start.tv_sec) + (stop.tv_usec - start.tv_usec);
        printf("%s use time = %f ms\n", who, timer / 1000);
    }

    return SPO_OK;
}
#endif


static SPO_RET_STATUS spo_do_create_proc_node(spo_proc_node_t *node)
{
    node->cfg   = NULL;
    node->pool  = NULL;
    node->hp_pkt   = NULL;
    node->snd_pkt = NULL;
    node->log   = NULL;
    node->dmn_data_header   = NULL;
    node->http_dmn_header   = NULL;
    node->info          = NULL;
    node->work_func     = NULL;
    node->hp_msgid    = NULL;
    node->dns_msgid     = NULL;
    node->pid       = 0;
    node->proc_idx  = 0;

    node->security  = 0;
    node->hp_cfg_security = 0;
    node->dns_cfg_security = 0;
    node->hp_data_security = 0;
    node->hp_cfg_tmp_security = 0;
    node->hp_data_tmp_security = 0;
    node->dns_cfg_tmp_security = 0;

    return SPO_OK;
}

/**
 *
 *  create proc nodes, and init it's elems to NULL or 0.
 *
 * */

spo_proc_node_t *spo_create_proc_node(int node_amount)
{
    spo_proc_node_t *nodes = NULL;
    int i = 0;

    if (node_amount <= 0) return NULL;

    if ((nodes = spo_calloc(node_amount * sizeof(spo_proc_node_t))) == NULL)
        return NULL;

    for (i = node_amount - 1; i >= 0; i--) {
        spo_do_create_proc_node(&nodes[i]);
    }

    return nodes;
}

/**
 *
 *  create a proc header struct.
 *
 * */

spo_proc_header_t *spo_create_proc_header()
{
    spo_proc_header_t *header = NULL;

    if ((header = spo_calloc(sizeof(spo_proc_header_t))) == NULL) return NULL;

    header->sniffers    = NULL;
    header->d_spofs     = NULL;
    header->h_spofs     = NULL;
    header->log         = NULL;
    header->sniff_n     = 0;
    header->d_spoof_n   = 0;
    header->h_spoof_n   = 0;
    header->snd_n = 0;

    return header;
}


/*  - -- - - - - - -- - -- - - -- - init system - -- - - -- - - -- - - - - -- -  */

/**
 *
 *  init proc queue header.
 *
 * */

static SPO_RET_STATUS spo_init_proc_hehader(spo_cfg_t *cfg, spo_proc_header_t *header)
{
    header->sniff_n = cfg->inf_header.sniffers;
    header->h_spoof_n = cfg->inf_header.h_spofs;
    header->d_spoof_n = cfg->inf_header.d_spofs;
    header->snd_n = cfg->inf_header.sender;

    if (header->sniff_n > 0) {
        header->sniffers = spo_create_proc_node(header->sniff_n);
        if (header->sniffers == NULL) goto spo_bad_init;
    }

    if (header->h_spoof_n > 0) {
        header->h_spofs = spo_create_proc_node(header->h_spoof_n);
        if (header->h_spofs == NULL) goto spo_bad_init;
    }

    if (header->d_spoof_n > 0) {
        header->d_spofs = spo_create_proc_node(header->d_spoof_n);
        if (header->d_spofs == NULL) goto spo_bad_init;
    }

    if (header->snd_n > 0) {
        header->senders = spo_create_proc_node(header->snd_n);
        if (header->senders == NULL) goto spo_bad_init;
    }

    header->log = spo_create_proc_node(1);
    if (header->log == NULL) goto spo_bad_init;

    return SPO_OK;

spo_bad_init:

    if (header->sniffers != NULL) spo_free(header->sniffers);
    if (header->h_spofs != NULL) spo_free(header->h_spofs);
    if (header->d_spofs != NULL) spo_free(header->d_spofs);
    if (header->senders != NULL) spo_free(header->senders);
    if (header->log != NULL) spo_free(header->log);

    return SPO_FAILURE;
}


/**
 *
 *  load all cfg file.
 *
 * */

static SPO_RET_STATUS spo_init_load_cfg()
{
    char *log_info = NULL;

    if ((prog_cfg = (spo_cfg_t *) spo_load_prog_cfg((const char *) "config")) == NULL) {
#if SPO_DEBUG
        printf("load cfg err, please cheak your config file\n");
#endif
        log_info = "load cfg err, please cheak your config file\n";
        goto spo_load_cfg_err;
    }

    hp_mtd = prog_cfg->global->hp_mtd;

    if ((hp_dmn = spo_load_http_dmn_cfg((const char *) prog_cfg->global->h_dmn_cfg_file)) == NULL) {
#if SPO_DEBUG
        printf("load http cfg err, please cheak your http config file\n");
#endif
        log_info = "load http cfg err, please cheak your http config file\n";
        goto spo_load_cfg_err;
    }

    if ((hp_data = spo_load_http_data_cfg((const char *) prog_cfg->global->h_data_path)) == NULL) {
#if SPO_DEBUG
        printf("load http data cfg err, please check your http data config\n");
#endif
        log_info = "load http data cfg err, please check your http data config\n";
        goto spo_load_cfg_err;
    }

    if ((dns_data = spo_load_dns_data_cfg((const char *) prog_cfg->global->d_data_path)) == NULL) {
#if SPO_DEBUG
        printf("load dns data err, please your dns data config file\n");
#endif
        log_info = "load dns data err, please your dns data config file\n";
        goto spo_load_cfg_err;
    }

#if SPO_DEBUG
    printf("load cfg success\n");
#endif
    log_info = "load cfg success\n";
    spo_snd_log_msg(sys_log, (const char *) log_info, SPO_MAIN, SPO_LOG_LEVEL_MSG, getpid());
    return SPO_OK;

spo_load_cfg_err:
    spo_snd_log_msg(sys_log, (const char *) log_info, SPO_MAIN, SPO_LOG_LEVEL_MSG, getpid());

    return SPO_FAILURE;
}


static void spo_do_init_working_func(spo_proc_node_t *nodes, void (*func) (void *), uint n)
{
    uint i = 0;

    for (i = 0; i < n; i++) {
        nodes[i].work_func = func;
    }
}


/**
 *
 *  init sub process working func.
 *
 * */

static SPO_RET_STATUS spo_init_working_func(spo_proc_header_t *p_header)
{
    spo_do_init_working_func(p_header->sniffers, spo_sniffers, p_header->sniff_n);
    spo_do_init_working_func(p_header->h_spofs, spo_http_spoofer, p_header->h_spoof_n);
    spo_do_init_working_func(p_header->d_spofs, spo_dns_spoofer, p_header->d_spoof_n);
    spo_do_init_working_func(p_header->senders, spo_http_sender, p_header->snd_n);
    spo_do_init_working_func(p_header->log, spo_loger_statiser, 1);

    return SPO_OK;
}


/**
 *
 *  init sub process's info struct.
 *
 * */

static SPO_RET_STATUS spo_proc_find_info(spo_proc_node_t *nodes, spo_cfg_t *cfg, const char *type, uint n)
{
    spo_info_t *info = cfg->inf_header.infos;
    uint i = 0;
    size_t len = strlen(type);

    for (i = 0; i < n; i++) {
        while (info != NULL) {
            if (memcmp(info->type, type, len) == 0) {
                nodes[i].info = info;
                info = info->next;
                break;
            }

            info = info->next;
        }
    }

    return SPO_OK;
}


/**
 *
 *  load cfg headers.
 *
 * */

static SPO_RET_STATUS spo_do_proc_load_cfg(spo_proc_node_t *nodes, uint n)
{
    uint i = 0;

    for (i = 0; i < n; i++) {
        nodes[i].cfg = prog_cfg;
        if ((nodes[i].dmn_data_header = spo_calloc(sizeof(spo_dmn_data_header_t))) == NULL) return SPO_FAILURE;
        nodes[i].dmn_data_header->http_data = hp_data;
        nodes[i].dmn_data_header->dns_data = dns_data;
        nodes[i].http_dmn_header = hp_dmn;
    }

    return SPO_OK;
}


/**
 *
 *  load process's cfg.
 *
 * */

static SPO_RET_STATUS spo_proc_load_cfg(spo_proc_header_t *p_header)
{
    if (spo_do_proc_load_cfg(p_header->sniffers, p_header->sniff_n) == SPO_FAILURE) return SPO_FAILURE;
    spo_proc_find_info(p_header->sniffers, prog_cfg, "sniffer", p_header->sniff_n);

    if (spo_do_proc_load_cfg(p_header->h_spofs, p_header->h_spoof_n) == SPO_FAILURE) return SPO_FAILURE;
    spo_proc_find_info(p_header->h_spofs, prog_cfg, "http_spoofer", p_header->h_spoof_n);

    if (spo_do_proc_load_cfg(p_header->d_spofs, p_header->d_spoof_n) == SPO_FAILURE) return SPO_FAILURE;
    spo_proc_find_info(p_header->d_spofs, prog_cfg, "dns_spoofer", p_header->d_spoof_n);

    if (spo_do_proc_load_cfg(p_header->senders, p_header->snd_n) == SPO_FAILURE) return SPO_FAILURE;
    spo_proc_find_info(p_header->senders, prog_cfg, "sender", p_header->snd_n);

    if (spo_do_proc_load_cfg(p_header->log, 1) == SPO_FAILURE) return SPO_FAILURE;

    return SPO_OK;
}


/**
 *
 *  create proc node, and load sub process's cfg.
 *
 * */

static SPO_RET_STATUS spo_init_proc_node(spo_proc_header_t *p_header)
{

    if (spo_proc_load_cfg(p_header) == SPO_FAILURE) return SPO_FAILURE;
    spo_init_working_func(p_header);

    return SPO_OK;
}


/**
 *
 *  fork sub processs.
 *
 * */

static SPO_RET_VALUE spo_create_sub_proc(spo_proc_node_t *nodes, uint n)
{
    uint i = 0;
    pid_t pid;

    for (i = 0; i < n ; i++) {
        if ((pid = fork()) == -1) return SPO_FAILURE;

        if (pid > 0) {  /* parent */
            nodes[i].proc_idx = i;
            nodes[i].pid = pid;
            continue;
        }

        if (pid == 0) { /* child */
            proc_idx = i;
            nodes[i].proc_idx = i;
            nodes[i].pid = getpid();
            current = &nodes[i];
            return nodes[i].pid;
        }
    }

    return 0;
}


/**
 *
 *  sub process init msg queue.
 *
 *
 * */

static SPO_RET_STATUS spo_sub_init_self_msg(spo_proc_node_t *self)
{
    int i = 0;
    spo_info_t *info = self->info;

    if (info == NULL) return SPO_OK;

    if (info->h_msgid != NULL) {
        if ((self->hp_msgid = spo_calloc((info->h_msgid[0] + 1) * sizeof(int))) == NULL) return SPO_FAILURE;
        self->hp_msgid[0] = info->h_msgid[0];

        for (i = 1; i <= info->h_msgid[0]; i++) {
            self->hp_msgid[i] = spo_create_msg_queue(info->h_msgid[i], 0666);
            if (self->hp_msgid[i] == SPO_FAILURE) return SPO_FAILURE;
        }
    }

    if (info->d_msgid != NULL) {
        if ((self->dns_msgid = spo_calloc((info->d_msgid[0] + 1) * sizeof(int))) == NULL) return SPO_FAILURE;
        self->dns_msgid[0] = info->d_msgid[0];

        for (i = 1; i <= info->d_msgid[0]; i++) {
            self->dns_msgid[i] = spo_create_msg_queue(info->d_msgid[i], 0666);
            if (self->dns_msgid[i] == SPO_FAILURE) return SPO_FAILURE;
        }
    }

    return SPO_OK;
}


/**
 *
 *  sub process start here.
 *
 * */

static void spo_sub_start()
{
    spo_sub_init_self_msg(current);
    current->work_func(current->info);

    exit(EXIT_FAILURE);
}


/**
 *
 *  init sub process's node.
 *
 *  start subproc here.
 *
 * */

static SPO_RET_STATUS spo_init_sub_proc(spo_proc_header_t *header)
{
    int ret = 0;

    if ((ret = spo_create_sub_proc(header->sniffers, header->sniff_n)) == SPO_FAILURE) return SPO_FAILURE;
    if (ret > 0) spo_sub_start();

    if ((ret = spo_create_sub_proc(header->h_spofs, header->h_spoof_n)) == SPO_FAILURE) return SPO_FAILURE;
    if (ret > 0) spo_sub_start();

    if ((ret = spo_create_sub_proc(header->d_spofs, header->d_spoof_n)) == SPO_FAILURE) return SPO_FAILURE;
    if (ret > 0) spo_sub_start();

    if ((ret = spo_create_sub_proc(header->senders, header->snd_n)) == SPO_FAILURE) return SPO_FAILURE;
    if (ret  > 0) spo_sub_start();

    if ((ret = spo_create_sub_proc(header->log, 1)) == SPO_FAILURE) return SPO_FAILURE;
    if (ret  > 0) spo_sub_start();

    return SPO_OK;
}

/**
 *
 *  set the main proc sig.
 *  sigterm programe exit.
 *  usr1 restart programe.
 *  child rebuild the sub process when they die.
 *
 *  @return int, is the exec result.
 *
 **/

static SPO_RET_STATUS spo_set_main_sig()
{
    sigset_t set;
    memset(&set, '\0', sizeof(sigset_t));

    spo_fill_sigmask(&set);

    spo_del_sig_in_set(SIGCHLD, &set);
    spo_del_sig_in_set(SIGTERM, &set);
    spo_del_sig_in_set(SIGUSR1, &set);

    spo_signal_a_sigset(&set);
    spo_signal_a_sig(SIGCHLD, spo_subproc_dead);
    spo_signal_a_sig(SIGTERM, spo_prog_exit);
    spo_signal_a_sig(SIGUSR1, spo_prog_restart);

    return SPO_OK;
}


/**
 *
 *  make the program running as a daemon.
 *
 *  @return int, is the exec status.
 *
 **/

static SPO_RET_STATUS spo_init_daemon()
{
    int i = 0 ;
    pid_t pid = 0;

    if ((pid = fork()) > 0) {
        exit(EXIT_SUCCESS);
    }else if (pid < 0) exit(EXIT_FAILURE);

    setsid();

    if ((pid = fork()) > 0) {
        exit(EXIT_SUCCESS);
    }else if (pid < 0) exit(EXIT_FAILURE);

    for (i = 0; i < SPO_NOFILE; i++) close(i);

    open("/dev/null", O_RDONLY);
    open("/dev/null", O_RDWR);
    open("/dev/null", O_RDWR);

    umask(0);

    spo_set_main_sig();

    return SPO_OK;
}


/**
 *
 *  init system.
 *
 *  load all cfg file.
 *
 *  init proc queue header and it's proc node.
 *
 *  fork sub processs.
 *
 * */

static SPO_RET_STATUS spo_init_system()
{
    /* load all cfg */
    if (spo_init_load_cfg() != SPO_OK) return SPO_FAILURE;

#if SPO_DAEMON
    spo_init_daemon();
#endif

    /* init the proc header */
    proc_queue = spo_create_proc_header();
    if (proc_queue == NULL) return SPO_FAILURE;

    if (spo_init_proc_hehader(prog_cfg, proc_queue) == SPO_FAILURE) return SPO_FAILURE;

    if (spo_init_proc_node(proc_queue) == SPO_FAILURE) return SPO_FAILURE;

    if (spo_init_sub_proc(proc_queue) == SPO_FAILURE) return SPO_FAILURE;

    return SPO_OK;
}



/* - - - -- - - - - - --- - - -- -  exit and rebirth  -- - - -- -  - ----- - - - - - -- -  --  */


static spo_proc_node_t *spo_search_dead(spo_proc_header_t *header, pid_t pid)
{
    uint i = 0;

    for (i = 0; i < header->sniff_n; i++)
        if (header->sniffers[i].pid == pid) return &header->sniffers[i];

    for (i = 0; i < header->h_spoof_n; i++)
        if (header->h_spofs[i].pid == pid) return &header->h_spofs[i];

    for (i = 0; i < header->d_spoof_n; i++)
        if (header->d_spofs[i].pid == pid) return &header->d_spofs[i];

    for (i = 0; i < header->snd_n; i++)
        if (header->senders[i].pid == pid) return &header->senders[i];

    if (pid == header->log->pid) return header->log;

    return NULL;
}


/**
 *
 *  record new process's infos
 *
 * */

static SPO_RET_STATUS spo_rebuild_sub(spo_proc_node_t *node)
{
    pid_t pid;

    if ((pid = fork()) == -1) return SPO_FAILURE;
    else if (pid > 0) {     /* parent */
        node->pid = pid;
    }else {     /* child */
        node->pid = getpid();
        current = node;
        proc_idx = node->proc_idx;

        return node->pid;
    }

    return SPO_OK;
}


static void spo_subproc_dead(int sig, siginfo_t *info, void *p)
{
    info = info;
    p = p;

    if (sig == SIGCHLD) {
        /* rebuild */
        int status;
        spo_proc_node_t *dead = NULL;
        pid_t pid = waitpid(-1, &status, WNOHANG);

        if ((dead = spo_search_dead(proc_queue, pid)) == NULL) return;

        if ((status = spo_rebuild_sub(dead)) == SPO_FAILURE)  return;
        else if (status == SPO_OK) return;
        else spo_sub_start();
    }
}


/**
 *
 *  kill all sub processs.
 *
 * */

static SPO_RET_STATUS spo_kill_subprocs(spo_proc_header_t *header)
{
    uint i = 0;

    for (i = 0; i < header->sniff_n; i++) {
        kill(header->sniffers[i].pid, SIGKILL);
    }

    for (i = 0; i < header->d_spoof_n; i++) {
        kill(header->d_spofs[i].pid, SIGKILL);
    }

    for (i = 0; i < header->h_spoof_n; i++) {
        kill(header->h_spofs[i].pid, SIGKILL);
    }

    for (i = 0; i < header->snd_n; i++) {
        kill(header->senders[i].pid, SIGKILL);
    }

    kill(header->log->pid, SIGKILL);

    return SPO_OK;
}


static void spo_prog_exit(int sig, siginfo_t *info, void *p)
{
    info = info;
    p = p;

    if (sig == SIGTERM) {
        spo_mask_all_sig();
        spo_kill_subprocs(proc_queue);
        exit(EXIT_SUCCESS);
    }
}


static void spo_prog_restart(int sig, siginfo_t *info, void *p)
{
    info = info;
    p = p;

    if (sig == SIGUSR1) {
        spo_mask_all_sig();
        spo_kill_subprocs(proc_queue);

        /* restart  prog */
        execl(prog_abso_path, prog_abso_name, (char *) 0);
    }
}


/*  - - -- - - - - -- - - -  manage  -- - - - -- - - - --  - - -- - -  */

static SPO_RET_STATUS spo_snd_manage_reply(int msgid, spo_mge_buf_t *buf, int status)
{
    memset(buf->instr.data, '\0', sizeof(buf->instr.data));

    if (status == SPO_OK)
        memcpy(buf->instr.data, "successful", sizeof("successful"));
    else
        memcpy(buf->instr.data, "fail", sizeof("fail"));

    buf->type = 10;
    spo_msgsnd(msgid, buf, sizeof(spo_mge_buf_t), 0);

    return SPO_OK;
}


/**
 *
 *  the instr was err.
 *
 * */

static SPO_RET_STATUS spo_do_nothing()
{
#if SPO_DEBUG
    printf("no this instruction, please input 'help'\n");
#endif
    return SPO_OK;
}


static SPO_RET_STATUS spo_do_shutdown_os()
{
    //record and exit;
#if SPO_DEBUG
    printf("get the shut down os\n");
#endif
    return SPO_OK;
}


static SPO_RET_STATUS spo_do_restart_os()
{
    //record and exit;
#if SPO_DEBUG
    printf("get the restart os\n");
#endif
    return SPO_OK;
}


static SPO_RET_STATUS spo_do_shutdown_spof()
{
    spo_mask_all_sig();
    spo_kill_subprocs(proc_queue);

    exit(EXIT_SUCCESS);

    return SPO_OK;
}


static SPO_RET_STATUS spo_do_restart_spof()
{
    spo_mask_all_sig();
    spo_kill_subprocs(proc_queue);

    /* restart  prog */
    execl(prog_abso_path, prog_abso_name, (char *) 0);

    return SPO_OK;
}


static SPO_RET_STATUS spo_do_rld_hp_cfg()
{
    uint i = 0;

    if (spo_reload_http_config(current->cfg, current) == SPO_FAILURE) return SPO_FAILURE;

    for (i = 0; i < proc_queue->sniff_n; i++) {
        kill(proc_queue->sniffers[i].pid, SIGUSR1);
    }

    for (i = 0; i < proc_queue->h_spoof_n; i++) {
        kill(proc_queue->h_spofs[i].pid, SIGUSR1);
    }

    return SPO_OK;
}


static SPO_RET_STATUS spo_do_rld_dns_cfg()
{
    uint i = 0;

    if (spo_reload_dns_data(current->cfg, current) == SPO_FAILURE) return SPO_FAILURE;

    for (i = 0; i < proc_queue->sniff_n; i++) {
        kill(proc_queue->sniffers[i].pid, SIGUSR2);
    }

    for (i = 0; i < proc_queue->d_spoof_n; i++) {
        kill(proc_queue->d_spofs[i].pid, SIGUSR1);
    }

    return SPO_OK;
}


static SPO_RET_STATUS spo_do_rld_hp_data()
{
    uint i = 0;

    if (spo_reload_http_data(current->cfg, current) == SPO_FAILURE) return SPO_FAILURE;

    for (i = 0; i < proc_queue->sniff_n; i++) {
        kill(proc_queue->sniffers[i].pid, SIGINT);
    }

    for (i = 0; i < proc_queue->h_spoof_n; i++) {
        kill(proc_queue->h_spofs[i].pid, SIGUSR2);
    }

    return SPO_OK;
}


static SPO_RET_STATUS spo_do_rld_hp_cfg_tmp()
{
#if SPO_DEBUG
    printf("get the reload hp cfg temp dirt\n");
#endif

    uint i = 0;

    for (i = 0; i < proc_queue->sniff_n; i++) {
        kill(proc_queue->sniffers[i].pid, SIGIO);
    }

    for (i = 0; i < proc_queue->h_spoof_n; i++) {
        kill(proc_queue->h_spofs[i].pid, SIGIO);
    }

    return SPO_OK;
}


static SPO_RET_STATUS spo_do_rld_dns_cfg_tmp()
{
#if SPO_DEBUG
    printf("get the reload dns cfg temp dirt\n");
#endif

    uint i = 0;

    for (i = 0; i < proc_queue->sniff_n; i++) {
        kill(proc_queue->sniffers[i].pid, SIGQUIT);
    }

    for (i = 0; i < proc_queue->d_spoof_n; i++) {
        kill(proc_queue->d_spofs[i].pid, SIGUSR2);
    }

    return SPO_OK;
}


static SPO_RET_STATUS spo_do_rld_hp_data_tmp()
{
#if SPO_DEBUG
    printf("get the reload hp data temp dirt\n");
#endif

    uint i = 0;

    for (i = 0; i < proc_queue->sniff_n; i++) {
        kill(proc_queue->sniffers[i].pid, SIGTRAP);
    }

    for (i = 0; i < proc_queue->h_spoof_n; i++) {
        kill(proc_queue->h_spofs[i].pid, SIGTRAP);
    }

    return SPO_OK;
}


static SPO_RET_STATUS spo_do_rst_def_cfg()
{
#if SPO_DEBUG
    printf("get the reload def cfg dirt\n");
#endif

    return SPO_OK;
}


static SPO_RET_STATUS spo_do_help()
{
#if SPO_DEBUG
    printf("get the help dirt\n");
#endif

    return SPO_OK;
}


/**
 *
 *  analysis instructions.
 *
 * */

static SPO_RET_STATUS spo_analysis_instructions(const char *inst)
{
    if (inst == NULL || strlen(inst) == 0) return 0;

    if (memcmp(inst, "shutdown_os", strlen(inst)) == 0) return 1;
    if (memcmp(inst, "restart_os", strlen(inst)) == 0) return 2;

    if (memcmp(inst, "shutdown_spof", strlen(inst)) == 0) return 3;
    if (memcmp(inst, "restart_spof", strlen(inst)) == 0) return 4;

    if (memcmp(inst, "rld_hp_cfg", strlen(inst)) == 0) return 5;
    if (memcmp(inst, "rld_dns_cfg", strlen(inst)) == 0) return 6;
    if (memcmp(inst, "rld_hp_data", strlen(inst)) == 0) return 7;

    if (memcmp(inst, "rld_hp_cfg_tmp", strlen(inst)) == 0) return 8;
    if (memcmp(inst, "rld_dns_cfg_tmp", strlen(inst)) == 0) return 9;
    if (memcmp(inst, "rld_hp_data_tmp", strlen(inst)) == 0) return 10;

    if (memcmp(inst, "rst_def_cfg", strlen(inst)) == 0) return 11;
    if (memcmp(inst, "help", strlen(inst)) == 0) return 12;

    return 0;
}


static void spo_manager()
{
    spo_mge_buf_t buf;
    int num = 0;

    int msgid = spo_create_msg_queue(19922015, 0666);
    if (msgid == SPO_FAILURE) return;

    while (1) {
        memset(&buf, '\0', sizeof(spo_mge_buf_t));
        if (spo_msgrcv(msgid, &buf, sizeof(spo_mge_buf_t), 9, 0) == SPO_FAILURE) {

#if SPO_DEBUG
            printf("get dirtv errn");
#endif
            spo_snd_log_msg(sys_log, (const char *) "get dirtv errn", SPO_MAIN, SPO_LOG_LEVEL_ERR, getpid());
            continue;
        }

#if SPO_DEBUG
        printf("get dirt is : --%s--\n", buf.instr.data);
        printf("num %d\n", (num = spo_analysis_instructions((char *) buf.instr.data)));
#endif
        num = spo_analysis_instructions((char *) buf.instr.data);

        if (inst_func[num]() == SPO_FAILURE)
            spo_snd_manage_reply(msgid, &buf, SPO_FAILURE);
        else
            spo_snd_manage_reply(msgid, &buf, SPO_OK);
    }
}


static void spo_init_inst_func()
{
    inst_func[0] = spo_do_nothing;

    inst_func[1] = spo_do_shutdown_os;
    inst_func[2] = spo_do_restart_os;

    inst_func[3] = spo_do_shutdown_spof;
    inst_func[4] = spo_do_restart_spof;

    inst_func[5] = spo_do_rld_hp_cfg;
    inst_func[6] = spo_do_rld_dns_cfg;
    inst_func[7] = spo_do_rld_hp_data;

    inst_func[8] = spo_do_rld_hp_cfg_tmp;
    inst_func[9] = spo_do_rld_dns_cfg_tmp;
    inst_func[10] = spo_do_rld_hp_data_tmp;

    inst_func[11] = spo_do_rst_def_cfg;
    inst_func[12] = spo_do_help;
}


/**
 *
 *  get the spoofer running path
 *
 * */

static SPO_RET_STATUS spo_running_path(const char *name)
{
    char *p = NULL;
    int len = 0;
    int i = 0;

    p = getcwd(NULL, SPO_MAX_PROG_NAME);

    strncpy(prog_abso_path, p, strlen(p));

    len = strlen(name);
    i = len;

    while (*(name + i) != '/' && i > 0) i--;

    if (i <= 0) {
        prog_abso_path[strlen(prog_abso_path)] = '/';
        strcat(prog_abso_path, name);
        strncpy(prog_abso_name, name, len);
    }else {
        strcat(prog_abso_path, (name + i));
        strncpy(prog_abso_name, (name + i + 1), len);
    }

    return SPO_OK;
}


static SPO_RET_STATUS spo_init_loger_msg()
{
    size_t size = sizeof(spo_msg_t) + sizeof(spo_log_t) + 257;
    spo_log_t *log = NULL;

    log_msgid = spo_create_msg_queue(20152015, 0666);
    if (log_msgid == SPO_FAILURE) return SPO_FAILURE;

    statis_msgid = spo_create_msg_queue(20152016, 0666);
    if (statis_msgid == SPO_FAILURE) return SPO_FAILURE;

    if ((sys_log = spo_calloc(size)) == NULL) return SPO_FAILURE;

    log = (spo_log_t *) ((char *) sys_log->data);
    log->size = size;

    return SPO_OK;
}

#if SPO_SEE_TIME
static SPO_RET_VALUE spo_init_sys_shm(int shmid)
{
    shmid = shmget((key_t) shmid, sizeof(struct timeval), IPC_CREAT | SHM_W | SHM_R);
    if (shmid == -1)
        spo_snd_log_msg(sys_log, (const char *) "init sys shm fail\n", SPO_MAIN, SPO_LOG_LEVEL_MSG, getpid());

    return shmid;
}
#endif


int main(int argc, char *argv[])
{
    argc = argc;

	//    if(spo_verification() == SPO_FAILURE) return SPO_FAILURE;
	//    return SPO_OK;

    spo_running_path(argv[0]);
    spo_init_inst_func();
    spo_init_loger_msg();

#if SPO_SEE_TIME
    sys_shmid = spo_init_sys_shm(98989);
#endif

    if (spo_init_system() == SPO_FAILURE) {
#if SPO_DEBUG
        printf("init system faile\n");
#endif
        exit(EXIT_FAILURE);
    }

#if SPO_DEBUG
    printf("init system success, i am main, pid is %d\n", getpid());
#endif

    spo_snd_log_msg(sys_log, (const char *) "init system success", SPO_MAIN, SPO_LOG_LEVEL_MSG, getpid());

    if ((current = spo_create_proc_node(1)) == NULL) spo_do_shutdown_spof();
    current->cfg = prog_cfg;

    if ((current->dmn_data_header = spo_create_dmn_data_header()) == NULL)

    current->dmn_data_header->http_data = hp_data;
    current->dmn_data_header->dns_data = dns_data;
    current->http_dmn_header = hp_dmn;

    spo_manager();
    /* manage */

    while (1) {
        sleep(10);
    }

    return 0;
}
