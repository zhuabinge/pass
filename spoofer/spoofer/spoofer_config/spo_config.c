#include "../spoofer_system/spoofer.h"
#include "spo_config.h"
#include "../spoofer_pool/spo_pool.h"
#include "../spoofer_linux/spo_linux.h"
#include "../spoofer_sniffer/spo_spoofer.h"
#include "../spoofer_log/spo_log.h"
#include "../spoofer_test/spo_test.h"

#include <dirent.h>
#include <regex.h>
#include <pcre.h>

#define SPO_DNS_H (12)

/* the cfg stat */
#define SPO_IN_START    (0)
#define SPO_IN_GLOBAL   (1)
#define SPO_IN_SNIFFER  (2)
#define SPO_IN_SPOOFER  (4)
#define SPO_IN_SENDER   (8)
#define SPO_IN_DOMAIN   (16)
#define SPO_IN_MTD      (32)


/* we default amount of msgid is 16, more tahn 16, we recalloc it */
#define SPO_DEF_MSGID_AMOUNT    (16)
#define SPO_INC_MSGID_AMOUNT    (4)

#define SPO_URL_TARGE           (5)     /* the url's targe in cfg file like ('url: ') */
#define SPO_COOKIES_TARGE       (9)
#define SPO_REFERER_TARGE       (9)


#define SPO_INFO_TAG_LEN (4)


/* for pcre */
#define SPO_COK_ARG     ("=([^;]+)")
#define SPO_REF_URI_ALL ("\\/\\/[^\\/]+(.*)")
#define SPO_REF_URI_ARG ("=([^&]+)")
#define SPO_REF_DMN     ("\\/\\/([^\\/]+)")


/* - - - -- - -- - - -- - - -- -  load http data  - -- - -- - - -- - - - - - - -- -  */

static spo_tree_header_t *
spo_load_data_cfg(const char *p_name,
                  spo_tree_node_t * (*load_data) (const char *, const char *),
                  int (*comp_func) (void *, void *), int (*spo_free_key_func) (void *));

static spo_tree_node_t *spo_do_load_http_data_cfg(const char *f_name, const char *dmn_name);


/* - - - - - fing tags starting with '$' on data cfgs and generate the patterns - - - - - */

static SPO_RET_STATUS spo_hp_data_tag_match(spo_hp_data_t *hp_data);
static SPO_RET_STATUS spo_http_data_pat_find(spo_hp_data_t *hp_data, u_char **tag);
static SPO_RET_STATUS spo_hp_url_tag(spo_hp_data_t *hp_data, spo_hp_data_info_t *info, u_char **tag, u_char *ch);
static SPO_RET_STATUS spo_hp_ref_tag(spo_hp_data_t *hp_data, spo_hp_data_info_t *info, u_char **tag, u_char *ch);
static SPO_RET_STATUS spo_deal_with_d_tag(spo_hp_data_t *hp_data, spo_hp_data_info_t *info, int type);
static SPO_RET_STATUS spo_deal_with_u_tag(spo_hp_data_t *hp_data,
                                          spo_hp_data_info_t *info, int type, u_char *ch, u_char **tag);
static SPO_RET_STATUS spo_hp_cok_tag(spo_hp_data_t *hp_data, spo_hp_data_info_t *info, u_char **tag, u_char *ch);
static SPO_RET_STATUS spo_hp_data_info_insert(spo_hp_data_t *hp_data, spo_hp_data_info_t *info);
static spo_hp_data_info_t *spo_create_hp_data_info();
static SPO_RET_STATUS spo_cp_http_data(spo_hp_data_t *hp_data, spo_str_t *data_cp, spo_str_t *data, size_t size);
static SPO_RET_VALUE spo_http_data_num(const char *dmn_name);
static SPO_RET_STATUS spo_http_data_dmn(spo_str_t *dmn, const char *dmn_name);


/* - - - -- - -- - - -- - - -- -  load dns data  - -- - -- - - -- - - - - - - -- -  */

static spo_tree_node_t *spo_do_load_dns_data_cfg(const char *absol_name, const char *dmn_name);
static SPO_RET_STATUS spo_init_dns_statis_msg(spo_dns_data_t *data, const char *dmn_name);
static SPO_RET_STATUS spo_cp_dns_data(spo_str_t *data, spo_str_t *data_cp);
static SPO_RET_STATUS spo_dns_data_dmn(spo_str_t *dmn, const char *dmn_name);
static SPO_RET_STATUS spo_change_dns_host_form(u_char *line);


/* - - - -- - -- - - -- - - -- -  load http cfg  - -- - -- - - -- - - - - - - -- -  */

static SPO_RET_STATUS spo_do_load_http_dmn_cfg(spo_dmn_t *dmn, FILE *fp);
static SPO_RET_STATUS spo_analy_http_dmn_cfg(spo_dmn_t *dmn, char *line, spo_cfg_stat *dmn_stat);
static SPO_RET_STATUS spo_analy_http_dmn_cfg_blk(spo_dmn_t *dmn, const char *line, spo_cfg_stat *dmn_stat);
static SPO_RET_STATUS spo_init_hp_statis_msg(void *hp_dmn_);
static spo_msg_t *spo_do_init_statis_msg(size_t size, spo_str_t *dmn);
static SPO_RET_STATUS spo_do_analy_http_dmn_cfg_blk(spo_dmn_t *dmn, char *line, const char *delim);
static SPO_RET_STATUS spo_insert_http_cfg_line(spo_hp_dmn_t *h_dmn, spo_hp_line_t *h_line);
static SPO_RET_STATUS spo_load_cfg_dmn_line(pcre **pr, const char *rege_, int *flg);


/* - - - -- - -- - - -- - - -- -  load prog cfg  - -- - -- - - -- - - - - - - -- -  */

void *spo_load_prog_cfg(const char *f_name);
static SPO_RET_STATUS spo_do_load_cfg(FILE *fp, spo_cfg_t *cfg);
static SPO_RET_STATUS spo_analysis_cfg(char *line, spo_cfg_t *cfg, spo_cfg_stat *status);
static SPO_RET_STATUS spo_hp_mtd_cfg(spo_cfg_t *cfg, spo_cfg_stat *status);
static SPO_RET_STATUS spo_cfg_proc_type(spo_cfg_t *cfg, spo_cfg_stat *status, int sta);
static SPO_RET_STATUS spo_do_analysis_cfg(spo_cfg_t *cfg, spo_cfg_stat *status);
static SPO_RET_STATUS spo_do_hp_mtd_cfg(spo_cfg_t *cfg, char *line, const char *delim);
static SPO_RET_STATUS spo_analysis_sender_cfg(spo_cfg_t *cfg, char *line, const char *delim);
static SPO_RET_STATUS spo_analysis_spoof_cfg(spo_cfg_t *cfg, char *line, const char *delim);
static SPO_RET_STATUS spo_analysis_sniff_cfg(spo_cfg_t *cfg, char *line, char *delim);
static SPO_RET_STATUS spo_init_cfg_dns_msgids(spo_info_t *info, const char *p);
static SPO_RET_STATUS spo_init_cfg_snif_hp_msgids(spo_info_t *info, const char *p);
static SPO_RET_STATUS spo_recalloc_cfg_http_msgids(spo_info_t *info);
static int *spo_create_cfg_msgids(uint n);
static SPO_RET_STATUS spo_analysis_global_instr(spo_cfg_t *cfg, char *line, char *delim);
static SPO_RET_VALUE spo_get_max_send_size(char *p);
static char *spo_deal_with_line(char *line);
static void spo_do_deal_with_line(char *line);


/* - - - -- - -- - - -- - - -- -  check prog cfg  - -- - -- - - -- - - - - - - -- -  */

static SPO_RET_STATUS spo_check_prog_cfg(spo_cfg_t *cfg);
static SPO_RET_STATUS spo_check_hp_mtd(spo_cfg_t *cfg);
static SPO_RET_STATUS spo_check_g_cfg(spo_cfg_g_t *g);
static SPO_RET_STATUS spo_check_proc_blk_cfg(spo_info_header_t *header);


volatile int load_err = 0;


SPO_RET_STATUS spo_init_cfg_info_header(spo_info_header_t *header)
{
    header->infos       = NULL;
    header->infos_tail  = NULL;

    header->sniffers    = 0;
    header->h_spofs     = 0;
    header->d_spofs     = 0;
    header->sender      = 0;

    return SPO_OK;
}


spo_info_t *spo_create_info(void)
{
    spo_info_t *info = NULL;

    if ((info = spo_calloc(sizeof(spo_info_t))) == NULL) return NULL;

    info->h_msgid   = NULL;
    info->d_msgid   = NULL;
    info->filter    = NULL;
    info->dev       = NULL;
    info->next      = NULL;
    info->pid       = 0;
    info->cpuid     = -1;

    return info;
}


/**
 *
 *  destory a info black;
 *
 * */

SPO_RET_STATUS spo_do_destory_info(spo_info_t *info)
{
    if (info == NULL) return SPO_OK;

    if (info->h_msgid != NULL)  spo_free(info->h_msgid);
    if (info->d_msgid != NULL)  spo_free(info->d_msgid);
    if (info->filter != NULL)   spo_free(info->filter);
    if (info->dev != NULL)      spo_free(info->dev);

    info->next = NULL;

    spo_free(info);

    return SPO_OK;
}


/**
 *
 *  destory all info blacks.
 *
 * */

SPO_RET_STATUS spo_destory_info(spo_info_t *info)
{
    spo_info_t *p = info;

    if (info == NULL) return SPO_OK;

    while (p != NULL) {
        info = info->next;
        spo_do_destory_info(p);
        p = info;
    }

    return SPO_OK;
}


spo_cfg_g_t *spo_create_cfg_g()
{
    spo_cfg_g_t *g = NULL;

    if ((g = spo_calloc(sizeof(spo_cfg_g_t))) == NULL) return NULL;

    g->max_dns_pkt_s    = 0;
    g->max_http_pkt_s   = 0;
    g->max_send_size    = 0;
    g->max_log_len      = 0;

    g->h_dmn_cfg_file   = NULL;
    g->h_data_path      = NULL;
    g->d_data_path      = NULL;
    g->log_file         = NULL;
    g->statis_file      = NULL;
    g->hp_mtd           = NULL;

    return g;
}


/**
 *
 *  destory global's Instruction cfg struct.
 *
 * */

SPO_RET_STATUS spo_destory_cfg_g(spo_cfg_g_t *cfg_g)
{
    if (cfg_g == NULL) return SPO_OK;

    if (cfg_g->h_dmn_cfg_file != NULL)  spo_free(cfg_g->h_dmn_cfg_file);
    if (cfg_g->h_data_path != NULL)     spo_free(cfg_g->h_data_path);
    if (cfg_g->d_data_path != NULL)     spo_free(cfg_g->d_data_path);
    if (cfg_g->log_file != NULL)        spo_free(cfg_g->log_file);
    if (cfg_g->statis_file != NULL)     spo_free(cfg_g->statis_file);

    spo_free(cfg_g);

    return SPO_OK;
}


SPO_RET_STATUS spo_destory_hp_mtd(void *mtd_)
{
    spo_str_t *mtd = (spo_str_t *) mtd_;

    if (mtd == NULL) return SPO_OK;

    if (mtd->data != NULL) spo_free(mtd->data);

    spo_free(mtd);

    return SPO_OK;
}


/**
 *
 *  create cfg struct.
 *
 * */

spo_cfg_t *spo_create_cfg()
{
    spo_cfg_t *cfg = NULL;

    if ((cfg = spo_calloc(sizeof(spo_cfg_t))) == NULL) return NULL;

    cfg->global     = NULL;
    spo_init_cfg_info_header(&cfg->inf_header);

    return cfg;
}


SPO_RET_STATUS spo_destory_cfg(spo_cfg_t *cfg)
{
    if (cfg == NULL) return SPO_OK;

    if (cfg->global != NULL) spo_destory_cfg_g(cfg->global);
    if (cfg->inf_header.infos != NULL) spo_destory_info(cfg->inf_header.infos);

    return SPO_OK;
}


spo_hp_data_t *spo_create_http_data()
{
    spo_hp_data_t *data = NULL;

    if ((data = spo_calloc(sizeof(spo_hp_data_t))) == NULL) return NULL;

    data->data.data     = NULL;
    data->data.len      = 0;
    data->data_satrt    = 0;

    data->dmn.data      = NULL;
    data->dmn.len       = 0;

    data->data_cp.data  = NULL;
    data->data_cp.len   = 0;

    data->num = 0;

    return data;
}


/**
 *
 *  destory a http data node.
 *
 * */

SPO_RET_STATUS spo_destory_http_data(void *data_)
{
    if (data_ == NULL) return SPO_OK;

    spo_hp_data_t *data = (spo_hp_data_t *)data_;

    if (data->data.data != NULL)    spo_free(data->data.data);
    if (data->dmn.data != NULL)     spo_free(data->dmn.data);
    if (data->data_cp.data != NULL) spo_free(data->data_cp.data);

    spo_free(data);

    return SPO_OK;
}


/**
 *
 *  create a http line node.
 *
 * */

spo_hp_line_t *spo_create_http_line()
{
    spo_hp_line_t *line = NULL;

    if ((line = spo_calloc(sizeof(spo_hp_line_t))) == NULL) return NULL;

    line->pcre_url = NULL;
    line->pcre_ref = NULL;
    line->pcre_cok = NULL;

    line->u_flg = 1;
    line->c_flg = 1;
    line->r_flg = 1;

    line->num   = 0;
    line->next  = NULL;

    return line;
}


/**
 *
 *  destory a line node.
 *
 * */

SPO_RET_STATUS spo_do_destory_http_line(spo_hp_line_t *line)
{
    if (line == NULL) return SPO_OK;

    if (line->pcre_url != NULL) pcre_free((pcre *) line->pcre_url);
    if (line->pcre_ref != NULL) pcre_free((pcre *) line->pcre_ref);
    if (line->pcre_cok != NULL) pcre_free((pcre *) line->pcre_cok);


    line->next = NULL;

    spo_free(line);

    return SPO_OK;
}


/**
 *  destory http line node for a domain.
 *
 * */

SPO_RET_STATUS spo_destory_http_line(spo_hp_line_t *line)
{
    spo_hp_line_t *p;

    if (line == NULL) return SPO_OK;

    p = line;

    while (p != NULL) {
        line = line->next;
        spo_do_destory_http_line(p);
        p = line;
    }

    return SPO_OK;
}


spo_hp_dmn_t *spo_create_http_dmn()
{
    spo_hp_dmn_t *dmn = NULL;

    if ((dmn = spo_calloc(sizeof(spo_hp_dmn_t))) == NULL) return NULL;

    dmn->dmn.data   = NULL;
    dmn->dmn.len    = 0;

    dmn->cfg_line       = NULL;
    dmn->cfg_line_tail  = NULL;

    dmn->statis = NULL;

    return dmn;
}


/**
 *
 *  destry http dmn struct.
 *
 *  http dmn node is the node of http dmn tree.
 *
 * */

SPO_RET_STATUS spo_destory_http_dmn(void *http_dmn_)
{
    if (http_dmn_ == NULL) return SPO_OK;

    spo_hp_dmn_t *http_dmn = (spo_hp_dmn_t *) http_dmn_;

    if (http_dmn->dmn.data != NULL) spo_free(http_dmn->dmn.data);

    if (http_dmn->statis != NULL) spo_free(http_dmn->statis);

    spo_destory_http_line(http_dmn->cfg_line);

    spo_free(http_dmn);

    return SPO_OK;
}


/**
 *
 *  create dns data node.
 *
 *  the data node is the data tree's node.
 *
 * */

spo_dns_data_t *spo_create_dns_data()
{
    spo_dns_data_t *data = NULL;

    if ((data = spo_calloc(sizeof(spo_dns_data_t))) == NULL) return NULL;

    data->dmn.data  = NULL;
    data->dmn.len   = 0;

    data->data.data = NULL;
    data->data.len  = 0;

    data->statis = NULL;

    return data;
}


/**
 *
 *  destory the dns data, when the data alloc by spo_calloc().
 *
 * */

SPO_RET_STATUS spo_destory_dns_data(void *data_)
{
    if (data_ == NULL) return SPO_OK;

    spo_dns_data_t *data = (spo_dns_data_t *)data_;

    if (data->dmn.data != NULL) spo_free(data->dmn.data);
    if (data->data.data != NULL) spo_free(data->data.data);
    if (data->statis != NULL) spo_free(data->statis);
    if (data->data_cp.data != NULL) spo_free(data->data_cp.data);

    spo_free(data);

    return SPO_OK;
}


/**
 *
 *  create dmn data header, the header save the http and dns date tree.
 *
 * */

spo_dmn_data_header_t *spo_create_dmn_data_header()
{
    spo_dmn_data_header_t *header = NULL;

    if((header = spo_calloc(sizeof(spo_dmn_data_header_t))) == NULL) return NULL;

    header->dns_data    = NULL;
    header->http_data   = NULL;

    return header;
}


/**
 *
 *  create domain cfg, for http domain.
 *
 * */

spo_dmn_t *spo_create_dmn()
{
    spo_dmn_t *dmn = NULL;

    if ((dmn = spo_calloc(sizeof(spo_dmn_t))) == NULL) return NULL;

    dmn->dmn = NULL;

    return dmn;
}


SPO_RET_STATUS spo_destory_dmn(spo_dmn_t *dmn)
{
    if (dmn == NULL) return SPO_OK;

    if (dmn->dmn != NULL) {
        spo_destory_tree(dmn->dmn, dmn->dmn->free_key);
    }

    spo_free(dmn);

    return SPO_OK;
}


/**
 *
 *  remove the '#' in cfg.
 *
 * */

static void spo_do_deal_with_line(char *line)
{
    int i = 0;
    int len = strlen(line);

    for (i = 0; i < len; i++) {
        if (line[i] == '#' && line[i + 1] == '#') break;
    }

    for (i--; i >= 0; i--) {
        if (line[i] != ' ' && line[i] != '\t') break;
    }

    line[i + 1] = '\0';
}


/**
 *  after read a new line, we remove the Space in start and end
 *
 *  @param line, the current we readed.
 *
 *  @return char *, is the line.
 *
 * */

static char *spo_deal_with_line(char *line)
{
    char *ch = line;
    char *end = NULL;
    int i = 0;
    int len = strlen(line);

    if (line == NULL) return NULL;

    /* remove the '\n' in the end of the line */
    if (line[len - 1] == '\n') {
        line[len - 1] = '\0';
    }

    /* remove the spcae in the line start */
    while ((*ch == ' ' || *ch == '\t') && i < len) {
        ch++;
        i++;
    }

    end = line + len - 2;

    while ((*end == ' ' || *end == '\t') && len > 0) {
        end--;
    }

    end++;
    *end = '\0';

    spo_do_deal_with_line(ch);

    return ch;
}


/*  - - -- - - - -- - - - - - -- load program cfg - - -- - - -- -- --- -- -  - -- - - --  */


static SPO_RET_VALUE spo_get_max_send_size(char *p)
{
    int size = 0;
    switch (*(p + strlen(p))) {
    case 'K': size = 1024; break;
    case 'k': size = 1024; break;
    case 'M': size = 1024 * 1024; break;
    case 'm': size = 1024 * 1024; break;
    default :size = 1024;
    }

    return size * atoi(p);
}


/**
 *
 *  analysis global's Instruction and save info in cfg_g struct.
 *
 * */

static SPO_RET_STATUS spo_analysis_global_instr(spo_cfg_t *cfg, char *line, char *delim)
{
    char *p = NULL;

    if ((p = strtok(line, delim)) == NULL) return SPO_FAILURE;

    if (strcmp(p, "max_dns_pkt_size") == 0) {
        if ((p = strtok(NULL, "")) != NULL) {
            cfg->global->max_dns_pkt_s = atoi(p);
            return SPO_OK;
        }
        return SPO_FAILURE;
    }

    if (strcmp(p, "max_http_pkt_size") == 0) {
        if ((p = strtok(NULL, "")) != NULL) {
            cfg->global->max_http_pkt_s = atoi(p);
            return SPO_OK;
        }
        return SPO_FAILURE;
    }

    if (strcmp(p, "max_send_size") == 0) {
        if ((p = strtok(NULL, "")) != NULL) {
            cfg->global->max_send_size = spo_get_max_send_size(p);
            return SPO_OK;
        }
        return SPO_FAILURE;
    }

    if (strcmp(p, "max_log_len") == 0) {
        if ((p = strtok(NULL, "")) != NULL) {
            cfg->global->max_log_len = atoi(p);
            return SPO_OK;
        }
        return SPO_FAILURE;
    }

    if (strcmp(p, "dns_dmn_data_path") == 0) {
        if ((p = strtok(NULL, "")) != NULL) {
            cfg->global->d_data_path = spo_calloc(strlen(p));
            if (cfg->global->d_data_path == NULL) return SPO_FAILURE;
            memcpy(cfg->global->d_data_path, p, strlen(p));
            return SPO_OK;
        }
        return SPO_FAILURE;
    }

    if (strcmp(p, "http_dmn_cfg_file") == 0) {
        if ((p = strtok(NULL, "")) != NULL) {
            cfg->global->h_dmn_cfg_file = spo_calloc(strlen(p));
            if (cfg->global->h_dmn_cfg_file == NULL) return SPO_FAILURE;

            memcpy(cfg->global->h_dmn_cfg_file, p, strlen(p));
            return SPO_OK;
        }
        return SPO_FAILURE;
    }

    if (strcmp(p, "http_dmn_data_path") == 0) {
        if ((p = strtok(NULL, "")) != NULL) {
            cfg->global->h_data_path = spo_calloc(strlen(p));
            if (cfg->global->h_data_path == NULL) return SPO_FAILURE;

            memcpy(cfg->global->h_data_path, p, strlen(p));
            return SPO_OK;
        }
        return SPO_FAILURE;
    }

    if (strcmp(p, "log_file") == 0) {
        if ((p = strtok(NULL, "")) != NULL) {
            cfg->global->log_file = spo_calloc(strlen(p));
            if (cfg->global->log_file == NULL) return SPO_FAILURE;

            memcpy(cfg->global->log_file, p, strlen(p));
            return SPO_OK;
        }
        return SPO_FAILURE;
    }

    if (strcmp(p, "statis_file") == 0) {
        if ((p = strtok(NULL, "")) != NULL) {
            cfg->global->statis_file = spo_calloc(strlen(p));
            if (cfg->global->statis_file == NULL) return SPO_FAILURE;

            memcpy(cfg->global->statis_file, p, strlen(p));
            return SPO_OK;
        }
        return SPO_FAILURE;
    }

    printf("no this global's' Instruction\n");

    return SPO_FAILURE;
}


/**
 *
 *  create the space for http msgids.
 *  we create 16 * sizeof(int) bits for start.
 *
 * */

static int *spo_create_cfg_msgids(uint n)
{
    int *msgids = NULL;
    int i = 0;

    if (n == 0) return NULL;

    msgids = spo_calloc(n * sizeof(int));
    if (msgids == NULL) return NULL;

    for (i = n - 1; i > 0; i--) {
        msgids[i] = -1;
    }

    msgids[0] = 0;

    return msgids;
}


/**
 *
 *  when msg's amount more than default, we realloc space for msg ids.
 *
 * */

static SPO_RET_STATUS spo_recalloc_cfg_http_msgids(spo_info_t *info)
{
    void *p = NULL;

    p = realloc(info->h_msgid, (info->h_msgid[0] + SPO_INC_MSGID_AMOUNT) * sizeof(int));
    if (p == NULL) return SPO_FAILURE;

    info->h_msgid = p;

    return SPO_OK;
}


/**
 *
 *  malloc the space for msgids.
 *
 * */

static SPO_RET_STATUS spo_init_cfg_snif_hp_msgids(spo_info_t *info, const char *p)
{
    static int max_amount = SPO_DEF_MSGID_AMOUNT;

    if (info->h_msgid == NULL)
        if ((info->h_msgid = spo_create_cfg_msgids(SPO_DEF_MSGID_AMOUNT)) == NULL)
            return SPO_FAILURE;

    if (info->h_msgid[0] >= max_amount)
        if (spo_recalloc_cfg_http_msgids(info) == SPO_OK)
            max_amount += SPO_INC_MSGID_AMOUNT;

    info->h_msgid[0]++;
    info->h_msgid[info->h_msgid[0]] = atoi(p);

    return SPO_OK;
}


static SPO_RET_STATUS spo_init_cfg_dns_msgids(spo_info_t *info, const char *p)
{
    static int d_max_amount = SPO_DEF_MSGID_AMOUNT;

    if (info->d_msgid == NULL)
        if ((info->d_msgid = spo_create_cfg_msgids(SPO_DEF_MSGID_AMOUNT)) == NULL)
            return SPO_FAILURE;

    if (info->d_msgid[0] >= d_max_amount) {
        info->d_msgid = realloc(info->h_msgid, (info->h_msgid[0] + SPO_INC_MSGID_AMOUNT) * sizeof(int));
        if (info->d_msgid == NULL) return SPO_FAILURE;
    }

    info->d_msgid[0]++;
    info->d_msgid[info->d_msgid[0]] = atoi(p);

    return SPO_OK;
}


/**
 *
 *  analysis Instructions in spo_sniffer scope.
 *
 * */

static SPO_RET_STATUS spo_analysis_sniff_cfg(spo_cfg_t *cfg, char *line, char *delim)
{
    spo_info_t *info = cfg->inf_header.infos_tail;
    char *p = NULL;
    char key[64] = {'\0'};
    int len = 0;

    if ((p = strtok(line, delim)) != NULL)
        strncpy(key, p, (len = strlen(p)) >= 64 ? 63 : len);
    else return SPO_FAILURE;

    if (strcmp(key, "filter") != 0) {
        if ((p = strtok(NULL, delim)) == NULL) return SPO_FAILURE;
    }else if ((p = strtok(NULL, "")) == NULL) return SPO_FAILURE;

    len = strlen(p);

    if (memcmp(key, "dev_r", strlen("dev_r")) == 0) {
        if ((info->dev = spo_calloc(len + 1)) == NULL) return SPO_FAILURE;
        memcpy(info->dev, p, len);
        return SPO_OK;
    }

    if (memcmp(key, "filter", strlen("filter")) == 0) {
        if ((info->filter = spo_calloc(len + 1)) == NULL) return SPO_FAILURE;
        memcpy(info->filter, p, len);
        return SPO_OK;
    }

    if (memcmp(key, "useing_lib", strlen("useing_lib")) == 0){
        memcpy(info->lib, p, len);
        return SPO_OK;
    }

    if (memcmp(key, "http_msgid", strlen("http_msgid")) == 0) {
        return spo_init_cfg_snif_hp_msgids(info, p);
    }

    if (memcmp(key, "dns_msgid", strlen("dns_msgid")) == 0) {
        return spo_init_cfg_dns_msgids(info, p);
    }

    if (memcmp(key, "proc_type", strlen("proc_type")) == 0) {
        memcpy(info->type, p, len);
        return SPO_OK;
    }

    if (memcmp(key, "cpuid", strlen("cpuid")) == 0) {
        info->cpuid = atoi(p);
        return SPO_OK;
    }

    if (memcmp(key, "data_direc", strlen("data_direc")) == 0) {
        if (memcmp(p, "rx", len) == 0) info->driection = 1;
        else if (memcmp(p, "tx", len) == 0) info->driection = 2;
        else info->driection = 3;

        return SPO_OK;
    }

    printf("no this Instruction in <spo_sniffer> scope\n");

    return SPO_FAILURE;
}


/**
 *
 *  analysis Instructions in spo_sniffer scope.
 *
 * */

static SPO_RET_STATUS spo_analysis_spoof_cfg(spo_cfg_t *cfg, char *line, const char *delim)
{
    spo_info_t *info = cfg->inf_header.infos_tail;
    char *p = NULL;
    char key[32] = {'\0'};
    int len = 0;

    if ((p = strtok(line, delim)) != NULL) {
        strncpy(key, p, (len = strlen(p)) >= 32 ? 31 : len);
    }else return SPO_FAILURE;

    if ((p = strtok(NULL, "")) == NULL) return SPO_FAILURE;

    len = strlen(p);

    if (memcmp(key, "rcv_msgid", strlen("rcv_msgid")) == 0) {
        info->h_msgid = spo_calloc(2 * sizeof(int));
        if (info->h_msgid == NULL) return SPO_FAILURE;
        info->h_msgid[0] = 1;
        info->h_msgid[1] = atoi(p);
        return SPO_OK;
    }

    if (memcmp(key, "snd_msgid", strlen("snd_msgid")) == 0) {
        return spo_init_cfg_dns_msgids(info, p);
    }

    if (memcmp(key, "proc_type", strlen("proc_type")) == 0) {
        memcpy(info->type, p, len);
        return SPO_OK;
    }

    if (memcmp(key, "cpuid", strlen("cpuid")) == 0) {
        info->cpuid = atoi(p);
        return SPO_OK;
    }

    printf("no this Instruction in <spo_spoofer> scope\n");

    return SPO_FAILURE;
}


/**
 *
 *  analysis Instructions in spo_sniffer scope.
 *
 * */

static SPO_RET_STATUS spo_analysis_sender_cfg(spo_cfg_t *cfg, char *line, const char *delim)
{
    spo_info_t *info = cfg->inf_header.infos_tail;
    char *p = NULL;
    char key[32] = {'\0'};
    int len = 0;

    if ((p = strtok(line, delim)) != NULL) {
        strncpy(key, p, (len = strlen(p)) >= 32 ? 31 : len);
    }else return SPO_FAILURE;

    if ((p = strtok(NULL, "")) == NULL) return SPO_FAILURE;

    len = strlen(p);

    if (memcmp(key, "dev_s", strlen("dev_s")) == 0) {
        if ((info->dev = spo_calloc(len + 1)) == NULL) return SPO_FAILURE;
        memcpy(info->dev, p, len);
        return SPO_OK;
    }

    if (memcmp(key, "rcv_msgid", strlen("rcv_msgid")) == 0) {
        info->h_msgid = spo_calloc(2 * sizeof(int));
        if (info->h_msgid == NULL) return SPO_FAILURE;
        info->h_msgid[0] = 1;
        info->h_msgid[1] = atoi(p);
        return SPO_OK;
    }

    if (memcmp(key, "proc_type", strlen("proc_type")) == 0) {
        memcpy(info->type, p, len);
        return SPO_OK;
    }

    if (memcmp(key, "cpuid", strlen("cpuid")) == 0) {
        info->cpuid = atoi(p);
        return SPO_OK;
    }

    printf("no this Instruction in <spo_sender> scope\n");

    return SPO_FAILURE;

}


/**
 *
 *  load the http method blk;
 *
 * */

static SPO_RET_STATUS spo_do_hp_mtd_cfg(spo_cfg_t *cfg, char *line, const char *delim)
{
    char *p         = NULL;
    size_t len      = 0;
    spo_str_t *mtd  = NULL;
    spo_tree_node_t *t_node = NULL;
    spo_tree_header_t *header = NULL;
    spo_bool_t taller = 0;

    header = cfg->global->hp_mtd;

    if ((p = strtok(line, delim)) == NULL) return SPO_FAILURE;
    if ((p = strtok(NULL, "")) == NULL) return SPO_FAILURE;

    len = strlen(p);

    if ((t_node = spo_create_tree_node()) == NULL) goto spo_bad_mtd;

    if ((mtd = spo_calloc(sizeof(spo_str_t))) == NULL) goto spo_bad_mtd;

    if ((mtd->data = spo_calloc(len + 1)) == NULL) goto spo_bad_mtd;
    mtd->len = len;

    memcpy(mtd->data, p, len);

    t_node->key = mtd;

    spo_insert_AVL(&(header->root), t_node, &taller, header->c);

    return SPO_OK;

spo_bad_mtd:

    spo_destory_hp_mtd(mtd);
    if (t_node != NULL) spo_free(t_node);

    return SPO_FAILURE;
}


/**
 *
 *  malloc the info spcae and insert in the info queue's tail.
 *
 * */

static SPO_RET_STATUS spo_do_analysis_cfg(spo_cfg_t *cfg, spo_cfg_stat *status)
{
    spo_info_t *info = NULL;

    if (*status != SPO_IN_GLOBAL && *status != SPO_IN_START) return SPO_FAILURE;

    info = spo_create_info();
    if (info == NULL) return SPO_FAILURE;

    if (cfg->inf_header.infos == NULL) {
        cfg->inf_header.infos = info;
        cfg->inf_header.infos_tail = info;
    }else {
        cfg->inf_header.infos_tail->next = info;
        cfg->inf_header.infos_tail = info;
    }

    return SPO_OK;
}


/**
 *
 *  when read a process blk;
 *
 * */

static SPO_RET_STATUS spo_cfg_proc_type(spo_cfg_t *cfg, spo_cfg_stat *status, int sta)
{
    int ret = 0;

    ret = spo_do_analysis_cfg(cfg, status);
    *status = sta;

    return ret;
}


/**
 *
 *  when read a mtd blk;
 *
 * */

static SPO_RET_STATUS spo_hp_mtd_cfg(spo_cfg_t *cfg, spo_cfg_stat *status)
{
    if ((cfg->global->hp_mtd = spo_create_tree_header()) == NULL) return SPO_FAILURE;

    cfg->global->hp_mtd->c = spo_comp_hp_mtd;
    cfg->global->hp_mtd->free_key = spo_destory_hp_mtd;
    *status = SPO_IN_MTD;

    return SPO_OK;
}


/**
 *
 *  load the cfg all infos.
 *
 * */

static SPO_RET_STATUS spo_analysis_cfg(char *line, spo_cfg_t *cfg, spo_cfg_stat *status)
{
    int ret = -1;

    if (memcmp(line, "</", 2) == 0) return (*status = SPO_IN_GLOBAL);

    if (*status == SPO_IN_SNIFFER) {
        return spo_analysis_sniff_cfg(cfg, line, " ");
    }

    if (*status == SPO_IN_SPOOFER) {
        return spo_analysis_spoof_cfg(cfg, line, " ");
    }

    if (*status == SPO_IN_SENDER) {
        return spo_analysis_sender_cfg(cfg, line, " ");
    }

    if (*status == SPO_IN_MTD) {
        return spo_do_hp_mtd_cfg(cfg, line, " ");
    }

    if (memcmp(line, "<spo_sniffer>", strlen("<spo_sniffer>")) == 0) {
        ret = spo_cfg_proc_type(cfg, status, SPO_IN_SNIFFER);
        cfg->inf_header.sniffers++;
        return ret;
    }

    if (memcmp(line, "<spo_dns_spoofer>", strlen("<spo_dns_spoofer>")) == 0) {
        ret = spo_cfg_proc_type(cfg, status, SPO_IN_SPOOFER);
        cfg->inf_header.d_spofs++;
        return ret;
    }

    if (memcmp(line, "<spo_http_spoofer>", strlen("<spo_http_spoofer>")) == 0) {
        ret = spo_cfg_proc_type(cfg, status, SPO_IN_SPOOFER);
        cfg->inf_header.h_spofs++;
        return ret;
    }

    if (memcmp(line, "<spo_sender>", strlen("<spo_sender>")) == 0) {
        ret = spo_cfg_proc_type(cfg, status, SPO_IN_SENDER);
        cfg->inf_header.sender++;
        return ret;
    }

    if (memcmp(line, "<spo_hp_method>", strlen("<spo_hp_method>")) == 0) {
        return spo_hp_mtd_cfg(cfg, status);
    }

    if (*status == SPO_IN_GLOBAL || *status == SPO_IN_START) {
        *status = SPO_IN_GLOBAL;
        return spo_analysis_global_instr(cfg, line, " ");
    }

    return SPO_FAILURE;
}


/**
 *
 *  we really load cfg file here.
 *
 * */

static SPO_RET_STATUS spo_do_load_cfg(FILE *fp, spo_cfg_t *cfg)
{
    size_t len  = 0;
    ssize_t read = 0;
    spo_cfg_stat cfg_stat = SPO_IN_START;
    char *line = NULL;
    int line_counter = 0;

    while ((read = getline(&line, &len, fp)) != -1) {
        char *ch = spo_deal_with_line(line);

        line_counter++;

        if (strncmp(ch, "#", 1) == 0 || strlen(ch) == 0) {   /* skip the annotate line */
            continue;
        }

        if (spo_analysis_cfg(ch, cfg, &cfg_stat) == SPO_FAILURE) {
            printf("analysis err %d\n\n", line_counter);
            return SPO_FAILURE;
        }
    }

    return SPO_OK;
}


/**
 *
 *  load cfg file info.
 *
 *  @param f_name, is the cfg file path and name.
 *
 *  @return , is the cfg struct.
 *
 * */

void *spo_load_prog_cfg(const char *f_name)
{
    FILE *fp = NULL;
    spo_cfg_t *cfg = NULL;

    if (f_name == NULL) return NULL;

    if ((fp = spo_fopen(f_name, "r")) == NULL) return NULL;

    if ((cfg = spo_create_cfg()) == NULL) goto spo_bad_load_prog;

    if ((cfg->global = spo_create_cfg_g()) == NULL) goto spo_bad_load_prog;

    if (spo_do_load_cfg(fp, cfg) == SPO_FAILURE) goto spo_bad_load_prog;

    spo_fclose(fp);

    if (spo_check_prog_cfg(cfg) == SPO_FAILURE) goto spo_bad_load_prog;

    return cfg;

spo_bad_load_prog:

    if (cfg != NULL) spo_destory_cfg(cfg);

    spo_fclose(fp);

    return NULL;
}


/*- - - - - - -- - -- - - - - load http domain cfg-- - - - - -- - - - - -- - - -- - -*/

/**
 *
 *  just copy the data that in file to line.
 *
 * */

static SPO_RET_STATUS spo_load_cfg_dmn_line(pcre **pr, const char *rege_, int *flg)
{
    char *rege = NULL;
    char *p = NULL;
    const char *error;
    uint len = 0;
    int  erroffset;

    if (rege_ == NULL) return SPO_FAILURE;

    if ((len = strlen(rege_)) == 0) {
        *pr = NULL;
        return SPO_OK;
    }

    if ((rege = spo_calloc(len + 1)) == NULL) return SPO_FAILURE;
    memcpy(rege, rege_, len);
    rege[len - 1] = '\0';       /* the rege is like '/^abc[1-8]/', we rm the '/' at tail */

    if (rege[0] == '!') {
        p = rege + 2;
        *flg = 0;
    }else {
        p = rege + 1;
        *flg = 1;
    }

    if ((*pr = pcre_compile(p, 0, &error, &erroffset, NULL)) == NULL) goto spo_bad_rege;

spo_bad_rege :

    if (rege != NULL) spo_free(rege);

    return SPO_FAILURE;
}


/**
 *
 *  insert the lne in http dmn line's queue.
 *
 * */

static SPO_RET_STATUS spo_insert_http_cfg_line(spo_hp_dmn_t *h_dmn, spo_hp_line_t *h_line)
{
    if (h_dmn->cfg_line == NULL) {
        h_dmn->cfg_line = h_line;
    }else {
        h_dmn->cfg_line_tail->next = h_line;
    }

    h_dmn->cfg_line_tail = h_line;

    return SPO_OK;
}


/**
 *
 *  when in domain black scope, we read the domain lines.
 *
 * */

static SPO_RET_STATUS spo_do_analy_http_dmn_cfg_blk(spo_dmn_t *dmn, char *line, const char *delim)
{
    char *p = NULL;

    spo_hp_line_t *cfg_line = NULL;

    spo_hp_dmn_t *http_dmn = (spo_hp_dmn_t *) dmn->dmn->current->key;

    if ((cfg_line = spo_create_http_line()) == NULL) return SPO_FAILURE;

    if ((p = spo_strtok(line, delim)) == NULL) return SPO_FAILURE;
    spo_load_cfg_dmn_line((pcre **) &cfg_line->pcre_url, (p = p + SPO_URL_TARGE), &cfg_line->u_flg);

    if ((p = spo_strtok(NULL, delim)) == NULL) return SPO_FAILURE;
    spo_load_cfg_dmn_line((pcre **) &cfg_line->pcre_cok, (p = p + SPO_COOKIES_TARGE), &cfg_line->c_flg);

    if ((p = spo_strtok(NULL, delim)) == NULL) return SPO_FAILURE;
    spo_load_cfg_dmn_line((pcre **) &cfg_line->pcre_ref, (p = p + SPO_REFERER_TARGE), &cfg_line->r_flg);

    if ((p = spo_strtok(NULL, delim)) == NULL) return SPO_FAILURE;
    cfg_line->num = atoi(p + 1);

    spo_insert_http_cfg_line(http_dmn, cfg_line);

    return SPO_OK;
}


static spo_msg_t *spo_do_init_statis_msg(size_t size, spo_str_t *dmn)
{
    spo_msg_t *msg = NULL;
    spo_statis_t *statis = NULL;

    if (size == 0) return NULL;
    if ((msg = spo_calloc(size)) == NULL) return NULL;

    msg->type = SPO_STATIS_MSG_TYPE;

    statis = (spo_statis_t *) ((char *) msg->data);

    spo_init_statis(statis);
    memcpy(statis->domain, dmn->data, dmn->len);
    statis->size = size;

    return msg;
}


/**
 *
 *  init the statis sturc.
 *  set the statis msg type be SPO_STATIS_MSG_TYPE (11)
 *
 * */

static SPO_RET_STATUS spo_init_hp_statis_msg(void *hp_dmn_)
{
    spo_hp_dmn_t *hp_dmn = (spo_hp_dmn_t *) hp_dmn_;
    size_t size = sizeof(spo_msg_t) + sizeof(spo_statis_t) + hp_dmn->dmn.len + 1;

    if ((hp_dmn->statis = spo_do_init_statis_msg(size, &hp_dmn->dmn)) == NULL) return SPO_FAILURE;

    return SPO_OK;
}


/**
 *
 *  get domain black. we record the domain.
 *
 * */

static SPO_RET_STATUS spo_analy_http_dmn_cfg_blk(spo_dmn_t *dmn, const char *line, spo_cfg_stat *dmn_stat)
{
    int len = 0;
    char *data = NULL;

    if (*dmn_stat != SPO_IN_GLOBAL && *dmn_stat != SPO_IN_START) return SPO_FAILURE;

    if ((dmn->dmn->current = spo_create_tree_node()) == NULL) return SPO_FAILURE;

    if ((dmn->dmn->current->key = (void *)spo_create_http_dmn()) == NULL) return SPO_FAILURE;

    char *ch_space = strrchr(line, ' ');
    if (ch_space == NULL) return SPO_FAILURE;

    /* get domain name in cfg file */
    char *ch = strrchr(line, '>');
    if (ch == NULL) return  SPO_FAILURE;

    if ((len = ch - ch_space - 1) <= 0) return SPO_FAILURE;

    data = spo_calloc(len + 1);

    if (data == NULL) return SPO_FAILURE;

    memcpy(data, (ch_space + 1), len);

    ((spo_hp_dmn_t *)dmn->dmn->current->key)->dmn.data = (u_char *)data;
    ((spo_hp_dmn_t *)dmn->dmn->current->key)->dmn.len = (size_t)len;

    if (spo_init_hp_statis_msg(dmn->dmn->current->key) == SPO_FAILURE) return SPO_FAILURE;

    *dmn_stat = SPO_IN_DOMAIN;

    return SPO_OK;
}


static SPO_RET_STATUS spo_analy_http_dmn_cfg(spo_dmn_t *dmn, char *line, spo_cfg_stat *dmn_stat)
{
    if (memcmp(line, "</", 2) == 0) {
        *dmn_stat = SPO_IN_GLOBAL;

        spo_bool_t taller = 0;
        spo_insert_AVL(&(dmn->dmn->root), dmn->dmn->current, &taller, spo_comp_http_dmn_node);

        return SPO_OK;
    }

    if (*dmn_stat == SPO_IN_DOMAIN) {
        return spo_do_analy_http_dmn_cfg_blk(dmn, line, ",,,");
    }

    if (memcmp(line, "<spo_domain", strlen("<spo_domain")) == 0) {
        return spo_analy_http_dmn_cfg_blk(dmn, line, dmn_stat);
    }

    return SPO_FAILURE;
}


static SPO_RET_STATUS spo_do_load_http_dmn_cfg(spo_dmn_t *dmn, FILE *fp)
{
    spo_cfg_stat dmn_stat = SPO_IN_START;
    ssize_t read = 0;
    size_t len = 0;
    char *line = NULL;
    int line_counter = 0;

    while ((read = getline(&line, &len, fp)) != -1) {
        char *ch = spo_deal_with_line(line);

        line_counter++;

        if (strncmp(ch, "#", 1) == 0 || strlen(ch) == 0) {   /* skip the annotate line */
            continue;
        }

        if (spo_analy_http_dmn_cfg(dmn, ch, &dmn_stat) == SPO_FAILURE) {
            printf("load http dmn cfg err in %d line\n", line_counter);
            return SPO_FAILURE;
        }
    }

    return SPO_OK;
}


/**
 *
 *  load http domain cfg infos.
 *
 * */

spo_dmn_t *spo_load_http_dmn_cfg(const char *f_name)
{
    spo_dmn_t *dmn = NULL;
    FILE *fp = NULL;

    if (f_name == NULL) return NULL;

    if ((fp = spo_fopen(f_name, "r")) == NULL) return NULL;

    if ((dmn = spo_create_dmn()) == NULL) goto spo_bad_load_http_dmn;

    if ((dmn->dmn = spo_create_tree_header()) == NULL) goto spo_bad_load_http_dmn;
    dmn->dmn->c = spo_comp_http_dmn_node;
    dmn->dmn->free_key = spo_destory_http_dmn;

    if (spo_do_load_http_dmn_cfg(dmn, fp) != SPO_OK) goto spo_bad_load_http_dmn;

    spo_fclose(fp);

    return dmn;

spo_bad_load_http_dmn:

    if (dmn != NULL) spo_destory_dmn(dmn);

    spo_fclose(fp);

    return NULL;
}


/* - - - ---- -- - - - -- -  load dns or http data cfg -- - - - -- - - - - -- - - -- - --  */


static SPO_RET_STATUS spo_change_dns_host_form(u_char *line)
{
    int i = 0;
    char j = 0;
    int len = strlen((const char *)line) - 1;
    u_char *ch = line + len;

    if (line == NULL)   return SPO_FAILURE;

    for (i = len; i >= 0; i--) {
        if (*ch == '.') {
            *ch = j;
            j = 0;
            ch--;
            continue;
        }
        ch--;
        j++;
    }

    return SPO_OK;
}


static SPO_RET_STATUS spo_dns_data_dmn(spo_str_t *dmn, const char *dmn_name)
{
    if ((dmn->data = spo_calloc(strlen(dmn_name) + 1)) == NULL) return SPO_FAILURE;

    dmn->len = strlen(dmn_name);
    memcpy(dmn->data, dmn_name, dmn->len);

    spo_change_dns_host_form(dmn->data);

    return SPO_OK;
}


static SPO_RET_STATUS spo_cp_dns_data(spo_str_t *data, spo_str_t *data_cp)
{
    size_t offset = sizeof(spo_msg_t) + sizeof(spo_bld_pkt_t) + sizeof(spo_dns_hjk_t);
    spo_msg_t *msg = NULL;
    spo_bld_pkt_t *bld_pkt = NULL;

    if ((data_cp->data = spo_calloc(data->len + offset - SPO_DNS_H)) == NULL) return SPO_FAILURE;
    data_cp->len = data->len + offset - SPO_DNS_H;

    msg = (spo_msg_t *) data_cp->data;
    bld_pkt = (spo_bld_pkt_t *) (msg->data);

    bld_pkt->len = data_cp->len;
    bld_pkt->snd_s = data_cp->len;
    bld_pkt->h_data_s = data->len - SPO_DNS_H;

    memcpy((data_cp->data + offset), (data->data + SPO_DNS_H), data->len - SPO_DNS_H);

    return SPO_OK;
}


static SPO_RET_STATUS spo_init_dns_statis_msg(spo_dns_data_t *data, const char *dmn_name)
{
    spo_msg_t *msg = NULL;
    spo_str_t str;
    size_t size = 0;

    str.data = (u_char *) dmn_name;
    str.len = strlen(dmn_name);

    size = sizeof(spo_msg_t) + sizeof(spo_statis_t) + str.len + 1;

    if ((msg = spo_do_init_statis_msg(size, &str)) == NULL) return SPO_FAILURE;

    data->statis = msg;

    return SPO_OK;
}


static spo_tree_node_t *spo_do_load_dns_data_cfg(const char *absol_name, const char *dmn_name)
{
    spo_tree_node_t *node = NULL;
    spo_dns_data_t *data = NULL;
    size_t f_size = 0;
    size_t ret = 0;

    if ((node = spo_create_tree_node()) == NULL) return NULL;

    if ((data = spo_create_dns_data()) == NULL) goto spo_bad_load_dns_data;

    if ((f_size = spo_file_size(absol_name)) == 0) goto spo_bad_load_dns_data;

    if (spo_init_dns_statis_msg(data, dmn_name) == SPO_FAILURE) goto spo_bad_load_dns_data;     /* init dns statis */

    if (spo_dns_data_dmn(&data->dmn, dmn_name) == SPO_FAILURE) goto spo_bad_load_dns_data;      /* copy domain */

    if ((data->data.data = spo_calloc(f_size)) == NULL) goto spo_bad_load_dns_data;

    if ((ret = spo_read_file_data(absol_name, data->data.data)) == 0) goto spo_bad_load_dns_data;
    data->data.len = ret;

    if (spo_cp_dns_data(&data->data, &data->data_cp) == SPO_FAILURE) goto spo_bad_load_dns_data;

    node->key = (void *) data;

    return node;

spo_bad_load_dns_data:

    if (data != NULL) spo_destory_dns_data(data);
    if (node != NULL) spo_destory_tree_node(node, spo_destory_dns_data);

    return NULL;
}


static SPO_RET_STATUS spo_http_data_dmn(spo_str_t *dmn, const char *dmn_name)
{
    char *start = NULL;
    char *end = NULL;
    size_t len = 0;

    start = strchr(dmn_name, '@');
    end = strchr(dmn_name, '_');

    if (start == NULL) {
        dmn->data = NULL;
        dmn->len = 0;
        return SPO_OK;
    }else start++;

    if (end == NULL) len = strlen(start);
    else len = (end - start);

    if ((dmn->data = spo_calloc(len + 1)) == NULL) return SPO_FAILURE;

    memcpy(dmn->data, start, len);

    dmn->len = len;

    return SPO_OK;
}


static SPO_RET_VALUE spo_http_data_num(const char *dmn_name)
{
    char *start = NULL;
    char *copy  = NULL;
    int num = 0;

    start = strchr(dmn_name, '@');
    if (start == NULL) return atoi(dmn_name);

    if ((copy = spo_calloc((start - dmn_name) + 1)) == NULL) return SPO_FAILURE;

    memcpy(copy, dmn_name, (start - dmn_name));

    num = atoi(copy);

    spo_free(copy);

    return num;
}


static SPO_RET_STATUS spo_cp_http_data(spo_hp_data_t *hp_data, spo_str_t *data_cp, spo_str_t *data, size_t size)
{
    size_t i = 0;
    spo_msg_t *msg = NULL;
    spo_bld_pkt_t *bld_pkt = NULL;
    char *h  = NULL;

    size_t len = data->len + size;

    if ((data_cp->data = spo_calloc(len)) == NULL) return SPO_FAILURE;

    h = (char *) (data_cp->data + size);

    msg = (spo_msg_t *) ((char *) data_cp->data);
    bld_pkt = (spo_bld_pkt_t *) ((char *) msg->data);

    u_char *p = (u_char *) data->data;

    for (i = 0; i < data->len; i++) {
        if (*p == 0x2f && *(p + 1) == 0x2a && *(p + 2) == 0x2a && *(p + 3) == 0x2f) {
            hp_data->data_satrt = p - data->data;
            p += 6;
            break;
        }

        p++;
    }

    if (i >= data->len) return SPO_FAILURE;

    bld_pkt->h_data_s = data->len - (size_t) (p - (u_char *) data->data);
    bld_pkt->len    = len;
    bld_pkt->snd_s  = len;

    bld_pkt->header_len = size;
    bld_pkt->h_header_s = 0;

    if (bld_pkt->h_data_s > 0) memcpy(h, p, bld_pkt->h_data_s);

    return SPO_OK;
}


static spo_hp_data_info_t *spo_create_hp_data_info()
{
    spo_hp_data_info_t *info = NULL;

    if ((info = spo_calloc(sizeof(spo_hp_data_info_t))) == NULL) return NULL;

    info->next      = NULL;
    info->prcv      = NULL;
    info->pr        = NULL;
    info->len       = 0;
    info->offset    = 0;
    info->type      = 0;

    return info;
}


static SPO_RET_STATUS spo_hp_data_info_insert(spo_hp_data_t *hp_data, spo_hp_data_info_t *info)
{
    if (hp_data->data_info == NULL) {
        hp_data->data_info = info;
        info->prcv = NULL;
        hp_data->tail = info;
    }else {
        hp_data->tail->next = info;
        info->prcv = hp_data->tail;
        hp_data->tail = info;
    }

    return SPO_OK;
}


/**
 *
 *  deal with $cok_arg, setting their type and generating patterns respectively
 *
 * */

static SPO_RET_STATUS spo_hp_cok_tag(spo_hp_data_t *hp_data, spo_hp_data_info_t *info, u_char **tag, u_char *ch)
{
    char temp[32] = {'\0'};
    const char *error;
    int i = 0;
    int  erroffset;

    while (i < 32) {
        if ((*(ch) == ';' || *(ch) == '&' || *(ch) == 0x27 || *(ch) == 0x0d)) break;
        temp[i] = *ch;
        i++;
        ch++;
    }

    if (i >= 31) return SPO_FAILURE;

    strcat(temp, SPO_COK_ARG);

    if ((info->pr = pcre_compile(temp, 0, &error, &erroffset, NULL)) == NULL) {
        printf("PCRE compilation failed at offset %d: %s\n", erroffset, error);
        return SPO_FAILURE;
    }

    info->len = ((size_t) (ch - hp_data->data.data)) - info->offset;

    spo_hp_data_info_insert(hp_data, info);
    (*tag) = ch;
    return SPO_OK;
}


/*
 *
 *  deal with $url_uri_all, $url_uri_arg, $ref_uri_all and $ref_uri_arg,
 *  setting their type and  generating their patterns rspectively
 *
 * */

static SPO_RET_STATUS spo_deal_with_u_tag(spo_hp_data_t *hp_data,
                                          spo_hp_data_info_t *info, int type, u_char *ch, u_char **tag)
{

    char temp[64]       = {'\0'};
    const char *error   = NULL;
    int  erroffset      = 0;
    int i               = 0;

    info->type = type;
    ch += 4;

    while (i < 64) {
        if ((*(ch) == ';' || *(ch) == '&' || *(ch) == 0x27 || *(ch) == 0x0d)) break;
        temp[i] = *ch;
        i++;
        ch++;
    }

    if (i >= 63) return SPO_FAILURE;

    if (memcmp(temp, "all", 3) == 0) {
        if (type == 3) info->type = 0;  /* set the type of $url_uri_all */
        else {  /* generate the pattern of $ref_uri_all */
            memcpy(temp, SPO_REF_URI_ALL, strlen(SPO_REF_URI_ALL));

            if ((info->pr = pcre_compile(temp, 0, &error, &erroffset, NULL)) == NULL) {
                printf("PCRE compilation failed at offset %d: %s\n", erroffset, error);
                return SPO_FAILURE;
            }
        }
    }else{      /* generate the pattern of $url_uri_arg or $ref_uri_arg */
        strcat(temp, SPO_REF_URI_ARG);

        if ((info->pr = pcre_compile(temp, 0, &error, &erroffset, NULL)) == NULL) {
            printf("PCRE compilation failed at offset %d: %s\n", erroffset, error);
            return SPO_FAILURE;
        }
    }

    info->len = ((size_t) (ch - hp_data->data.data)) - info->offset;
    (*tag) += info->len;
    spo_hp_data_info_insert(hp_data, info);

    return SPO_OK;
}


/*
 *
 *  deal with $url_dmn and $ref_dmn, setting their type
 *  and  generating their patterns rspectively
 *
 * */

static SPO_RET_STATUS spo_deal_with_d_tag(spo_hp_data_t *hp_data, spo_hp_data_info_t *info, int type)
{
    char temp[32] = {'\0'};
    const char *error   = NULL;
    int  erroffset      = 0;

    info->len = 8;
    info->type = type;

    if (type != 1) {
        /* $ref_dmn */
        memcpy(temp, SPO_REF_DMN, strlen(SPO_REF_DMN));

        if ((info->pr = pcre_compile(temp, 0, &error, &erroffset, NULL)) == NULL) {
            printf("PCRE compilation failed at offset %d: %s\n", erroffset, error);
            return SPO_FAILURE;
        }
    }

    spo_hp_data_info_insert(hp_data, info);

    return SPO_OK;
}


/**
 *
 *  deal with three kinds of tags starting with $ref
 *
 * */

static SPO_RET_STATUS spo_hp_ref_tag(spo_hp_data_t *hp_data, spo_hp_data_info_t *info, u_char **tag, u_char *ch)
{
    if (*ch == 'a') {
        info->type = 2;
        info->len = 8;
        (*tag) += 8;
        spo_hp_data_info_insert(hp_data, info);
        return SPO_OK;
    }

    if (*ch == 'd') {
        if (spo_deal_with_d_tag(hp_data, info, 4) == SPO_FAILURE) return SPO_FAILURE;
        (*tag) += 8;
        return  SPO_OK;
    }

    if (*ch == 'u') return spo_deal_with_u_tag(hp_data, info, 5, ch, tag);

    return SPO_FAILURE;
}


/**
 *
 *  deal with two kinds of tags starting with $url
 *
 * */

static SPO_RET_STATUS spo_hp_url_tag(spo_hp_data_t *hp_data, spo_hp_data_info_t *info, u_char **tag, u_char *ch)
{
    if (*ch == 'd') {

        if (spo_deal_with_d_tag(hp_data, info, 1) == SPO_FAILURE) return SPO_FAILURE;

        (*tag) += 8;
        return  SPO_OK;
    }

    if (*ch == 'u') return spo_deal_with_u_tag(hp_data, info, 3, ch, tag);

    return SPO_FAILURE;
}


static SPO_RET_STATUS spo_http_data_pat_find(spo_hp_data_t *hp_data, u_char **tag)
{
    spo_hp_data_info_t *info = NULL;
    u_char *ch = (*tag);

    if ((info = spo_create_hp_data_info()) == NULL) return SPO_FAILURE;

    info->offset = ch - hp_data->data.data;

    ch++;

    if (memcmp(ch, "cok_", SPO_INFO_TAG_LEN) == 0) {
        ch += 4;
        info->type = 6;
        return spo_hp_cok_tag(hp_data, info, tag, ch);
    }

    if (memcmp(ch, "ref_", SPO_INFO_TAG_LEN) == 0) {
        ch += 4;
        return spo_hp_ref_tag(hp_data, info, tag, ch);
    }

    if (memcmp(ch, "url_", SPO_INFO_TAG_LEN) == 0) {
        ch += 4;

        return spo_hp_url_tag(hp_data, info, tag, ch);
    }

    return SPO_OK;
}


static SPO_RET_STATUS spo_hp_data_tag_match(spo_hp_data_t *hp_data)
{
    size_t i = 0;
    u_char *ch = hp_data->data.data;

    if (ch == NULL) return SPO_FAILURE;

    while (i < hp_data->data.len) {
        if (*ch == 0x2f && *(ch + 1) == 0x2a && *(ch + 2) == 0x2a && *(ch + 3) == 0x2f)
            return SPO_OK;

        if (*ch == '$') {
            spo_http_data_pat_find(hp_data, &ch);
            i += hp_data->tail->len;
            continue;
        }

        i++;
        ch++;
    }

    return SPO_FAILURE;
}


static spo_tree_node_t *spo_do_load_http_data_cfg(const char *f_name, const char *dmn_name)
{
    spo_tree_node_t *node = NULL;
    spo_hp_data_t *data = NULL;
    size_t ret = 0;
    size_t f_size = 0;

    if ((node = spo_create_tree_node()) == NULL) return NULL;

    if ((data = spo_create_http_data()) == NULL) goto spo_bad_http_load;

    if ((f_size = spo_file_size(f_name)) == 0) goto spo_bad_http_load;

    if (spo_http_data_dmn(&data->dmn, dmn_name) == SPO_FAILURE) goto spo_bad_http_load;

    if ((data->data.data = spo_calloc(f_size)) == NULL) goto spo_bad_http_load;

    if ((ret = spo_read_file_data(f_name, data->data.data)) == 0) goto spo_bad_http_load;
    data->data.len = ret;

    data->num = spo_http_data_num(dmn_name);

    if (spo_cp_http_data(data, &data->data_cp, &data->data, 1 * 8192) == SPO_FAILURE) goto spo_bad_http_load;

    if (spo_hp_data_tag_match(data) == SPO_FAILURE) goto spo_bad_http_load;

    node->key = (void *)data;

    return node;

spo_bad_http_load:

    if (data != NULL) spo_destory_http_data(data);
    if (node != NULL) spo_destory_tree_node(node, spo_destory_dns_data);
    return NULL;
}


static spo_tree_header_t *
spo_load_data_cfg(const char *p_name,
                  spo_tree_node_t * (*load_data) (const char *, const char *),
                  int (*comp_func) (void *, void *), int (*spo_free_key_func) (void *))
{
    spo_tree_header_t *header = NULL;
    struct dirent *dp = NULL;
    DIR *dirp = NULL;
    char *absol_name = NULL;

    if ((dirp = opendir(p_name)) == NULL) return NULL;

    if ((header = spo_create_tree_header()) == NULL) goto spo_bad_load_data;
    header->c = comp_func;
    header->free_key = spo_free_key_func;

    if ((absol_name = spo_calloc(SPO_MAX_FILE_NAME_LEN)) == NULL) goto spo_bad_load_data;

    while ((dp = readdir(dirp)) != NULL) {
        /*"." or ".." not we want.*/
        if (strncmp(dp->d_name, ".", 1) == 0 || dp->d_name[strlen(dp->d_name) - 1] == '~') {
            continue;
        }

        if (spo_merg_absol_path_name(p_name, dp->d_name, absol_name) == SPO_OK) {
            spo_tree_node_t *node = load_data(absol_name, dp->d_name);
            if (node == NULL) goto spo_bad_load_data;

            spo_bool_t taller = 0;
            spo_insert_AVL(&(header->root), node, &taller, header->c);
        }
    }

    spo_free(absol_name);
    closedir(dirp);

    return header;

spo_bad_load_data:

    if (dirp != NULL) closedir(dirp);
    if (header != NULL) spo_destory_tree(header, header->free_key);
    if (absol_name != NULL) spo_free(absol_name);
    return NULL;
}


spo_tree_header_t *spo_load_dns_data_cfg(const char *p_name)
{
    return spo_load_data_cfg(p_name, spo_do_load_dns_data_cfg,
                             spo_comp_dns_data_dmn_node, spo_destory_dns_data);
}


spo_tree_header_t *spo_load_http_data_cfg(const char *p_name)
{
    return spo_load_data_cfg(p_name, spo_do_load_http_data_cfg,
                             spo_comp_http_data_dmn_node, spo_destory_http_data);
}


static SPO_RET_STATUS spo_check_g_cfg(spo_cfg_g_t *g)
{
    if (g == NULL) return SPO_FAILURE;

    if (g->max_http_pkt_s < 1024) g->max_http_pkt_s = 8 * 1024;
    if (g->max_dns_pkt_s < 256) g->max_dns_pkt_s = 2 * 1024;
    if (g->max_send_size < 8 * 1024) g->max_send_size = 32 * 8192;
    if (g->max_log_len < 32) g->max_log_len = 512;

    if (g->d_data_path == NULL) {
        if ((g->d_data_path = spo_calloc(strlen("dns_domain_data") + 1)) == NULL)
            return SPO_FAILURE;

        memcpy(g->d_data_path, "dns_domain_data", strlen("dns_domain_data"));
    }

    if (g->h_dmn_cfg_file == NULL) {
        if ((g->h_dmn_cfg_file = spo_calloc(strlen("http_dmn_config") + 1)) == NULL)
            return SPO_FAILURE;

        memcpy(g->h_dmn_cfg_file, "http_dmn_config", strlen("http_dmn_config"));
    }

    if (g->h_data_path == NULL) {
        if ((g->h_data_path = spo_calloc(strlen("http_domain_data") + 1)) == NULL)
            return SPO_FAILURE;

        memcpy(g->h_data_path, "http_domain_data", strlen("http_domain_data"));
    }

    if (g->log_file == NULL) {
        if ((g->log_file = spo_calloc(strlen("spoofer_log.log") + 1)) == NULL)
            return SPO_FAILURE;

        memcpy(g->log_file, "spoofer_log.log", strlen("spoofer_log.log"));
    }

    if (g->statis_file == NULL) {
        if ((g->statis_file = spo_calloc(strlen("spoofer_statis.log") + 1)) == NULL)
            return SPO_FAILURE;

        memcpy(g->statis_file, "spoofer_statis.log", strlen("spoofer_statis.log"));
    }

    return SPO_OK;
}


static SPO_RET_STATUS spo_check_hp_mtd(spo_cfg_t *cfg)
{
    if (cfg == NULL || cfg->global == NULL) return SPO_FAILURE;

    if (cfg->global->hp_mtd == NULL) {
        spo_tree_header_t *header = NULL;
        spo_str_t *mtd = NULL;

        if ((header = spo_create_tree_header()) == NULL) return SPO_FAILURE;
        header->c = spo_comp_hp_mtd;

        if ((header->root = spo_create_tree_node()) == NULL) return SPO_FAILURE;

        if ((mtd = spo_calloc(sizeof(spo_str_t))) == NULL) return SPO_FAILURE;
        if ((mtd->data = spo_calloc(strlen("GET") + 1)) == NULL) return SPO_FAILURE;

        mtd->len =strlen("GET");
        memcpy(mtd->data, "GET", mtd->len);

        header->root->key = mtd;
        cfg->global->hp_mtd = header;

        return SPO_OK;
    }

    return SPO_OK;
}


static SPO_RET_STATUS spo_check_proc_blk_cfg(spo_info_header_t *header)
{
    spo_info_t *info = NULL;

    if (header == NULL) return SPO_FAILURE;
    if ((info = header->infos) == NULL) return SPO_FAILURE;

    while (info != NULL) {
        if (memcmp(info->type, "sniffer", strlen("sniffer")) == 0) {
            if (info->dev == NULL) {
                const char *log = (const char *) "must cfg sniffer's dev\n";
                spo_snd_log_msg(sys_log, log, SPO_MAIN, SPO_LOG_LEVEL_MSG, getpid());
                return SPO_FAILURE;
            }

            if (memcmp(info->lib, "pf", 2) == 0) {
                if (info->driection == 0) {
                    const char *log = (const char *) "lib is pf, but not dircation\n";
                    spo_snd_log_msg(sys_log, log, SPO_MAIN, SPO_LOG_LEVEL_MSG, getpid());
                    return SPO_FAILURE;
                }
            }

            if (info->h_msgid == NULL && info->d_msgid == NULL) {
                const char *log = (const char *) "dns and http msg can't be void At the same time\n";
                spo_snd_log_msg(sys_log, log, SPO_MAIN, SPO_LOG_LEVEL_MSG, getpid());
                return SPO_FAILURE;
            }

        }

        if (memcmp(info->type, "sender", strlen("sender")) == 0) {
            if (info->dev == NULL) {
                const char *log = (const char *) "please cfg sender's dev\n";
                spo_snd_log_msg(sys_log, log, SPO_MAIN, SPO_LOG_LEVEL_MSG, getpid());
                return SPO_FAILURE;
            }
        }

        info = info->next;
    }

    return SPO_OK;
}


/**
 *
 *  check the prog cfg.
 *
 *  if users not set the Necessary value, we set it defaultly.
 *
 * */

static SPO_RET_STATUS spo_check_prog_cfg(spo_cfg_t *cfg)
{
    if (cfg == NULL) return SPO_FAILURE;

    if (spo_check_g_cfg(cfg->global) == SPO_FAILURE) return SPO_FAILURE;

    if (spo_check_hp_mtd(cfg) == SPO_FAILURE) return SPO_FAILURE;

    if (spo_check_proc_blk_cfg(&cfg->inf_header) == SPO_FAILURE) return SPO_FAILURE;

    return SPO_OK;
}



/* - - - - -- - - - -- - -reload dns or http data - -- - - - -- - - - - - - -- */


SPO_RET_STATUS spo_reload_http_config(spo_cfg_t *cfg, spo_proc_node_t *node)
{
    spo_dmn_t *dmn = (spo_dmn_t *) spo_load_http_dmn_cfg(cfg->global->h_dmn_cfg_file);
    if (dmn == NULL) {
        spo_destory_dmn(dmn);
        return SPO_FAILURE;
    }

    spo_destory_dmn(node->http_dmn_header);

    node->http_dmn_header = dmn;

    hp_dmn = dmn;
#if SPO_DEBUG
    InOrderTraverse(node->http_dmn_header->dmn->root, spo_visist_http_dmn_cfg);
#endif

    return SPO_OK;
}


SPO_RET_STATUS spo_reload_http_data(spo_cfg_t *cfg, spo_proc_node_t *node)
{
    spo_tree_header_t *header = spo_load_http_data_cfg(cfg->global->h_data_path);
    if (header == NULL) {
        spo_destory_tree(header, spo_destory_http_data);
        return SPO_FAILURE;
    }

    spo_destory_tree(node->dmn_data_header->http_data, spo_destory_http_data);

    node->dmn_data_header->http_data = header;
    hp_data = header;
#if SPO_DEBUG
    InOrderTraverse(node->dmn_data_header->http_data->root, spo_visist_http_data);
#endif

    return SPO_OK;
}


SPO_RET_STATUS spo_reload_dns_data(spo_cfg_t *cfg, spo_proc_node_t *node)
{
    spo_tree_header_t *header = spo_load_dns_data_cfg(cfg->global->d_data_path);
    if (header == NULL) {
        spo_destory_tree(header, spo_destory_dns_data);
        return SPO_FAILURE;
    }

    spo_destory_tree(node->dmn_data_header->dns_data, spo_destory_dns_data);

    node->dmn_data_header->dns_data = header;
    dns_data = header;
#if SPO_DEBUG
    InOrderTraverse(node->dmn_data_header->dns_data->root, spo_visist_dns_data);
#endif

    return SPO_OK;
}
