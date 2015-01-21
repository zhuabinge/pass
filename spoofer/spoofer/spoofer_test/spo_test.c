#include "../spoofer_system/spoofer.h"
#include "../spoofer_config/spo_config.h"
#include "../spoofer_pool/spo_pool.h"
#include "../spoofer_linux/spo_linux.h"
#include "../spoofer_test/spo_test.h"
#include "../spoofer_sniffer/spo_sniffer.h"
#include "../spoofer_sender/spo_sender.h"
#include "../spoofer_system/spo_system.h"



void spo_str_printf(spo_str_t *str, int type)
{
    size_t i = 0;

    if (str == NULL || str->data == NULL) return;

    if (type == 0) {
        for (i = 0; i < str->len; i++) {
            printf("%02x ", *(str->data + i));
        }
    }else {
        for (i = 0; i < str->len; i++) {
            printf("%c", *(str->data + i));
        }
    }

    printf("\n");
}


void spo_test_cfg_g(spo_cfg_t *cfg)
{
    printf("max dns pkt %ld\n", cfg->global->max_dns_pkt_s);
    printf("max http pkt %ld\n", cfg->global->max_http_pkt_s);
    printf("max send size %ld\n", cfg->global->max_send_size);
    printf("max log len %ld\n", cfg->global->max_log_len);
    printf("dns data path --%s--\n", cfg->global->d_data_path);
    printf("http dmn cfg file --%s--\n", cfg->global->h_dmn_cfg_file);
    printf("http data path --%s--\n", cfg->global->h_data_path);

    spo_info_t *info = NULL;
    info = cfg->inf_header.infos;
    while (info != NULL) {
        printf("dev --%s--\n", info->dev);
        printf("filter --%s--\n", info->filter);
        printf("useing lib --%s--\n", info->lib);
        printf("proc type --%s--\n", info->type);
        printf("cpu id %d\n", info->cpuid);
        int i = 0;

        if (info->h_msgid != NULL) {
            printf("hp msgid amount %d\n", info->h_msgid[0]);

            for (i = 1; i <= info->h_msgid[0]; i++) {
                printf("msgid    %d\n", info->h_msgid[i]);
            }
        }

        if (info->d_msgid != NULL) {
            printf("\ndns msgid amount %d\n", info->d_msgid[0]);
            for (i = 1; i <= info->d_msgid[0]; i++) {
                printf("msgid    %d\n", info->d_msgid[i]);
            }
        }

        printf("\n\n next ----\n");
        info = info->next;
    }
}


SPO_RET_STATUS spo_test_insert_tree_queue(spo_tree_header_t *header, spo_tree_node_t *node)
{
    if (header->root == NULL) header->root = node;
    else {
        node->link.next = &header->root->link;
        header->root = node;
    }

    return SPO_OK;
}


static SPO_RET_BOOLEN spo_test_comp_dmn(spo_str_t *dmn, spo_str_t *host)
{
    if (dmn == NULL || dmn->data == NULL || host == NULL || host->data == NULL)
        return SPO_FALSE;

    if (dmn->len == host->len)
        if (memcmp(dmn->data, host->data, dmn->len) == 0)  return SPO_TRUE;

    return SPO_FALSE;
}



SPO_RET_BOOLEN spo_test_comp_http_dmn(spo_tree_node_t *node, spo_str_t *host)
{
    spo_hp_dmn_t *http_dmn = (spo_hp_dmn_t *) node->key;
    return spo_test_comp_dmn((spo_str_t *)&http_dmn->dmn, host);
}

SPO_RET_BOOLEN spo_test_comp_http_data_dmn(spo_tree_node_t *node, spo_str_t *host)
{
    spo_hp_data_t *data = (spo_hp_data_t *) node->key;
    return spo_test_comp_dmn((spo_str_t *) &data->dmn, host);
}


SPO_RET_BOOLEN spo_test_comp_dns_data_dmn(spo_tree_node_t *node, spo_str_t *host)
{
    spo_dns_data_t *data = (spo_dns_data_t *) node->key;
    return spo_test_comp_dmn((spo_str_t *) &data->dmn, host);
}


spo_tree_node_t *spo_search_node_by_host(spo_tree_header_t *header, spo_str_t *host,
                                         int (*comp_func) (spo_tree_node_t *, spo_str_t *))
{
    spo_tree_node_t *node = NULL;
    spo_cnt_t *p = &header->root->link;

    while (p != NULL) {
        node = spo_container_data(p, spo_tree_node_t, link);
        if (comp_func(node, host) ==  SPO_TRUE) return node;

        p = p->next;
    }

    return NULL;
}


static SPO_RET_STATUS spo_test_http_cfg_line(spo_hp_line_t *cfg_line)
{
//    printf("url --%s--\n", cfg_line->url.data);
//    printf("cookies --%s--\n", cfg_line->cookie.data);
//    printf("rederer --%s--\n", cfg_line->referer.data);

    return SPO_OK;
}


void spo_test_http_dmn_cfg(spo_hp_dmn_t *dmn)
{
    printf("domain name --%s--\n", dmn->dmn.data);
    printf("domain name len %d\n", (int)dmn->dmn.len);

    spo_hp_line_t *line = dmn->cfg_line;

    while (line != NULL) {
        spo_test_http_cfg_line(line);
        line = line->next;
    }

    printf("\n\n");
}


void spo_test_dmn_cfg(spo_dmn_t *dmn)
{
    spo_cnt_t *p = NULL;
    spo_tree_node_t *node = NULL;

    p = &dmn->dmn->root->link;

    while (p != NULL) {
        node = spo_container_data(p, spo_tree_node_t, link);
        spo_hp_dmn_t *h_dmn = (spo_hp_dmn_t *) node->key;
        spo_test_http_dmn_cfg(h_dmn);
        p = p->next;
    }
}


SPO_RET_STATUS spo_test_dns_data(void *data_)
{
    if (data_ == NULL) {
        printf("dns data is null\n");
        return SPO_FAILURE;
    }

    spo_dns_data_t *data = (spo_dns_data_t *) data_;
    printf("dmn len -- %d\n", (int)data->dmn.len);
    printf("dmn name --%s--\n", data->dmn.data);
        size_t i = 0;
    for (i = 0; i < data->dmn.len; i++) {
        printf("%02x ", *(data->dmn.data + i));
    }
    printf("\n");

    printf("data len %d\n", (int)data->data.len);
    printf("data dataq --%s--\n", data->data.data);

    return SPO_OK;
}


SPO_RET_STATUS spo_test_http_data(void *data_)
{
    if (data_ == NULL) {
        printf("http data is null\n");
        return SPO_FAILURE;
    }

    spo_hp_data_t *data = (spo_hp_data_t *) data_;

    printf("dmn len -- %d\n", (int)data->dmn.len);
    printf("dmn name --%s--\n", data->dmn.data);

    printf("data len %d\n", (int)data->data.len);
    printf("data dataq --%s--\n", data->data.data);

    printf("num -- %d\n", data->num);

    return SPO_OK;
}


/* ---------  test for search module ---------- */

void spo_test_http_data_search()
{
/* test http domain data */
    spo_tree_header_t *header = spo_load_http_data_cfg("http_domain_data");
    PreOrderTraverse(header->root, spo_visist_http_data);
    printf("deep %d\n", spo_find_tree_deep(&header->root->link));
    int num = 0;
    while (1) {
        printf("input a num to find the data\n");
        scanf("%d", &num);
        printf("input num is %d\n", num);
        if (num == -1) break;
        spo_tree_node_t *node = spo_tree_match(header, &num, spo_comp_http_data_dmn);
        if (node == NULL) printf("no match\n");
        else {
            printf("------- the node data is ------\n");
            spo_visist_http_data(node->key);
            printf("------\n\n");
        }
    }
}


void spo_test_http_dmn_search()
{
    /* test http cfg dmn */
    spo_dmn_t *dmn_cfg = (spo_dmn_t *)spo_load_http_dmn_cfg("http_dmn_config");
    spo_tree_header_t *header = dmn_cfg->dmn;
    spo_str_t str;
    char domain[64] = {'\0'};

    printf("\n\n");
    PreOrderTraverse(header->root, spo_visist_http_dmn_cfg);
    printf("------\n\n");
    InOrderTraverse(header->root, spo_visist_http_dmn_cfg);
    printf("deep %d\n", spo_find_tree_deep(&header->root->link));

    while (1) {
        printf("input a http domain to find the data\n");
        scanf("%s", domain);
        printf("the input domain is --%s--\n", domain);
        if (memcmp(domain, "exit", 4) == 0) break;

        str.data = (u_char *)domain;
        str.len = strlen(domain);

        spo_tree_node_t *node = spo_tree_match(header, &str, spo_comp_http_dmn);
        if (node == NULL) printf("no match\n");
        else {
            printf("------- the node data is ------\n");
            spo_visist_http_dmn_cfg(node->key);
            printf("------\n\n");
        }

        memset(domain, '\0', 64);
    }
}


void spo_test_dns_data_search()
{
    spo_str_t str;
    char domain[64] = {'\0'};

    /* tets dns data cfg */
    spo_tree_header_t *header = spo_load_dns_data_cfg("dns_domain_data");
    PreOrderTraverse(header->root, spo_visist_dns_data);
    printf("deep %d\n", spo_find_tree_deep(&header->root->link));

    spo_destory_tree(header, spo_destory_dns_data);
    printf("destory success\n");

    return;

    while (1) {
        printf("input a dns domain to find the data\n");
        scanf("%s", domain);
        printf("the input domain is --%s--\n", domain);

        if (memcmp(domain, "exit", 4) == 0) break;

        str.data = (u_char *)domain;
        str.len = strlen(domain);

        spo_tree_node_t *node = spo_tree_match(header, &str, spo_comp_dns_data_dmn);
        if (node == NULL) printf("no match\n");
        else {
            printf("------- the node data is ------\n");
            spo_visist_dns_data(node->key);
            printf("------\n\n");
        }

        memset(domain, '\0', 64);
    }
}


void spo_printf_mtd(void *mtd_)
{
    spo_str_t *mtd = (spo_str_t *) mtd_;

    printf("--%s-- %d\n", mtd->data, (int) mtd->len);
}


void spo_test_prog_cfg()
{
    /* test program cfg */
    spo_cfg_t *cfg = (spo_cfg_t *)spo_load_prog_cfg("config");
    spo_test_cfg_g(cfg);

    InOrderTraverse(cfg->global->hp_mtd->root, spo_printf_mtd);
}


void spo_test_sys()
{

//    char *set_cok = "Cookies: BDSVRTM=130; path=/BD_HOME=1;"
//    " path=/H_PS_PSSID=6255_10162_1432_10624_10572_10490_10213_10501_10496_10510_"
//    "10647_10052_10459_10065_10218_10687_9392_10356_10666_10096_10658_10442_10403_9950_10688_10627;"
//    " path=/; domain=.baidu.com\r\n"
//    "Host: www.baidu.com\r\n\r\n";

//    int i = 0;

//    for (i = 0; i < strlen(set_cok); i++) {
//        printf("%2x ", *(set_cok + i));
//    }
//    printf("\n");


    int fd;
    int ret = 0;
    int i = 0;

//    fd = spo_open("/home/lele/fork", O_CREAT | O_RDWR, 0666);

//    if (fd == SPO_FAILURE) {
//        perror("2\n");
//    }

//    int ret = spo_write(fd, set_cok, strlen(set_cok));
//    if (ret == SPO_FAILURE) {
//        printf("fail\n");
//        perror(":");
//    }

//    spo_close(fd);
    fd = spo_open("/home/lele/9@yhd.com_301", O_CREAT | O_RDWR, 0666);

    char buf[600];
    memset(buf, '\0', 600);

    ret = spo_read(fd, buf, 600);
    printf("ret %d\n", ret);

    for (i = 0; i < ret; i++) {
        printf("%02x ", buf[i]);
    }
    printf("---\n\n");


    /* test load all config */
    //spo_test_http_data_search();

    //spo_test_http_dmn_search();

    //spo_test_dns_data_search();

    //spo_test_prog_cfg();
}




void spo_test_snif_proc(void *v)
{
    v = v;

    printf("i am sniffer , my pid is %d\n", getpid());

    while (1) {
        sleep(1);
    }

    return;
}



void spo_test_hp_spof_proc(void *v)
{
    v = v;

    printf("i am http spoofer , my pid is %d\n", getpid());

    while (1) {
        sleep(1);
    }

    return;
}


void spo_test_dns_spof_proc(void *v)
{
    v = v;

    //printf("i am dns spoofer , my pid is %d\n", getpid());

    while (1) {
        sleep(1);
    }

    return;
}


void spo_test_snd_proc(void *v)
{
    v = v;

    //printf("i am  sender , my pid is %d\n", getpid());

    while (1) {
        sleep(1);
    }

    return;
}

//void spo_test_log_proc(void *v)
//{
//    if (v == NULL) printf("log v is NULL\n");

//    //printf("i am  loger , my pid is %d\n", getpid());

//    while (1) {
//        sleep(1);
//    }

//    return;
//}








