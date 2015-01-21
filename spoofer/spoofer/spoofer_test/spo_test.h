#ifndef SPO_TEST_H
#define SPO_TEST_H

#define SPO_TIME_START  0
#define SPO_TIME_END    1


void spo_test_cfg_g(spo_cfg_t *cfg);

/**
 *  insert the tree node to the avl tree, but now we use the queue to replace it.
 *
 * */

SPO_RET_STATUS spo_test_insert_tree_queue(spo_tree_header_t *header, spo_tree_node_t *node);

/**
 *
 *  spo_dmn_match(spo_tree_header_t *header, spo_str_t *host);
 *
 * */

/* comp func */
SPO_RET_BOOLEN spo_test_comp_dns_data_dmn(spo_tree_node_t *node, spo_str_t *host);
SPO_RET_BOOLEN spo_test_comp_http_data_dmn(spo_tree_node_t *node, spo_str_t *host);
SPO_RET_BOOLEN spo_test_comp_http_dmn(spo_tree_node_t *node, spo_str_t *host);

/*  */
spo_tree_node_t *spo_search_node_by_host(spo_tree_header_t *header, spo_str_t *host,
                                         int (*comp_func) (spo_tree_node_t *, spo_str_t *));

///* printf all info in spo_http_dmn_t */
//void spo_test_http_dmn_cfg(spo_http_dmn_t *dmn);

/* printf all info in spo_dmn_t (the tree's node's key is spo_http_dmn_t) */
void spo_test_dmn_cfg(spo_dmn_t *dmn);

/* printf all info in dns data file . the param data_ is the tree node's key*/
SPO_RET_STATUS spo_test_dns_data(void *data_);

/*  printf all info in http data file . the param data_ is the tree node's key*/
SPO_RET_STATUS spo_test_http_data(void *data_);

/* test search module */
void spo_test_http_data_search();
void spo_test_http_dmn_search();
void spo_test_dns_data_search();
void spo_test_prog_cfg();


/**
 *
 * debug printf, type == 0, printf hex, other printf char
 *
 * */

void spo_str_printf(spo_str_t *str, int type);

SPO_RET_STATUS test_sniffer(spo_cfg_t *cfg);

/* just smiply init system */
void spo_test_sys();

void spo_test_snd_proc(void *v);
void spo_test_dns_spof_proc(void *v);
void spo_test_hp_spof_proc(void *v);
void spo_test_snif_proc(void *v);
void spo_test_log_proc(void *v);




#endif // SPO_TEST_H
