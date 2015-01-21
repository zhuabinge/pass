#ifndef SPO_KERNEL_H
#define SPO_KERNEL_H

#include <sys/types.h>


/* tree's type */
#define SPO_HTTP_DMN_TREE   (1)
#define SPO_HTTP_DATA_TREE  (2)
#define SPO_DNS_TREE        (4)


/* get container's data */
#define spo_container_data(q, type, link) (type *) \
    ((u_char *) q - offsetof(type, link))


/* comp func */
typedef int (spo_comp_tree_func) (void *, void *);

/* destory tree node key func */
typedef int (spo_free_key_func) (void *);

/* tree's status */
typedef enum spo_bool_e {
    FALSE   = 0,
    TRUE    = 1
}spo_bool_t;


/* string */
typedef struct spo_string_s {
    size_t len;
    u_char *data;
}spo_str_t;

/* a container for spoofer system */
typedef struct spo_container_s {
    struct spo_container_s *prev;
    struct spo_container_s *next;
}spo_cnt_t;


/* record a rbt node */
struct spo_tree_node_s {
    spo_cnt_t link;
    void *key;			//数据
    struct spo_tree_node_s *parent;   /* Reserve */
    int bf;                         /* Balance factor */
};


/* is the rbt header */
struct spo_tree_header_s {
    spo_tree_node_t *root;          /* this tree root */
    spo_tree_node_t *current;       /* the current node, use it to targe */
    spo_comp_tree_func *c;          /* record the comp func, when used to insert a node */
    spo_free_key_func *free_key;    /* uesd to free the tree node's key */
    int rbt_type;                   /* tree type */
    int amonut;                     /* this tree size, node amount */
};

/* init the string */
inline SPO_RET_STATUS spo_init_str(spo_str_t *str);


/*  get the tree node by container. */
inline spo_tree_node_t *spo_cnt_tree_node(spo_cnt_t *cnt);


/* comp strings */
inline SPO_RET_VALUE spo_comp_str(spo_str_t *str, spo_str_t *comp);
inline SPO_RET_STATUS spo_comp_string(spo_str_t *str, const char *string);

/* create and init tree struct */
spo_tree_node_t *spo_create_tree_node();
spo_tree_header_t *spo_create_tree_header();

/* destory tree struct */
SPO_RET_STATUS spo_destory_tree_node(spo_tree_node_t *node, int (*free_node_data) (void *));
void spo_do_destory_tree(spo_cnt_t *node_link, int (*free_node_key_func) (void *));
SPO_RET_STATUS spo_destory_tree(spo_tree_header_t *header, int (*free_node_key) (void *));


/* deep */
SPO_RET_VALUE spo_find_tree_deep(spo_cnt_t *BT);

/* visist */
void spo_visist_http_data(void *data_);
void spo_visist_dns_data(void *data_);
void spo_visist_http_dmn_cfg(void *data_);

void InOrderTraverse(spo_tree_node_t *root, void (*visist_func) (void *));
void PreOrderTraverse(spo_tree_node_t *root, void (*visist_func) (void *));


/* node's key comp func, for match domain */
inline SPO_RET_VALUE spo_comp_http_dmn(void *http_dmn_, void *host);
inline SPO_RET_VALUE spo_comp_http_data_dmn(void *h_data_, void *num_);
inline SPO_RET_VALUE spo_comp_dns_data_dmn(void *d_data_, void *host);
inline SPO_RET_VALUE spo_comp_hp_mtd(void *mtd_, void *mtd_new_);

/* tree node comp func, for insert node */
inline SPO_RET_VALUE spo_comp_http_dmn_node(void *t_node, void *i_node);
inline SPO_RET_VALUE spo_comp_http_data_dmn_node(void *t_node, void *i_node);
inline SPO_RET_VALUE spo_comp_dns_data_dmn_node(void *t_node, void *i_node);

/* build tree */
spo_bool_t spo_insert_AVL(spo_tree_node_t **t,
                          spo_tree_node_t *node, spo_bool_t *taller, int (*comp_func) (void *, void *));

/* serch a tree node in avl tree */
spo_tree_node_t *spo_tree_match(spo_tree_header_t *header, void *data,
                                  int (*comp_func) (void *, void *));

#endif // SPO_KERNEL_H
