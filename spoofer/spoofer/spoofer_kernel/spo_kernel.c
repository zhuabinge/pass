#include "../spoofer_system/spoofer.h"
#include "../spoofer_pool/spo_pool.h"
#include "spo_kernel.h"
#include "../spoofer_config/spo_config.h"


static SPO_RET_BOOLEN spo_insert_AVL_right(spo_tree_node_t **t, spo_tree_node_t *node,
                                           spo_bool_t *taller, int (*comp_func) (void *, void *));
static SPO_RET_BOOLEN spo_do_insert_AVL_left(spo_tree_node_t **t, spo_tree_node_t *node,
                                             spo_bool_t *taller, int (*comp_func) (void *, void *));

static void spo_right_balance(spo_tree_node_t **T);
static void spo_left_balance(spo_tree_node_t **T);

static void spo_l_rotate(spo_tree_node_t **p);
static void spo_r_rotate(spo_tree_node_t **p);

static inline SPO_RET_VALUE spo_tree_node_comp(spo_tree_node_t *t_node,
                                        spo_tree_node_t *i_node, int (*comp_func) (void *, void *));


typedef enum spo_bh_e
{
    EH  = 0,
    LH  = 1,
    RH  = -1
}spo_bh_t;


inline SPO_RET_STATUS spo_init_str(spo_str_t *str)
{
    if (str == NULL) return SPO_FAILURE;

    str->data   = NULL;
    str->len    = 0;

    return SPO_OK;
}


spo_tree_node_t *spo_create_tree_node()
{
    spo_tree_node_t *node = NULL;

    node = spo_calloc(sizeof(spo_tree_node_t));
    if (node == NULL) return NULL;

    node->key = NULL;

    node->link.next = NULL;
    node->link.prev = NULL;

    node->parent  = NULL;
    node->bf = EH;

    return node;
}


/**
 *
 *  destory a tree node.
 *
 * */

SPO_RET_STATUS spo_destory_tree_node(spo_tree_node_t *node, int (*free_node_data) (void *))
{
    if (node == NULL) return SPO_OK;

    free_node_data(node->key);

    spo_free(node);

    return SPO_OK;
}


spo_tree_header_t *spo_create_tree_header()
{
    spo_tree_header_t *header = NULL;

    header = spo_calloc(sizeof(spo_tree_header_t));
    if (header == NULL) return NULL;

    header->root        = NULL;
    header->current     = NULL;
    header->amonut      = 0;
    header->c           = NULL;
    header->free_key    = NULL;
    header->rbt_type    = -1;

    return header;
}


/**
 *
 *  get the tree node by container.
 *
 * */

inline spo_tree_node_t *spo_cnt_tree_node(spo_cnt_t *cnt)
{
    spo_tree_node_t *node = NULL;

    if (cnt == NULL) return NULL;

    node = (spo_tree_node_t *) spo_container_data(cnt, spo_tree_node_t, link);

    return node;
}


/* -- - - - -- - - - -- - dmn string comp- - - - -- - - -- - - -- - - -- */


/**
 *
 *  string.len > host.len; return 1;
 *  else if string.len < host.len; rerurn -1;
 *
 *  if len eq, return
 *
 *  so, string is new in come.
 *
 * */

inline SPO_RET_VALUE spo_comp_str(spo_str_t *str, spo_str_t *comp)
{
    if (comp->len > str->len) return 1;
    else {
        if (comp->len < str->len) return -1;
        else {
            return memcmp(comp->data, str->data, comp->len);
        }
    }

    return SPO_FAILURE;
}





inline SPO_RET_STATUS spo_comp_string(spo_str_t *str, const char *string)
{
    size_t len = strlen(string);

    if (len > str->len) return 1;
    else if (len < len) return -1;
        else return memcmp(string, str->data, len);

}


/**
 *
 *  when the tree's node's key is http_dmn_cfg, we comp the dmn string here.
 *
 *  used for domain match.
 *
 * */

inline SPO_RET_VALUE spo_comp_http_dmn(void *http_dmn_, void *host)
{
    spo_hp_dmn_t *http_dmn = (spo_hp_dmn_t *) http_dmn_;
    return spo_comp_str((spo_str_t *)&http_dmn->dmn, (spo_str_t *) host);
}


/**
 *
 *  when the tree's node's key is http_data_dmn_t, we comp the dmn string here.
 *
 *  used for domain match.
 *
 * */

inline SPO_RET_VALUE spo_comp_http_data_dmn(void *h_data_, void *num_)
{
    spo_hp_data_t *h_data = (spo_hp_data_t *) h_data_;
    int *num = (int *) num_;

    /* find the way to improve *********************************************************************/
    if (*num > h_data->num) return 1;
    else {
        if (*num < h_data->num) return -1;
        else return 0;
    }
}

/**
 *
 *  when the tree's node's key is dns_data_dmn_t, we comp the dmn string here.
 *
 *  used for domain match.
 *
 * */

inline SPO_RET_VALUE spo_comp_dns_data_dmn(void *d_data_, void *host)
{
    spo_dns_data_t *data = (spo_dns_data_t *) d_data_;
    return spo_comp_str((spo_str_t *) (&data->dmn), (spo_str_t *)host);
}


inline SPO_RET_VALUE spo_comp_hp_mtd(void *mtd_, void *mtd_new_)
{
    spo_str_t *mtd = (spo_str_t *) mtd_;
    spo_str_t *mtd_new = (spo_str_t *) mtd_new_;

    return spo_comp_str(mtd, mtd_new);
}


/* --- -- - - - -- - - - - -- - -  node comp -- - - - -- - - - -- - - -  - - - - -- - -  */

/**
 *
 *  when the tree's node's key is http_dmn_cfg, we comp the key here.
 *
 *  used for insert.
 *
 * */

inline SPO_RET_VALUE spo_comp_http_dmn_node(void *t_node, void *i_node)
{
    spo_hp_dmn_t *t_dmn = (spo_hp_dmn_t *) t_node;
    spo_hp_dmn_t *i_dmn = (spo_hp_dmn_t *) i_node;

    return spo_comp_str((spo_str_t *) (&t_dmn->dmn), (spo_str_t *) (&i_dmn->dmn));
}

/**
 *
 *  when the tree's node's key is http_data_dmn_t, we comp the key here.
 *
 *  used for insert.
 *
 * */

inline SPO_RET_VALUE spo_comp_http_data_dmn_node(void *t_node, void *i_node)
{
    spo_hp_data_t *t_data = (spo_hp_data_t *) t_node;
    spo_hp_data_t *i_data = (spo_hp_data_t *) i_node;

    /* find the way to improve *********************************************************************/
    if (i_data->num > t_data->num)return 1;
    else {
        if (i_data->num < t_data->num) return -1;
        else return 0;
    }
}


/**
 *
 *  when the tree's node's key is dns_dmn_data_t, we comp the key here.
 *
 *  used for insert.
 *
 * */

inline SPO_RET_VALUE spo_comp_dns_data_dmn_node(void *t_node, void *i_node)
{
    spo_dns_data_t *t_data = (spo_dns_data_t *) t_node;
    spo_dns_data_t *i_data = (spo_dns_data_t *) i_node;

    return spo_comp_str((spo_str_t *) (&t_data->dmn), (spo_str_t *) (&i_data->dmn));
}


/**
 *
 *  comp a node's key.
 *
 *  i_node.key > t_node, return 1.
 *
 *  i_node.key < t_node, return -1.
 *
 *  i_node.key = t_node, return 0.
 *
 * */

static inline SPO_RET_VALUE spo_tree_node_comp(spo_tree_node_t *t_node,
                                        spo_tree_node_t *i_node, int (*comp_func) (void *, void *))
{
    return comp_func(t_node->key, i_node->key);
}


/* -- - - -- - - - -- - - - --  avl tree start here  - - -- -  - - - - - -- - - - */

void spo_visist_http_data(void *data_)
{
    if (data_ == NULL) return;

    spo_hp_data_t *data = (spo_hp_data_t *) data_;

    printf("\n\n");
    printf("http data's dmn is %s\n", data->dmn.data);
    printf("http data's num is %d\n", data->num);
    printf("http data's data is %s\n", data->data.data);
    printf("\n\n");
}

void spo_visist_dns_data(void *data_)
{
    if (data_ == NULL) return;

    spo_dns_data_t *data = (spo_dns_data_t *) data_;

    printf("\n\n");
    printf("dns data's dmn is %s\n", data->dmn.data);
    printf("dns data's data is %s\n", data->data.data);
    printf("\n\n");
}

void spo_visist_http_dmn_cfg(void *data_)
{
    if (data_ == NULL) return;

    spo_hp_dmn_t *data = (spo_hp_dmn_t *) data_;

    printf("\n");
    printf("http_dmn_cfg data's dmn is %s\n", data->dmn.data);

    spo_hp_line_t *line = data->cfg_line;

    while (line != NULL) {
//        printf("url --%s--\n", line->url.data);

//        if (line->url.data == NULL) printf("*********null\n");

//        printf("referer --%s--\n", line->referer.data);
//        printf("cok --%s--\n\n\n", line->cookie.data);

        line = line->next;
    }

    printf("\n");
}


void spo_visist_tree_node(spo_tree_node_t *node, void (*visist_func) (void *))
{
    if (node == NULL) return;
    visist_func(node->key);
}

void InOrderTraverse(spo_tree_node_t *root, void (*visist_func) (void *))
{
    if(NULL != root)
    {
        spo_cnt_t *link_lc = root->link.prev;
        spo_tree_node_t *node_lc = spo_cnt_tree_node(link_lc);
        InOrderTraverse(node_lc, visist_func);
        spo_visist_tree_node(root, visist_func);
        spo_cnt_t *link_rc = root->link.next;
        spo_tree_node_t *node_rc = spo_cnt_tree_node(link_rc);
        InOrderTraverse(node_rc, visist_func);
    }
}


void PreOrderTraverse(spo_tree_node_t *root, void (*visist_func) (void *))
{
    if(NULL != root)
    {
        spo_visist_tree_node(root, visist_func);
        spo_cnt_t *link_lc = root->link.prev;
        spo_tree_node_t *node_lc = spo_cnt_tree_node(link_lc);
        PreOrderTraverse(node_lc, visist_func);
        spo_cnt_t *link_rc = root->link.next;
        spo_tree_node_t *node_rc = spo_cnt_tree_node(link_rc);
        PreOrderTraverse(node_rc, visist_func);
    }
}

/**
 *
 *  get the tree's deep, just for test.
 *
 * */

SPO_RET_VALUE spo_find_tree_deep(spo_cnt_t *BT)
{
     int deep=0;

     if(BT){
         int lchilddeep=spo_find_tree_deep(BT->prev);
         int rchilddeep=spo_find_tree_deep(BT->next);
         deep = lchilddeep >= rchilddeep ? lchilddeep + 1 : rchilddeep + 1;
     }

     return deep;
}


/**
 *
 *  adjust sub tree.
 *
 * */

static void spo_r_rotate(spo_tree_node_t **p)
{
    spo_cnt_t *link_lc = ((*p)->link).prev;

    (*p)->link.prev = link_lc->next;

    /* link_lc's right child's parent changed */
    if (link_lc->next != NULL) {
        spo_tree_node_t *node_rd = spo_cnt_tree_node(link_lc->next);
        node_rd->parent = (*p);
    }

    link_lc->next = &((*p)->link);

    spo_tree_node_t *parent = (*p)->parent;

    /* change the p's parent's child */
    if (parent != NULL) {
        if (parent->link.next == &((*p)->link)) {
            parent->link.next = link_lc;
        }else {
            if (parent->link.prev == &((*p)->link)) {
                parent->link.prev = link_lc;
            }else return;
        }

        spo_tree_node_t *node_lc = spo_cnt_tree_node(link_lc);
        node_lc->parent = parent;

        (*p)->parent = node_lc;
    }else {
        /* when change the tree root, we do it */
        spo_tree_node_t *node_lc = spo_cnt_tree_node(link_lc);
        node_lc->parent = NULL;
        (*p)->parent = node_lc;
        *p = spo_cnt_tree_node(link_lc);
    }
}


/**
 *
 *  adjust sub tree.
 *
 * */

static void spo_l_rotate(spo_tree_node_t **p)
{
    spo_cnt_t *link_rc = ((*p)->link).next;

    (*p)->link.next = link_rc->prev;

    /* link_rc's left child's parent changed */
    if (link_rc->prev != NULL) {
        spo_tree_node_t *node_ld = spo_cnt_tree_node(link_rc->prev);
        node_ld->parent = (*p);
    }

    link_rc->prev = &((*p)->link);

    spo_tree_node_t *parent = (*p)->parent;

    /* change the p's parent's child */
    if (parent != NULL) {
        if (parent->link.next == &((*p)->link)) {
            parent->link.next = link_rc;
        }else {
            if (parent->link.prev == &((*p)->link)) {
                parent->link.prev = link_rc;
            }else return;
        }

        spo_tree_node_t *node_rc = spo_cnt_tree_node(link_rc);
        node_rc->parent = parent;

        (*p)->parent = node_rc;
    }else {
        /* when change the tree root, we do it */
        spo_tree_node_t *node_rc = spo_cnt_tree_node(link_rc);
        node_rc->parent = NULL;
        (*p)->parent = node_rc;
        *p = spo_cnt_tree_node(link_rc);
    }
}

/**
 *
 *  when the tree not balance, we adjust it
 *
 * */

static void spo_left_balance(spo_tree_node_t **T)
{
    spo_cnt_t *link_lc = (*T)->link.prev;
    spo_tree_node_t *node_lc = spo_cnt_tree_node(link_lc);

    spo_cnt_t *link_rd = link_lc->next;
    spo_tree_node_t *node_rd = spo_cnt_tree_node(link_rd);

    switch(node_lc->bf) {
    case LH:
        (*T)->bf = node_lc->bf = EH;
        spo_r_rotate(T);
        break;

    case RH:
        switch(node_rd->bf) {
        case LH:
            (*T)->bf = RH;
            node_lc->bf = EH;
            break;

        case EH:
            (*T)->bf = node_lc->bf = EH;
            break;

        case RH:
            (*T)->bf = EH;
            node_lc->bf = LH;
            break;
        }

        node_rd->bf = EH;
        spo_l_rotate(&(node_lc));
        spo_r_rotate(T);
        break;
    }
}


/**
 *
 *  when the tree not balance, we adjust it
 *
 * */

static void spo_right_balance(spo_tree_node_t **T)
{
    spo_cnt_t *link_rc = (*T)->link.next;
    spo_tree_node_t *node_rc = spo_cnt_tree_node(link_rc);

    spo_cnt_t *link_ld = link_rc->prev;
    spo_tree_node_t *node_ld = spo_cnt_tree_node(link_ld);

    switch(node_rc->bf) {
    case RH:
        (*T)->bf = node_rc->bf = EH;
        spo_l_rotate(T);
        break;

    case LH:
        switch(node_ld->bf) {
        case RH:
            (*T)->bf = LH;
            node_rc->bf = EH;
            break;

        case EH:
            (*T)->bf = node_rc->bf = EH;
            break;

        case LH:
            (*T)->bf = EH;
            node_rc->bf = RH;
            break;
        }

        node_ld->bf = EH;
        spo_r_rotate(&(node_rc));
        spo_l_rotate(T);
        break;
    }
}


/**
 *
 *  insert a node in t's left.
 *
 * */

static SPO_RET_BOOLEN spo_do_insert_AVL_left(spo_tree_node_t **t, spo_tree_node_t *node,
                                             spo_bool_t *taller, int (*comp_func) (void *, void *))
{
    spo_cnt_t *link_lc = (*t)->link.prev;

    if (link_lc == NULL) {
        (*t)->link.prev = &(node->link);
        node->parent = (*t);
        *taller = TRUE;
    }else {
        spo_tree_node_t *node_lc = spo_cnt_tree_node(link_lc);
        if(FALSE == spo_insert_AVL(&node_lc, node, taller, comp_func)) return FALSE;
    }

    if(*taller) {
        switch((*t)->bf) {
        case LH:
            spo_left_balance(t);
            *taller = FALSE;
            break;

        case EH:
            (*t)->bf = LH;
            *taller = TRUE;
            break;

        case RH:
            (*t)->bf=EH;
            *taller=FALSE;
            break;
        }
    }

    return TRUE;
}

/**
 *
 *  insert a node in t's right.
 *
 * */

static SPO_RET_BOOLEN spo_insert_AVL_right(spo_tree_node_t **t, spo_tree_node_t *node,
                                           spo_bool_t *taller, int (*comp_func) (void *, void *))
{
    spo_cnt_t *link_rc = (*t)->link.next;

    if (link_rc == NULL) {
        (*t)->link.next = &(node->link);
        node->parent = (*t);
        *taller = TRUE;
    }else {
        spo_tree_node_t *node_rc = spo_cnt_tree_node(link_rc);
        if(FALSE == spo_insert_AVL(&node_rc, node, taller, comp_func)) return FALSE;
    }

    if(*taller) {
        switch((*t)->bf) {
        case RH:
            spo_right_balance(t);
            *taller=FALSE;
            break;

        case EH:
            (*t)->bf=RH;
            *taller=TRUE;
            break;

        case LH:
            (*t)->bf=EH;
            *taller=FALSE;
            break;
        }
    }

    return TRUE;
}


/**
 *
 *  t is the tree or sub tree's root's pointer.
 *
 * */

spo_bool_t spo_insert_AVL(spo_tree_node_t **t, spo_tree_node_t *node,
                          spo_bool_t *taller, int (*comp_func) (void *, void *))
{
    if(NULL == t) return FALSE;

    if(NULL == *t) {
        *t = node;
        if(NULL == *t) return FALSE;
        *taller = TRUE;
    }else {

        if(spo_tree_node_comp((*t), node, comp_func) == 0) {
            *taller = FALSE;
            return FALSE;
        }

        if(spo_tree_node_comp((*t), node, comp_func) < 0){
            if (spo_do_insert_AVL_left(t, node, taller, comp_func) == FALSE) return FALSE;
        }else if (spo_insert_AVL_right(t, node, taller, comp_func) == FALSE) return FALSE;
    }

    return TRUE;
}



/* - -- - -- -- --  search the avl tree, Complexity lon(n) - - -- - -- -- - - */


inline static SPO_RET_VALUE spo_do_tree_match(spo_cnt_t *cnt, void *data,
                                             int (*comp_func) (void *, void *))
{
    spo_tree_node_t *node = spo_cnt_tree_node(cnt);
    return comp_func(node->key, data);
}


spo_tree_node_t *spo_tree_match(spo_tree_header_t *header, void *data,
                                     int (*comp_func) (void *, void *))
{
    spo_tree_node_t *root = header->root;
    spo_cnt_t *p = &(root->link);
    int ret = 0;

    while (p) {
        if ((ret = spo_do_tree_match(p, data, comp_func)) > 0) {
            p = p->next;
        }else {
            if (ret < 0) {
                p = p->prev;
            }else return spo_cnt_tree_node(p);
        }
    }

    return NULL;
}


/*  - - --- -- - - --  Recursive  to destory tree node - - -- --- - - -- - - - - --  */

void spo_do_destory_tree(spo_cnt_t *node_link, int (*free_node_key_func) (void *))
{
    if(node_link == NULL) return;

    spo_do_destory_tree(node_link->prev, free_node_key_func);
    spo_do_destory_tree(node_link->next, free_node_key_func);

    spo_tree_node_t *node = spo_cnt_tree_node(node_link);

    free_node_key_func(node->key);

    node->parent = NULL;
    node->link.prev = NULL;
    node->link.next = NULL;

    spo_free(node);
}


/*  - - - -- - - - -- - -- -  destory a tree  - - - -- - - - - -- - - -- - -  */

SPO_RET_STATUS spo_destory_tree(spo_tree_header_t *header, int (*free_node_key_func) (void *))
{
    if (header == NULL) return SPO_OK;

    if (header->root != NULL) {
        spo_do_destory_tree(&header->root->link, free_node_key_func);

        header->current = NULL;
        header->root = NULL;
    }

    spo_free(header);

    return SPO_OK;
}
