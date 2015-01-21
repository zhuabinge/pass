#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "../spoofer_system/spoofer.h"
#include "spo_pool.h"



void *spo_alloc(size_t size)
{
    void *p = NULL;
    p = malloc(size);

    return p;
}

void *spo_calloc(size_t size)
{
    void *p = NULL;

    p = spo_alloc(size);
    if (p)  spo_memzero(p, size);

    return p;
}


void *spo_memalign(size_t alignment, size_t size)
{
    int err = 0;
    void *p = NULL;

    err = posix_memalign(&p, alignment, size);
    if (err)    p = NULL;

    return p;
}


/**
 *
 *  alloc a mem in a pool.
 *
 * */

void *spo_palloc(spo_pool_t *pool, size_t size)
{
    u_char *m;
    spo_pool_t *p;

    if (size <= pool->max) {

        p = pool->current;

        do {
            m = spo_align_ptr(p->data.last, SPO_POOL_ALIGNMENT);
            if ((size_t)(p->data.end - m) >= size) {
                p->data.last = m + size;
                return m;
            }
            p = p->data.next;
        }while(p);

        return spo_palloc_block(pool, size);
    }

    return spo_palloc_big_pool(pool, size);
}


void *spo_palloc_block(spo_pool_t *pool, size_t size)
{
    u_char *m;
    size_t psize;
    spo_pool_t *p, *new_p, *current_p;

    psize = (size_t)(pool->data.end - (u_char*)pool);

    m = spo_memalign(SPO_POOL_ALIGNMENT, psize);
    if (m == NULL) return NULL;

    new_p = (spo_pool_t *)m;

    new_p->data.end = m + psize;
    new_p->data.next = NULL;
    new_p->data.failure = 0;

    m += sizeof(spo_pool_data_t);
    m = spo_align_ptr(m, SPO_POOL_ALIGNMENT);
    new_p->data.last = m + size;

    current_p = pool->current;

    for (p = current_p; p->data.next; p = p->data.next) {
        if (p->data.failure++ > 4) {
            current_p  = p->data.next;
        }
    }

    p->data.next = new_p;
    pool->current = current_p ? current_p : new_p;

    return m;
}


void *spo_palloc_big_pool(spo_pool_t *pool, size_t size)
{
    void *p;
    int n = 0;
    spo_big_pool_t *big_p;

    p = spo_alloc(size);
    if (p == NULL) return NULL;

    n = 0;

    for (big_p = pool->big_pool; big_p; big_p = big_p->next) {
        if (big_p->alloc == NULL) {
            big_p->alloc = p;
            return p;
        }

        if (n++ > 3) {
            break;
        }
    }

    big_p = spo_palloc(pool, sizeof(spo_big_pool_t));
    if (big_p == NULL) {
        spo_free(big_p);
        return NULL;
    }

    big_p->alloc = p;
    big_p->next = pool->big_pool;
    pool->big_pool = big_p;

    return p;
}


void *spo_create_pool(size_t size)
{
    spo_pool_t *p;

    p = spo_memalign(SPO_POOL_ALIGNMENT, size);
    if (p == NULL) return NULL;

    p->data.last = (u_char *)p + sizeof(spo_pool_t);
    p->data.end = (u_char *)p + size;

    p->data.failure = 0;
    p->data.next = NULL;

    size = size - sizeof(spo_pool_t);
    p->max = (size < SPO_PAGE_SIZE -1) ? size : (SPO_PAGE_SIZE - 1);

    p->current = p;
    p->big_pool = NULL;

    return p;
}


/**
 *
 *  only free the big pool.
 *
 * */

SPO_RET_STATUS spo_pfree(spo_pool_t *pool, void *p)
{
    spo_big_pool_t *big_p = NULL;

    for (big_p = pool->big_pool; big_p; big_p = big_p->next) {

        if (big_p->alloc == p) {
            spo_free(big_p->alloc);
            big_p->alloc = NULL;
            return SPO_OK;
        }
    }

    return SPO_OK;
}
