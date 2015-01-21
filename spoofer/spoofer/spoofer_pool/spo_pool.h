#ifndef SPO_POOL_H
#define SPO_POOL_H

#include <malloc.h>

#define SPO_POOL_ALIGNMENT sizeof(unsigned long)
#define SPO_PAGE_SIZE ((size_t) getpagesize())

#define spo_align(d, a) (((d) + (a - 1)) & ~(a - 1))
#define spo_align_ptr(p, a) (u_char *)\
    (((uintptr_t) (p) + ((uintptr_t) a - 1)) & ~((uintptr_t) a - 1))

#define spo_memzero(buf,size) (void)memset(buf,0, size)
#define spo_memset(buf, c, size) (void)memset(buf, c, size)

#define spo_free free


typedef struct spo_pool_data_s {
    u_char *last;
    u_char *end;
    struct spo_pool_s *next;
    unsigned int failure;
}spo_pool_data_t;


struct spo_big_pool_s {
    struct spo_big_pool_s *next;
    void *alloc;
};


struct spo_pool_s {
    spo_pool_data_t data;
    size_t max;
    struct spo_pool_s * current;
    struct spo_big_pool_s *big_pool;
};

void *spo_alloc(size_t size);
void *spo_calloc(size_t size);
void *spo_memalign(size_t alignment, size_t size);

void *spo_palloc(spo_pool_t *pool, size_t size);
void *spo_palloc_block(spo_pool_t *pool, size_t size);
void *spo_palloc_big_pool(spo_pool_t *pool, size_t size);
void *spo_create_pool(size_t size);
SPO_RET_STATUS spo_pfree(spo_pool_t *pool, void *p);

#endif // SPO_POOL_H
