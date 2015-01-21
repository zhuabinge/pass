#include<stdio.h>
#include<stdlib.h>
#define __USE_GNU
#define _GNU_SOURCE
#include <sched.h>
#include <sys/wait.h>

#include "../spoofer_system/spoofer.h"
#include "spo_linux.h"

/**
 *
 *  bind cpu for the process.
 *
 *  @param cpu_id, is the cpu id.
 *
 *  @param pid, is the proc id.
 *
 *  @return nothing.
 *
 *  status finished, tested.
 *
 **/

void spo_bind_cpu(int cpu_id, pid_t pid)
{
    cpu_set_t mask; /*mask set.*/

    cpu_id = cpu_id % sysconf(_SC_NPROCESSORS_CONF);

    CPU_ZERO(&mask);    /*clear mask*/
    CPU_SET(cpu_id, &mask); /*bind cpu*/

    if (sched_setaffinity(pid, sizeof(mask), &mask) == -1) {
#if SPO_DEBUG
        printf("bind cpu err\n");
#endif
    }
}


char *spo_strtok(char *str, const char *delim)
{
    static char *p = NULL;
    static char *start = NULL;
    size_t i = 0;
    size_t len = 0;
    size_t del_len = 0;

    if (str != NULL) start = p = str;

    start = p;
    len = strlen(p);

    if (delim == NULL) return p;
    del_len = strlen(delim);

    for (i = 0; i < len; i++) {
        if (memcmp(p, delim, del_len) == 0) {
            *p = '\0';
            p += del_len;
            return start;
        }
        p++;
    }

    return start;
}
