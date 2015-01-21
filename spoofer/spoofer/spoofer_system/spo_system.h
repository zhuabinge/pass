#ifndef SPO_SYSTEM_H
#define SPO_SYSTEM_H

spo_proc_node_t *spo_create_proc_node(int node_amount);
SPO_RET_STATUS spo_use_time(int when, const char *who);

#endif // SPO_SYSTEM_H
