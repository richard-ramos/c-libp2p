/* src/util/list.h — intrusive doubly-linked list */
#ifndef LP2P_UTIL_LIST_H
#define LP2P_UTIL_LIST_H

#include <stddef.h>

typedef struct lp2p_list_node {
    struct lp2p_list_node *prev;
    struct lp2p_list_node *next;
} lp2p_list_node_t;

typedef struct {
    lp2p_list_node_t head;
    size_t           count;
} lp2p_list_t;

void lp2p_list_init(lp2p_list_t *list);
void lp2p_list_push_back(lp2p_list_t *list, lp2p_list_node_t *node);
void lp2p_list_push_front(lp2p_list_t *list, lp2p_list_node_t *node);
void lp2p_list_remove(lp2p_list_t *list, lp2p_list_node_t *node);
lp2p_list_node_t *lp2p_list_pop_front(lp2p_list_t *list);
int  lp2p_list_empty(const lp2p_list_t *list);

#define lp2p_container_of(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))

#endif /* LP2P_UTIL_LIST_H */
