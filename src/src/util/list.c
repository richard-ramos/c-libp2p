/* src/util/list.c — intrusive doubly-linked list */
#include "util/list.h"
#include <stddef.h>

void lp2p_list_init(lp2p_list_t *list) {
    list->head.prev = &list->head;
    list->head.next = &list->head;
    list->count     = 0;
}

void lp2p_list_push_back(lp2p_list_t *list, lp2p_list_node_t *node) {
    node->prev = list->head.prev;
    node->next = &list->head;
    list->head.prev->next = node;
    list->head.prev       = node;
    list->count++;
}

void lp2p_list_push_front(lp2p_list_t *list, lp2p_list_node_t *node) {
    node->next = list->head.next;
    node->prev = &list->head;
    list->head.next->prev = node;
    list->head.next       = node;
    list->count++;
}

void lp2p_list_remove(lp2p_list_t *list, lp2p_list_node_t *node) {
    node->prev->next = node->next;
    node->next->prev = node->prev;
    node->prev = NULL;
    node->next = NULL;
    list->count--;
}

lp2p_list_node_t *lp2p_list_pop_front(lp2p_list_t *list) {
    if (lp2p_list_empty(list))
        return NULL;
    lp2p_list_node_t *node = list->head.next;
    lp2p_list_remove(list, node);
    return node;
}

int lp2p_list_empty(const lp2p_list_t *list) {
    return list->head.next == &list->head;
}
