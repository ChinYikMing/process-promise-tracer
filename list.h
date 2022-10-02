#ifndef LIST_HDR
#define LIST_HDR

#define LIST_INIT(list) { \
	list->head = NULL; \
	list->tail = NULL; \
	list->size = 0; \
}

#define LIST_FOR_EACH(list, iter) \
	for(iter = list->head; iter != NULL; iter = iter->next) \

#define LIST_ENTRY(iter, type) \
	(type *) iter->data; \

#include "basis.h"

typedef struct node Node;
struct node {
    void *data;
    Node *next;
};

typedef struct list {
    Node *head;
    Node *tail;
    size_t size;
} List;

size_t list_size(List *list);
int list_push_back(List *list, Node *node);
int list_push_front(List *list, Node *node);
int list_delete(List *list, int id);
Node *node_create(void *data);
void node_destroy(Node *node);
Node *list_get_node_by_pid(List *list, pid_t pid, bool *pre_exist);

#endif
