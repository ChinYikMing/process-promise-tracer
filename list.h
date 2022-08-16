#ifndef LIST_HDR
#define LIST_HDR

#define LIST_INIT(list) { \
	list.head = NULL; \
	list.size = 0; \
}

#include "basis.h"

typedef struct node Node;
struct node {
    void *data;
    Node *next;
    Node *prev;
};

typedef struct list {
    Node *head;
    size_t size;
} List;

int list_push_back(List *list, Node *node);
int list_push_front(List *list, Node *node);
int list_delete(List *list, int id);
Node *node_create(void *data);
void node_destroy(Node *node);
Node *list_get_node_by_pid(List *list, pid_t pid, bool *pre_exist);

#endif
