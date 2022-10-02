#include "basis.h"
#include "process.h"
#include "list.h"

Node *node_create(void *data){
    Node *new_node = malloc(sizeof(Node));
    new_node->data = data;
    new_node->next = NULL;

    return new_node;
}

void node_destroy(Node *node){
	free(node);
}

size_t list_size(List *list){
	return list->size;
}

int list_push_back(List *list, Node *node){
    if(!list)
	    return 1;

    size_t size = list_size(list);
    if(0 == size){
    	list->head = node;
	list->tail = node;
	goto add_node;
    }

    list->tail->next = node;
    list->tail = node;

add_node:
    list->size++;
    return 0;
}

int list_push_front(List *list, Node *node){
    if(!list)
	    return 1;

    size_t size = list_size(list);
    if(0 == size){
    	list->head = node;
	list->tail = node;
	goto add_node;
    }

    node->next = list->head;
    list->head = node;

add_node:
    list->size++;
    return 0;
}

Node *list_get_node_by_pid(List *list, pid_t pid, bool *pre_exist){
	Node *node = NULL;
	Process *proc = NULL;

	LIST_FOR_EACH(list, node){
		proc = LIST_ENTRY(node, Process);
		if(proc->pid == pid){
			*pre_exist = true;
			return node;
		}
	}

	*pre_exist = false;
	return NULL;
}

