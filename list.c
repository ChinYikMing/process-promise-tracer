#include "basis.h"
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

