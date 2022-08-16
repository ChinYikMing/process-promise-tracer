#include "basis.h"
#include "process.h"
#include "list.h"

Node *node_create(void *data){
    Node *new_node = malloc(sizeof(Node));
    new_node->data = data;
    new_node->next = NULL;
    new_node->prev = NULL;

    return new_node;
}

void node_destroy(Node *node){
	free(node);
}

int list_push_back(List *list, Node *node){
    list->size++;

    if(!list->head){
	list->head = node;
	return 0;
    }

    Node *ptr = list->head;
    while(ptr->next && ptr->next != list->head)
	ptr = ptr->next;

    ptr->next = node;
    node->prev = ptr; 

    /* implement circular linked list */
    node->next = list->head;
    list->head->prev = node;
    return 0;
}

int list_push_front(List *list, Node *node){
    list->size++;

    if(!list->head){
	list->head = node;
	return 0;
    }

    /* find the last node to implement circular linked list */
    Node *ptr = list->head;
    while(ptr->next && ptr->next != list->head)
	ptr = ptr->next;

    ptr->next = node;
    node->prev = ptr;

    /* implement circular linked list */
    node->next = list->head;
    list->head->prev = node;
    list->head = node;
    return 0;
}

Node *list_get_node_by_pid(List *list, pid_t pid, bool *pre_exist){
	Node *head = list->head;
	Node **start = &list->head;
	Node *node = NULL;
	Process *proc = NULL;

	while((node = *start)){
		proc = node->data;
		if(proc->pid == pid){
			*pre_exist = true;
			return node;
		}

		start = &node->next;
		if(*start == head)
			break;
	}

	*pre_exist = false;
	proc = process_create(pid);
	assert(proc != NULL);
	node = node_create((void *) proc);
	assert(node != NULL);

	return node;
}

