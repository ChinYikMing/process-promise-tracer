#include "../../list.h"
#include "../../basis.h"

struct data {
 	int val;
};

struct data *data_new(int val){
	struct data *d = malloc(sizeof(struct data));
	if(!d)
		return NULL;

	d->val = val;
	return d;
}

int main(){
	List *list = malloc(sizeof(List));
	LIST_INIT(list);

	struct data *d;
	Node *node;
	for(int i = 0; i < 10; i++){
		d = data_new(i);
		node = node_create(d);
		list_push_back(list, node);
	}

	Node *iter;
	struct data *dd;
	LIST_FOR_EACH(list, iter){
		dd = LIST_ENTRY(iter, struct data);

		printf("val: %d\n", dd->val);
	}
}
