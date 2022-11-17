#include "config.h"
#include "list.h"
#include "basis.h"

int config_init(Config *cf){
	cf->list = malloc(sizeof(List));
	if(!cf->list)
		return 1;

	LIST_INIT(cf->list);
	return 0;
}

int config_parse(const char *config_file){
	return CONFIG_PARSE_SUCCESS;
}

int config_read(Config *cf, const char *config_file){
	FILE *config_fptr = fopen(config_file, "r");
	if(!config_fptr)
		return 1;

	char buf[BUF_SIZE] = {0};
	Conf *c = NULL;
	int mark = 0;
	char title1[] = "[Daemon]";
	char title2[] = "[Untrusted Program]";
	while(fgets(buf, BUF_SIZE, config_fptr)){
		buf[strcspn(buf, "\r\n")] = 0;
		if(strcmp(title1, buf)){
			mark=1;
			continue;
		}
		else{break;}
		if(strcmp(title2, buf)){
			mark=2;
			continue;
		}
		else{break;}
		if(mark == 1){
			char *type, *val;
			type = strtok(buf, "=");
			val = strtok(NULL, "=");
			c = conf_create(type, val);
			config_add(cf, c);
		}
		else if(mark == 2){
			char *val;
			val = buf;
			c = conf_create(CONF_TYPE_PROG, val);
			config_add(cf, c);
		}
		// c = conf_create(CONF_TYPE_PROG, buf);
		// config_add(cf, c);
	}

	fclose(config_fptr);
	return 0;
}

int config_add(Config *cf, Conf *c){
	Node *node = node_create((void *) c);
	if(!node)
		return 1;

	return list_push_back(cf->list, node);
}

int config_del(Config *cf, Conf *c){
	/*
	Node *found = list_get_node_by_data((void *) c);
	if(!found)
		return 1;
	*/

	return 0;
}

int config_destroy(Config *cf){
	return 0;
}

Conf *conf_create(const char *key, const char *val){
	Conf *conf = malloc(sizeof(Conf));
	if(!conf)
		return NULL;

	strcpy(conf->key, key);
	strcpy(conf->val, val);

	return conf;
}
