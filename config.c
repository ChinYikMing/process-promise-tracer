#include "config.h"
#include "list.h"
#include "basis.h"

Config *cf = NULL;

int config_init(Config **cf){
	Config *tmp = malloc(sizeof(Config));
	if(!tmp)
		return 1;

	tmp->list = malloc(sizeof(List));
	if(!tmp->list)
		return 1;

	LIST_INIT(tmp->list);
	*cf = tmp;
	return 0;
}

int config_parse(const char *config_file){
	return CONFIG_PARSE_SUCCESS;
}

int config_read(Config *cf){
	FILE *config_fptr = fopen(CONFIG_FILE, "r");
        if(!config_fptr)
                return 1;

        char buf[BUF_SIZE] = {0};
        Conf *c = NULL;
        int mark = 0;
        char title1[] = "[Daemon]";
        char title2[] = "[Untrusted Program]";
        size_t buf_len;

        while(fgets(buf, BUF_SIZE, config_fptr)){
                buf[strcspn(buf, "\r\n")] = 0;
                buf_len = strlen(buf);
                if(!buf_len)
                        continue;

                if(0 == strcmp(title1, buf)){
                        mark=1;
                        continue;
                }
                else if(0 == strcmp(title2, buf)){
                        mark=2;
                        continue;
                }
                else{
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
                }
        }

	/* debug print
        Node *iter;
        Conf *conf;
        LIST_FOR_EACH(cf->list, iter){
                conf = LIST_ENTRY(iter, Conf);
                printf("key: %s, val: %s\n", conf->key, conf->val);
        }
        exit(1);
	*/

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
