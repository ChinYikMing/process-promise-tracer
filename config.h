#ifndef CONFIG_HDR
#define CONFIG_HDR

#include "list.h"

#define CONFIG_FILE "/etc/process_promise_tracer.conf"
#define CONFIG_PARSE_SUCCESS 0
#define CONFIG_PARSE_FAILURE 4

#define CONF_TYPE_PROG   "prog"
#define CONF_TYPE_USER   "user"
#define CONF_BUF_MAX 128
typedef struct conf {
	char key[CONF_BUF_MAX];
	char val[CONF_BUF_MAX];
} Conf;
Conf *conf_create(const char *key, const char *val);

#define CONFIG_INIT(cf) { \
	LIST_INIT(cf.list) \
}
typedef struct config {
	List list;
} Config;

int config_parse(const char *config_file);
int config_read(Config *cf, const char *config_file);
int config_add(Config *cf, Conf *c);
int config_del(Config *cf, Conf *c);
int config_destroy(Config *cf);

#endif
