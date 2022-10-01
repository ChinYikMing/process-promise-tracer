#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>
#include <limits.h>
#include <dirent.h>
#include <stdarg.h>
#include <assert.h>
#include <signal.h>
#include <stdbool.h>

typedef struct dirent DIRent;
typedef struct stat Stat;

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096 // normally is 4096, to be more precise would be sysconf(PAGESIZE)
#endif

#ifndef BUF_SIZE
#define BUF_SIZE 1024
#endif
