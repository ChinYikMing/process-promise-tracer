#ifndef NET_HDR
#define NET_HDR

#include "basis.h"
#include "process.h"

int parse_net_lines(FILE *netfile, const char *sock_inode, char *rem_addr);
int get_sock_inode_by_sockfd(Process *proc, int sockfd, char *sock_inode);
void get_ip_port_from_rem_addr(char *rem_addr, int ipv4, char *ip, char *port);
int get_rem_addr_by_sockfd(Process *proc, int sockfd, char *rem_addr, int *tcp, int *ipv4);

#endif
