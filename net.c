#include "net.h"
#include <arpa/inet.h>

int parse_net_lines(FILE *netfile, const char *sock_inode, char *rem_addr){
        char buf[BUF_SIZE];
        char *rem_addr_ptr;
        char *rem_addr_qtr;
        size_t len;

        while(fgets(buf, BUF_SIZE, netfile)){
                rem_addr_ptr = buf;

                if(strstr(buf, sock_inode)){
                        rem_addr_ptr = strchr(rem_addr_ptr + 1, ':');
                        for(int i = 0; i < 2; i++)
                                rem_addr_ptr = strchr(rem_addr_ptr + 1, ' ');
                        rem_addr_qtr = strchr(rem_addr_ptr + 1, ' ');
                        len = rem_addr_qtr - rem_addr_ptr;
                        strncpy(rem_addr, rem_addr_ptr + 1, len);
                        rem_addr[len] = 0;
                        return 0;
                }
        }

        return 1;
}

int get_sock_inode_by_sockfd(Process *proc, int sockfd, char *sock_inode){
        char buf[BUF_SIZE] = {0};
        char path[BUF_SIZE] = {0};
        char pidstr[32] = {0};
        char sockfdstr[32] = {0};
        int ret;
        char *ptr, *qtr;

        sprintf(pidstr, "%d", proc->pid);
        sprintf(sockfdstr, "%d", sockfd);

        strcpy(path, PROC_DIR);
        strcat(path, "/");
        strcat(path, pidstr);
        strcat(path, "/");
        strcat(path, "fd");
        strcat(path, "/");
        strcat(path, sockfdstr);

        ret = readlink(path, buf, BUF_SIZE);
        if(-1 == ret)
                return 1;
        buf[ret] = 0;

        ptr = buf;
        ptr = strchr(buf, '[') + 1;
        qtr = strchr(ptr, ']');
        strncpy(sock_inode, ptr, qtr - ptr);
        sock_inode[qtr - ptr] = 0;
        //printf("sock_inode: %s, %d, %c, %c\n", sock_inode, qtr - ptr, *ptr, *qtr);
        return 0;
}

void get_ip_port_from_rem_addr(char *rem_addr, int ipv4, char *ip, char *port){
        char tmp[64] = {0};
        uint16_t port_val;
        char *ptr, *qtr;

        ptr = rem_addr;
        if(ipv4){
                uint8_t *rtr;
                uint32_t ip_val;

                qtr = strchr(ptr, ':');
                strcpy(tmp, "0x");
                strncat(tmp, ptr, qtr - ptr);
                tmp[qtr - ptr + 2] = 0;
                ip_val = (uint32_t) strtoul(tmp, NULL, 16);
                ip_val = ntohl(ip_val);

                rtr = ((uint8_t *) &ip_val) + 3;
                for(int i = 4; i > 0; i--){
                        memset(tmp, 0, 64);
                        sprintf(tmp, "%u", *rtr);

                        if(i == 1){
                                strcat(ip, tmp);
                                break;
                        }

                        strcat(ip, tmp);
                        strcat(ip, ".");
                        rtr--;
                }
        } else { // ipv6
                qtr = strchr(ptr, ':');
                strncat(tmp, ptr, qtr - ptr);
                tmp[qtr - ptr] = 0;

                ptr = ptr + 31;
                for(int i = 0; i < 8; i++){
                        for(int j = 0; j < 4; j++){
                                sprintf(tmp, "%c", *ptr);
                                strcat(ip, tmp);
                                ptr--;
                        }

                        if(i == 7)
                                break;

                        strcat(ip, ":");
                }
        }

        ptr = strchr(rem_addr, ':') + 1;
        memset(tmp, 0, 64);
        strcpy(tmp, "0x");
        strcat(tmp, ptr);
        port_val = (uint16_t) strtoul(tmp, NULL, 16);
        sprintf(port, "%u", port_val);
}

int get_rem_addr_by_sockfd(Process *proc, int sockfd, char *rem_addr, int *tcp, int *ipv4){
        int ret;
        char sock_inode[16];
        ret = get_sock_inode_by_sockfd(proc, sockfd, sock_inode);
        if(ret)
                return 1;

        // try tcp first
        char tcp_file[32] = {0};
        strcpy(tcp_file, PROC_DIR);
        strcat(tcp_file, "/net/tcp");
        FILE *net_file_ptr = fopen(tcp_file, "r");
        if(!net_file_ptr)
                return 1;

        ret = parse_net_lines(net_file_ptr, sock_inode, rem_addr);
        fclose(net_file_ptr);
        if(!ret) {
                *tcp = 1;
                *ipv4 = 1;
                return 0;
        }

        // try tcp6 first
        memset(tcp_file, 0, 32);
        strcpy(tcp_file, PROC_DIR);
        strcat(tcp_file, "/net/tcp6");
        net_file_ptr = fopen(tcp_file, "r");
        if(!net_file_ptr)
                return 1;

        ret = parse_net_lines(net_file_ptr, sock_inode, rem_addr);
        fclose(net_file_ptr);
        if(!ret){
                *tcp = 1;
                *ipv4 = 0;
                return 0;
        }

        // try udp
        char udp_file[32] = {0};
        strcpy(udp_file, PROC_DIR);
        strcat(udp_file, "/net/udp");
        net_file_ptr = fopen(udp_file, "r");
        if(!net_file_ptr)
                return 1;

        ret = parse_net_lines(net_file_ptr, sock_inode, rem_addr);
        fclose(net_file_ptr);
        if(!ret){
                *tcp = 0;
                *ipv4 = 1;
                return 0;
        }

        // try udp6
        memset(udp_file, 0, 32);
        strcpy(udp_file, PROC_DIR);
        strcat(udp_file, "/net/udp6");
        net_file_ptr = fopen(udp_file, "r");
        if(!net_file_ptr)
                return 1;

        ret = parse_net_lines(net_file_ptr, sock_inode, rem_addr);
        fclose(net_file_ptr);
        if(!ret){
                *tcp = 0;
                *ipv4 = 0;
                return 0;
        }

        return 1;
}

