#ifndef ADDR_WHITE_LIST_H_
#define ADDR_WHITE_LIST_H_

#include <arpa/inet.h>
#include <sys/socket.h>

struct addr_whitelist {
    struct addr_whitelist *next;
    socklen_t addrlen;
    struct sockaddr *addr;
    int prefix;
    int check_scope_id;
};

int addr_whitelist_check(struct addr_whitelist *wl, struct sockaddr *saddr);
int addr_whitelist_add(struct addr_whitelist **wl, char *net);
int addr_whitelist_add_spec(struct addr_whitelist **wl, const char *spec);

#endif
