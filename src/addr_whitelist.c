#include "addr_whitelist.h"

#include <stdlib.h>
#include <string.h>

#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <unistd.h>

int addr_whitelist_check(
        struct addr_whitelist *wl,
        struct sockaddr *saddr)
{
    if (saddr->sa_family == AF_INET) {
        struct sockaddr_in *addr = (struct sockaddr_in *) saddr;

        while (wl) {
            if (wl->addr->sa_family == AF_INET) {
                struct sockaddr_in *wladdr;
                int shift;

                wladdr = (struct sockaddr_in *) wl->addr;
                if (wl->prefix < 32) {
                    shift = 32 - wl->prefix;
                } else {
                    shift = 0;
                }

                if (ntohl(addr->sin_addr.s_addr) >> shift ==
                        ntohl(wladdr->sin_addr.s_addr) >> shift) {
                    return 1;
                }
            }

            wl = wl->next;
        }
    } else if (saddr->sa_family == AF_INET6) {
        struct sockaddr_in6 *addr = (struct sockaddr_in6 *) saddr;

        while (wl) {
            if (wl->addr->sa_family == AF_INET6) {
                struct sockaddr_in6 *wladdr;
                int prefix, i;

                wladdr = (struct sockaddr_in6 *) wl->addr;
                prefix = wl->prefix < 128 ? wl->prefix : 128;
                i = 0;

                while (prefix) {
                    int shift;
                    if (prefix > 8) {
                        shift = 0;
                        prefix -= 8;
                    } else {
                        shift = 8 - prefix;
                        prefix = 0;
                    }

                    if (addr->sin6_addr.s6_addr[i] >> shift !=
                            wladdr->sin6_addr.s6_addr[i] >> shift) {
                        goto next6;
                    }

                    i++;
                }

                if (wl->check_scope_id && addr->sin6_scope_id != 
                        wladdr->sin6_scope_id) {
                    goto next6;
                }

                return 1;
            }

next6:
            wl = wl->next;
        }
    }

    return 0;
}

int addr_whitelist_add(
        struct addr_whitelist **wl,
        char *net)
{
    char *addr = net, *range;
    struct addrinfo hints, *res = NULL;
    struct addr_whitelist *wli = NULL;

    for (range = addr; *range != 0 && *range != '/'; ++range);

    if (*range == '/') {
        *range++ = 0;
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;

    if (!*range) {
        hints.ai_flags |= AI_NUMERICHOST;
    }

    if (getaddrinfo(addr, NULL, &hints, &res)) {
        res = NULL;
        goto err;
    }

    if (res->ai_addr->sa_family != AF_INET
            && res->ai_addr->sa_family != AF_INET6) {
        goto err;
    }

    wli = malloc(sizeof *wli);
    if (!wli) {
        goto err;
    }

    wli->addr = malloc(res->ai_addrlen);
    if (!wli->addr) {
        goto err;
    }

    wli->next = *wl;
    wli->addrlen = res->ai_addrlen;
    memcpy(wli->addr, res->ai_addr, res->ai_addrlen);

    wli->prefix = 128;
    wli->check_scope_id = 0;

    if (*range == '%') {
        wli->check_scope_id = 1;
        ++range;
    }

    if (*range) {
        wli->prefix = atoi(range);
    }

    if (wli->addr->sa_family == AF_INET) {
        if (wli->prefix > 32) {
            wli->prefix = 32;
        }
    } else if (wli->addr->sa_family == AF_INET6) {
        if (wli->prefix > 128) {
            wli->prefix = 128;
        }
    }


    *wl = wli;
    freeaddrinfo(res);
    return 0;

err:
    if (wli) {
        free(wli->addr);
        free(wli);
    }
    if (res) {
        freeaddrinfo(res);
    }
    return 1;
}

int addr_whitelist_add_spec(
        struct addr_whitelist **wl,
        const char *spec)
{
    char buf[128], *d;
    const char *s;

    for (s = spec, d = buf; ; ++s, ++d) {
        if (*s == 0 || *s == ',' || d - buf >= 127) {
            int ret;

            *d = 0;
            if ((ret = addr_whitelist_add(wl, buf))) {
                return ret;
            }

            if (!*s) {
                return 0;
            }

            d = buf;
        } else {
            *d = *s;
        }
    }
}

// vim: et ts=4 sw=4 colorcolumn=80 nu
