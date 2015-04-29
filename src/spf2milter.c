#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <grp.h>
#include <netinet/in.h>
#include <pwd.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <libmilter/mfapi.h>
#include <spf2/spf.h>

#include "addr_whitelist.h"

#define EXIT_UNAVAILIBLE 1
#define EXIT_USAGE 2

struct spf2milter_context {
    SPF_request_t *req;
    char *received_spf;
};

static SPF_server_t *spf_server;
static struct addr_whitelist *whitelist = NULL;

static void spf2milter_context_free(struct spf2milter_context *spfctx)
{
    if (spfctx) {
        if (spfctx->req) {
            SPF_request_free(spfctx->req);
        }

        if (spfctx->received_spf) {
            free(spfctx->received_spf);
        }

        free(spfctx);
    }
}

static sfsistat spf2milter_connect(SMFICTX *ctx, char *hostname,
        _SOCK_ADDR *hostaddr)
{
    struct spf2milter_context *spfctx;

    if (!(hostaddr->sa_family == AF_INET || hostaddr->sa_family == AF_INET6)) {
        goto cont;
    }

    if (addr_whitelist_check(whitelist, hostaddr)) {
        goto cont;
    }

    spfctx = malloc(sizeof *spfctx);
    smfi_setpriv(ctx, spfctx);

    spfctx->req = SPF_request_new(spf_server);
    spfctx->received_spf = NULL;

    if (hostaddr->sa_family == AF_INET) {
        SPF_request_set_ipv4(spfctx->req,
                ((struct sockaddr_in *) hostaddr)->sin_addr);
    } else if (hostaddr->sa_family == AF_INET6) {
        SPF_request_set_ipv6(spfctx->req,
                ((struct sockaddr_in6 *) hostaddr)->sin6_addr);
    }

cont:
    return SMFIS_CONTINUE;
}


static sfsistat spf2milter_close(SMFICTX *ctx)
{
    struct spf2milter_context *spfctx;
    spfctx = smfi_getpriv(ctx);

    if (!spfctx) {
        goto cont;
    }

    spf2milter_context_free(spfctx);
    smfi_setpriv(ctx, NULL);

cont:
    return SMFIS_CONTINUE;
}

static sfsistat spf2milter_helo(SMFICTX *ctx, char *helohost)
{
    struct spf2milter_context *spfctx;
    spfctx = smfi_getpriv(ctx);

    if (!spfctx) {
        goto cont;
    }

    if (SPF_request_set_helo_dom(spfctx->req, helohost)) {
        goto err;
    }

cont:
    return SMFIS_CONTINUE;
err:
    spf2milter_context_free(spfctx);
    smfi_setpriv(ctx, NULL);
    return SMFIS_CONTINUE;
}

static sfsistat spf2milter_envfrom(SMFICTX *ctx, char **argv)
{
    struct spf2milter_context *spfctx;
    size_t received_spf_remain = SPF_RECEIVED_SPF_SIZE;
    const char *received_spf;
    char *rcpt = NULL, *addr_start, *addr_end;

    SPF_response_t *resp = NULL;

    spfctx = smfi_getpriv(ctx);

    if (!spfctx) {
        goto cont;
    }

    if (!((addr_start = strchr(argv[0], '<'))
            && (addr_end = strchr(++addr_start, '>')))) {
        addr_start = argv[0];
        addr_end = addr_start + strlen(argv[0]);
    }
    rcpt = malloc(addr_end - addr_start + 1);

    if (!rcpt) {
        goto err;
    }

    strncpy(rcpt, addr_start, addr_end - addr_start);
    rcpt[addr_end - addr_start] = 0;

    if (SPF_request_set_env_from(spfctx->req, rcpt)) {
        goto err;
    }

    SPF_request_query_mailfrom(spfctx->req, &resp);

    received_spf = SPF_response_get_received_spf_value(resp);
    if (received_spf) {
        spfctx->received_spf = malloc(strlen(received_spf) + 1);
        if (!spfctx->received_spf) {
            goto err;
        }
        strcpy(spfctx->received_spf, received_spf);
    }

    SPF_response_free(resp);
    SPF_request_free(spfctx->req);
    spfctx->req = NULL;
    free(rcpt);

cont:
    return SMFIS_CONTINUE;
err:
    if (resp) {
        SPF_response_free(resp);
    }
    free(rcpt);
    spf2milter_context_free(spfctx);
    smfi_setpriv(ctx, NULL);
    return SMFIS_CONTINUE;
}

static sfsistat spf2milter_eom(SMFICTX *ctx)
{
    struct spf2milter_context *spfctx;

    spfctx = smfi_getpriv(ctx);

    if (!spfctx) {
        goto cont;
    }

    smfi_insheader(ctx, 0, "Received-SPF", spfctx->received_spf);

    spf2milter_context_free(spfctx);
    smfi_setpriv(ctx, NULL);

cont:
    return SMFIS_CONTINUE;
}

static int childpid = 0;

static void killchild(int sig)
{
    if (childpid > 0) {
        kill(childpid, sig);
    }
}

static int setup_signal_handler()
{
    struct sigaction sact;

    sact.sa_handler = killchild;
    sigemptyset(&sact.sa_mask);
    sigaddset(&sact.sa_mask, SIGTERM);
    sact.sa_flags = 0;

    if (sigaction(SIGTERM, &sact, NULL)) {
        fprintf(stderr, "sigaction(SIGTERM): %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

int main(int argc, char **argv)
{
    int opt;
    char *addr = NULL, *sockfn = NULL, *chrootdir = NULL,
         *user = NULL, *group = NULL;
    int setuser = 0, setgroup = 0, rmsocket = 0;
    uid_t uid;
    gid_t gid;
    pid_t pid;
    int ret;

    while ((opt = getopt(argc, argv, "fg:hr:u:w:")) != -1) {
        switch (opt) {
            case 'f':
                rmsocket = 1;
                break;
            case 'r':
                chrootdir = optarg;
                break;
            case 'u':
                user = optarg;
                break;
            case 'g':
                group = optarg;
                break;
            case 'w':
                if (addr_whitelist_add_spec(&whitelist, optarg)) {
                    return EXIT_USAGE;
                }
                break;
            case '?':
            case 'h':
                printf("Illegal arguments.\n");
                return EXIT_USAGE;
        }
    }

    if (optind + 1 != argc) {
        return EXIT_USAGE;
    }

    addr = argv[optind];

    // prepare sockfn
    if (addr[0] == '/') {
        sockfn = addr;
    } else if (strncmp(addr, "unix:", 5) == 0) {
        sockfn = addr + 5;
    } else if (strncmp(addr, "local:", 6) == 0) {
        sockfn = addr + 6;
    }

    // split user and group if they are specified in one argument
    if (user) {
        size_t i;
        size_t len = strlen(user);
        for (i = 0; i != len; ++i) {
            if (user[i] == ':') {
                user[i] = 0;
                group = user + i + 1;
                break;
            }
        }
    }

    // prepare setuser & uid
    if (user && user[0]) {
        if (isdigit(user[0])) {
            uid = atoi(user);
        } else {
            const struct passwd *pw = getpwnam(user);
            if (!pw) {
                fprintf(stderr, "Failed to get gid of group \"%s\": "
                        "getpwname: %s\n", user, strerror(errno));
                return EXIT_UNAVAILIBLE;
            }
            uid = pw->pw_uid;
        }

        setuser = 1;
    }

    // prepare setgroup & gid
    if (group && group[0]) {
        if (isdigit(group[0])) {
            gid = atoi(group);
        } else {
            const struct group *gr = getgrnam(group);
            if (!gr) {
                fprintf(stderr, "Failed to get gid of group \"%s\": "
                        "getgrname: %s\n", group, strerror(errno));
                return EXIT_UNAVAILIBLE;
            }
            gid = gr->gr_gid;
        }

        setgroup = 1;

    }

    // chroot
    if (chrootdir) {
        if (chroot(chrootdir)) {
            fprintf(stderr, "chroot: %s\n", strerror(errno));
            return EXIT_UNAVAILIBLE;
        }
    }

    struct smfiDesc smfilter;

    memset(&smfilter, 0, sizeof smfilter);

    smfilter.xxfi_name = "spf2milter";
    smfilter.xxfi_version = SMFI_VERSION;
    smfilter.xxfi_flags = SMFIF_ADDHDRS;

    smfilter.xxfi_connect = spf2milter_connect;
    smfilter.xxfi_helo = spf2milter_helo;
    smfilter.xxfi_envfrom = spf2milter_envfrom;
    smfilter.xxfi_eom = spf2milter_eom;
    smfilter.xxfi_close = spf2milter_close;

    if (smfi_register(smfilter) == MI_FAILURE) {
        fprintf(stderr, "Failed to register filter\n");
        return EXIT_UNAVAILIBLE;
    }

    if (smfi_setconn(addr) == MI_FAILURE) {
        fprintf(stderr, "Failed to set address to %s\n", argv[optind]);
        return EXIT_UNAVAILIBLE;
    }

    if (setgroup) {
        if (setgid(gid)) {
            fprintf(stderr, "setgid: %s\n", strerror(errno));
            return EXIT_UNAVAILIBLE;
        }
    }

    if (setuser) {
        if (setuid(uid)) {
            fprintf(stderr, "setuid: %s\n", strerror(errno));
            return EXIT_UNAVAILIBLE;
        }
    }

    if (setup_signal_handler()) {
            return EXIT_UNAVAILIBLE;
    }

spawn_child:
    if ((childpid = pid = fork()) == -1) {
            fprintf(stderr, "fork: %s\n", strerror(errno));
            return EXIT_UNAVAILIBLE;
    }

    if (pid) {
        siginfo_t info;

        rmsocket = 1;

        while (1) {
            if (waitid(P_PID, pid, &info, WEXITED) == -1) {
                if (errno == EINTR) {
                    continue;
                } else if (errno == ECHILD) {
                    goto spawn_child;
                } else {
                    fprintf(stderr, "wait: %s\n", strerror(errno));
                    return EXIT_UNAVAILIBLE;
                }
            }

            switch (info.si_code) {
                case CLD_EXITED:
                    return info.si_status;

                case CLD_KILLED:
                case CLD_DUMPED:
                    goto spawn_child;

                default:
                    return EXIT_UNAVAILIBLE;
            }
        }
    } else {
        if (prctl(PR_SET_PDEATHSIG, SIGTERM) == -1) {
            fprintf(stderr, "Failed to setup PR_SET_PDEATHSIG\n");
            return EXIT_UNAVAILIBLE;
        }

        if (smfi_opensocket(rmsocket) == MI_FAILURE) {
            fprintf(stderr, "Failed to create socket\n");
            return EXIT_UNAVAILIBLE;
        }

        spf_server = SPF_server_new(SPF_DNS_CACHE, 0);

        ret = smfi_main();

        SPF_server_free(spf_server);

        return ret;
    }
}

// vim: et ts=4 sw=4 colorcolumn=80 nu
