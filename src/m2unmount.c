/* m2unmount - PS5 payload: keep the console's own view of the M.2 unmounted.
 *
 * The M.2 in the expansion slot carries PS5-Linux inside the console's bfs
 * volume (/dev/ssd1.user, mounted at /mnt/ext1). PS5-OS mounts that volume at
 * every boot and marks it dirty; a session that ends in a kexec into Linux
 * leaves it dirty, so the next boot has to repair it. Unmounting it right
 * after the jailbreak writes the clean state and keeps PS5-OS off the drive
 * for the rest of the session.
 *
 * Loading the ELF is the whole interface: it unmounts every volume on the
 * M.2, says so on screen, then stays resident and unmounts again whenever the
 * console mounts one (e.g. after rest mode). Loading it again replaces the
 * running copy. It never forces: a busy volume is retried, not yanked.
 *
 * It does no periodic work while games run: it sleeps until the kernel reports
 * a mount or unmount (EVFILT_FS), then checks once after the burst settles (a
 * launch mounts dozens of sandboxes), plus a safety check every 10 minutes. One
 * check reads the mount table: ~0.2 ms with ~940 mounts. Entering rest mode
 * breaks its status socket, so it reopens it; and it never wakes more than 10
 * times a second, whatever happens.
 *
 *   status  TCP :9211 - connect and read a short report (nc <ps5> 9211)
 *   log     /data/m2unmount.log - events only, rotated at 256 KiB
 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/event.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <netinet/in.h>
#include <ps5/klog.h>

#define NAME     "m2unmount.elf"
#define VERSION  "1.3"
#define PORT     9211
#define SETTLE_MS 2000                    /* after a mount event, check once it settles */
#define MIN_GAP_S 10                      /* at most one event-driven check per 10 s */
#define SAFETY_S  600                     /* check anyway, in case an event is missed */
#define RETRY_S   10                      /* while an unmount keeps failing */
#define POLL_S    60                      /* only if the kernel gives no mount events */
#define RELISTEN_S 5                      /* reopen the status socket after it breaks */
#define MAX_WAKES 10                      /* per second; more means something is wrong */
#define LOG_PATH "/data/m2unmount.log"
#define LOG_MAX  (256 * 1024)
#define RING     16

/* On-screen toast. The struct layout is the console's, not ours. */
typedef struct notify_request {
    char pad[45];
    char message[3075];
} notify_request_t;
int sceKernelSendNotificationRequest(int, notify_request_t *, size_t, int);

static time_t g_start;
static int    g_unmounts;                 /* successful unmounts since start */
static time_t g_last_unmount;
static int    g_failing;                  /* a failure was reported, no success since */
static int    g_checks, g_bursts;         /* mount-table reads; mount/unmount bursts */
static int    g_watching;                 /* the kernel delivers mount events */
static long   g_wakeups;                  /* times the main loop woke up */
static char   g_state[200] = "starting";
static char   g_ring[RING][200];          /* recent events, for the status port */
static int    g_ring_n;

static void stamp(time_t t, char *buf, size_t n) {
    struct tm tm;
    gmtime_r(&t, &tm);
    strftime(buf, n, "%Y-%m-%d %H:%M:%S UTC", &tm);
}

/* Record an event in the log file, the kernel log and the status ring; with
 * toast set, also show it on the TV. */
static void event(int toast, const char *fmt, ...) {
    char msg[160], ts[32];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    stamp(time(NULL), ts, sizeof(ts));

    snprintf(g_ring[g_ring_n++ % RING], sizeof(g_ring[0]), "%s %s", ts, msg);
    klog_printf("[m2unmount] %s\n", msg);

    struct stat st;
    if (stat(LOG_PATH, &st) == 0 && st.st_size > LOG_MAX)
        rename(LOG_PATH, LOG_PATH ".1");
    int fd = open(LOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0666);
    if (fd >= 0) {
        char line[200];
        int n = snprintf(line, sizeof(line), "%s %s\n", ts, msg);
        (void)write(fd, line, n < (int)sizeof(line) ? (size_t)n : sizeof(line) - 1);
        close(fd);
    }

    if (toast) {
        notify_request_t req;
        memset(&req, 0, sizeof(req));
        snprintf(req.message, sizeof(req.message), "m2unmount: %s", msg);
        sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
    }
}

/* Other processes whose main thread is called NAME. kinfo_proc offsets are
 * this kernel's, as shsrv reads them. */
static int find_others(pid_t *out, int max) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PROC, 0};
    size_t sz = 0;
    if (sysctl(mib, 4, NULL, &sz, NULL, 0) != 0) return 0;
    sz += 16 * 1024;                          /* processes may start meanwhile */
    uint8_t *buf = malloc(sz);
    if (!buf) return 0;
    if (sysctl(mib, 4, buf, &sz, NULL, 0) != 0) { free(buf); return 0; }
    int n = 0;
    pid_t me = getpid();
    for (uint8_t *p = buf; p + 464 <= buf + sz && n < max;) {
        int len = *(int *)p;
        if (len <= 0) break;
        pid_t pid = *(pid_t *)(p + 72);
        if (pid != me && strncmp((const char *)(p + 447), NAME, 17) == 0)
            out[n++] = pid;
        p += len;
    }
    free(buf);
    return n;
}

/* A newer copy wins: an update takes effect by just loading it. */
static void replace_old(void) {
    pid_t pids[8];
    int n = find_others(pids, 8);
    if (n == 0) return;
    pid_t old = pids[0];
    for (int i = 0; i < n; i++) kill(pids[i], SIGKILL);
    for (int t = 0; t < 50 && find_others(pids, 8) > 0; t++) usleep(100 * 1000);
    event(0, "replaced the running copy (pid %d)", old);
}

/* The M.2 in the expansion slot is ssd1 ("/dev/ssd1.user"); the internal
 * drive is ssd0, which this console reports without the "/dev/" prefix. */
static int is_m2_device(const char *dev) {
    if (strncmp(dev, "/dev/", 5) == 0) dev += 5;
    return strncmp(dev, "ssd", 3) == 0 && dev[3] >= '1' && dev[3] <= '9';
}

/* The mount table in a buffer we own (getmntinfo()'s is reused). */
static struct statfs *read_mounts(int *count) {
    int n = getfsstat(NULL, 0, MNT_NOWAIT);
    if (n <= 0) return NULL;
    n += 16;                                  /* headroom for new mounts */
    struct statfs *buf = malloc((size_t)n * sizeof(*buf));
    if (!buf) return NULL;
    n = getfsstat(buf, (long)((size_t)n * sizeof(*buf)), MNT_NOWAIT);
    if (n <= 0) { free(buf); return NULL; }
    *count = n;
    return buf;
}

/* Unmount every M.2 volume. Returns how many stay mounted, -1 if the mount
 * table can't be read. */
static int sweep(int first) {
    int n = 0, left = 0;
    g_checks++;
    struct statfs *m = read_mounts(&n);
    if (!m) {
        snprintf(g_state, sizeof(g_state), "UNKNOWN: can't read the mount table (%s)", strerror(errno));
        return -1;
    }
    for (int i = 0; i < n; i++) {
        const char *on = m[i].f_mntonname, *from = m[i].f_mntfromname;
        if (!is_m2_device(from)) continue;
        if (unmount(on, 0) == 0) {
            g_unmounts++;
            g_last_unmount = time(NULL);
            g_failing = 0;
            if (first) event(1, "%s unmounted, the M.2 is Linux-only now", on);
            else       event(1, "the console mounted %s again - unmounted it", on);
            continue;
        }
        int e = errno;
        left++;
        snprintf(g_state, sizeof(g_state), "MOUNTED: %s (%s), unmount fails: %s", on, from, strerror(e));
        if (!g_failing)
            event(1, "can't unmount %s: %s - retrying every %d s", on, strerror(e), RETRY_S);
        g_failing = 1;
    }
    free(m);
    if (left == 0) {
        g_failing = 0;
        snprintf(g_state, sizeof(g_state), "not mounted, the M.2 is Linux-only");
    }
    return left;
}

static int listen_status(int tries) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_port        = htons(PORT);
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    for (int t = 0; t < tries; t++) {         /* a replaced copy may hold it a moment */
        if (t) sleep(1);
        if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) == 0 && listen(s, 4) == 0)
            return s;
    }
    close(s);
    return -1;
}

static void serve_status(int c) {
    char buf[8192], ts[32];
    size_t len = 0;
    long up = (long)(time(NULL) - g_start);
#define OUT(...) do { if (len < sizeof(buf)) len += snprintf(buf + len, sizeof(buf) - len, __VA_ARGS__); } while (0)
    OUT("m2unmount %s pid %d, up %ldh%02ldm\n", VERSION, getpid(), up / 3600, up / 60 % 60);
    OUT("M.2: %s\n", g_state);
    if (g_unmounts) {
        stamp(g_last_unmount, ts, sizeof(ts));
        OUT("unmounts: %d, last %s\n", g_unmounts, ts);
    } else {
        OUT("unmounts: 0\n");
    }
    if (g_watching)
        OUT("checks: %d (%d after mount/unmount bursts), wakes on mounts + every %d min; wakeups: %ld\n",
            g_checks, g_bursts, SAFETY_S / 60, g_wakeups);
    else
        OUT("checks: %d, every %d s (no mount events from the kernel); wakeups: %ld\n",
            g_checks, POLL_S, g_wakeups);
    OUT("events:\n");
    for (int i = g_ring_n > RING ? g_ring_n - RING : 0; i < g_ring_n; i++)
        OUT("  %s\n", g_ring[i % RING]);
#undef OUT
    if (len > sizeof(buf)) len = sizeof(buf);
    struct timeval tv = {2, 0};
    setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    (void)write(c, buf, len);
}

static long mono_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000L + t.tv_nsec / 1000000;
}

/* Subscribe to (EV_ADD) or drop (EV_DELETE) the kernel's mount events. */
static int fs_events(int kq, int op) {
    struct kevent ev;
    EV_SET(&ev, 0, EVFILT_FS, op == EV_ADD ? EV_ADD | EV_CLEAR : op, 0, 0, NULL);
    return kevent(kq, &ev, 1, NULL, 0, NULL);
}

/* Open the status socket and watch it in kq; -1 if the port can't be had. */
static int status_open(int kq, int tries) {
    int ls = listen_status(tries);
    if (ls >= 0 && kq >= 0) {
        struct kevent ev;
        EV_SET(&ev, ls, EVFILT_READ, EV_ADD, 0, 0, NULL);
        kevent(kq, &ev, 1, NULL, 0, NULL);
    }
    return ls;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    syscall(SYS_thr_set_name, -1, NAME);
    g_start = time(NULL);
    replace_old();
    event(0, "%s started (pid %d)", VERSION, getpid());

    int kq = kqueue();                        /* subscribe first: no mount slips by */
    g_watching = kq >= 0 && fs_events(kq, EV_ADD) == 0;
    if (!g_watching)
        event(0, "no mount events from the kernel (%s) - checking every %d s", strerror(errno), POLL_S);

    int left = sweep(1);
    if (left < 0)
        event(1, "can't read the mount table: %s", strerror(errno));
    else if (left == 0 && g_unmounts == 0)
        event(1, "the M.2 is not mounted - watching");

    int ls = status_open(kq, 10);
    long relisten = 0;                        /* when to reopen a broken status socket */
    if (ls < 0) {
        event(0, "status port %d unavailable: %s", PORT, strerror(errno));
        relisten = mono_ms() + 30 * 1000L;
    }

    long last = mono_ms(), due = 0;           /* due: the check after a mount burst */
    long burst_start = last;                  /* wakeup rate guard */
    int burst = 0, throttled = 0;
    for (;;) {
        long every = 1000L * (g_failing ? RETRY_S : g_watching ? SAFETY_S : POLL_S);
        long next = due && due < last + every ? due : last + every;
        if (ls < 0 && relisten && relisten < next) next = relisten;
        long wait = next - mono_ms();
        if (wait < 0) wait = 0;
        struct timespec to = {wait / 1000, (wait % 1000) * 1000000};
        if (kq < 0) {
            nanosleep(&to, NULL);
        } else {
            struct kevent ev[8];
            int n = kevent(kq, NULL, 0, ev, 8, &to);
            if (n < 0 && errno != EINTR) sleep(1);    /* never spin */
            for (int i = 0; i < n; i++) {
                if (ev[i].filter == EVFILT_READ && (int)ev[i].ident == ls) {
                    /* entering rest mode breaks listening sockets (EV_ERROR, or
                     * accept() failing forever while kevent reports it ready) */
                    int c = -1, broken = ev[i].flags & (EV_EOF | EV_ERROR);
                    if (broken)
                        errno = ev[i].flags & EV_ERROR ? (int)ev[i].data
                              : ev[i].fflags ? (int)ev[i].fflags : ECONNRESET;
                    else
                        c = accept(ls, NULL, NULL);
                    if (c >= 0) {
                        serve_status(c);
                        close(c);
                    } else if (broken || (errno != EINTR && errno != EAGAIN)) {
                        event(0, "status socket broke (flags 0x%x, %s) - reopening in %d s",
                              ev[i].flags, strerror(errno), RELISTEN_S);
                        close(ls);
                        ls = -1;
                        relisten = mono_ms() + RELISTEN_S * 1000L;
                    }
                } else if (ev[i].filter == EVFILT_FS && !due) {
                    /* launching or closing an app mounts or unmounts dozens of
                     * sandboxes: stop listening until the check, one wakeup per burst */
                    g_bursts++;
                    fs_events(kq, EV_DELETE);
                    due = mono_ms() + SETTLE_MS;
                    if (due < last + MIN_GAP_S * 1000L) due = last + MIN_GAP_S * 1000L;
                }
            }
        }
        g_wakeups++;
        long now = mono_ms();
        if (ls < 0 && relisten && now >= relisten) {
            ls = status_open(kq, 1);
            relisten = ls < 0 ? now + 30 * 1000L : 0;
            if (ls >= 0) event(0, "status socket reopened");
        }
        if ((due && now >= due) || now >= last + every) {
            if (due && fs_events(kq, EV_ADD) != 0 && g_watching) {   /* before the check */
                g_watching = 0;
                event(0, "lost mount events (%s) - checking every %d s", strerror(errno), POLL_S);
            }
            due = 0;
            sweep(0);
            last = mono_ms();
        }
        /* whatever happens, never wake more than MAX_WAKES times a second */
        if (now - burst_start >= 1000) {
            burst_start = now;
            burst = 0;
        } else if (++burst > MAX_WAKES) {
            if (!throttled++) event(0, "too many wakeups - throttling to %d/s", MAX_WAKES);
            sleep(1);
        }
    }
}
