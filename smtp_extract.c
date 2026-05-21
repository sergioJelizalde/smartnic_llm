/*
 * smtp_extract.c — single-core DPDK TCP flow reconstructor + SMTP email extractor
 * -----------------------------------------------------------------------------
 * LIVE CAPTURE BUILD. Polls a real DPDK port (default port 0), reassembles the
 * client->server byte stream of SMTP sessions (TCP dst port 25), locates the
 * DATA command, captures the message up to the <CRLF>.<CRLF> terminator,
 * dot-unstuffs it, and splits the RFC 822 head from the body ("corpus").
 * Each completed email is printed and written to message_N.eml.
 *
 * One lcore, no locks. Runs until Ctrl-C.
 *
 * Live (port bound to a DPDK driver via dpdk-devbind.py):
 *   ./build/smtp_extract -l 0 -n 4 -- -p 0x1
 *
 * Offline replay still works (uses the net_pcap PMD):
 *   ./build/smtp_extract -l 0 -n 1 --no-huge \
 *       --vdev=net_pcap0,rx_pcap=smtp.pcap -- -p 0x1
 *
 * Build: see Makefile (needs a DPDK install discoverable by pkg-config).
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <inttypes.h>
#include <getopt.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_ip_frag.h>

/* ----------------------------- tunables ---------------------------------- */
#define RX_RING_SIZE     2048           /* deeper ring for sustained live RX */
#define NUM_MBUFS        16383
#define MBUF_CACHE_SIZE  256
#define BURST_SIZE       64
#define MAX_FLOWS        65536          /* power of two; open-addressed       */
#define STREAM_MAX       (64u << 20)    /* hard cap per stream: 64 MiB        */
#define FLOW_TIMEOUT_S   120            /* evict flows idle this long          */
#define AGE_INTERVAL_S   5              /* how often to sweep / print stats    */

#define SMTP_PORT        25

/* IPv4 reassembly (rte_ip_frag) */
#define FRAG_BUCKETS         4096
#define FRAG_BUCKET_ENTRIES  16
#define FRAG_MAX_ENTRIES     (FRAG_BUCKETS * FRAG_BUCKET_ENTRIES)
#define FRAG_TTL_MS          1000          /* drop incomplete datagrams after  */
#define DEATH_ROW_PREFETCH   3

/* ------------------------- reassembly structures -------------------------- */

struct seg {                  /* an out-of-order TCP segment, parked          */
    uint32_t    off;          /* byte offset in the stream (seq - base_seq)   */
    uint32_t    len;
    uint8_t    *data;
    struct seg *next;         /* sorted by off                                */
};

enum smtp_state { SMTP_CMD = 0, SMTP_DATA };

enum slot_state { SLOT_FREE = 0, SLOT_USED, SLOT_DEAD };  /* tombstone hashing */

struct flow {
    enum slot_state slot;
    uint32_t  src_ip, dst_ip;     /* network byte order, as seen on the wire  */
    uint16_t  src_port, dst_port;

    int       base_set;
    uint32_t  base_seq;           /* seq of stream[0]                          */
    uint32_t  delivered;          /* contiguous bytes in `stream`              */
    struct seg *ooo;              /* sorted future segments                    */

    uint8_t  *stream;
    uint32_t  stream_cap;

    enum smtp_state state;
    uint32_t  scan_pos;
    uint32_t  data_start;

    uint64_t  last_seen;          /* tsc of last segment, for aging            */
};

static struct flow g_flows[MAX_FLOWS];
static int         g_email_count;
static uint64_t    g_pkts, g_active_flows;

/* IPv4 reassembly state (single core -> no locking) */
static struct rte_ip_frag_tbl       *g_frag_tbl;
static struct rte_ip_frag_death_row  g_death_row;

/* --------------------------- flow table ----------------------------------- */

static inline uint32_t
tuple_hash(uint32_t sip, uint32_t dip, uint16_t sp, uint16_t dp)
{
    return sip * 2654435761u ^ dip * 40503u ^
           ((uint32_t)sp << 16 | dp) * 2246822519u;
}

/* Tombstone-aware lookup-or-insert. Probes past DEAD/USED until a FREE slot
 * proves absence; reuses the first DEAD slot seen for insertion.             */
static struct flow *
flow_lookup(uint32_t sip, uint32_t dip, uint16_t sp, uint16_t dp)
{
    uint32_t h = tuple_hash(sip, dip, sp, dp);
    long tomb = -1;
    for (uint32_t i = 0; i < MAX_FLOWS; i++) {
        uint32_t idx = (h + i) & (MAX_FLOWS - 1);
        struct flow *f = &g_flows[idx];

        if (f->slot == SLOT_FREE) {
            struct flow *t = (tomb >= 0) ? &g_flows[tomb] : f;
            memset(t, 0, sizeof(*t));
            t->slot = SLOT_USED;
            t->src_ip = sip; t->dst_ip = dip;
            t->src_port = sp; t->dst_port = dp;
            t->state = SMTP_CMD;
            g_active_flows++;
            return t;
        }
        if (f->slot == SLOT_DEAD) { if (tomb < 0) tomb = idx; continue; }
        if (f->src_ip == sip && f->dst_ip == dip &&
            f->src_port == sp && f->dst_port == dp)
            return f;
    }
    if (tomb >= 0) {                          /* table full but a tombstone... */
        struct flow *t = &g_flows[tomb];
        memset(t, 0, sizeof(*t));
        t->slot = SLOT_USED;
        t->src_ip = sip; t->dst_ip = dip;
        t->src_port = sp; t->dst_port = dp;
        t->state = SMTP_CMD;
        g_active_flows++;
        return t;
    }
    return NULL;
}

static void
flow_free(struct flow *f)
{
    struct seg *s = f->ooo;
    while (s) { struct seg *n = s->next; rte_free(s->data); rte_free(s); s = n; }
    if (f->stream) rte_free(f->stream);
    f->stream = NULL; f->ooo = NULL;
    f->slot = SLOT_DEAD;                       /* tombstone, not FREE          */
    if (g_active_flows) g_active_flows--;
}

/* ------------------------- stream management ------------------------------- */

static int
stream_reserve(struct flow *f, uint32_t need)
{
    if (need <= f->stream_cap) return 0;
    uint32_t cap = f->stream_cap ? f->stream_cap : 65536;
    while (cap < need) {
        if (cap >= STREAM_MAX) return -1;
        cap <<= 1;
    }
    if (cap > STREAM_MAX) cap = STREAM_MAX;
    uint8_t *p = rte_realloc(f->stream, cap, 0);
    if (!p) return -1;
    f->stream = p; f->stream_cap = cap;
    return 0;
}

static int
stream_append(struct flow *f, const uint8_t *src, uint32_t len)
{
    if (stream_reserve(f, f->delivered + len) < 0) return -1;
    rte_memcpy(f->stream + f->delivered, src, len);
    f->delivered += len;
    return 0;
}

/* Drop the first `consumed` bytes of the stream and shift all bookkeeping so a
 * long-lived connection that sends many messages doesn't grow without bound.  */
static void
stream_compact(struct flow *f, uint32_t consumed)
{
    if (consumed == 0) return;
    if (consumed > f->delivered) consumed = f->delivered;
    memmove(f->stream, f->stream + consumed, f->delivered - consumed);
    f->delivered -= consumed;
    f->base_seq  += consumed;                  /* keep seq->offset mapping     */
    f->data_start = (f->data_start > consumed) ? f->data_start - consumed : 0;
    f->scan_pos   = (f->scan_pos   > consumed) ? f->scan_pos   - consumed : 0;
    for (struct seg *s = f->ooo; s; s = s->next) s->off -= consumed;
}

/* --------------------- out-of-order segment list --------------------------- */

static void
ooo_insert(struct flow *f, uint32_t off, const uint8_t *data, uint32_t len)
{
    struct seg *s = rte_malloc("seg", sizeof(*s), 0);
    if (!s) return;
    s->off = off; s->len = len;
    s->data = rte_malloc("segdata", len, 0);
    if (!s->data) { rte_free(s); return; }
    rte_memcpy(s->data, data, len);
    struct seg **pp = &f->ooo;
    while (*pp && (*pp)->off < off) pp = &(*pp)->next;
    s->next = *pp; *pp = s;
}

static void
ooo_drain(struct flow *f)
{
    struct seg *s;
    while ((s = f->ooo) && s->off <= f->delivered) {
        uint32_t end = s->off + s->len;
        if (end > f->delivered)
            stream_append(f, s->data + (f->delivered - s->off),
                          end - f->delivered);
        f->ooo = s->next;
        rte_free(s->data); rte_free(s);
    }
}

/* --------------------------- email output ---------------------------------- */

static void
emit_email(struct flow *f, uint32_t msg_off, uint32_t msg_end)
{
    uint32_t raw_len = msg_end - msg_off;
    uint8_t *raw = f->stream + msg_off;

    uint8_t *msg = malloc(raw_len + 1);
    if (!msg) return;
    uint32_t n = 0;
    for (uint32_t i = 0; i < raw_len; ) {       /* RFC 5321 dot-unstuffing      */
        int bol = (i == 0) ||
                  (i >= 2 && raw[i-2] == '\r' && raw[i-1] == '\n');
        if (bol && i + 1 < raw_len && raw[i] == '.' && raw[i+1] == '.')
            i++;
        msg[n++] = raw[i++];
    }
    msg[n] = 0;

    uint32_t split = 0, body = n;               /* head | corpus at blank line  */
    for (uint32_t i = 0; i + 3 < n; i++)
        if (msg[i]=='\r'&&msg[i+1]=='\n'&&msg[i+2]=='\r'&&msg[i+3]=='\n')
            { split = i; body = i + 4; break; }

    int idx = ++g_email_count;
    printf("\n========== EMAIL #%d  "
           "%u.%u.%u.%u:%u -> %u.%u.%u.%u:%u  (%u bytes) ==========\n", idx,
        (f->src_ip)&0xff,(f->src_ip>>8)&0xff,(f->src_ip>>16)&0xff,(f->src_ip>>24)&0xff,
        rte_be_to_cpu_16(f->src_port),
        (f->dst_ip)&0xff,(f->dst_ip>>8)&0xff,(f->dst_ip>>16)&0xff,(f->dst_ip>>24)&0xff,
        rte_be_to_cpu_16(f->dst_port), n);
    printf("---- HEAD ----\n%.*s\n", (int)split, msg);
    printf("---- CORPUS (%u bytes) ----\n%.*s\n", n - body, (int)(n - body), msg + body);

    char path[64];
    snprintf(path, sizeof(path), "message_%d.eml", idx);
    FILE *fp = fopen(path, "wb");
    if (fp) { fwrite(msg, 1, n, fp); fclose(fp); printf("[written: %s]\n", path); }
    fflush(stdout);
    free(msg);
}

/* ------------------------- SMTP state machine ------------------------------ */

static void
smtp_scan(struct flow *f)
{
    uint8_t *s   = f->stream;
    uint32_t end = f->delivered;

    for (;;) {
        if (f->state == SMTP_CMD) {
            uint32_t i = f->scan_pos;
            long found = -1;
            for (; i + 6 <= end; i++) {
                int bol = (i == 0) ||
                          (i >= 2 && s[i-2]=='\r' && s[i-1]=='\n');
                if (bol && s[i]=='D'&&s[i+1]=='A'&&s[i+2]=='T'&&s[i+3]=='A'
                        && s[i+4]=='\r'&&s[i+5]=='\n') { found = i; break; }
            }
            if (found < 0) {                    /* keep a small tail for splits */
                f->scan_pos = (end >= 5) ? end - 5 : 0;
                return;
            }
            f->data_start = (uint32_t)found + 6;
            f->scan_pos   = f->data_start;
            f->state      = SMTP_DATA;
        }

        if (f->state == SMTP_DATA) {
            uint32_t i = (f->scan_pos > f->data_start) ? f->scan_pos : f->data_start;
            long found = -1;
            for (; i + 5 <= end; i++)
                if (s[i]=='\r'&&s[i+1]=='\n'&&s[i+2]=='.'
                        &&s[i+3]=='\r'&&s[i+4]=='\n') { found = i; break; }
            if (found < 0) {
                f->scan_pos = (end >= 4) ? end - 4 : f->data_start;
                return;
            }
            emit_email(f, f->data_start, (uint32_t)found + 2);

            /* Drop everything through the terminator so memory stays bounded
             * on long, multi-message connections; resume cleanly at a BOL.    */
            stream_compact(f, (uint32_t)found + 5);
            f->state = SMTP_CMD;
            f->data_start = 0;
            f->scan_pos   = 0;
            s   = f->stream;                    /* reload after compaction      */
            end = f->delivered;
        }
    }
}

/* ----------------------- per-packet ingestion ------------------------------ */

static void
handle_segment(struct flow *f, uint32_t seq, const uint8_t *payload, uint32_t len)
{
    if (len == 0) return;
    if (!f->base_set) { f->base_seq = seq; f->base_set = 1; }

    uint32_t off = seq - f->base_seq;           /* 32-bit modular arithmetic    */
    if (off > STREAM_MAX) return;

    if (off == f->delivered) {
        if (stream_append(f, payload, len) < 0) return;
        ooo_drain(f); smtp_scan(f);
    } else if (off > f->delivered) {
        ooo_insert(f, off, payload, len);
    } else {
        uint32_t already = f->delivered - off;
        if (already < len) {
            if (stream_append(f, payload + already, len - already) < 0) return;
            ooo_drain(f); smtp_scan(f);
        }
    }
}

/* Owns the mbuf: frees it (or hands it to the frag table) before returning.   */
static void
process_packet(struct rte_mbuf *m, uint64_t now)
{
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
        rte_pktmbuf_free(m);
        return;
    }
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);

    /* ---- IPv4 fragment reassembly (DPDK rte_ip_frag) ----------------------
     * A fragmented datagram only yields a usable TCP segment once whole, so we
     * must reassemble at L3 before touching TCP. The table parks fragments and
     * returns the completed datagram (possibly a chained mbuf) on the last one.
     */
    if (rte_ipv4_frag_pkt_is_fragmented(ip)) {
        m->l2_len = sizeof(struct rte_ether_hdr);
        m->l3_len = rte_ipv4_hdr_len(ip);
        struct rte_mbuf *mo =
            rte_ipv4_frag_reassemble_packet(g_frag_tbl, &g_death_row, m, now, ip);
        rte_ip_frag_free_death_row(&g_death_row, DEATH_ROW_PREFETCH);
        if (mo == NULL)
            return;                  /* need more fragments; table owns mbuf  */
        m   = mo;                     /* reassembled datagram — we own it now  */
        eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
        ip  = (struct rte_ipv4_hdr *)(eth + 1);
    }

    /* Contiguous view of the whole IP datagram. For a single-segment mbuf this
     * is a zero-copy pointer; for a reassembled chain it copies into scratch.  */
    static uint8_t scratch[65536];
    uint16_t l2  = sizeof(struct rte_ether_hdr);
    uint16_t tot = rte_be_to_cpu_16(ip->total_length);
    const uint8_t *dg = rte_pktmbuf_read(m, l2, tot, scratch);
    if (dg == NULL) { rte_pktmbuf_free(m); return; }
    ip = (const struct rte_ipv4_hdr *)dg;

    if (ip->next_proto_id != IPPROTO_TCP) { rte_pktmbuf_free(m); return; }
    uint32_t ip_hlen = rte_ipv4_hdr_len(ip);
    const struct rte_tcp_hdr *tcp = (const struct rte_tcp_hdr *)(dg + ip_hlen);
    if (tcp->dst_port != rte_cpu_to_be_16(SMTP_PORT)) {  /* client->server */
        rte_pktmbuf_free(m);
        return;
    }

    uint32_t tcp_hlen = ((tcp->data_off & 0xf0) >> 4) * 4;
    uint32_t paylen   = tot - ip_hlen - tcp_hlen;        /* no bound check     */
    const uint8_t *payload = dg + ip_hlen + tcp_hlen;
    uint32_t seq = rte_be_to_cpu_32(tcp->sent_seq);

    struct flow *f = flow_lookup(ip->src_addr, ip->dst_addr,
                                 tcp->src_port, tcp->dst_port);
    if (f) {
        f->last_seen = now;
        handle_segment(f, seq, payload, paylen);
        if (tcp->tcp_flags & (RTE_TCP_FIN_FLAG | RTE_TCP_RST_FLAG))
            flow_free(f);                            /* connection torn down   */
    }
    rte_pktmbuf_free(m);
}

/* ----------------------------- aging / stats ------------------------------- */

static void
age_flows(uint64_t now, uint64_t timeout_cyc)
{
    for (uint32_t i = 0; i < MAX_FLOWS; i++) {
        struct flow *f = &g_flows[i];
        if (f->slot == SLOT_USED && (now - f->last_seen) > timeout_cyc)
            flow_free(f);
    }
}

/* ----------------------------- port setup ---------------------------------- */

static int
port_init(uint16_t port, struct rte_mempool *pool)
{
    struct rte_eth_conf conf;
    memset(&conf, 0, sizeof(conf));

    struct rte_eth_dev_info info;
    if (rte_eth_dev_info_get(port, &info) != 0) return -1;
    if (info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
        conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

    if (rte_eth_dev_configure(port, 1, 0, &conf) != 0) return -1;

    uint16_t nb_rx = RX_RING_SIZE, nb_tx = 0;
    if (rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rx, &nb_tx) != 0) return -1;

    if (rte_eth_rx_queue_setup(port, 0, nb_rx,
            rte_eth_dev_socket_id(port), NULL, pool) < 0) return -1;

    if (rte_eth_dev_start(port) < 0) return -1;
    rte_eth_promiscuous_enable(port);
    return 0;
}

/* ------------------------------- main -------------------------------------- */

static volatile sig_atomic_t g_force_quit;

static void
on_signal(int sig) { (void)sig; g_force_quit = 1; }

int
main(int argc, char **argv)
{
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "EAL init failed\n");
    argc -= ret; argv += ret;

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    uint16_t portid = 0;
    int opt;
    while ((opt = getopt(argc, argv, "p:")) != -1)
        if (opt == 'p') portid = (uint16_t)__builtin_ctz(strtoul(optarg, NULL, 16));

    if (rte_eth_dev_count_avail() == 0)
        rte_exit(EXIT_FAILURE, "No ethernet ports available\n");

    struct rte_mempool *pool = rte_pktmbuf_pool_create(
        "MBUF_POOL", NUM_MBUFS, MBUF_CACHE_SIZE, 0,
        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!pool) rte_exit(EXIT_FAILURE, "mbuf pool create failed\n");

    if (port_init(portid, pool) != 0)
        rte_exit(EXIT_FAILURE, "port %u init failed\n", portid);

    const uint64_t hz          = rte_get_tsc_hz();
    const uint64_t timeout_cyc = (uint64_t)FLOW_TIMEOUT_S * hz;
    const uint64_t age_cyc     = (uint64_t)AGE_INTERVAL_S * hz;
    uint64_t next_age = rte_get_tsc_cycles() + age_cyc;

    /* IPv4 reassembly table: parks fragments until a datagram is complete or
     * its TTL expires; mbufs to release land in the death row each call.       */
    uint64_t frag_cyc = (hz + 999) / 1000 * FRAG_TTL_MS;
    g_frag_tbl = rte_ip_frag_table_create(FRAG_BUCKETS, FRAG_BUCKET_ENTRIES,
                     FRAG_MAX_ENTRIES, frag_cyc, rte_socket_id());
    if (!g_frag_tbl) rte_exit(EXIT_FAILURE, "ip_frag table create failed\n");
    memset(&g_death_row, 0, sizeof(g_death_row));

    printf("smtp_extract: live capture on port %u, lcore %u — Ctrl-C to stop\n",
           portid, rte_lcore_id());

    while (!g_force_quit) {
        struct rte_mbuf *bufs[BURST_SIZE];
        uint16_t nb = rte_eth_rx_burst(portid, 0, bufs, BURST_SIZE);

        uint64_t now = rte_get_tsc_cycles();
        for (uint16_t i = 0; i < nb; i++) {
            g_pkts++;
            process_packet(bufs[i], now);       /* owns + frees the mbuf        */
        }
        if (nb == 0) rte_pause();               /* be polite while idle         */

        if (now >= next_age) {                  /* periodic sweep + stats       */
            age_flows(now, timeout_cyc);
            printf("[stats] pkts=%" PRIu64 " active_flows=%" PRIu64
                   " emails=%d\n", g_pkts, g_active_flows, g_email_count);
            fflush(stdout);
            next_age = now + age_cyc;
        }
    }

    printf("\nShutting down. Extracted %d email(s).\n", g_email_count);
    rte_ip_frag_table_destroy(g_frag_tbl);
    rte_eth_dev_stop(portid);
    rte_eth_dev_close(portid);
    rte_eal_cleanup();
    return 0;
}

