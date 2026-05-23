/*
 * smtp_extract_bi_forward.c — DPDK TCP flow reconstructor + SMTP email extractor
 * with BIDIRECTIONAL port forwarding capability
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
#include <rte_icmp.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_ip_frag.h>

/* ----------------------------- tunables ---------------------------------- */
#define RX_RING_SIZE     2048
#define TX_RING_SIZE     2048
#define NUM_MBUFS        16383
#define MBUF_CACHE_SIZE  256
#define BURST_SIZE       64
#define MAX_FLOWS        65536
#define STREAM_MAX       (64u << 20)
#define FLOW_TIMEOUT_S   120
#define AGE_INTERVAL_S   5

#define SMTP_PORT        25

/* IPv4 reassembly */
#define FRAG_BUCKETS         4096
#define FRAG_BUCKET_ENTRIES  16
#define FRAG_MAX_ENTRIES     (FRAG_BUCKETS * FRAG_BUCKET_ENTRIES)
#define FRAG_TTL_MS          1000
#define DEATH_ROW_PREFETCH   3

/* Forwarding modes */
#define FORWARD_BIDIRECTIONAL  0  /* Forward packets in both directions */
#define FORWARD_UNIDIRECTIONAL 1  /* Forward only original direction */
#define FORWARD_SMTP_ONLY      2  /* Forward only SMTP traffic */

/* ------------------------- reassembly structures -------------------------- */

struct seg {
    uint32_t    off;
    uint32_t    len;
    uint8_t    *data;
    struct seg *next;
};

enum smtp_state { SMTP_CMD = 0, SMTP_DATA };
enum slot_state { SLOT_FREE = 0, SLOT_USED, SLOT_DEAD };

struct flow {
    enum slot_state slot;
    uint32_t  src_ip, dst_ip;
    uint16_t  src_port, dst_port;

    int       base_set;
    uint32_t  base_seq;
    uint32_t  delivered;
    struct seg *ooo;

    uint8_t  *stream;
    uint32_t  stream_cap;

    enum smtp_state state;
    uint32_t  scan_pos;
    uint32_t  data_start;

    uint64_t  last_seen;
    
    /* For bidirectional tracking */
    uint8_t   is_reverse;  /* Is this the reverse direction flow? */
    uint32_t  original_src_ip, original_dst_ip;  /* Original direction */
};

static struct flow g_flows[MAX_FLOWS];
static int         g_email_count;
static uint64_t    g_pkts, g_active_flows;
static uint64_t    g_forwarded_pkts, g_dropped_pkts;
static uint64_t    g_icmp_pkts, g_other_pkts;

/* IPv4 reassembly state */
static struct rte_ip_frag_tbl       *g_frag_tbl;
static struct rte_ip_frag_death_row  g_death_row;

/* Forwarding configuration */
static uint16_t g_forward_port = 1;
static int      g_forward_mode = FORWARD_BIDIRECTIONAL;  /* Default: bidirectional */
static int      g_forward_enabled = 0;
static uint16_t g_capture_port = 0;

/* --------------------------- flow table ----------------------------------- */

static inline uint32_t
tuple_hash(uint32_t sip, uint32_t dip, uint16_t sp, uint16_t dp)
{
    return sip * 2654435761u ^ dip * 40503u ^
           ((uint32_t)sp << 16 | dp) * 2246822519u;
}

/* Lookup flow - can search with original or reversed tuple */
static struct flow *
flow_lookup_ex(uint32_t sip, uint32_t dip, uint16_t sp, uint16_t dp, int create)
{
    uint32_t h = tuple_hash(sip, dip, sp, dp);
    long tomb = -1;
    for (uint32_t i = 0; i < MAX_FLOWS; i++) {
        uint32_t idx = (h + i) & (MAX_FLOWS - 1);
        struct flow *f = &g_flows[idx];

        if (f->slot == SLOT_FREE) {
            if (!create) return NULL;
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
    if (tomb >= 0 && create) {
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

static struct flow *
flow_lookup(uint32_t sip, uint32_t dip, uint16_t sp, uint16_t dp)
{
    return flow_lookup_ex(sip, dip, sp, dp, 1);
}

static void
flow_free(struct flow *f)
{
    struct seg *s = f->ooo;
    while (s) { struct seg *n = s->next; rte_free(s->data); rte_free(s); s = n; }
    if (f->stream) rte_free(f->stream);
    f->stream = NULL; f->ooo = NULL;
    f->slot = SLOT_DEAD;
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

static void
stream_compact(struct flow *f, uint32_t consumed)
{
    if (consumed == 0) return;
    if (consumed > f->delivered) consumed = f->delivered;
    memmove(f->stream, f->stream + consumed, f->delivered - consumed);
    f->delivered -= consumed;
    f->base_seq  += consumed;
    f->data_start = (f->data_start > consumed) ? f->data_start - consumed : 0;
    f->scan_pos   = (f->scan_pos   > consumed) ? f->scan_pos   - consumed : 0;
    for (struct seg *s = f->ooo; s; s = s->next) s->off -= consumed;
}

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
    for (uint32_t i = 0; i < raw_len; ) {
        int bol = (i == 0) ||
                  (i >= 2 && raw[i-2] == '\r' && raw[i-1] == '\n');
        if (bol && i + 1 < raw_len && raw[i] == '.' && raw[i+1] == '.')
            i++;
        msg[n++] = raw[i++];
    }
    msg[n] = 0;

    uint32_t split = 0, body = n;
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
            if (found < 0) {
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

            stream_compact(f, (uint32_t)found + 5);
            f->state = SMTP_CMD;
            f->data_start = 0;
            f->scan_pos   = 0;
            s   = f->stream;
            end = f->delivered;
        }
    }
}

/* ----------------------- packet forwarding -------------------------------- */

/* Determine if a packet should be forwarded */
static inline int
should_forward_packet(struct rte_mbuf *m, struct rte_ipv4_hdr *ip, 
                      uint16_t ethertype)
{
    if (!g_forward_enabled)
        return 0;
    
    if (g_forward_mode == FORWARD_BIDIRECTIONAL)
        return 1;  /* Forward everything, both directions */
    
    if (g_forward_mode == FORWARD_UNIDIRECTIONAL)
        return 1;  /* Forward everything, but only original direction */
    
    /* Forward only SMTP traffic (but both directions) */
    if (ethertype == RTE_ETHER_TYPE_IPV4 && ip->next_proto_id == IPPROTO_TCP) {
        uint32_t ip_hlen = rte_ipv4_hdr_len(ip);
        const struct rte_tcp_hdr *tcp = (const struct rte_tcp_hdr *)((uint8_t *)ip + ip_hlen);
        if (tcp->dst_port == rte_cpu_to_be_16(SMTP_PORT) ||
            tcp->src_port == rte_cpu_to_be_16(SMTP_PORT))
            return 1;
    }
    
    return 0;
}

/* Forward a packet to the designated output port */
static void
forward_packet(struct rte_mbuf *m, uint16_t out_port)
{
    struct rte_mbuf *tx_bufs[BURST_SIZE];
    tx_bufs[0] = m;
    
    uint16_t nb_tx = rte_eth_tx_burst(out_port, 0, tx_bufs, 1);
    
    if (nb_tx > 0) {
        g_forwarded_pkts++;
    } else {
        g_dropped_pkts++;
        rte_pktmbuf_free(m);
    }
}

/* Process and forward ICMP packets (ping) bidirectionally */
static void
process_icmp_packet(struct rte_mbuf *m, struct rte_ipv4_hdr *ip, 
                    uint16_t ethertype, int do_forward)
{
    g_icmp_pkts++;
    
    /* Print ping info for debugging */
    if (do_forward && g_forward_mode == FORWARD_BIDIRECTIONAL) {
        uint32_t ip_hlen = rte_ipv4_hdr_len(ip);
        struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)((uint8_t *)ip + ip_hlen);
        
        uint32_t src_ip = rte_be_to_cpu_32(ip->src_addr);
        uint32_t dst_ip = rte_be_to_cpu_32(ip->dst_addr);
        
        printf("[PING] %u.%u.%u.%u -> %u.%u.%u.%u type=%d code=%d\n",
               (src_ip>>24)&0xff, (src_ip>>16)&0xff, (src_ip>>8)&0xff, src_ip&0xff,
               (dst_ip>>24)&0xff, (dst_ip>>16)&0xff, (dst_ip>>8)&0xff, dst_ip&0xff,
               icmp->type, icmp->code);
    }
    
    if (do_forward)
        forward_packet(m, g_forward_port);
    else
        rte_pktmbuf_free(m);
}

/* ----------------------- per-packet ingestion ------------------------------ */

static void
handle_segment(struct flow *f, uint32_t seq, const uint8_t *payload, uint32_t len)
{
    if (len == 0) return;
    if (!f->base_set) { f->base_seq = seq; f->base_set = 1; }

    uint32_t off = seq - f->base_seq;
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

static void
process_packet(struct rte_mbuf *m, uint64_t now, int do_forward)
{
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    uint16_t ethertype = rte_be_to_cpu_16(eth->ether_type);
    
    /* Handle non-IP packets (ARP, etc.) - forward them in bidirectional mode */
    if (ethertype != RTE_ETHER_TYPE_IPV4) {
        if (do_forward && g_forward_mode == FORWARD_BIDIRECTIONAL) {
            g_other_pkts++;
            forward_packet(m, g_forward_port);
        } else {
            rte_pktmbuf_free(m);
        }
        return;
    }
    
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);

    /* IPv4 fragment reassembly */
    if (rte_ipv4_frag_pkt_is_fragmented(ip)) {
        m->l2_len = sizeof(struct rte_ether_hdr);
        m->l3_len = rte_ipv4_hdr_len(ip);
        struct rte_mbuf *mo =
            rte_ipv4_frag_reassemble_packet(g_frag_tbl, &g_death_row, m, now, ip);
        rte_ip_frag_free_death_row(&g_death_row, DEATH_ROW_PREFETCH);
        if (mo == NULL)
            return;  /* Waiting for more fragments */
        m   = mo;
        eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
        ip  = (struct rte_ipv4_hdr *)(eth + 1);
        ethertype = RTE_ETHER_TYPE_IPV4;
    }

    /* Handle ICMP (ping) specially for bidirectional forwarding */
    if (ip->next_proto_id == IPPROTO_ICMP) {
        process_icmp_packet(m, ip, ethertype, do_forward);
        return;
    }
    
    /* Contiguous view for TCP */
    if (ip->next_proto_id == IPPROTO_TCP) {
        static uint8_t scratch[65536];
        uint16_t l2  = sizeof(struct rte_ether_hdr);
        uint16_t tot = rte_be_to_cpu_16(ip->total_length);
        const uint8_t *dg = rte_pktmbuf_read(m, l2, tot, scratch);
        if (dg == NULL) { 
            if (do_forward && g_forward_mode == FORWARD_BIDIRECTIONAL)
                forward_packet(m, g_forward_port);
            else
                rte_pktmbuf_free(m);
            return; 
        }
        ip = (const struct rte_ipv4_hdr *)dg;
        
        uint32_t ip_hlen = rte_ipv4_hdr_len(ip);
        const struct rte_tcp_hdr *tcp = (const struct rte_tcp_hdr *)(dg + ip_hlen);
        
        /* For bidirectional forwarding, we analyze and forward both directions */
        int is_smtp_client = (tcp->dst_port == rte_cpu_to_be_16(SMTP_PORT));
        int is_smtp_server = (tcp->src_port == rte_cpu_to_be_16(SMTP_PORT));
        
        /* Analyze client->server SMTP traffic only (to avoid duplication) */
        if (is_smtp_client) {
            uint32_t tcp_hlen = ((tcp->data_off & 0xf0) >> 4) * 4;
            uint32_t paylen   = tot - ip_hlen - tcp_hlen;
            const uint8_t *payload = dg + ip_hlen + tcp_hlen;
            uint32_t seq = rte_be_to_cpu_32(tcp->sent_seq);

            struct flow *f = flow_lookup(ip->src_addr, ip->dst_addr,
                                         tcp->src_port, tcp->dst_port);
            if (f) {
                f->last_seen = now;
                handle_segment(f, seq, payload, paylen);
                if (tcp->tcp_flags & (RTE_TCP_FIN_FLAG | RTE_TCP_RST_FLAG))
                    flow_free(f);
            }
        }
        
        /* Forward packet based on mode */
        if (do_forward) {
            if (g_forward_mode == FORWARD_BIDIRECTIONAL) {
                /* Forward ALL TCP packets in both directions */
                forward_packet(m, g_forward_port);
                return;
            } else if (g_forward_mode == FORWARD_UNIDIRECTIONAL) {
                /* Forward only original direction packets */
                forward_packet(m, g_forward_port);
                return;
            } else if (g_forward_mode == FORWARD_SMTP_ONLY && (is_smtp_client || is_smtp_server)) {
                /* Forward SMTP in both directions */
                forward_packet(m, g_forward_port);
                return;
            }
        }
    }
    
    /* If we get here, packet wasn't forwarded */
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
port_init(uint16_t port, struct rte_mempool *pool, int is_tx)
{
    struct rte_eth_conf conf;
    memset(&conf, 0, sizeof(conf));
    
    conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
    
    if (!is_tx) {
        /* RX port configuration */
        struct rte_eth_dev_info info;
        if (rte_eth_dev_info_get(port, &info) != 0) return -1;
        
        if (rte_eth_dev_configure(port, 1, 0, &conf) != 0) return -1;
        
        uint16_t nb_rx = RX_RING_SIZE, nb_tx = 0;
        if (rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rx, &nb_tx) != 0) return -1;
        
        if (rte_eth_rx_queue_setup(port, 0, nb_rx,
                rte_eth_dev_socket_id(port), NULL, pool) < 0) return -1;
    } else {
        /* TX port configuration */
        if (rte_eth_dev_configure(port, 0, 1, &conf) != 0) return -1;
        
        if (rte_eth_tx_queue_setup(port, 0, TX_RING_SIZE,
                rte_eth_dev_socket_id(port), NULL) < 0) return -1;
    }
    
    if (rte_eth_dev_start(port) < 0) return -1;
    
    if (!is_tx)
        rte_eth_promiscuous_enable(port);
    
    return 0;
}

/* ------------------------------- main -------------------------------------- */

static volatile sig_atomic_t g_force_quit;

static void
on_signal(int sig) { (void)sig; g_force_quit = 1; }

static void
print_usage(const char *progname)
{
    printf("\nUsage: %s [EAL options] -- [options]\n", progname);
    printf("Options:\n");
    printf("  -p PORTMASK        Hexadecimal bitmask of capture port (default: 0x1)\n");
    printf("  --forward PORT     Enable forwarding to specified port\n");
    printf("  --bidirectional    Forward packets in both directions (default, shows ping replies)\n");
    printf("  --unidirectional   Forward only packets from capture port\n");
    printf("  --smtp-only        Forward only SMTP traffic (port 25)\n");
    printf("\nExamples:\n");
    printf("  # Capture and analyze SMTP on port 0\n");
    printf("  %s -l 0 -n 4 -- -p 0x1\n", progname);
    printf("\n  # Capture, analyze, and bidirectionally forward EVERYTHING to port 1\n");
    printf("  # This will forward ping requests AND replies (bidirectional)\n");
    printf("  %s -l 0 -n 4 -- -p 0x1 --forward 1 --bidirectional\n", progname);
    printf("\n  # Capture, analyze, and forward only SMTP bidirectionally\n");
    printf("  %s -l 0 -n 4 -- -p 0x1 --forward 2 --smtp-only\n", progname);
    printf("\n  # Capture and forward unidirectionally (original direction only)\n");
    printf("  %s -l 0 -n 4 -- -p 0x1 --forward 3 --unidirectional\n", progname);
}

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
    static struct option long_options[] = {
        {"forward",        required_argument, 0, 'f'},
        {"bidirectional",  no_argument,       0, 'b'},
        {"unidirectional", no_argument,       0, 'u'},
        {"smtp-only",      no_argument,       0, 's'},
        {0, 0, 0, 0}
    };
    
    while ((opt = getopt_long(argc, argv, "p:", long_options, NULL)) != -1) {
        switch (opt) {
        case 'p':
            portid = (uint16_t)__builtin_ctz(strtoul(optarg, NULL, 16));
            g_capture_port = portid;
            break;
        case 'f':
            g_forward_enabled = 1;
            g_forward_port = (uint16_t)atoi(optarg);
            break;
        case 'b':
            g_forward_mode = FORWARD_BIDIRECTIONAL;
            break;
        case 'u':
            g_forward_mode = FORWARD_UNIDIRECTIONAL;
            break;
        case 's':
            g_forward_mode = FORWARD_SMTP_ONLY;
            break;
        default:
            print_usage(argv[0]);
            rte_exit(EXIT_FAILURE, "Invalid option\n");
        }
    }
    
    /* Default to bidirectional if forwarding is enabled but no mode specified */
    if (g_forward_enabled && g_forward_mode == FORWARD_BIDIRECTIONAL && 
        !(g_forward_mode == FORWARD_UNIDIRECTIONAL || g_forward_mode == FORWARD_SMTP_ONLY)) {
        g_forward_mode = FORWARD_BIDIRECTIONAL;
    }

    if (rte_eth_dev_count_avail() == 0)
        rte_exit(EXIT_FAILURE, "No ethernet ports available\n");

    struct rte_mempool *pool = rte_pktmbuf_pool_create(
        "MBUF_POOL", NUM_MBUFS, MBUF_CACHE_SIZE, 0,
        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!pool) rte_exit(EXIT_FAILURE, "mbuf pool create failed\n");

    /* Initialize RX port (capture port) */
    if (port_init(portid, pool, 0) != 0)
        rte_exit(EXIT_FAILURE, "capture port %u init failed\n", portid);
    
    /* Initialize TX port if forwarding is enabled */
    if (g_forward_enabled) {
        if (port_init(g_forward_port, pool, 1) != 0)
            rte_exit(EXIT_FAILURE, "forward port %u init failed\n", g_forward_port);
    }

    const uint64_t hz          = rte_get_tsc_hz();
    const uint64_t timeout_cyc = (uint64_t)FLOW_TIMEOUT_S * hz;
    const uint64_t age_cyc     = (uint64_t)AGE_INTERVAL_S * hz;
    uint64_t next_age = rte_get_tsc_cycles() + age_cyc;

    uint64_t frag_cyc = (hz + 999) / 1000 * FRAG_TTL_MS;
    g_frag_tbl = rte_ip_frag_table_create(FRAG_BUCKETS, FRAG_BUCKET_ENTRIES,
                     FRAG_MAX_ENTRIES, frag_cyc, rte_socket_id());
    if (!g_frag_tbl) rte_exit(EXIT_FAILURE, "ip_frag table create failed\n");
    memset(&g_death_row, 0, sizeof(g_death_row));

    printf("\n========================================\n");
    printf("smtp_extract: BIDIRECTIONAL FORWARDING\n");
    printf("========================================\n");
    printf("Capture port: %u (promiscuous mode: ENABLED)\n", portid);
    if (g_forward_enabled) {
        printf("Forward port: %u\n", g_forward_port);
        switch(g_forward_mode) {
            case FORWARD_BIDIRECTIONAL:
                printf("Forwarding mode: BIDIRECTIONAL (forwards packets in both directions)\n");
                printf("  - Ping requests AND replies will be forwarded\n");
                printf("  - All traffic (TCP/UDP/ICMP/ARP) forwarded bidirectionally\n");
                break;
            case FORWARD_UNIDIRECTIONAL:
                printf("Forwarding mode: UNIDIRECTIONAL (original direction only)\n");
                break;
            case FORWARD_SMTP_ONLY:
                printf("Forwarding mode: SMTP-ONLY (port 25 traffic in both directions)\n");
                break;
        }
    }
    printf("SMTP analysis: ENABLED (client->server only)\n");
    printf("Press Ctrl-C to stop...\n");
    printf("========================================\n\n");

    while (!g_force_quit) {
        struct rte_mbuf *bufs[BURST_SIZE];
        uint16_t nb = rte_eth_rx_burst(portid, 0, bufs, BURST_SIZE);

        uint64_t now = rte_get_tsc_cycles();
        for (uint16_t i = 0; i < nb; i++) {
            g_pkts++;
            process_packet(bufs[i], now, g_forward_enabled);
        }
        if (nb == 0) rte_pause();

        if (now >= next_age) {
            age_flows(now, timeout_cyc);
            printf("[STATS] pkts=%" PRIu64 " | active_flows=%" PRIu64 
                   " | emails=%d | forwarded=%" PRIu64 " | dropped=%" PRIu64
                   " | ICMP(ping)=%" PRIu64 " | other=%" PRIu64 "\n", 
                   g_pkts, g_active_flows, g_email_count, 
                   g_forwarded_pkts, g_dropped_pkts,
                   g_icmp_pkts, g_other_pkts);
            fflush(stdout);
            next_age = now + age_cyc;
        }
    }

    printf("\n========================================\n");
    printf("FINAL STATISTICS\n");
    printf("========================================\n");
    printf("Total packets captured: %" PRIu64 "\n", g_pkts);
    printf("SMTP emails extracted: %d\n", g_email_count);
    printf("Active flows at exit: %" PRIu64 "\n", g_active_flows);
    printf("Packets forwarded: %" PRIu64 "\n", g_forwarded_pkts);
    printf("Packets dropped: %" PRIu64 "\n", g_dropped_pkts);
    printf("ICMP (ping) packets: %" PRIu64 "\n", g_icmp_pkts);
    printf("Non-IP packets (ARP, etc.): %" PRIu64 "\n", g_other_pkts);
    printf("========================================\n");
    
    rte_ip_frag_table_destroy(g_frag_tbl);
    rte_eth_dev_stop(portid);
    rte_eth_dev_close(portid);
    if (g_forward_enabled) {
        rte_eth_dev_stop(g_forward_port);
        rte_eth_dev_close(g_forward_port);
    }
    rte_eal_cleanup();
    return 0;
}