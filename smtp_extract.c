/*
 * smtp_extract.c — Bidirectional forwarder + SMTP analyzer (with debug)
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <inttypes.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_icmp.h>
#include <rte_arp.h>
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
#define CAPTURE_PORT     0
#define FORWARD_PORT     1

/* IPv4 reassembly */
#define FRAG_BUCKETS         4096
#define FRAG_BUCKET_ENTRIES  16
#define FRAG_MAX_ENTRIES     (FRAG_BUCKETS * FRAG_BUCKET_ENTRIES)
#define FRAG_TTL_MS          1000
#define DEATH_ROW_PREFETCH   3

/* Debug flags */
#define DEBUG_ICMP 1
#define DEBUG_ARP  1
#define DEBUG_TX   1

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
};

static struct flow g_flows[MAX_FLOWS];

static int      g_email_count;
static uint64_t g_pkts_rx;
static uint64_t g_pkts_tx;
static uint64_t g_active_flows;
static uint64_t g_icmp_req;
static uint64_t g_icmp_reply;
static uint64_t g_arp_pkts;
static uint64_t g_tx_drops;
static uint64_t g_other_pkts;

/* IPv4 reassembly state */
static struct rte_ip_frag_tbl       *g_frag_tbl;
static struct rte_ip_frag_death_row  g_death_row;

/* --------------------------- flow table ----------------------------------- */

static inline uint32_t
tuple_hash(uint32_t sip, uint32_t dip, uint16_t sp, uint16_t dp)
{
    return sip * 2654435761u ^
           dip * 40503u ^
           ((uint32_t)sp << 16 | dp) * 2246822519u;
}

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
            t->src_ip = sip;
            t->dst_ip = dip;
            t->src_port = sp;
            t->dst_port = dp;
            t->state = SMTP_CMD;
            g_active_flows++;
            return t;
        }

        if (f->slot == SLOT_DEAD) {
            if (tomb < 0)
                tomb = idx;
            continue;
        }

        if (f->src_ip == sip &&
            f->dst_ip == dip &&
            f->src_port == sp &&
            f->dst_port == dp) {
            return f;
        }
    }

    if (tomb >= 0) {
        struct flow *t = &g_flows[tomb];
        memset(t, 0, sizeof(*t));
        t->slot = SLOT_USED;
        t->src_ip = sip;
        t->dst_ip = dip;
        t->src_port = sp;
        t->dst_port = dp;
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

    while (s) {
        struct seg *n = s->next;
        rte_free(s->data);
        rte_free(s);
        s = n;
    }

    if (f->stream)
        rte_free(f->stream);

    f->stream = NULL;
    f->ooo = NULL;
    f->slot = SLOT_DEAD;

    if (g_active_flows)
        g_active_flows--;
}

/* ------------------------- stream management ------------------------------ */

static int
stream_reserve(struct flow *f, uint32_t need)
{
    if (need <= f->stream_cap)
        return 0;

    uint32_t cap = f->stream_cap ? f->stream_cap : 65536;

    while (cap < need) {
        if (cap >= STREAM_MAX)
            return -1;
        cap <<= 1;
    }

    if (cap > STREAM_MAX)
        cap = STREAM_MAX;

    uint8_t *p = rte_realloc(f->stream, cap, 0);
    if (!p)
        return -1;

    f->stream = p;
    f->stream_cap = cap;

    return 0;
}

static int
stream_append(struct flow *f, const uint8_t *src, uint32_t len)
{
    if (stream_reserve(f, f->delivered + len) < 0)
        return -1;

    rte_memcpy(f->stream + f->delivered, src, len);
    f->delivered += len;

    return 0;
}

static void
stream_compact(struct flow *f, uint32_t consumed)
{
    if (consumed == 0)
        return;

    if (consumed > f->delivered)
        consumed = f->delivered;

    memmove(f->stream, f->stream + consumed, f->delivered - consumed);

    f->delivered -= consumed;
    f->base_seq  += consumed;
    f->data_start = (f->data_start > consumed) ? f->data_start - consumed : 0;
    f->scan_pos   = (f->scan_pos > consumed) ? f->scan_pos - consumed : 0;

    for (struct seg *s = f->ooo; s; s = s->next)
        s->off -= consumed;
}

static void
ooo_insert(struct flow *f, uint32_t off, const uint8_t *data, uint32_t len)
{
    struct seg *s = rte_malloc("seg", sizeof(*s), 0);
    if (!s)
        return;

    s->off = off;
    s->len = len;
    s->data = rte_malloc("segdata", len, 0);

    if (!s->data) {
        rte_free(s);
        return;
    }

    rte_memcpy(s->data, data, len);

    struct seg **pp = &f->ooo;

    while (*pp && (*pp)->off < off)
        pp = &(*pp)->next;

    s->next = *pp;
    *pp = s;
}

static void
ooo_drain(struct flow *f)
{
    struct seg *s;

    while ((s = f->ooo) && s->off <= f->delivered) {
        uint32_t end = s->off + s->len;

        if (end > f->delivered) {
            stream_append(f,
                          s->data + (f->delivered - s->off),
                          end - f->delivered);
        }

        f->ooo = s->next;
        rte_free(s->data);
        rte_free(s);
    }
}

/* --------------------------- email output --------------------------------- */

static void
emit_email(struct flow *f, uint32_t msg_off, uint32_t msg_end)
{
    uint32_t raw_len = msg_end - msg_off;
    uint8_t *raw = f->stream + msg_off;

    uint8_t *msg = malloc(raw_len + 1);
    if (!msg)
        return;

    uint32_t n = 0;

    for (uint32_t i = 0; i < raw_len; ) {
        int bol = (i == 0) ||
                  (i >= 2 && raw[i - 2] == '\r' && raw[i - 1] == '\n');

        if (bol && i + 1 < raw_len && raw[i] == '.' && raw[i + 1] == '.')
            i++;

        msg[n++] = raw[i++];
    }

    msg[n] = 0;

    uint32_t split = 0;
    uint32_t body = n;

    for (uint32_t i = 0; i + 3 < n; i++) {
        if (msg[i] == '\r' &&
            msg[i + 1] == '\n' &&
            msg[i + 2] == '\r' &&
            msg[i + 3] == '\n') {
            split = i;
            body = i + 4;
            break;
        }
    }

    int idx = ++g_email_count;

    printf("\n========== EMAIL #%d  "
           "%u.%u.%u.%u:%u -> %u.%u.%u.%u:%u  (%u bytes) ==========\n",
           idx,
           (f->src_ip) & 0xff,
           (f->src_ip >> 8) & 0xff,
           (f->src_ip >> 16) & 0xff,
           (f->src_ip >> 24) & 0xff,
           rte_be_to_cpu_16(f->src_port),
           (f->dst_ip) & 0xff,
           (f->dst_ip >> 8) & 0xff,
           (f->dst_ip >> 16) & 0xff,
           (f->dst_ip >> 24) & 0xff,
           rte_be_to_cpu_16(f->dst_port),
           n);

    printf("---- HEAD ----\n%.*s\n", (int)split, msg);
    printf("---- CORPUS (%u bytes) ----\n%.*s\n",
           n - body,
           (int)(n - body),
           msg + body);

    char path[64];
    snprintf(path, sizeof(path), "message_%d.eml", idx);

    FILE *fp = fopen(path, "wb");
    if (fp) {
        fwrite(msg, 1, n, fp);
        fclose(fp);
        printf("[written: %s]\n", path);
    }

    fflush(stdout);
    free(msg);
}

/* ------------------------- SMTP state machine ----------------------------- */

static void
smtp_scan(struct flow *f)
{
    uint8_t *s = f->stream;
    uint32_t end = f->delivered;

    for (;;) {
        if (f->state == SMTP_CMD) {
            uint32_t i = f->scan_pos;
            long found = -1;

            for (; i + 6 <= end; i++) {
                int bol = (i == 0) ||
                          (i >= 2 && s[i - 2] == '\r' && s[i - 1] == '\n');

                if (bol &&
                    s[i] == 'D' &&
                    s[i + 1] == 'A' &&
                    s[i + 2] == 'T' &&
                    s[i + 3] == 'A' &&
                    s[i + 4] == '\r' &&
                    s[i + 5] == '\n') {
                    found = i;
                    break;
                }
            }

            if (found < 0) {
                f->scan_pos = (end >= 5) ? end - 5 : 0;
                return;
            }

            f->data_start = (uint32_t)found + 6;
            f->scan_pos = f->data_start;
            f->state = SMTP_DATA;
        }

        if (f->state == SMTP_DATA) {
            uint32_t i = (f->scan_pos > f->data_start)
                         ? f->scan_pos
                         : f->data_start;
            long found = -1;

            for (; i + 5 <= end; i++) {
                if (s[i] == '\r' &&
                    s[i + 1] == '\n' &&
                    s[i + 2] == '.' &&
                    s[i + 3] == '\r' &&
                    s[i + 4] == '\n') {
                    found = i;
                    break;
                }
            }

            if (found < 0) {
                f->scan_pos = (end >= 4) ? end - 4 : f->data_start;
                return;
            }

            emit_email(f, f->data_start, (uint32_t)found + 2);

            stream_compact(f, (uint32_t)found + 5);

            f->state = SMTP_CMD;
            f->data_start = 0;
            f->scan_pos = 0;

            s = f->stream;
            end = f->delivered;
        }
    }
}

/* ----------------------- packet forwarding helpers ------------------------ */

static void
forward_packet(struct rte_mbuf *m, uint16_t out_port, const char *direction)
{
    /* 
     * For transparent bridging, we should NOT modify the packet at all.
     * The packet should be forwarded exactly as received.
     * The destination MAC determines which port it goes to.
     * 
     * If you need to modify MACs (for routing/NAT), uncomment the appropriate section.
     */
    
    /* Send packet without any modification (true transparent bridging) */
    uint16_t nb_tx = rte_eth_tx_burst(out_port, 0, &m, 1);

    if (nb_tx == 1) {
        g_pkts_tx++;
#if DEBUG_TX
        struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
        printf("[TX] %s -> port %u (dst MAC: %02x:%02x:%02x:%02x:%02x:%02x)\n", 
               direction, out_port,
               eth->dst_addr.addr_bytes[0],
               eth->dst_addr.addr_bytes[1],
               eth->dst_addr.addr_bytes[2],
               eth->dst_addr.addr_bytes[3],
               eth->dst_addr.addr_bytes[4],
               eth->dst_addr.addr_bytes[5]);
#endif
    } else {
        g_tx_drops++;
        printf("[TX-DROP] Failed to send packet on port %u (%s)\n", out_port, direction);
        rte_pktmbuf_free(m);
    }
}

static void
print_icmp_packet(const char *tag, struct rte_ipv4_hdr *ip)
{
    uint32_t src_ip = rte_be_to_cpu_32(ip->src_addr);
    uint32_t dst_ip = rte_be_to_cpu_32(ip->dst_addr);

    uint32_t ip_hlen = rte_ipv4_hdr_len(ip);
    struct rte_icmp_hdr *icmp =
        (struct rte_icmp_hdr *)((uint8_t *)ip + ip_hlen);

    const char *type_str = (icmp->icmp_type == 8) ? "REQUEST" :
                           (icmp->icmp_type == 0) ? "REPLY" : "OTHER";

    printf("[ICMP %s] %s %u.%u.%u.%u -> %u.%u.%u.%u type=%u code=%u\n",
           type_str,
           tag,
           (src_ip >> 24) & 0xff,
           (src_ip >> 16) & 0xff,
           (src_ip >> 8) & 0xff,
           src_ip & 0xff,
           (dst_ip >> 24) & 0xff,
           (dst_ip >> 16) & 0xff,
           (dst_ip >> 8) & 0xff,
           dst_ip & 0xff,
           icmp->icmp_type,
           icmp->icmp_code);
}

/* ----------------------- SMTP packet analyzer ----------------------------- */

static void
analyze_smtp(struct rte_mbuf *m, uint64_t now)
{
    struct rte_ether_hdr *eth =
        rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

    if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
        return;

    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);

    /*
     * Handle fragmented packets.
     */
    if (rte_ipv4_frag_pkt_is_fragmented(ip)) {
        m->l2_len = sizeof(struct rte_ether_hdr);
        m->l3_len = rte_ipv4_hdr_len(ip);

        struct rte_mbuf *mo =
            rte_ipv4_frag_reassemble_packet(g_frag_tbl,
                                             &g_death_row,
                                             m,
                                             now,
                                             ip);

        rte_ip_frag_free_death_row(&g_death_row, DEATH_ROW_PREFETCH);

        if (mo == NULL)
            return;

        m = mo;
        eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
        ip = (struct rte_ipv4_hdr *)(eth + 1);
    }

    if (ip->next_proto_id != IPPROTO_TCP)
        return;

    uint32_t ip_hlen = rte_ipv4_hdr_len(ip);
    struct rte_tcp_hdr *tcp =
        (struct rte_tcp_hdr *)((uint8_t *)ip + ip_hlen);

    /*
     * Only analyze client -> server SMTP.
     */
    if (tcp->dst_port != rte_cpu_to_be_16(SMTP_PORT))
        return;

    uint16_t tot_len = rte_be_to_cpu_16(ip->total_length);
    uint32_t tcp_hlen = ((tcp->data_off & 0xf0) >> 4) * 4;

    if (tot_len < ip_hlen + tcp_hlen)
        return;

    uint32_t pay_len = tot_len - ip_hlen - tcp_hlen;

    if (pay_len == 0)
        return;

    uint8_t *payload = (uint8_t *)tcp + tcp_hlen;
    uint32_t seq = rte_be_to_cpu_32(tcp->sent_seq);

    struct flow *f = flow_lookup(ip->src_addr,
                                 ip->dst_addr,
                                 tcp->src_port,
                                 tcp->dst_port);

    if (!f)
        return;

    f->last_seen = now;

    if (!f->base_set) {
        f->base_seq = seq;
        f->base_set = 1;
    }

    uint32_t off = seq - f->base_seq;

    if (off <= STREAM_MAX) {
        if (off == f->delivered) {
            if (stream_append(f, payload, pay_len) == 0) {
                ooo_drain(f);
                smtp_scan(f);
            }
        } else if (off > f->delivered) {
            ooo_insert(f, off, payload, pay_len);
        } else {
            uint32_t already = f->delivered - off;

            if (already < pay_len) {
                if (stream_append(f,
                                  payload + already,
                                  pay_len - already) == 0) {
                    ooo_drain(f);
                    smtp_scan(f);
                }
            }
        }
    }

    if (tcp->tcp_flags & (RTE_TCP_FIN_FLAG | RTE_TCP_RST_FLAG))
        flow_free(f);
}

/* ----------------------- packet processing -------------------------------- */

static void
process_capture_packet(struct rte_mbuf *m, uint64_t now)
{
    struct rte_ether_hdr *eth =
        rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

    /* Handle ARP packets */
    if (eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
        g_arp_pkts++;
#if DEBUG_ARP
        printf("[ARP] 0->1 forwarding\n");
#endif
        forward_packet(m, FORWARD_PORT, "ARP_0->1");
        return;
    }

    if (eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
        struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);

        if (ip->next_proto_id == IPPROTO_ICMP) {
            uint32_t ip_hlen = rte_ipv4_hdr_len(ip);
            struct rte_icmp_hdr *icmp =
                (struct rte_icmp_hdr *)((uint8_t *)ip + ip_hlen);
            
            if (icmp->icmp_type == 8) {
                g_icmp_req++;
            } else if (icmp->icmp_type == 0) {
                g_icmp_reply++;
            }
            
            print_icmp_packet("0->1", ip);
            forward_packet(m, FORWARD_PORT, "ICMP_0->1");
            return;
        }

        if (ip->next_proto_id == IPPROTO_TCP) {
            analyze_smtp(m, now);
            forward_packet(m, FORWARD_PORT, "TCP_0->1");
            return;
        }
    }

    /* Forward all other packets */
    g_other_pkts++;
    forward_packet(m, FORWARD_PORT, "OTHER_0->1");
}

static void
process_forward_packet(struct rte_mbuf *m)
{
    struct rte_ether_hdr *eth =
        rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

    /* Handle ARP packets */
    if (eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
        g_arp_pkts++;
#if DEBUG_ARP
        printf("[ARP] 1->0 forwarding\n");
#endif
        forward_packet(m, CAPTURE_PORT, "ARP_1->0");
        return;
    }

    if (eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
        struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);

        if (ip->next_proto_id == IPPROTO_ICMP) {
            uint32_t ip_hlen = rte_ipv4_hdr_len(ip);
            struct rte_icmp_hdr *icmp =
                (struct rte_icmp_hdr *)((uint8_t *)ip + ip_hlen);
            
            if (icmp->icmp_type == 8) {
                g_icmp_req++;
            } else if (icmp->icmp_type == 0) {
                g_icmp_reply++;
            }
            
            print_icmp_packet("1->0", ip);
            forward_packet(m, CAPTURE_PORT, "ICMP_1->0");
            return;
        }
    }

    /* Forward all other packets */
    g_other_pkts++;
    forward_packet(m, CAPTURE_PORT, "OTHER_1->0");
}

/* ----------------------------- aging / stats ------------------------------ */

static void
age_flows(uint64_t now, uint64_t timeout_cyc)
{
    for (uint32_t i = 0; i < MAX_FLOWS; i++) {
        struct flow *f = &g_flows[i];

        if (f->slot == SLOT_USED &&
            (now - f->last_seen) > timeout_cyc) {
            flow_free(f);
        }
    }
}

/* ----------------------------- port setup --------------------------------- */

static int
port_init(uint16_t port, struct rte_mempool *pool)
{
    struct rte_eth_conf conf;
    memset(&conf, 0, sizeof(conf));

    conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;

    struct rte_eth_dev_info info;
    if (rte_eth_dev_info_get(port, &info) != 0)
        return -1;

    if (rte_eth_dev_configure(port, 1, 1, &conf) != 0)
        return -1;

    uint16_t nb_rx = RX_RING_SIZE;
    uint16_t nb_tx = TX_RING_SIZE;

    if (rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rx, &nb_tx) != 0)
        return -1;

    if (rte_eth_rx_queue_setup(port,
                               0,
                               nb_rx,
                               rte_eth_dev_socket_id(port),
                               NULL,
                               pool) < 0) {
        return -1;
    }

    if (rte_eth_tx_queue_setup(port,
                               0,
                               nb_tx,
                               rte_eth_dev_socket_id(port),
                               NULL) < 0) {
        return -1;
    }

    if (rte_eth_dev_start(port) < 0)
        return -1;

    rte_eth_promiscuous_enable(port);

    struct rte_ether_addr mac;
    rte_eth_macaddr_get(port, &mac);

    printf("Port %u MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           port,
           mac.addr_bytes[0],
           mac.addr_bytes[1],
           mac.addr_bytes[2],
           mac.addr_bytes[3],
           mac.addr_bytes[4],
           mac.addr_bytes[5]);

    return 0;
}

/* ------------------------------- main ------------------------------------- */

static volatile sig_atomic_t g_force_quit;

static void
on_signal(int sig)
{
    (void)sig;
    g_force_quit = 1;
}

int
main(int argc, char **argv)
{
    int ret = rte_eal_init(argc, argv);

    if (ret < 0)
        rte_exit(EXIT_FAILURE, "EAL init failed\n");

    argc -= ret;
    argv += ret;

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    (void)argc;
    (void)argv;

    if (rte_eth_dev_count_avail() < 2) {
        rte_exit(EXIT_FAILURE, "Need at least 2 ports: 0 and 1\n");
    }

    struct rte_mempool *pool =
        rte_pktmbuf_pool_create("MBUF_POOL",
                                NUM_MBUFS,
                                MBUF_CACHE_SIZE,
                                0,
                                RTE_MBUF_DEFAULT_BUF_SIZE,
                                rte_socket_id());

    if (!pool)
        rte_exit(EXIT_FAILURE, "mbuf pool create failed\n");

    if (port_init(CAPTURE_PORT, pool) != 0) {
        rte_exit(EXIT_FAILURE,
                 "capture port %u init failed\n",
                 CAPTURE_PORT);
    }

    if (port_init(FORWARD_PORT, pool) != 0) {
        rte_exit(EXIT_FAILURE,
                 "forward port %u init failed\n",
                 FORWARD_PORT);
    }

    const uint64_t hz = rte_get_tsc_hz();

    uint64_t frag_cyc = (hz + 999) / 1000 * FRAG_TTL_MS;

    g_frag_tbl =
        rte_ip_frag_table_create(FRAG_BUCKETS,
                                 FRAG_BUCKET_ENTRIES,
                                 FRAG_MAX_ENTRIES,
                                 frag_cyc,
                                 rte_socket_id());

    if (!g_frag_tbl)
        rte_exit(EXIT_FAILURE, "ip_frag table create failed\n");

    memset(&g_death_row, 0, sizeof(g_death_row));

    const uint64_t timeout_cyc = (uint64_t)FLOW_TIMEOUT_S * hz;
    const uint64_t age_cyc = (uint64_t)AGE_INTERVAL_S * hz;

    uint64_t next_age = rte_get_tsc_cycles() + age_cyc;

    printf("\n========================================\n");
    printf("SMTP Extractor + Transparent Forwarder\n");
    printf("========================================\n");
    printf("Port %u <----> Port %u\n", CAPTURE_PORT, FORWARD_PORT);
    printf("Mode: transparent bidirectional L2 forwarding\n");
    printf("ARP: forwarded transparently (no replies generated)\n");
    printf("ICMP: forwarded both directions\n");
    printf("SMTP: extracting TCP dst port %d from port %u -> port %u\n",
           SMTP_PORT,
           CAPTURE_PORT,
           FORWARD_PORT);
    printf("\nNOTE: Make sure 172.16.1.3 is reachable and has proper ARP entries\n");
    printf("      You may need to add static ARP on both sides:\n");
    printf("      arp -s 172.16.1.1 <MAC of port 0>\n");
    printf("      arp -s 172.16.1.3 <MAC of port 1>\n");
    printf("========================================\n\n");

    while (!g_force_quit) {
        struct rte_mbuf *bufs_capture[BURST_SIZE];
        struct rte_mbuf *bufs_forward[BURST_SIZE];

        uint64_t now = rte_get_tsc_cycles();

        uint16_t nb_capture =
            rte_eth_rx_burst(CAPTURE_PORT,
                             0,
                             bufs_capture,
                             BURST_SIZE);

        for (uint16_t i = 0; i < nb_capture; i++) {
            g_pkts_rx++;
            process_capture_packet(bufs_capture[i], now);
        }

        uint16_t nb_forward =
            rte_eth_rx_burst(FORWARD_PORT,
                             0,
                             bufs_forward,
                             BURST_SIZE);

        for (uint16_t i = 0; i < nb_forward; i++) {
            g_pkts_rx++;
            process_forward_packet(bufs_forward[i]);
        }

        if (nb_capture == 0 && nb_forward == 0)
            usleep(100);

        if (now >= next_age) {
            age_flows(now, timeout_cyc);

            printf("[STATS] RX=%" PRIu64
                   " TX=%" PRIu64
                   " TX_DROP=%" PRIu64
                   " | flows=%" PRIu64
                   " | emails=%d"
                   " | ICMP_REQ=%" PRIu64
                   " | ICMP_REPLY=%" PRIu64
                   " | ARP=%" PRIu64
                   " | OTHER=%" PRIu64
                   "\n",
                   g_pkts_rx,
                   g_pkts_tx,
                   g_tx_drops,
                   g_active_flows,
                   g_email_count,
                   g_icmp_req,
                   g_icmp_reply,
                   g_arp_pkts,
                   g_other_pkts);

            fflush(stdout);
            next_age = now + age_cyc;
        }
    }

    printf("\n========================================\n");
    printf("FINAL STATISTICS\n");
    printf("========================================\n");
    printf("Packets received:       %" PRIu64 "\n", g_pkts_rx);
    printf("Packets forwarded:      %" PRIu64 "\n", g_pkts_tx);
    printf("TX drops:               %" PRIu64 "\n", g_tx_drops);
    printf("SMTP emails extracted:  %d\n", g_email_count);
    printf("ICMP Requests:          %" PRIu64 "\n", g_icmp_req);
    printf("ICMP Replies:           %" PRIu64 "\n", g_icmp_reply);
    printf("ARP packets:            %" PRIu64 "\n", g_arp_pkts);
    printf("Other packets:          %" PRIu64 "\n", g_other_pkts);
    printf("Active flows at exit:   %" PRIu64 "\n", g_active_flows);
    printf("========================================\n");

    if (g_frag_tbl)
        rte_ip_frag_table_destroy(g_frag_tbl);

    rte_eth_dev_stop(CAPTURE_PORT);
    rte_eth_dev_close(CAPTURE_PORT);

    rte_eth_dev_stop(FORWARD_PORT);
    rte_eth_dev_close(FORWARD_PORT);

    rte_eal_cleanup();

    return 0;
}