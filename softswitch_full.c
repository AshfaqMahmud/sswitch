/*
 * softswitch_full.c
 *
 * Feature-rich educational Layer-2 software switch using libpcap.
 *
 * Features:
 *  - Multi-interface capture & injection using libpcap
 *  - Per-VLAN learning MAC table (MAC+VLAN -> port)
 *  - VLAN (802.1Q) parsing and tag handling
 *  - Port modes: ACCESS (untagged) and TRUNK (tagged)
 *  - Static MAC entries (persist until removed)
 *  - MAC aging with configurable timeout
 *  - Per-port simple ACLs (deny list by MAC)
 *  - Port mirroring (SPAN): copy traffic to mirror port
 *  - CLI over stdin to inspect & configure the switch live
 *  - BPDU detection: drop from learning/forwarding (prevents naive loops)
 *
 * Build:
 *   gcc softswitch_full.c -o softswitch_full -lpcap -lpthread
 *
 * Run:
 *   sudo ./softswitch_full if0 if1 if2 ...
 *
 * Notes:
 *  - This is for learning & testing. Not meant for production.
 *  - There are many opportunities for performance improvements (packet batching,
 *    AF_PACKET, lock sharding, zero-copy, etc).
 *  - VLAN behavior: ACCESS ports send untagged; TRUNK ports send tagged.
 *    Native VLANs are not implemented; trunk sends tag for all VLANs.
 *
 * Author: (generated for you) — read and learn!
 */

#define _POSIX_C_SOURCE 200809L
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <net/ethernet.h> /* struct ether_header */
#include <netinet/if_ether.h>
#include <errno.h>
#include <ctype.h>

/* ----------------- Configurable defaults ----------------- */
#define MAX_IFACES 32
#define SNAPLEN 65535
#define PROMISC 1
#define READ_TIMEOUT_MS 1000
#define MAC_TABLE_SIZE 8192
#define MAC_AGE_SECONDS_DEFAULT 300
#define MAX_CLI_LINE 256

/* ----------------- Types & enums ----------------- */

typedef enum
{
    PORT_MODE_ACCESS = 0,
    PORT_MODE_TRUNK = 1
} port_mode_t;

typedef struct
{
    char ifname[64];
    pcap_t *handle;
    int index;
    pthread_t thread;
    unsigned long rx_packets;
    unsigned long tx_packets;
    port_mode_t mode;         /* access or trunk */
    unsigned int access_vlan; /* used only in access mode (1..4094) */
    int mirror_to;            /* -1 means no mirror; otherwise port index to mirror to */
    /* ACL: deny list of MACs (simple array) */
    unsigned char acl_denies[64][6];
    int acl_count;
} iface_t;

/* Mac entry: unique by MAC + VLAN */
typedef struct mac_entry
{
    unsigned char mac[6];
    unsigned short vlan; /* 0 means native/untagged default VLAN (0 allowed but avoid) */
    int port;            /* port index */
    int is_static;       /* if true, not removed by aging */
    time_t last_seen;
    struct mac_entry *next;
} mac_entry;

/* ----------------- Global state ----------------- */

iface_t ifaces[MAX_IFACES];
int iface_count = 0;

mac_entry *mac_table[MAC_TABLE_SIZE];
pthread_mutex_t mac_table_lock = PTHREAD_MUTEX_INITIALIZER;

volatile sig_atomic_t keep_running = 1;
int mac_age_seconds = MAC_AGE_SECONDS_DEFAULT;

/* ----------------- Utilities ----------------- */

static inline unsigned int mix32(unsigned int x)
{
    /* simple integer mixing */
    x ^= x >> 16;
    x *= 0x7feb352d;
    x ^= x >> 15;
    x *= 0x846ca68b;
    x ^= x >> 16;
    return x;
}

static inline unsigned int mac_vlan_hash(const unsigned char mac[6], unsigned short vlan)
{
    unsigned int h = 0;
    for (int i = 0; i < 6; ++i)
        h = (h * 31) + mac[i];
    h = h ^ (unsigned int)vlan;
    return mix32(h) % MAC_TABLE_SIZE;
}

void mac_to_str(const unsigned char mac[6], char out[18])
{
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* returns 1 if mac equals broadcast */
int is_broadcast_mac(const unsigned char mac[6])
{
    for (int i = 0; i < 6; ++i)
        if (mac[i] != 0xff)
            return 0;
    return 1;
}

/* multicast if lowest bit of first octet is 1 */
int is_multicast_mac(const unsigned char mac[6])
{
    return (mac[0] & 0x01) ? 1 : 0;
}

/* BPDU detection: STP BPDUs are Ethernet type 0x0026? Historically they use 802.1D payload with
   destination 01:80:c2:00:00:00; commonly recognized BPDU dest MAC. We'll drop frames to that address.
*/
int is_bpdu(const unsigned char dst[6])
{
    unsigned char bpdu[6] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x00};
    return (memcmp(dst, bpdu, 6) == 0);
}

/* ----------------- MAC table ops ----------------- */

/* lookup port; if found and not static, update last_seen (unless is_static) */
int mac_lookup_port_vlan(const unsigned char mac[6], unsigned short vlan)
{
    unsigned int idx = mac_vlan_hash(mac, vlan);
    pthread_mutex_lock(&mac_table_lock);
    mac_entry *e = mac_table[idx];
    while (e)
    {
        if (e->vlan == vlan && memcmp(e->mac, mac, 6) == 0)
        {
            e->last_seen = time(NULL);
            int port = e->port;
            pthread_mutex_unlock(&mac_table_lock);
            return port;
        }
        e = e->next;
    }
    pthread_mutex_unlock(&mac_table_lock);
    return -1;
}

/* Learn MAC+VLAN on port. If exists, update port/time. */
void mac_learn_vlan(const unsigned char mac[6], unsigned short vlan, int port, int make_static)
{
    unsigned int idx = mac_vlan_hash(mac, vlan);
    time_t now = time(NULL);

    pthread_mutex_lock(&mac_table_lock);
    mac_entry *e = mac_table[idx];
    while (e)
    {
        if (e->vlan == vlan && memcmp(e->mac, mac, 6) == 0)
        {
            /* update */
            e->port = port;
            e->last_seen = now;
            if (make_static)
                e->is_static = 1;
            pthread_mutex_unlock(&mac_table_lock);
            return;
        }
        e = e->next;
    }

    /* new entry */
    mac_entry *ne = malloc(sizeof(mac_entry));
    if (!ne)
    {
        fprintf(stderr, "mac_learn_vlan: malloc failed\n");
        pthread_mutex_unlock(&mac_table_lock);
        return;
    }
    memcpy(ne->mac, mac, 6);
    ne->vlan = vlan;
    ne->port = port;
    ne->is_static = make_static;
    ne->last_seen = now;
    ne->next = mac_table[idx];
    mac_table[idx] = ne;
    pthread_mutex_unlock(&mac_table_lock);
}

/* Add static entry wrapper */
void mac_add_static(const unsigned char mac[6], unsigned short vlan, int port)
{
    mac_learn_vlan(mac, vlan, port, 1);
}

/* Delete static or any entry (by mac+vlan) */
void mac_delete(const unsigned char mac[6], unsigned short vlan)
{
    unsigned int idx = mac_vlan_hash(mac, vlan);
    pthread_mutex_lock(&mac_table_lock);
    mac_entry **prev = &mac_table[idx];
    mac_entry *cur = mac_table[idx];
    while (cur)
    {
        if (cur->vlan == vlan && memcmp(cur->mac, mac, 6) == 0)
        {
            *prev = cur->next;
            free(cur);
            pthread_mutex_unlock(&mac_table_lock);
            return;
        }
        prev = &cur->next;
        cur = cur->next;
    }
    pthread_mutex_unlock(&mac_table_lock);
}

/* Age out dynamic entries */
void mac_table_age(int age_seconds)
{
    time_t now = time(NULL);
    pthread_mutex_lock(&mac_table_lock);
    for (int i = 0; i < MAC_TABLE_SIZE; ++i)
    {
        mac_entry **prev = &mac_table[i];
        mac_entry *cur = mac_table[i];
        while (cur)
        {
            if (!cur->is_static && ((now - cur->last_seen) > age_seconds))
            {
                mac_entry *del = cur;
                *prev = cur->next;
                cur = *prev;
                free(del);
            }
            else
            {
                prev = &cur->next;
                cur = cur->next;
            }
        }
    }
    pthread_mutex_unlock(&mac_table_lock);
}

/* Print table */
void mac_table_print(void)
{
    pthread_mutex_lock(&mac_table_lock);
    printf("----- MAC table -----\n");
    for (int i = 0; i < MAC_TABLE_SIZE; ++i)
    {
        mac_entry *e = mac_table[i];
        while (e)
        {
            char s[18];
            mac_to_str(e->mac, s);
            printf("VLAN %u | %s -> port %d %s (seen %lds)\n",
                   e->vlan, s, e->port, e->is_static ? "[static]" : "",
                   (long)(time(NULL) - e->last_seen));
            e = e->next;
        }
    }
    printf("---------------------\n");
    pthread_mutex_unlock(&mac_table_lock);
}

/* Flush entire table */
void mac_table_flush(void)
{
    pthread_mutex_lock(&mac_table_lock);
    for (int i = 0; i < MAC_TABLE_SIZE; ++i)
    {
        mac_entry *e = mac_table[i];
        while (e)
        {
            mac_entry *n = e->next;
            free(e);
            e = n;
        }
        mac_table[i] = NULL;
    }
    pthread_mutex_unlock(&mac_table_lock);
}

/* ----------------- VLAN parsing helpers -----------------
   We'll detect 802.1Q tags (ethertype 0x8100). On receive, we return:
     - vlan_id (1..4094) if tagged
     - 0 if untagged (we'll treat as access VLAN to be determined by port)
   Also we return pointer and length of payload after tag so forwarding sends correct bytes.
*/
int parse_8021q(const unsigned char *pkt, int pkt_len, unsigned short *out_vlan, const unsigned char **payload, int *payload_len, unsigned short *ethertype_out)
{
    if (pkt_len < sizeof(struct ether_header))
        return -1;
    const struct ether_header *eth = (const struct ether_header *)pkt;
    unsigned short eth_type = ntohs(eth->ether_type);
    const unsigned char *ptr = pkt + sizeof(struct ether_header);
    int remaining = pkt_len - sizeof(struct ether_header);

    if (eth_type == ETHERTYPE_VLAN)
    { /* 0x8100 */
        if (remaining < 4)
            return -1;
        unsigned short tci = ntohs(*(unsigned short *)ptr);
        unsigned short vlan_id = tci & 0x0fff; /* 12-bit VLAN ID */
        unsigned short next_type = ntohs(*(unsigned short *)(ptr + 2));
        *out_vlan = vlan_id;
        *ethertype_out = next_type;
        *payload = ptr + 4;
        *payload_len = remaining - 4;
        return 0;
    }
    else
    {
        *out_vlan = 0; /* untagged */
        *ethertype_out = eth_type;
        *payload = ptr;
        *payload_len = remaining;
        return 0;
    }
}

/* Helper to build a tagged frame in a temp buffer (we preserve original dst/src and payload).
   tag_vlan=0 means untagged (copy original packet).
   Returns length of buffer in outbuf_len. Caller must provide sufficiently large buffer (SNAPLEN).
*/
int build_out_frame(const unsigned char *in_pkt, int in_len, unsigned short tag_vlan, unsigned char *outbuf, int outbuf_size)
{
    if (in_len < sizeof(struct ether_header))
        return -1;
    if (tag_vlan == 0)
    {
        /* send as-is (untagged) */
        if (in_len > outbuf_size)
            return -1;
        memcpy(outbuf, in_pkt, in_len);
        return in_len;
    }
    else
    {
        /* need to insert 802.1Q tag after src MAC (i.e., after dest(6)+src(6) add 4 bytes and then rest) */
        if (in_len + 4 > outbuf_size)
            return -1;
        /* copy dest + src (12 bytes) */
        memcpy(outbuf, in_pkt, 12);
        /* tpid 0x8100 */
        outbuf[12] = 0x81;
        outbuf[13] = 0x00;
        /* tci: priority 0, CFI 0, vlan id lower 12 bits */
        unsigned short tci = htons(tag_vlan & 0x0fff);
        memcpy(outbuf + 14, &tci, 2);
        /* copy the rest (original ethertype+payload) */
        memcpy(outbuf + 16, in_pkt + 12, in_len - 12);
        return in_len + 4;
    }
}

/* ----------------- ACL & mirror helpers ----------------- */

int port_acl_denies(int port, const unsigned char mac[6])
{
    iface_t *p = &ifaces[port];
    for (int i = 0; i < p->acl_count; ++i)
    {
        if (memcmp(p->acl_denies[i], mac, 6) == 0)
            return 1;
    }
    return 0;
}

/* mirror: if ifaces[i].mirror_to != -1 then also send a copy to that port (unconditional) */

/* ----------------- Forwarding logic ----------------- */

void send_packet_to_port(int out_port, const unsigned char *pkt, int pkt_len, unsigned short vlan_id, int incoming_port)
{
    if (out_port < 0 || out_port >= iface_count)
        return;
    /* enforce ACL: if destination MAC is denied on out_port, drop */
    const struct ether_header *eth = (const struct ether_header *)pkt;
    unsigned char dst[6];
    memcpy(dst, eth->ether_dhost, 6);
    if (port_acl_denies(out_port, dst))
        return;

    /* Build output frame according to port mode:
       - ACCESS: send untagged; use that port's access_vlan as outer VLAN (if mismatch drop/strip)
       - TRUNK: send tagged with vlan_id
    */
    iface_t *op = &ifaces[out_port];
    unsigned char outbuf[SNAPLEN];
    int out_len = 0;

    if (op->mode == PORT_MODE_ACCESS)
    {
        /* send untagged. If incoming frame was tagged for a different VLAN than this access VLAN,
           the frame should not be forwarded to this access port (port isolation by VLAN).
           Therefore only forward if vlan_id == op->access_vlan OR frame is untagged and op->access_vlan==0
        */
        if (vlan_id != op->access_vlan)
        {
            /* do not forward across VLANs to access port */
            return;
        }
        /* send untagged: if input was tagged, strip tag; we assume pkt is the raw packet as captured */
        /* If pkt is tagged, it has tag bytes present; but packet we received might be tagged or untagged.
           For simplicity, we reconstruct an untagged frame by removing tag if present.
        */
        /* detect if packet is tagged by checking ethertype at offset 12 */
        if (pkt_len >= 16)
        {
            unsigned short maybe_tpid = ntohs(*(unsigned short *)(pkt + 12));
            if (maybe_tpid == 0x8100 && pkt_len > 16)
            {
                /* strip 4 bytes */
                memcpy(outbuf, pkt, 12);
                memcpy(outbuf + 12, pkt + 16, pkt_len - 16);
                out_len = pkt_len - 4;
            }
            else
            {
                memcpy(outbuf, pkt, pkt_len);
                out_len = pkt_len;
            }
        }
        else
        {
            memcpy(outbuf, pkt, pkt_len);
            out_len = pkt_len;
        }
    }
    else
    {
        /* TRUNK: send tagged with vlan_id (we always tag for trunk) */
        if (vlan_id == 0)
        {
            /* untagged incoming: treat vlan 1 or port.access_vlan? We'll treat untagged as port's access_vlan if it was configured as access on sender (but tricky).
               Simpler policy: tag with vlan_id 1 if unknown (legacy). But better: we don't guess: we'll tag with 1. */
            vlan_id = 1;
        }
        out_len = build_out_frame(pkt, pkt_len, vlan_id, outbuf, sizeof(outbuf));
        if (out_len < 0)
            return;
    }

    int res = pcap_sendpacket(ifaces[out_port].handle, outbuf, out_len);
    if (res == 0)
    {
        ifaces[out_port].tx_packets++;
    }
    else
    {
        fprintf(stderr, "send failed on %s: %s\n", ifaces[out_port].ifname, pcap_geterr(ifaces[out_port].handle));
    }

    /* mirror if configured: mirror_to sends copy to that port (no VLAN filtering) */
    if (ifaces[out_port].mirror_to != -1 && ifaces[out_port].mirror_to != out_port)
    {
        int mport = ifaces[out_port].mirror_to;
        /* just forward same outbuf to mirror port but do not loop mirror indefinitely */
        if (mport >= 0 && mport < iface_count)
        {
            pcap_sendpacket(ifaces[mport].handle, outbuf, out_len);
        }
    }
}

/* Flood: send to all ports in same VLAN except incoming; honoring ACLs and port membership */
void flood_packet_vlan(const unsigned char *pkt, int pkt_len, unsigned short vlan_id, int incoming_idx)
{
    for (int i = 0; i < iface_count; ++i)
    {
        if (i == incoming_idx)
            continue;
        /* port membership: access ports only accept their access_vlan; trunk accepts all */
        iface_t *p = &ifaces[i];
        if (p->mode == PORT_MODE_ACCESS)
        {
            if (p->access_vlan != vlan_id)
                continue;
        }
        /* send */
        send_packet_to_port(i, pkt, pkt_len, vlan_id, incoming_idx);
    }
}

/* ----------------- Packet callback (per-interface) ----------------- */

/* user parameter will be a pointer to an int (index) allocated per thread */
void packet_callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    int incoming_idx = *((int *)user);
    iface_t *incoming = &ifaces[incoming_idx];
    incoming->rx_packets++;

    if (h->caplen < sizeof(struct ether_header))
        return;

    const struct ether_header *eth = (const struct ether_header *)bytes;
    unsigned char dst[6], src[6];
    memcpy(dst, eth->ether_dhost, 6);
    memcpy(src, eth->ether_shost, 6);

    /* Drop if ACL on incoming port forbids source? We'll not block learning by source ACLs here. */
    if (is_bpdu(dst))
    {
        /* Drop BPDU: do not learn or forward. */
        return;
    }

    /* Determine VLAN: parse 802.1Q */
    unsigned short vlan = 0;
    const unsigned char *payload = NULL;
    int payload_len = 0;
    unsigned short ethertype = 0;
    if (parse_8021q(bytes, h->caplen, &vlan, &payload, &payload_len, &ethertype) < 0)
    {
        /* malformed; ignore */
        return;
    }

    /* If untagged (vlan==0) we map it to incoming access VLAN if the port is ACCESS.
       If port is TRUNK and untagged, we treat vlan as 0 (or default to 1). We'll treat vlan 0 as special.
    */
    if (vlan == 0 && incoming->mode == PORT_MODE_ACCESS)
    {
        vlan = incoming->access_vlan;
    }
    else if (vlan == 0 && incoming->mode == PORT_MODE_TRUNK)
    {
        /* Keep 0; in forwarding we'll tag trunk frames. But to avoid VLAN-less ambiguity, map to 1 */
        vlan = 1;
    }

    /* Learn source MAC -> incoming port for this VLAN (unless ACL denies learning?) */
    mac_learn_vlan(src, vlan, incoming_idx, 0);

    /* If destination is broadcast or multicast -> flood */
    if (is_broadcast_mac(dst) || is_multicast_mac(dst))
    {
        flood_packet_vlan(bytes, h->caplen, vlan, incoming_idx);
        return;
    }

    /* If destination is in ACL deny for incoming port (?) We'll check destination ACL on outgoing port during send */
    /* find port for dst */
    int out_port = mac_lookup_port_vlan(dst, vlan);
    if (out_port >= 0)
    {
        /* Known: if out_port == incoming -> drop (already on same port) */
        if (out_port == incoming_idx)
        {
            return;
        }
        /* send to that port (will enforce ACL & VLAN membership inside send_packet_to_port) */
        send_packet_to_port(out_port, bytes, h->caplen, vlan, incoming_idx);
    }
    else
    {
        /* Unknown: flood */
        flood_packet_vlan(bytes, h->caplen, vlan, incoming_idx);
    }
}

/* Thread function for interface capture */
void *iface_loop_fn(void *arg)
{
    iface_t *iface = (iface_t *)arg;
    int *idxptr = malloc(sizeof(int));
    if (!idxptr)
        return NULL;
    *idxptr = iface->index;
    int r = pcap_loop(iface->handle, -1, packet_callback, (u_char *)idxptr);
    if (r == -1)
    {
        fprintf(stderr, "pcap_loop error on %s: %s\n", iface->ifname, pcap_geterr(iface->handle));
    }
    free(idxptr);
    return NULL;
}

/* ----------------- Aging thread ----------------- */
void *aging_thread_fn(void *arg)
{
    (void)arg;
    while (keep_running)
    {
        sleep(5);
        mac_table_age(mac_age_seconds);
    }
    return NULL;
}

/* ----------------- CLI handling (stdin) ----------------- */

void show_help(void)
{
    printf("Commands:\n");
    printf("  help                     - show this help\n");
    printf("  ports                    - list ports and modes\n");
    printf("  macs                     - show MAC table\n");
    printf("  stats                    - show per-port stats\n");
    printf("  flush                    - flush MAC table\n");
    printf("  aging <seconds>          - set MAC aging time\n");
    printf("  addstatic <mac> <vlan> <port> - add static mac (mac e.g. aa:bb:cc:dd:ee:ff)\n");
    printf("  delmac <mac> <vlan>     - delete entry by mac+vlan\n");
    printf("  setport <port> access <vlan> - set port to access mode with VLAN\n");
    printf("  setport <port> trunk     - set port to trunk mode\n");
    printf("  mirror <src> <dst>      - mirror traffic from src port to dst port (-1 to disable)\n");
    printf("  acladd <port> <mac>     - add mac to port deny list\n");
    printf("  aclclear <port>         - clear ACL for port\n");
    printf("  quit                    - exit\n");
}

/* parse MAC string like aa:bb:cc:dd:ee:ff (case-insensitive) into 6-byte array. Returns 0 on success */
int parse_mac(const char *s, unsigned char mac[6])
{
    int values[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x",
               &values[0], &values[1], &values[2],
               &values[3], &values[4], &values[5]) != 6)
        return -1;
    for (int i = 0; i < 6; ++i)
        mac[i] = (unsigned char)values[i];
    return 0;
}

void cli_loop(void)
{
    char line[MAX_CLI_LINE];
    while (keep_running)
    {
        printf("switch> ");
        fflush(stdout);
        if (!fgets(line, sizeof(line), stdin))
        {
            /* EOF (pipe closed) -> exit */
            keep_running = 0;
            break;
        }
        /* trim newline */
        char *nl = strchr(line, '\n');
        if (nl)
            *nl = 0;
        /* tokenize */
        char *cmd = strtok(line, " \t");
        if (!cmd)
            continue;

        if (strcmp(cmd, "help") == 0)
        {
            show_help();
        }
        else if (strcmp(cmd, "ports") == 0)
        {
            for (int i = 0; i < iface_count; ++i)
            {
                printf("port %d: %s mode=%s access_vlan=%u mirror=%d acl_count=%d\n",
                       i, ifaces[i].ifname,
                       ifaces[i].mode == PORT_MODE_ACCESS ? "ACCESS" : "TRUNK",
                       ifaces[i].access_vlan, ifaces[i].mirror_to, ifaces[i].acl_count);
            }
        }
        else if (strcmp(cmd, "macs") == 0)
        {
            mac_table_print();
        }
        else if (strcmp(cmd, "stats") == 0)
        {
            for (int i = 0; i < iface_count; ++i)
            {
                printf("%s: rx=%lu tx=%lu\n", ifaces[i].ifname, ifaces[i].rx_packets, ifaces[i].tx_packets);
            }
        }
        else if (strcmp(cmd, "flush") == 0)
        {
            mac_table_flush();
            printf("mac table flushed\n");
        }
        else if (strcmp(cmd, "aging") == 0)
        {
            char *arg = strtok(NULL, " \t");
            if (!arg)
            {
                printf("usage: aging <seconds>\n");
                continue;
            }
            int v = atoi(arg);
            if (v <= 0)
            {
                printf("invalid\n");
                continue;
            }
            mac_age_seconds = v;
            printf("aging set to %d seconds\n", mac_age_seconds);
        }
        else if (strcmp(cmd, "addstatic") == 0)
        {
            char *macs = strtok(NULL, " \t");
            char *vlans = strtok(NULL, " \t");
            char *ports = strtok(NULL, " \t");
            if (!macs || !vlans || !ports)
            {
                printf("usage: addstatic <mac> <vlan> <port>\n");
                continue;
            }
            unsigned char m[6];
            if (parse_mac(macs, m) != 0)
            {
                printf("bad mac\n");
                continue;
            }
            int vlan = atoi(vlans);
            int port = atoi(ports);
            if (port < 0 || port >= iface_count)
            {
                printf("bad port\n");
                continue;
            }
            mac_add_static(m, vlan, port);
            printf("added static %s vlan %d -> port %d\n", macs, vlan, port);
        }
        else if (strcmp(cmd, "delmac") == 0)
        {
            char *macs = strtok(NULL, " \t");
            char *vlans = strtok(NULL, " \t");
            if (!macs || !vlans)
            {
                printf("usage: delmac <mac> <vlan>\n");
                continue;
            }
            unsigned char m[6];
            if (parse_mac(macs, m) != 0)
            {
                printf("bad mac\n");
                continue;
            }
            int vlan = atoi(vlans);
            mac_delete(m, vlan);
            printf("deleted %s vlan %d\n", macs, vlan);
        }
        else if (strcmp(cmd, "setport") == 0)
        {
            char *ports = strtok(NULL, " \t");
            char *mod = strtok(NULL, " \t");
            char *vlanstr = strtok(NULL, " \t");
            if (!ports || !mod)
            {
                printf("usage: setport <port> access <vlan> | setport <port> trunk\n");
                continue;
            }
            int port = atoi(ports);
            if (port < 0 || port >= iface_count)
            {
                printf("bad port\n");
                continue;
            }
            if (strcmp(mod, "access") == 0)
            {
                if (!vlanstr)
                {
                    printf("access requires VLAN\n");
                    continue;
                }
                int vlan = atoi(vlanstr);
                if (vlan < 1 || vlan > 4094)
                {
                    printf("invalid vlan\n");
                    continue;
                }
                ifaces[port].mode = PORT_MODE_ACCESS;
                ifaces[port].access_vlan = vlan;
                printf("port %d set to ACCESS VLAN %d\n", port, vlan);
            }
            else if (strcmp(mod, "trunk") == 0)
            {
                ifaces[port].mode = PORT_MODE_TRUNK;
                printf("port %d set to TRUNK\n", port);
            }
            else
            {
                printf("unknown mode\n");
            }
        }
        else if (strcmp(cmd, "mirror") == 0)
        {
            char *srcs = strtok(NULL, " \t");
            char *dsts = strtok(NULL, " \t");
            if (!srcs || !dsts)
            {
                printf("usage: mirror <src> <dst>\n");
                continue;
            }
            int src = atoi(srcs);
            int dst = atoi(dsts);
            if (src < 0 || src >= iface_count || dst < -1 || dst >= iface_count)
            {
                printf("bad ports\n");
                continue;
            }
            if (dst == -1)
            {
                ifaces[src].mirror_to = -1;
                printf("mirror disabled on port %d\n", src);
            }
            else
            {
                ifaces[src].mirror_to = dst;
                printf("port %d mirrored to %d\n", src, dst);
            }
        }
        else if (strcmp(cmd, "acladd") == 0)
        {
            char *ports = strtok(NULL, " \t");
            char *macs = strtok(NULL, " \t");
            if (!ports || !macs)
            {
                printf("usage: acladd <port> <mac>\n");
                continue;
            }
            int port = atoi(ports);
            if (port < 0 || port >= iface_count)
            {
                printf("bad port\n");
                continue;
            }
            unsigned char m[6];
            if (parse_mac(macs, m) != 0)
            {
                printf("bad mac\n");
                continue;
            }
            if (ifaces[port].acl_count < (int)(sizeof(ifaces[port].acl_denies) / 6))
            {
                memcpy(ifaces[port].acl_denies[ifaces[port].acl_count++], m, 6);
                printf("added deny %s to port %d\n", macs, port);
            }
            else
            {
                printf("acl full\n");
            }
        }
        else if (strcmp(cmd, "acllclear") == 0)
        {
            char *ports = strtok(NULL, " \t");
            if (!ports)
            {
                printf("usage: aclclear <port>\n");
                continue;
            }
            int port = atoi(ports);
            if (port < 0 || port >= iface_count)
            {
                printf("bad port\n");
                continue;
            }
            ifaces[port].acl_count = 0;
            printf("cleared ACL on port %d\n", port);
        }
        else if (strcmp(cmd, "quit") == 0 || strcmp(cmd, "exit") == 0)
        {
            keep_running = 0;
            break;
        }
        else
        {
            printf("unknown command (type help)\n");
        }
    }
}

/* ----------------- Signal handler ----------------- */
void handle_sigint(int sig)
{
    (void)sig;
    keep_running = 0;
    for (int i = 0; i < iface_count; ++i)
    {
        if (ifaces[i].handle)
            pcap_breakloop(ifaces[i].handle);
    }
}

/* ----------------- Main ----------------- */

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: sudo %s <if1> [if2] [if3] ...\n", argv[0]);
        return 1;
    }
    if (argc - 1 > MAX_IFACES)
    {
        fprintf(stderr, "max %d interfaces\n", MAX_IFACES);
        return 1;
    }

    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);

    iface_count = argc - 1;
    for (int i = 0; i < iface_count; ++i)
    {
        memset(&ifaces[i], 0, sizeof(iface_t));
        strncpy(ifaces[i].ifname, argv[i + 1], sizeof(ifaces[i].ifname) - 1);
        ifaces[i].index = i;
        ifaces[i].handle = NULL;
        ifaces[i].mode = PORT_MODE_ACCESS;
        ifaces[i].access_vlan = 1; /* default access VLAN 1 */
        ifaces[i].mirror_to = -1;
        ifaces[i].acl_count = 0;
    }

    /* open handles */
    char errbuf[PCAP_ERRBUF_SIZE];
    for (int i = 0; i < iface_count; ++i)
    {
        pcap_t *h = pcap_open_live(ifaces[i].ifname, SNAPLEN, PROMISC, READ_TIMEOUT_MS, errbuf);
        if (!h)
        {
            fprintf(stderr, "pcap_open_live(%s) failed: %s\n", ifaces[i].ifname, errbuf);
            return 1;
        }
        ifaces[i].handle = h;
        printf("Opened %s\n", ifaces[i].ifname);
    }

    /* spawn capture threads */
    for (int i = 0; i < iface_count; ++i)
    {
        int rc = pthread_create(&ifaces[i].thread, NULL, iface_loop_fn, &ifaces[i]);
        if (rc)
        {
            fprintf(stderr, "pthread_create failed: %s\n", strerror(rc));
            return 1;
        }
    }

    /* aging thread */
    pthread_t aging_thread;
    if (pthread_create(&aging_thread, NULL, aging_thread_fn, NULL) != 0)
    {
        fprintf(stderr, "failed to create aging thread\n");
        return 1;
    }

    /* Run CLI in main thread */
    printf("softswitch_full running. Type 'help' for commands.\n");
    cli_loop();

    /* shutdown: break pcap loops */
    for (int i = 0; i < iface_count; ++i)
    {
        if (ifaces[i].handle)
            pcap_breakloop(ifaces[i].handle);
    }

    /* wait for threads */
    for (int i = 0; i < iface_count; ++i)
    {
        pthread_join(ifaces[i].thread, NULL);
    }
    pthread_join(aging_thread, NULL);

    /* close handles */
    for (int i = 0; i < iface_count; ++i)
    {
        if (ifaces[i].handle)
            pcap_close(ifaces[i].handle);
    }

    /* free mac table */
    mac_table_flush();

    printf("softswitch_full exiting cleanly.\n");
    return 0;
}
