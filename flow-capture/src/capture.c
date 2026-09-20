#include "capture.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
    #include <winsock2.h>
#else
    #include <unistd.h>
#endif

#include "net_compat.h"
#include "time_compat.h"
#include <signal.h>

#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20
#define TCP_FLAG_ECE 0x40
#define TCP_FLAG_CWR 0x80

/* Gap after which a still-arriving flow is considered to have started a new
 * subflow (Subflow_Fwd_Packets, flow_features.md sec.1). */
#define SUBFLOW_IDLE_GAP_US 1000000ULL
/* Gap after which an in-progress bulk run is closed out and a new one
 * started (flow_features.md sec.8). */
#define BULK_GAP_RESET_US   1000000ULL

static inline void update_stat_acc(stat_accumulator_t *acc, double val) {
    acc->count++;
    acc->sum += val;
    acc->sum_sq += (val * val);
    if (val < acc->min) acc->min = val;
    if (val > acc->max) acc->max = val;
}

static void update_bulk_tracker(bulk_tracker_t *bulk, uint32_t payload_len, uint64_t pkt_time_us) {
    if (payload_len == 0) {
        /* Application data only counts toward a bulk run */
        return;
    }

    /* Gap since the last bulk-eligible packet closes the current run: commit
     * it to the totals if it reached the 4-packet minimum, then start fresh.
     * A run is committed exactly once, here, never incrementally while it is
     * still open, so packets are never double-counted. */
    if (bulk->last_pkt_us > 0 && (pkt_time_us - bulk->last_pkt_us > BULK_GAP_RESET_US)) {
        if (bulk->current_run_pkts >= 4) {
            bulk->total_bulk_bytes += bulk->current_run_bytes;
            bulk->total_bulk_duration_us += (bulk->last_pkt_us - bulk->current_run_start_us);
        }
        bulk->current_run_pkts = 0;
        bulk->current_run_bytes = 0;
        bulk->current_run_start_us = 0;
    }

    if (bulk->current_run_pkts == 0) {
        bulk->current_run_start_us = pkt_time_us;
    }

    bulk->current_run_pkts++;
    bulk->current_run_bytes += payload_len;
    bulk->last_pkt_us = pkt_time_us;
}

static void process_packet(u_char *user, const struct pcap_pkthdr *hdr, const u_char *bytes) {
    capture_engine_t *engine = (capture_engine_t *)user;
    if (!engine || !engine->is_running) return;

    engine->total_packets++;
    engine->total_bytes += hdr->len;

    uint64_t pkt_time_us = (uint64_t)hdr->ts.tv_sec * 1000000ULL + (uint64_t)hdr->ts.tv_usec;

    /* Periodic timeout check every 512 packets (cheap power-of-two mask) */
    if ((engine->total_packets & 0x1FF) == 0) {
        flow_table_expire_flows(engine->flow_table, pkt_time_us);
    }

    /* Link layer parsing (Ethernet II, VLAN) */
    size_t link_hdr_len = sizeof(struct ether_header);
    if (hdr->caplen < link_hdr_len) return;

    const struct ether_header *eth = (const struct ether_header *)bytes;
    uint16_t ether_type = ntohs(eth->ether_type);

    if (ether_type == ETHERTYPE_VLAN) {
        link_hdr_len += 4;
        if (hdr->caplen < link_hdr_len) return;
        ether_type = ntohs(*(const uint16_t *)(bytes + 16));
    }

    /* We focus on IPv4 */
    if (ether_type != ETHERTYPE_IP) {
        engine->non_ip_packets++;
        return;
    }

    const struct iphdr *ip = (const struct iphdr *)(bytes + link_hdr_len);
    /* ihl below 5 (20 bytes) is not a valid IPv4 header; reject before it is
     * used to compute the transport-layer offset. Well-formed traffic always
     * has ihl >= 5, so this never affects normal packets. */
    if (ip->ihl < 5) return;
    size_t ip_hdr_len = ip->ihl * 4;
    if (hdr->caplen < link_hdr_len + ip_hdr_len) return;

    uint16_t ip_total_len = ntohs(ip->tot_len);
    double pkt_wire_len = (double)ip_total_len; /* Wire length excluding link framing */

    flow_key_t key;
    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;
    key.protocol = ip->protocol;
    key.src_port = 0;
    key.dst_port = 0;

    const u_char *transport_data = bytes + link_hdr_len + ip_hdr_len;
    size_t remaining_len = (hdr->caplen > link_hdr_len + ip_hdr_len)
        ? (hdr->caplen - (link_hdr_len + ip_hdr_len))
        : 0;

    uint8_t tcp_flags = 0;
    uint16_t tcp_win = 0;
    uint32_t tcp_hdr_len = 0;
    uint32_t payload_len = 0;

    if (ip->protocol == IPPROTO_TCP) {
        engine->tcp_packets++;
        if (remaining_len < sizeof(struct tcphdr)) return;
        const struct tcphdr *tcp = (const struct tcphdr *)transport_data;
        key.src_port = tcp->source;
        key.dst_port = tcp->dest;
        tcp_hdr_len = tcp->doff * 4;
        tcp_flags = *((const uint8_t *)tcp + 13);
        tcp_win = ntohs(tcp->window);

        if (ip_total_len > (ip_hdr_len + tcp_hdr_len)) {
            payload_len = ip_total_len - (ip_hdr_len + tcp_hdr_len);
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        engine->udp_packets++;
        if (remaining_len < sizeof(struct udphdr)) return;
        const struct udphdr *udp = (const struct udphdr *)transport_data;
        key.src_port = udp->source;
        key.dst_port = udp->dest;
        if (ntohs(udp->len) > sizeof(struct udphdr)) {
            payload_len = ntohs(udp->len) - sizeof(struct udphdr);
        }
    } else {
        engine->other_packets++;
        return;
    }

    /* Lookup or create bidirectional flow */
    bool is_forward = true;
    flow_entry_t *flow = flow_table_get_or_create(engine->flow_table, &key,
                                                 pkt_time_us, &is_forward);
    if (!flow) return;

    /* Update packet timestamps & subflows */
    if (pkt_time_us > flow->last_packet_us) {
        /* If idle gap is > 1s, count as a subflow transition */
        if (flow->last_packet_us > 0 && (pkt_time_us - flow->last_packet_us > SUBFLOW_IDLE_GAP_US)) {
            flow->subflow_count++;
        }
        flow->last_packet_us = pkt_time_us;
    }

    /* Update flow IAT.
     * Guarded against out-of-order arrival: if pkt_time_us were ever less
     * than prev_flow_ts_us, the uint64 subtraction below would underflow to
     * a huge value and corrupt flow_iat's mean/max. For in-order packets
     * (the normal case) pkt_time_us >= prev_flow_ts_us always holds, so this
     * guard changes nothing there -- it only discards the single malformed
     * sample that a reordered timestamp would otherwise produce. prev_flow_ts_us
     * is likewise only ever advanced, never rewound, so a later in-order
     * packet's IAT is computed exactly as it would have been without the
     * out-of-order packet ever arriving. */
    if ((flow->total_fwd_packets + flow->total_bwd_packets) > 0 &&
        pkt_time_us >= flow->prev_flow_ts_us) {
        double flow_iat = (double)(pkt_time_us - flow->prev_flow_ts_us);
        update_stat_acc(&flow->flow_iat, flow_iat);
    }
    if (pkt_time_us > flow->prev_flow_ts_us) {
        flow->prev_flow_ts_us = pkt_time_us;
    }

    /* Combined packet length */
    update_stat_acc(&flow->combined_pkt_len, pkt_wire_len);

    if (is_forward) {
        /* Forward direction */
        flow->total_fwd_packets++;
        flow->total_fwd_bytes += ip_total_len;
        update_stat_acc(&flow->fwd_pkt_len, pkt_wire_len);

        if (flow->total_fwd_packets > 1 && pkt_time_us >= flow->prev_fwd_ts_us) {
            double fwd_iat = (double)(pkt_time_us - flow->prev_fwd_ts_us);
            update_stat_acc(&flow->fwd_iat, fwd_iat);
        }
        if (pkt_time_us > flow->prev_fwd_ts_us) {
            flow->prev_fwd_ts_us = pkt_time_us;
        }

        /* Bulk-run tracking applies to any forward payload-bearing packet,
         * TCP or UDP (flow_features.md sec.8 is protocol-agnostic). */
        update_bulk_tracker(&flow->fwd_bulk, payload_len, pkt_time_us);

        if (ip->protocol == IPPROTO_TCP) {
            if (tcp_flags & TCP_FLAG_PSH) flow->fwd_psh_flags++;
            if (tcp_flags & TCP_FLAG_RST) flow->fwd_rst_flags++;
            if (tcp_flags & TCP_FLAG_FIN) flow->fwd_fin_seen = true;
            uint32_t tcp_seg_size = ip_total_len - ip_hdr_len;  
            if (tcp_seg_size < flow->fwd_seg_size_min) {
                flow->fwd_seg_size_min = tcp_seg_size;
            }
            if (flow->init_fwd_win_bytes == -1) {
                flow->init_fwd_win_bytes = (int32_t)tcp_win;
            }
        }
    } else {
        /* Backward direction */
        flow->total_bwd_packets++;
        flow->total_bwd_bytes += ip_total_len;
        update_stat_acc(&flow->bwd_pkt_len, pkt_wire_len);

        if (flow->total_bwd_packets > 1 && pkt_time_us >= flow->prev_bwd_ts_us) {
            double bwd_iat = (double)(pkt_time_us - flow->prev_bwd_ts_us);
            update_stat_acc(&flow->bwd_iat, bwd_iat);
        }
        if (pkt_time_us > flow->prev_bwd_ts_us) {
            flow->prev_bwd_ts_us = pkt_time_us;
        }

        if (ip->protocol == IPPROTO_TCP) {
            if (tcp_flags & TCP_FLAG_PSH) flow->bwd_psh_flags++;
            if (tcp_flags & TCP_FLAG_FIN) flow->bwd_fin_seen = true;
            if (flow->init_bwd_win_bytes == -1) {
                flow->init_bwd_win_bytes = (int32_t)tcp_win;
            }
        }
    }

    /* Overall TCP flags */
    if (ip->protocol == IPPROTO_TCP) {
        if (tcp_flags & TCP_FLAG_FIN) flow->fin_flag_count++;
        if (tcp_flags & TCP_FLAG_SYN) flow->syn_flag_count++;
        if (tcp_flags & TCP_FLAG_RST) flow->rst_flag_count++;
        if (tcp_flags & TCP_FLAG_CWR) flow->cwr_flag_count++;
        if (tcp_flags & TCP_FLAG_ECE) flow->ece_flag_count++;

        /* TCP Teardown tracking:
         * RST terminates flow immediately.
         * A FIN observed in BOTH directions marks a true mutual close.
         * (fin_flag_count alone is not enough: a single retransmitted FIN
         * from one side would reach 2 without the other side ever closing.)
         */
        if ((tcp_flags & TCP_FLAG_RST) || (flow->fwd_fin_seen && flow->bwd_fin_seen)) {
            flow->is_terminated = true;
            flow->termination_us = pkt_time_us;
        }
    }
}

capture_engine_t *capture_engine_init(const capture_config_t *config,
                                     flow_finalized_cb_t callback,
                                     void *user_data) {
#ifdef _WIN32
    /* MUST happen before any Winsock call (inet_ntop_win / WSAAddressToStringA
     * used later on every flow finalize). Without this, address-to-string
     * conversion silently fails and leaves stack buffers uninitialized. */
    if (net_compat_wsa_init() != 0) {
        fprintf(stderr, "[flow-capture ERROR] Winsock initialization failed; "
                        "aborting to avoid corrupted flow records.\n");
        return NULL;
    }
#endif

    capture_engine_t *engine = (capture_engine_t *)calloc(1, sizeof(capture_engine_t));
    if (!engine) return NULL;

    engine->config = *config;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};

    int snaplen = (config->snaplen > 0) ? config->snaplen : 65535;
    int timeout_ms = (config->timeout_ms > 0) ? config->timeout_ms : 50;

    engine->pcap_handle = pcap_open_live(config->device, snaplen, config->promisc,
                                         timeout_ms, errbuf);
    if (!engine->pcap_handle) {
        fprintf(stderr, "[flow-capture ERROR] pcap_open_live failed on %s: %s\n",
                config->device, errbuf);
        free(engine);
        return NULL;
    }

    /* Compile and apply BPF filter if provided */
    if (strlen(config->bpf_filter) > 0) {
        struct bpf_program fp;
        if (pcap_compile(engine->pcap_handle, &fp, config->bpf_filter, 1, PCAP_NETMASK_UNKNOWN) == -1) {
            fprintf(stderr, "[flow-capture ERROR] BPF compile failed: %s\n", pcap_geterr(engine->pcap_handle));
        } else {
            pcap_setfilter(engine->pcap_handle, &fp);
            pcap_freecode(&fp);
        }
    }

    uint64_t active_timeout_us = (config->active_timeout_sec > 0)
        ? (config->active_timeout_sec * 1000000ULL)
        : DEFAULT_ACTIVE_TIMEOUT_US;
    uint64_t idle_timeout_us = (config->idle_timeout_sec > 0)
        ? (config->idle_timeout_sec * 1000000ULL)
        : DEFAULT_IDLE_TIMEOUT_US;

    engine->flow_table = flow_table_create(config->flow_table_size,
                                           config->max_flows,
                                           active_timeout_us,
                                           idle_timeout_us,
                                           callback, user_data);
    if (!engine->flow_table) {
        pcap_close(engine->pcap_handle);
        free(engine);
        return NULL;
    }

    engine->is_running = false;
    return engine;
}

int capture_engine_start(capture_engine_t *engine) {
    if (!engine || !engine->pcap_handle) return -1;
    engine->is_running = true;

    printf("[flow-capture] Capturing live traffic on interface: %s ...\n", engine->config.device);

    while (engine->is_running) {
        int ret = pcap_dispatch(engine->pcap_handle, 50, process_packet, (u_char *)engine);
        if (ret < 0) {
            if (ret == -1) {
                fprintf(stderr, "[flow-capture] pcap_dispatch error: %s\n", pcap_geterr(engine->pcap_handle));
            }
            break;
        }

        /* Periodic timer sweep when no packets are coming in */
        struct timeval now;
        gettimeofday(&now, NULL);
        uint64_t now_us = (uint64_t)now.tv_sec * 1000000ULL + (uint64_t)now.tv_usec;
        flow_table_expire_flows(engine->flow_table, now_us);
    }

    return 0;
}

void capture_engine_stop(capture_engine_t *engine) {
    if (!engine) return;
    engine->is_running = false;
    if (engine->pcap_handle) {
        pcap_breakloop(engine->pcap_handle);
    }
}

void capture_engine_cleanup(capture_engine_t *engine) {
    if (!engine) return;
    capture_engine_stop(engine);

    if (engine->flow_table) {
        flow_table_flush(engine->flow_table);
        flow_table_destroy(engine->flow_table);
        engine->flow_table = NULL;
    }

    if (engine->pcap_handle) {
        pcap_close(engine->pcap_handle);
        engine->pcap_handle = NULL;
    }

    free(engine);

#ifdef _WIN32
    net_compat_wsa_cleanup();
#endif
}

int flow_record_to_json(const flow_record_t *r, char *buf, size_t max_len) {
    return snprintf(buf, max_len,
        "{"
        "\"flow_id\":\"%s\","
        "\"src_ip\":\"%s\","
        "\"dst_ip\":\"%s\","
        "\"src_port\":%u,"
        "\"dst_port\":%u,"
        "\"protocol\":%u,"
        "\"start_time_us\":%llu,"
        "\"end_time_us\":%llu,"
        "\"features\":{"
            "\"Total_Fwd_Packets\":%llu,"
            "\"Total_Backward_Packets\":%llu,"
            "\"Subflow_Fwd_Packets\":%.4f,"
            "\"Fwd_Packet_Length_Max\":%.4f,"
            "\"Fwd_Packet_Length_Mean\":%.4f,"
            "\"Bwd_Packet_Length_Max\":%.4f,"
            "\"Bwd_Packet_Length_Mean\":%.4f,"
            "\"Packet_Length_Mean\":%.4f,"
            "\"Packet_Length_Std\":%.4f,"
            "\"Packet_Length_Variance\":%.4f,"
            "\"Flow_Bytes_s\":%.4f,"
            "\"Flow_Packets_s\":%.4f,"
            "\"Flow_Duration\":%.2f,"
            "\"Flow_IAT_Mean\":%.4f,"
            "\"Flow_IAT_Std\":%.4f,"
            "\"Flow_IAT_Max\":%.4f,"
            "\"Fwd_IAT_Mean\":%.4f,"
            "\"Fwd_IAT_Std\":%.4f,"
            "\"Fwd_IAT_Max\":%.4f,"
            "\"Fwd_IAT_Total\":%.4f,"
            "\"Bwd_IAT_Mean\":%.4f,"
            "\"Bwd_IAT_Min\":%.4f,"
            "\"Bwd_IAT_Std\":%.4f,"
            "\"Bwd_IAT_Total\":%.4f,"
            "\"Fwd_PSH_Flags\":%u,"
            "\"Bwd_PSH_Flags\":%u,"
            "\"Fwd_RST_Flags\":%u,"
            "\"FIN_Flag_Count\":%u,"
            "\"SYN_Flag_Count\":%u,"
            "\"RST_Flag_Count\":%u,"
            "\"CWR_Flag_Count\":%u,"
            "\"ECE_Flag_Count\":%u,"
            "\"Down_Up_Ratio\":%.4f,"
            "\"Fwd_Avg_Bulk_Rate\":%.4f,"
            "\"Fwd_Seg_Size_Min\":%u,"
            "\"Init_Fwd_Win_Bytes\":%d,"
            "\"Init_Bwd_Win_Bytes\":%d,"
            "\"Total_TCP_Flow_Time\":%.2f"
        "}"
        "}",
        r->flow_id,
        r->src_ip_str,
        r->dst_ip_str,
        r->src_port,
        r->dst_port,
        r->protocol,
        (unsigned long long)r->start_time_us,
        (unsigned long long)r->end_time_us,
        (unsigned long long)r->total_fwd_packets,
        (unsigned long long)r->total_bwd_packets,
        r->subflow_fwd_packets,
        r->fwd_packet_length_max,
        r->fwd_packet_length_mean,
        r->bwd_packet_length_max,
        r->bwd_packet_length_mean,
        r->packet_length_mean,
        r->packet_length_std,
        r->packet_length_variance,
        r->flow_bytes_s,
        r->flow_packets_s,
        r->flow_duration,
        r->flow_iat_mean,
        r->flow_iat_std,
        r->flow_iat_max,
        r->fwd_iat_mean,
        r->fwd_iat_std,
        r->fwd_iat_max,
        r->fwd_iat_total,
        r->bwd_iat_mean,
        r->bwd_iat_min,
        r->bwd_iat_std,
        r->bwd_iat_total,
        r->fwd_psh_flags,
        r->bwd_psh_flags,
        r->fwd_rst_flags,
        r->fin_flag_count,
        r->syn_flag_count,
        r->rst_flag_count,
        r->cwr_flag_count,
        r->ece_flag_count,
        r->down_up_ratio,
        r->fwd_avg_bulk_rate,
        r->fwd_seg_size_min,
        r->init_fwd_win_bytes,
        r->init_bwd_win_bytes,
        r->total_tcp_flow_time
    );
}