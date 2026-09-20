#include "flow_table.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>

/*
 * Murmur/Jenkins style 32-bit mix
 */
static inline uint32_t hash_mix(uint32_t a) {
    a = (a ^ 61) ^ (a >> 16);
    a = a + (a << 3);
    a = a ^ (a >> 4);
    a = a * 0x27d4eb2d;
    a = a ^ (a >> 15);
    return a;
}

/*
 * Symmetric hash so both (A->B) and (B->A) map to the exact same bucket.
 */
static uint32_t compute_symmetric_hash(uint32_t ip1, uint32_t ip2,
                                      uint16_t p1, uint16_t p2,
                                      uint8_t proto) {
    uint32_t ip_low = (ip1 < ip2) ? ip1 : ip2;
    uint32_t ip_high = (ip1 < ip2) ? ip2 : ip1;
    uint16_t p_low = (p1 < p2) ? p1 : p2;
    uint16_t p_high = (p1 < p2) ? p2 : p1;

    uint32_t h = 0x811c9dc5; /* FNV offset basis */
    h = (h ^ hash_mix(ip_low)) * 0x01000193;
    h = (h ^ hash_mix(ip_high)) * 0x01000193;
    h = (h ^ ((uint32_t)p_low | ((uint32_t)p_high << 16))) * 0x01000193;
    h = (h ^ (uint32_t)proto) * 0x01000193;
    return h;
}

/*
 * LRU doubly-linked list helpers
 */
static void lru_append_tail(flow_table_t *tbl, flow_entry_t *entry) {
    entry->lru_next = NULL;
    entry->lru_prev = tbl->lru_tail;
    if (tbl->lru_tail) {
        tbl->lru_tail->lru_next = entry;
    } else {
        tbl->lru_head = entry;
    }
    tbl->lru_tail = entry;
}

static void lru_remove(flow_table_t *tbl, flow_entry_t *entry) {
    if (entry->lru_prev) {
        entry->lru_prev->lru_next = entry->lru_next;
    } else {
        tbl->lru_head = entry->lru_next;
    }
    if (entry->lru_next) {
        entry->lru_next->lru_prev = entry->lru_prev;
    } else {
        tbl->lru_tail = entry->lru_prev;
    }
    entry->lru_prev = NULL;
    entry->lru_next = NULL;
}

static void lru_move_to_tail(flow_table_t *tbl, flow_entry_t *entry) {
    if (tbl->lru_tail == entry) return;
    lru_remove(tbl, entry);
    lru_append_tail(tbl, entry);
}

flow_table_t *flow_table_create(size_t num_buckets, size_t max_flows,
                                uint64_t active_timeout_us, uint64_t idle_timeout_us,
                                flow_finalized_cb_t callback, void *user_data) {
    flow_table_t *tbl = (flow_table_t *)calloc(1, sizeof(flow_table_t));
    if (!tbl) return NULL;

    tbl->num_buckets = (num_buckets > 0) ? num_buckets : DEFAULT_FLOW_TABLE_BUCKETS;
    tbl->buckets = (flow_entry_t **)calloc(tbl->num_buckets, sizeof(flow_entry_t *));
    if (!tbl->buckets) {
        free(tbl);
        return NULL;
    }

    tbl->max_flows = (max_flows > 0) ? max_flows : 500000;
    tbl->active_timeout_us = (active_timeout_us > 0) ? active_timeout_us : DEFAULT_ACTIVE_TIMEOUT_US;
    tbl->idle_timeout_us = (idle_timeout_us > 0) ? idle_timeout_us : DEFAULT_IDLE_TIMEOUT_US;
    tbl->tcp_closed_timeout_us = DEFAULT_TCP_CLOSED_TIMEOUT_US;
    tbl->on_flow_finalized = callback;
    tbl->cb_user_data = user_data;

    return tbl;
}

static void init_stat_acc(stat_accumulator_t *acc) {
    acc->count = 0;
    acc->sum = 0.0;
    acc->sum_sq = 0.0;
    acc->min = 1e15;
    acc->max = 0.0;
}

static flow_entry_t *allocate_flow_entry(const flow_key_t *key, uint64_t pkt_time_us) {
    flow_entry_t *entry = (flow_entry_t *)calloc(1, sizeof(flow_entry_t));
    if (!entry) return NULL;

    entry->key = *key;
    entry->first_packet_us = pkt_time_us;
    entry->last_packet_us = pkt_time_us;
    entry->prev_flow_ts_us = pkt_time_us;
    entry->subflow_count = 1;

    init_stat_acc(&entry->fwd_pkt_len);
    init_stat_acc(&entry->bwd_pkt_len);
    init_stat_acc(&entry->combined_pkt_len);

    init_stat_acc(&entry->flow_iat);
    init_stat_acc(&entry->fwd_iat);
    init_stat_acc(&entry->bwd_iat);

    entry->fwd_seg_size_min = UINT32_MAX;
    entry->init_fwd_win_bytes = -1;
    entry->init_bwd_win_bytes = -1;

    struct in_addr src_addr = { .s_addr = key->src_ip };
    struct in_addr dst_addr = { .s_addr = key->dst_ip };
    /* Zero-initialized (never left uninitialized): if inet_ntop fails for any
     * reason, these stay as empty, null-terminated strings instead of
     * leaking whatever garbage was previously on the stack into flow_id. */
    char src_str[INET_ADDRSTRLEN] = {0};
    char dst_str[INET_ADDRSTRLEN] = {0};

    if (!inet_ntop(AF_INET, &src_addr, src_str, sizeof(src_str))) {
        fprintf(stderr, "[flow_table ERROR] inet_ntop failed for src_ip=0x%08x\n",
                (unsigned int)key->src_ip);
    }
    if (!inet_ntop(AF_INET, &dst_addr, dst_str, sizeof(dst_str))) {
        fprintf(stderr, "[flow_table ERROR] inet_ntop failed for dst_ip=0x%08x\n",
                (unsigned int)key->dst_ip);
    }

    /* The 5-tuple alone is not a unique identifier for a flow *occurrence*:
     * the same src/dst IP:port/protocol combination legitimately recurs
     * over time (repeated brute-force attempts, repeated scans, back-to-back
     * DDoS bursts), and each recurrence starts a brand new flow_entry here.
     * Appending the flow's start time (microsecond resolution) makes
     * flow_id unique per occurrence, not just per 5-tuple, which is what
     * every downstream consumer (the database's UNIQUE(flow_id) columns in
     * particular) actually assumes. */
    snprintf(entry->flow_id, sizeof(entry->flow_id), "%s:%u-%s:%u-%u-%llu",
             src_str, ntohs(key->src_port),
             dst_str, ntohs(key->dst_port),
             key->protocol,
             (unsigned long long)pkt_time_us);

    return entry;
}

flow_entry_t *flow_table_get_or_create(flow_table_t *tbl, const flow_key_t *key,
                                      uint64_t pkt_time_us, bool *out_is_forward) {
    if (!tbl || !key) return NULL;

    uint32_t h = compute_symmetric_hash(key->src_ip, key->dst_ip,
                                       key->src_port, key->dst_port,
                                       key->protocol);
    size_t idx = h % tbl->num_buckets;

    flow_entry_t *curr = tbl->buckets[idx];
    while (curr) {
        if (curr->key.protocol == key->protocol) {
            /* Forward match */
            if (curr->key.src_ip == key->src_ip &&
                curr->key.dst_ip == key->dst_ip &&
                curr->key.src_port == key->src_port &&
                curr->key.dst_port == key->dst_port) {
                *out_is_forward = true;
                lru_move_to_tail(tbl, curr);
                return curr;
            }
            /* Backward match */
            if (curr->key.src_ip == key->dst_ip &&
                curr->key.dst_ip == key->src_ip &&
                curr->key.src_port == key->dst_port &&
                curr->key.dst_port == key->src_port) {
                *out_is_forward = false;
                lru_move_to_tail(tbl, curr);
                return curr;
            }
        }
        curr = curr->hash_next;
    }

    /* Evict oldest flow if table exceeds max capacity */
    if (tbl->active_flows_count >= tbl->max_flows && tbl->lru_head) {
        flow_table_finalize_flow(tbl, tbl->lru_head);
    }

    /* Create new flow */
    flow_entry_t *new_flow = allocate_flow_entry(key, pkt_time_us);
    if (!new_flow) return NULL;

    new_flow->hash_next = tbl->buckets[idx];
    tbl->buckets[idx] = new_flow;
    lru_append_tail(tbl, new_flow);

    tbl->active_flows_count++;
    tbl->total_flows_created++;
    *out_is_forward = true;

    return new_flow;
}

static inline double calc_mean(const stat_accumulator_t *acc) {
    if (acc->count == 0) return 0.0;
    return acc->sum / (double)acc->count;
}

static inline double calc_variance(const stat_accumulator_t *acc) {
    if (acc->count == 0) return 0.0;
    double mean = acc->sum / (double)acc->count;
    double var = (acc->sum_sq / (double)acc->count) - (mean * mean);
    return (var < 0.0) ? 0.0 : var;
}

static inline double calc_std(const stat_accumulator_t *acc) {
    return sqrt(calc_variance(acc));
}

static inline double calc_min(const stat_accumulator_t *acc) {
    return (acc->count == 0 || acc->min >= 1e14) ? 0.0 : acc->min;
}

static inline double calc_max(const stat_accumulator_t *acc) {
    return (acc->count == 0) ? 0.0 : acc->max;
}

void flow_table_finalize_flow(flow_table_t *tbl, flow_entry_t *flow) {
    if (!tbl || !flow) return;

    /* Build flow_record_t */
    flow_record_t rec;
    memset(&rec, 0, sizeof(rec));

    snprintf(rec.flow_id, sizeof(rec.flow_id), "%s", flow->flow_id);

    struct in_addr src_addr = { .s_addr = flow->key.src_ip };
    struct in_addr dst_addr = { .s_addr = flow->key.dst_ip };
    /* rec was memset(0) above, so on failure these fields stay "" rather
     * than uninitialized -- but we still want the failure visible. */
    if (!inet_ntop(AF_INET, &src_addr, rec.src_ip_str, sizeof(rec.src_ip_str))) {
        fprintf(stderr, "[flow_table ERROR] inet_ntop failed for src_ip on finalize (flow_id=%s)\n",
                flow->flow_id);
    }
    if (!inet_ntop(AF_INET, &dst_addr, rec.dst_ip_str, sizeof(rec.dst_ip_str))) {
        fprintf(stderr, "[flow_table ERROR] inet_ntop failed for dst_ip on finalize (flow_id=%s)\n",
                flow->flow_id);
    }

    rec.src_port = ntohs(flow->key.src_port);
    rec.dst_port = ntohs(flow->key.dst_port);
    rec.protocol = flow->key.protocol;
    rec.start_time_us = flow->first_packet_us;
    rec.end_time_us = flow->last_packet_us;

    /* 1. Volume / Counts */
    rec.total_fwd_packets = flow->total_fwd_packets;
    rec.total_bwd_packets = flow->total_bwd_packets;
    uint32_t subflows = (flow->subflow_count > 0) ? flow->subflow_count : 1;
    rec.subflow_fwd_packets = (double)flow->total_fwd_packets / (double)subflows;

    /* 2. Packet Lengths */
    rec.fwd_packet_length_max = calc_max(&flow->fwd_pkt_len);
    rec.fwd_packet_length_mean = calc_mean(&flow->fwd_pkt_len);
    rec.bwd_packet_length_max = calc_max(&flow->bwd_pkt_len);
    rec.bwd_packet_length_mean = calc_mean(&flow->bwd_pkt_len);
    rec.packet_length_mean = calc_mean(&flow->combined_pkt_len);
    rec.packet_length_std = calc_std(&flow->combined_pkt_len);
    rec.packet_length_variance = calc_variance(&flow->combined_pkt_len);

    /* 4. Duration */
    rec.flow_duration = (flow->last_packet_us >= flow->first_packet_us)
        ? (double)(flow->last_packet_us - flow->first_packet_us)
        : 0.0;

    /* 3. Rates (bytes/s, packets/s) */
    double duration_sec = rec.flow_duration / 1000000.0;
    if (duration_sec > 0.000001) {
        rec.flow_bytes_s = (double)(flow->total_fwd_bytes + flow->total_bwd_bytes) / duration_sec;
        rec.flow_packets_s = (double)(flow->total_fwd_packets + flow->total_bwd_packets) / duration_sec;
    } else {
        rec.flow_bytes_s = 0.0;
        rec.flow_packets_s = 0.0;
    }

    /* 5. Inter-Arrival Times */
    rec.flow_iat_mean = calc_mean(&flow->flow_iat);
    rec.flow_iat_std = calc_std(&flow->flow_iat);
    rec.flow_iat_max = calc_max(&flow->flow_iat);

    rec.fwd_iat_mean = calc_mean(&flow->fwd_iat);
    rec.fwd_iat_std = calc_std(&flow->fwd_iat);
    rec.fwd_iat_max = calc_max(&flow->fwd_iat);
    rec.fwd_iat_total = flow->fwd_iat.sum;

    rec.bwd_iat_mean = calc_mean(&flow->bwd_iat);
    rec.bwd_iat_min = calc_min(&flow->bwd_iat);
    rec.bwd_iat_std = calc_std(&flow->bwd_iat);
    rec.bwd_iat_total = flow->bwd_iat.sum;

    /* 6. TCP Flags */
    rec.fwd_psh_flags = flow->fwd_psh_flags;
    rec.bwd_psh_flags = flow->bwd_psh_flags;
    rec.fwd_rst_flags = flow->fwd_rst_flags;
    rec.fin_flag_count = flow->fin_flag_count;
    rec.syn_flag_count = flow->syn_flag_count;
    rec.rst_flag_count = flow->rst_flag_count;
    rec.cwr_flag_count = flow->cwr_flag_count;
    rec.ece_flag_count = flow->ece_flag_count;

    /* 7. Ratio */
    rec.down_up_ratio = (flow->total_fwd_packets > 0) 
        ? (double)flow->total_bwd_packets / (double)flow->total_fwd_packets 
        : 0.0;

    /* 8. Bulk */
    /* A run in progress when the flow closes never saw the gap that would
     * normally commit it (update_bulk_tracker only commits on gap-reset) —
     * flush it here so a bulk transfer active at flow end is not lost. */
    if (flow->fwd_bulk.current_run_pkts >= 4) {
        flow->fwd_bulk.total_bulk_bytes += flow->fwd_bulk.current_run_bytes;
        flow->fwd_bulk.total_bulk_duration_us +=
            (flow->fwd_bulk.last_pkt_us - flow->fwd_bulk.current_run_start_us);
    }
    if (flow->fwd_bulk.total_bulk_duration_us > 0) {
        double bulk_sec = (double)flow->fwd_bulk.total_bulk_duration_us / 1000000.0;
        rec.fwd_avg_bulk_rate = (double)flow->fwd_bulk.total_bulk_bytes / bulk_sec;
    } else {
        rec.fwd_avg_bulk_rate = 0.0;
    }

    /* 9. Segment / Window */
    /* Sentinel fix: the field is initialized to UINT32_MAX (0xFFFFFFFF) in
     * allocate_flow_entry(), meaning "never updated" (true for every UDP
     * flow, since only the TCP branch in capture.c's process_packet()
     * touches fwd_seg_size_min). The old comparison checked for 65535
     * (0xFFFF) instead, which this value never equals, so UDP flows -- and
     * any TCP flow whose forward segment size genuinely never got smaller
     * than the initial sentinel -- serialized Fwd_Seg_Size_Min as literal
     * 4294967295 into the JSON/feature vector instead of 0. */
    rec.fwd_seg_size_min = (flow->fwd_seg_size_min == UINT32_MAX) ? 0 : flow->fwd_seg_size_min;
    rec.init_fwd_win_bytes = flow->init_fwd_win_bytes;
    rec.init_bwd_win_bytes = flow->init_bwd_win_bytes;

    /* 10. Corrected TCP Flow Time */
    if (flow->key.protocol == IPPROTO_TCP && flow->is_terminated) {
        rec.total_tcp_flow_time = (double)(flow->termination_us - flow->first_packet_us);
    } else if (flow->key.protocol == IPPROTO_TCP) {
        rec.total_tcp_flow_time = rec.flow_duration;
    } else {
        rec.total_tcp_flow_time = 0.0;
    }

    /* Invoke consumer callback */
    if (tbl->on_flow_finalized) {
        tbl->on_flow_finalized(&rec, tbl->cb_user_data);
    }

    /* Unlink from hash table */
    uint32_t h = compute_symmetric_hash(flow->key.src_ip, flow->key.dst_ip,
                                       flow->key.src_port, flow->key.dst_port,
                                       flow->key.protocol);
    size_t idx = h % tbl->num_buckets;

    flow_entry_t **tracer = &tbl->buckets[idx];
    while (*tracer) {
        if (*tracer == flow) {
            *tracer = flow->hash_next;
            break;
        }
        tracer = &((*tracer)->hash_next);
    }

    /* Unlink from LRU */
    lru_remove(tbl, flow);

    tbl->active_flows_count--;
    free(flow);
}

size_t flow_table_expire_flows(flow_table_t *tbl, uint64_t current_time_us) {
    if (!tbl) return 0;
    size_t expired_count = 0;

    flow_entry_t *curr = tbl->lru_head;
    while (curr) {
        flow_entry_t *next = curr->lru_next;

        bool should_expire = false;
        if (curr->is_terminated && (current_time_us - curr->termination_us > tbl->tcp_closed_timeout_us)) {
            should_expire = true;
            tbl->total_flows_expired_tcp++;
        } else if (current_time_us - curr->last_packet_us > tbl->idle_timeout_us) {
            should_expire = true;
            tbl->total_flows_expired_idle++;
        } else if (current_time_us - curr->first_packet_us > tbl->active_timeout_us) {
            should_expire = true;
            tbl->total_flows_expired_active++;
        }

        if (should_expire) {
            flow_table_finalize_flow(tbl, curr);
            expired_count++;
        }

        curr = next;
    }

    return expired_count;
}

void flow_table_flush(flow_table_t *tbl) {
    if (!tbl) return;
    while (tbl->lru_head) {
        flow_table_finalize_flow(tbl, tbl->lru_head);
    }
}

void flow_table_destroy(flow_table_t *tbl) {
    if (!tbl) return;
    flow_table_flush(tbl);
    free(tbl->buckets);
    free(tbl);
}