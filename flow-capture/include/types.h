#ifndef NIDS_TYPES_H
#define NIDS_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include "net_compat.h"
#include "time_compat.h"

#define MAX_IP_STR_LEN 46
#define FLOW_ID_STR_LEN 128

/*
 * Bidirectional 5-tuple flow key.
 * Direction normalization ensures both forward and backward packets
 * map to the same flow table entry.
 */
typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
} flow_key_t;

/*
 * Single-pass running statistic accumulator (Welford/Sum-of-squares).
 * Allows computing count, sum, min, max, mean, variance, and stddev in O(1) memory.
 */
typedef struct {
    uint64_t count;
    double   sum;
    double   sum_sq;
    double   min;
    double   max;
} stat_accumulator_t;

/*
 * State tracking for Bulk Transfer detection (runs of >= 4 packets with payload > 0).
 */
typedef struct {
    uint32_t current_run_pkts;
    uint64_t current_run_bytes;
    uint64_t current_run_start_us;
    uint64_t last_pkt_us;

    uint64_t total_bulk_bytes;
    uint64_t total_bulk_duration_us;
} bulk_tracker_t;

/*
 * Full internal flow tracking structure stored in the Flow Table.
 */
typedef struct flow_entry {
    flow_key_t key;
    char       flow_id[FLOW_ID_STR_LEN];

    /* Flow lifecycle timestamps (in microseconds) */
    uint64_t first_packet_us;
    uint64_t last_packet_us;
    uint64_t termination_us;   /* For Total_TCP_Flow_Time calculation */
    bool     is_terminated;

    /* Packet and Byte volume counters */
    uint64_t total_fwd_packets;
    uint64_t total_bwd_packets;
    uint64_t total_fwd_bytes;
    uint64_t total_bwd_bytes;
    uint32_t subflow_count;

    /* Packet Length accumulators */
    stat_accumulator_t fwd_pkt_len;
    stat_accumulator_t bwd_pkt_len;
    stat_accumulator_t combined_pkt_len;

    /* Inter-Arrival Time (IAT) tracking */
    uint64_t prev_flow_ts_us;
    uint64_t prev_fwd_ts_us;
    uint64_t prev_bwd_ts_us;

    stat_accumulator_t flow_iat;
    stat_accumulator_t fwd_iat;
    stat_accumulator_t bwd_iat;

    /* TCP Flags */
    uint32_t fwd_psh_flags;
    uint32_t bwd_psh_flags;
    uint32_t fwd_rst_flags;
    uint32_t fin_flag_count;
    uint32_t syn_flag_count;
    uint32_t rst_flag_count;
    uint32_t cwr_flag_count;
    uint32_t ece_flag_count;

    /* TCP Connection State Tracking */
    uint8_t  fwd_tcp_state;
    uint8_t  bwd_tcp_state;
    bool     fwd_fin_seen;     /* FIN observed in forward direction */
    bool     bwd_fin_seen;     /* FIN observed in backward direction */
    uint32_t fwd_seg_size_min;
    int32_t  init_fwd_win_bytes;
    int32_t  init_bwd_win_bytes;

    /* Bulk Transfer */
    bulk_tracker_t fwd_bulk;

    /* Hash table chaining and LRU linked list pointers */
    struct flow_entry *hash_next;
    struct flow_entry *lru_prev;
    struct flow_entry *lru_next;
} flow_entry_t;

/*
 * Finalized Flow Record with all computed features ready for LightGBM / Kafka.
 * Conforms strictly to Flow Feature Specification (v1) and CICIDS2018.
 */
typedef struct {
    char     flow_id[FLOW_ID_STR_LEN];
    char     src_ip_str[MAX_IP_STR_LEN];
    char     dst_ip_str[MAX_IP_STR_LEN];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
    uint64_t start_time_us;
    uint64_t end_time_us;

    /* 1. Volume / Counts */
    uint64_t total_fwd_packets;
    uint64_t total_bwd_packets;
    double   subflow_fwd_packets;

    /* 2. Packet Lengths */
    double   fwd_packet_length_max;
    double   fwd_packet_length_mean;
    double   bwd_packet_length_max;
    double   bwd_packet_length_mean;
    double   packet_length_mean;
    double   packet_length_std;
    double   packet_length_variance;

    /* 3. Flow Rates */
    double   flow_bytes_s;
    double   flow_packets_s;

    /* 4. Duration */
    double   flow_duration; /* in microseconds */

    /* 5. Inter-Arrival Times (IAT) */
    double   flow_iat_mean;
    double   flow_iat_std;
    double   flow_iat_max;
    double   fwd_iat_mean;
    double   fwd_iat_std;
    double   fwd_iat_max;
    double   fwd_iat_total;
    double   bwd_iat_mean;
    double   bwd_iat_min;
    double   bwd_iat_std;
    double   bwd_iat_total;

    /* 6. TCP Flags */
    uint32_t fwd_psh_flags;
    uint32_t bwd_psh_flags;
    uint32_t fwd_rst_flags;
    uint32_t fin_flag_count;
    uint32_t syn_flag_count;
    uint32_t rst_flag_count;
    uint32_t cwr_flag_count;
    uint32_t ece_flag_count;

    /* 7. Ratio */
    double  down_up_ratio;

    /* 8. Bulk */
    double   fwd_avg_bulk_rate;

    /* 9. Segment / Window */
    uint32_t fwd_seg_size_min;
    int32_t  init_fwd_win_bytes;
    int32_t  init_bwd_win_bytes;

    /* 10. Corrected TCP Flow Time */
    double   total_tcp_flow_time;
} flow_record_t;

/* Callback signature when a flow finishes and its features are finalized */
typedef void (*flow_finalized_cb_t)(const flow_record_t *record, void *user_data);

#endif /* NIDS_TYPES_H */
