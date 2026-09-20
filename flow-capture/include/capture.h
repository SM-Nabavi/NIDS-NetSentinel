#ifndef NIDS_CAPTURE_H
#define NIDS_CAPTURE_H

#include "types.h"
#include "flow_table.h"
#include <pcap.h>

typedef struct {
    char device[64];
    char bpf_filter[256];
    int snaplen;
    int promisc;
    int timeout_ms;
    size_t flow_table_size;
    size_t max_flows;
    uint64_t active_timeout_sec;
    uint64_t idle_timeout_sec;
    bool verbose;
} capture_config_t;

typedef struct {
    pcap_t *pcap_handle;
    flow_table_t *flow_table;
    capture_config_t config;
    volatile bool is_running;

    /* Metrics */
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t dropped_packets;
    uint64_t non_ip_packets;
    uint64_t tcp_packets;
    uint64_t udp_packets;
    uint64_t other_packets;
} capture_engine_t;

/*
 * Initialize capture engine on a specified network interface.
 */
capture_engine_t *capture_engine_init(const capture_config_t *config,
                                     flow_finalized_cb_t callback,
                                     void *user_data);

/*
 * Start the blocking packet capture loop.
 */
int capture_engine_start(capture_engine_t *engine);

/*
 * Stop the packet capture loop safely.
 */
void capture_engine_stop(capture_engine_t *engine);

/*
 * Cleanup and free engine resources.
 */
void capture_engine_cleanup(capture_engine_t *engine);

/*
 * Helper to serialize a flow record to clean JSON string.
 */
int flow_record_to_json(const flow_record_t *record, char *buf, size_t max_len);

#endif /* NIDS_CAPTURE_H */
