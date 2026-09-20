#ifndef NIDS_FLOW_TABLE_H
#define NIDS_FLOW_TABLE_H

#include "types.h"
#include <stddef.h>

#define DEFAULT_FLOW_TABLE_BUCKETS 65536
#define DEFAULT_ACTIVE_TIMEOUT_US  120000000ULL /* 120 seconds */
#define DEFAULT_IDLE_TIMEOUT_US     15000000ULL /* 15 seconds */
#define DEFAULT_TCP_CLOSED_TIMEOUT_US 2000000ULL /* 2 seconds after mutual FIN/RST */

typedef struct flow_table {
    flow_entry_t **buckets;
    size_t num_buckets;
    size_t active_flows_count;
    size_t max_flows;

    /* Double-linked LRU list for efficient timeout scanning */
    flow_entry_t *lru_head;
    flow_entry_t *lru_tail;

    /* Configurable timeouts */
    uint64_t active_timeout_us;
    uint64_t idle_timeout_us;
    uint64_t tcp_closed_timeout_us;

    /* Callback when a flow terminates */
    flow_finalized_cb_t on_flow_finalized;
    void *cb_user_data;

    /* Metrics */
    uint64_t total_flows_created;
    uint64_t total_flows_expired_active;
    uint64_t total_flows_expired_idle;
    uint64_t total_flows_expired_tcp;
} flow_table_t;

/*
 * Initialize the flow table.
 */
flow_table_t *flow_table_create(size_t num_buckets, size_t max_flows,
                                uint64_t active_timeout_us, uint64_t idle_timeout_us,
                                flow_finalized_cb_t callback, void *user_data);

/*
 * Lookup or create a flow for the given packet 5-tuple.
 * Sets is_forward to true if packet aligns with original flow direction, false if reverse.
 */
flow_entry_t *flow_table_get_or_create(flow_table_t *tbl, const flow_key_t *key,
                                      uint64_t pkt_time_us, bool *out_is_forward);

/*
 * Periodically purge flows that exceeded idle or active timeouts.
 */
size_t flow_table_expire_flows(flow_table_t *tbl, uint64_t current_time_us);

/*
 * Finalize an individual flow, invoke the callback, and free memory.
 */
void flow_table_finalize_flow(flow_table_t *tbl, flow_entry_t *flow);

/*
 * Flush all active flows (e.g. on shutdown).
 */
void flow_table_flush(flow_table_t *tbl);

/*
 * Destroy and free all table resources.
 */
void flow_table_destroy(flow_table_t *tbl);

#endif /* NIDS_FLOW_TABLE_H */
