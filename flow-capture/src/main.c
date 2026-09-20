#include "capture.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#ifdef _WIN32
#else
    #include <unistd.h>
#endif

static capture_engine_t *global_engine = NULL;

static void sig_handler(int sig) {
    (void)sig;
    if (global_engine) {
        printf("\n[flow-capture] Interrupted! Stopping capture engine and flushing active flows...\n");
        capture_engine_stop(global_engine);
    }
}

static void on_flow_finalized_print(const flow_record_t *record, void *user_data) {
    FILE *out = (FILE *)user_data;
    if (!out) out = stdout;

    char json_buf[4096];
    int len = flow_record_to_json(record, json_buf, sizeof(json_buf));
    if (len > 0) {
        fprintf(out, "%s\n", json_buf);
        fflush(out);
    }
}

static void print_usage(const char *prog) {
    printf("Usage: %s [OPTIONS]\n", prog);
    printf("Options:\n");
    printf("  -i, --interface <iface>   Network interface to capture from (default: any or eth0)\n");
    printf("  -b, --bpf <filter>        BPF packet filter expression (e.g. 'ip and (tcp or udp)')\n");
    printf("  -a, --active-timeout <sec>Active flow timeout in seconds (default: 120)\n");
    printf("  -t, --idle-timeout <sec>  Idle flow timeout in seconds (default: 15)\n");
    printf("  -o, --output <path>       Output file for JSON flows (default: stdout)\n");
    printf("  -v, --verbose             Enable verbose logging\n");
    printf("  -h, --help                Show this help message\n");
}

int main(int argc, char *argv[]) {
    capture_config_t config;
    memset(&config, 0, sizeof(config));
    strncpy(config.device, "any", sizeof(config.device) - 1);
    config.snaplen = 65535;
    config.promisc = 1;
    config.timeout_ms = 50;
    config.flow_table_size = 65536;
    config.max_flows = 500000;
    config.active_timeout_sec = 120;
    config.idle_timeout_sec = 15;
    config.verbose = false;

    char output_path[256] = {0};

    for (int i = 1; i < argc; i++) {
        char *arg = argv[i];
        if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(arg, "-i") == 0 || strcmp(arg, "--interface") == 0) {
            if (i + 1 < argc) {
                strncpy(config.device, argv[++i], sizeof(config.device) - 1);
            } else {
                fprintf(stderr, "Error: -i requires an interface name\n");
                return 1;
            }
        } else if (strcmp(arg, "-b") == 0 || strcmp(arg, "--bpf") == 0) {
            if (i + 1 < argc) {
                strncpy(config.bpf_filter, argv[++i], sizeof(config.bpf_filter) - 1);
            } else {
                fprintf(stderr, "Error: -b requires a BPF filter\n");
                return 1;
            }
        } else if (strcmp(arg, "-a") == 0 || strcmp(arg, "--active-timeout") == 0) {
            if (i + 1 < argc) {
                config.active_timeout_sec = (uint64_t)strtoull(argv[++i], NULL, 10);
            } else {
                fprintf(stderr, "Error: -a requires a timeout value\n");
                return 1;
            }
        } else if (strcmp(arg, "-t") == 0 || strcmp(arg, "--idle-timeout") == 0) {
            if (i + 1 < argc) {
                config.idle_timeout_sec = (uint64_t)strtoull(argv[++i], NULL, 10);
            } else {
                fprintf(stderr, "Error: -t requires a timeout value\n");
                return 1;
            }
        } else if (strcmp(arg, "-o") == 0 || strcmp(arg, "--output") == 0) {
            if (i + 1 < argc) {
                strncpy(output_path, argv[++i], sizeof(output_path) - 1);
            } else {
                fprintf(stderr, "Error: -o requires a file path\n");
                return 1;
            }
        } else if (strcmp(arg, "-v") == 0 || strcmp(arg, "--verbose") == 0) {
            config.verbose = true;
        } else {
            fprintf(stderr, "Unknown option: %s\n", arg);
            print_usage(argv[0]);
            return 1;
        }
    }

    FILE *out_file = stdout;
    if (strlen(output_path) > 0) {
        out_file = fopen(output_path, "a");
        if (!out_file) {
            fprintf(stderr, "[flow-capture ERROR] Failed to open output file: %s\n", output_path);
            return 1;
        }
    }

    /* Register signal handlers for clean teardown */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("====================================================\n");
    printf("  NIDS Flow Capture & Feature Extractor (C Engine)  \n");
    printf("====================================================\n");
    printf("Interface:        %s\n", config.device);
    printf("BPF Filter:       %s\n", strlen(config.bpf_filter) > 0 ? config.bpf_filter : "(none)");
    printf("Active Timeout:   %llu seconds\n", (unsigned long long)config.active_timeout_sec);
    printf("Idle Timeout:     %llu seconds\n", (unsigned long long)config.idle_timeout_sec);
    printf("Output:           %s\n", strlen(output_path) > 0 ? output_path : "stdout");
    printf("Starting live capture...\n");

    capture_engine_t *engine = capture_engine_init(&config, on_flow_finalized_print, (void *)out_file);
    if (!engine) {
        fprintf(stderr, "[flow-capture ERROR] Failed to initialize capture engine.\n");
        if (out_file != stdout) fclose(out_file);
        return 1;
    }

    global_engine = engine;
    capture_engine_start(engine);

    /* Print statistics on finish */
    printf("\n--- Capture Summary ---\n");
    printf("Total Packets:    %llu\n", (unsigned long long)engine->total_packets);
    printf("Total Bytes:      %llu\n", (unsigned long long)engine->total_bytes);
    printf("TCP Packets:      %llu\n", (unsigned long long)engine->tcp_packets);
    printf("UDP Packets:      %llu\n", (unsigned long long)engine->udp_packets);
    printf("Non-IP Packets:   %llu\n", (unsigned long long)engine->non_ip_packets);
    if (engine->flow_table) {
        printf("Total Flows:      %llu\n", (unsigned long long)engine->flow_table->total_flows_created);
        printf("Expired (Idle):   %llu\n", (unsigned long long)engine->flow_table->total_flows_expired_idle);
        printf("Expired (Active): %llu\n", (unsigned long long)engine->flow_table->total_flows_expired_active);
        printf("Expired (TCP):    %llu\n", (unsigned long long)engine->flow_table->total_flows_expired_tcp);
    }

    capture_engine_cleanup(engine);
    global_engine = NULL;

    if (out_file != stdout) {
        fclose(out_file);
    }

    printf("[flow-capture] Shutdown completed successfully.\n");
    return 0;
}
