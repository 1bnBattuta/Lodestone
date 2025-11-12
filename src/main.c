#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <pthread.h>

#include "utils/common.h"
#include "utils/packet.h"
#include "utils/buffer.h"
#include "capture/capture.h"
#include "capture/mmap_capture.h"
#include "capture/filter.h"
#include "parser/parser.h"
#include "output/display.h"
#include "output/pcap_writer.h"
#include "output/logger.h"
#include "output/stats.h"
#include "analysis/stream.h"
#include "analysis/detector.h"

// Global configuration
typedef struct {
    char *interface;
    char *filter_expr;
    char *output_file;
    char *log_file;
    log_format_t log_format;
    display_mode_t display_mode;
    int promiscuous;
    int packet_count;
    int use_mmap;
    int use_colors;
    int show_stats;
    int verbose;
    int quiet;
    
    // Analysis options
    int enable_stream_reassembly;
    int enable_anomaly_detection;
    int show_alerts;
} config_t;

// Global state
typedef struct {
    capture_ctx_t *capture_ctx;
    mmap_capture_ctx_t *mmap_ctx;
    display_ctx_t *display_ctx;
    pcap_writer_ctx_t *pcap_ctx;
    logger_ctx_t *logger_ctx;
    stats_ctx_t *stats_ctx;
    filter_ctx_t *filter_ctx;
    
    // Analysis
    stream_tracker_t *stream_tracker;
    detector_ctx_t *detector_ctx;
    
    uint64_t packet_count;
    int packet_limit;
    int running;
    pthread_t worker_thread;
    ring_buffer_t *packet_queue;
} app_state_t;

static app_state_t *g_app_state = NULL;

// Signal handler for graceful shutdown
void signal_handler(int signum) {
    if (g_app_state) {
        printf("\n\nReceived signal %d, shutting down...\n", signum);
        g_app_state->running = 0;
        
        if (g_app_state->capture_ctx) {
            capture_stop(g_app_state->capture_ctx);
        }
        if (g_app_state->mmap_ctx) {
            g_app_state->mmap_ctx->running = 0;
        }
    }
}

// Callback for reassembled TCP stream data
void stream_data_callback(tcp_stream_t *stream, stream_direction_t dir,
                          const uint8_t *data, size_t len, void *user_data) {
    config_t *config = (config_t*)user_data;
    
    if (config->verbose) {
        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        struct in_addr addr;
        
        addr.s_addr = stream->src_ip;
        inet_ntop(AF_INET, &addr, src_ip, sizeof(src_ip));
        addr.s_addr = stream->dst_ip;
        inet_ntop(AF_INET, &addr, dst_ip, sizeof(dst_ip));
        
        printf("\n[STREAM DATA] %s:%u -> %s:%u (%s)\n",
               src_ip, ntohs(stream->src_port),
               dst_ip, ntohs(stream->dst_port),
               dir == STREAM_DIR_FORWARD ? "forward" : "reverse");
        printf("Data (%zu bytes):\n", len);
        
        // Print first 256 bytes
        size_t print_len = len > 256 ? 256 : len;
        for (size_t i = 0; i < print_len; i++) {
            if (data[i] >= 32 && data[i] <= 126) {
                printf("%c", data[i]);
            } else if (data[i] == '\n') {
                printf("\n");
            } else {
                printf(".");
            }
        }
        if (len > 256) {
            printf("\n... (%zu more bytes)\n", len - 256);
        }
        printf("\n");
    }
}

// Callback for anomaly detection alerts
void alert_callback(const alert_t *alert, void *user_data) {
    config_t *config = (config_t*)user_data;
    
    if (config->show_alerts) {
        alert_print(alert, stdout);
    }
}

// Print usage information
void print_usage(const char *prog_name) {
    printf("Usage: %s [OPTIONS]\n\n", prog_name);
    printf("Packet Sniffer - High Performance Network Packet Capture Tool\n\n");
    printf("Options:\n");
    printf("  -i, --interface <name>     Network interface to capture from (required)\n");
    printf("  -f, --filter <expr>        BPF filter expression (e.g., 'tcp port 80')\n");
    printf("  -o, --output <file>        Save packets to PCAP file\n");
    printf("  -l, --log <file>           Log packets to file\n");
    printf("  -F, --log-format <fmt>     Log format: text, csv, json, xml (default: text)\n");
    printf("  -c, --count <num>          Stop after capturing <num> packets\n");
    printf("  -p, --promiscuous          Enable promiscuous mode (default: enabled)\n");
    printf("  -P, --no-promiscuous       Disable promiscuous mode\n");
    printf("  -m, --mmap                 Use memory-mapped capture (higher performance)\n");
    printf("  -d, --display <mode>       Display mode: brief, detailed, hex, full (default: brief)\n");
    printf("  -C, --no-color             Disable colored output\n");
    printf("  -s, --stats                Show statistics on exit\n");
    printf("  -v, --verbose              Verbose output\n");
    printf("  -q, --quiet                Quiet mode (no packet display)\n");
    printf("\n");
    printf("Analysis Options:\n");
    printf("  -r, --reassemble           Enable TCP stream reassembly\n");
    printf("  -a, --detect-anomalies     Enable anomaly detection (port scans, floods, etc.)\n");
    printf("  -A, --show-alerts          Show security alerts\n");
    printf("\n");
    printf("  -h, --help                 Display this help message\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -i eth0                                    # Capture all packets on eth0\n", prog_name);
    printf("  %s -i eth0 -f \"tcp port 80\"                  # Capture HTTP traffic\n", prog_name);
    printf("  %s -i eth0 -o capture.pcap                   # Save to PCAP file\n", prog_name);
    printf("  %s -i eth0 -a -A                             # Enable anomaly detection with alerts\n", prog_name);
    printf("  %s -i eth0 -r -v                             # TCP stream reassembly with verbose output\n", prog_name);
    printf("  %s -i eth0 -f \"tcp port 80\" -r -d detailed  # HTTP analysis with stream tracking\n", prog_name);
    printf("\n");
}

// Parse command line arguments
int parse_arguments(int argc, char **argv, config_t *config) {
    static struct option long_options[] = {
        {"interface",         required_argument, 0, 'i'},
        {"filter",            required_argument, 0, 'f'},
        {"output",            required_argument, 0, 'o'},
        {"log",               required_argument, 0, 'l'},
        {"log-format",        required_argument, 0, 'F'},
        {"count",             required_argument, 0, 'c'},
        {"promiscuous",       no_argument,       0, 'p'},
        {"no-promiscuous",    no_argument,       0, 'P'},
        {"mmap",              no_argument,       0, 'm'},
        {"display",           required_argument, 0, 'd'},
        {"no-color",          no_argument,       0, 'C'},
        {"stats",             no_argument,       0, 's'},
        {"verbose",           no_argument,       0, 'v'},
        {"quiet",             no_argument,       0, 'q'},
        {"reassemble",        no_argument,       0, 'r'},
        {"detect-anomalies",  no_argument,       0, 'a'},
        {"show-alerts",       no_argument,       0, 'A'},
        {"help",              no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    
    int option_index = 0;
    int c;
    
    // Set defaults
    memset(config, 0, sizeof(config_t));
    config->promiscuous = 1;
    config->use_colors = 1;
    config->display_mode = DISPLAY_MODE_BRIEF;
    config->log_format = LOG_FORMAT_TEXT;
    config->packet_count = -1; // Unlimited
    
    while ((c = getopt_long(argc, argv, "i:f:o:l:F:c:pPmd:CsvqraAh", long_options, &option_index)) != -1) {
        switch (c) {
            case 'i':
                config->interface = strdup(optarg);
                break;
            case 'f':
                config->filter_expr = strdup(optarg);
                break;
            case 'o':
                config->output_file = strdup(optarg);
                break;
            case 'l':
                config->log_file = strdup(optarg);
                break;
            case 'F':
                if (strcmp(optarg, "text") == 0) {
                    config->log_format = LOG_FORMAT_TEXT;
                } else if (strcmp(optarg, "csv") == 0) {
                    config->log_format = LOG_FORMAT_CSV;
                } else if (strcmp(optarg, "json") == 0) {
                    config->log_format = LOG_FORMAT_JSON;
                } else if (strcmp(optarg, "xml") == 0) {
                    config->log_format = LOG_FORMAT_XML;
                } else {
                    fprintf(stderr, "Invalid log format: %s\n", optarg);
                    return ERROR;
                }
                break;
            case 'c':
                config->packet_count = atoi(optarg);
                if (config->packet_count <= 0) {
                    fprintf(stderr, "Invalid packet count: %s\n", optarg);
                    return ERROR;
                }
                break;
            case 'p':
                config->promiscuous = 1;
                break;
            case 'P':
                config->promiscuous = 0;
                break;
            case 'm':
                config->use_mmap = 1;
                break;
            case 'd':
                if (strcmp(optarg, "brief") == 0) {
                    config->display_mode = DISPLAY_MODE_BRIEF;
                } else if (strcmp(optarg, "detailed") == 0) {
                    config->display_mode = DISPLAY_MODE_DETAILED;
                } else if (strcmp(optarg, "hex") == 0) {
                    config->display_mode = DISPLAY_MODE_HEX;
                } else if (strcmp(optarg, "full") == 0) {
                    config->display_mode = DISPLAY_MODE_FULL;
                } else {
                    fprintf(stderr, "Invalid display mode: %s\n", optarg);
                    return ERROR;
                }
                break;
            case 'C':
                config->use_colors = 0;
                break;
            case 's':
                config->show_stats = 1;
                break;
            case 'v':
                config->verbose = 1;
                break;
            case 'q':
                config->quiet = 1;
                break;
            case 'r':
                config->enable_stream_reassembly = 1;
                break;
            case 'a':
                config->enable_anomaly_detection = 1;
                break;
            case 'A':
                config->show_alerts = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                exit(0);
            case '?':
                return ERROR;
            default:
                return ERROR;
        }
    }
    
    // Validate required arguments
    if (!config->interface) {
        fprintf(stderr, "Error: Network interface is required (-i option)\n\n");
        print_usage(argv[0]);
        return ERROR;
    }
    
    // If anomaly detection or stream reassembly enabled, automatically enable show_alerts
    if (config->enable_anomaly_detection && !config->show_alerts) {
        config->show_alerts = 1;
    }
    
    return SUCCESS;
}

// Packet processing callback
void process_packet(packet_t *pkt, void *user_data) {
    app_state_t *state = (app_state_t*)user_data;
    
    if (!state || !pkt) return;
    
    // Parse packet layers
    if (parse_packet_layers(pkt) != PARSE_SUCCESS) {
        packet_destroy(pkt);
        return;
    }
    
    state->packet_count++;
    
    // Update statistics
    if (state->stats_ctx) {
        stats_update(state->stats_ctx, pkt);
    }
    
    // Stream reassembly
    if (state->stream_tracker && pkt->tcp_hdr) {
        stream_tracker_process_packet(state->stream_tracker, pkt);
    }
    
    // Anomaly detection
    if (state->detector_ctx) {
        detector_process_packet(state->detector_ctx, pkt);
    }
    
    // Display packet
    if (state->display_ctx && state->running) {
        display_packet(state->display_ctx, pkt, state->packet_count);
    }
    
    // Write to PCAP file
    if (state->pcap_ctx) {
        pcap_writer_write_packet(state->pcap_ctx, pkt);
    }
    
    // Write to log file
    if (state->logger_ctx) {
        logger_write_packet(state->logger_ctx, pkt, state->packet_count);
    }
    
    packet_destroy(pkt);

    if (state->packet_limit > 0 && state->packet_count >= (uint64_t)state->packet_limit) {
        printf("\nReached packet limit (%d packets captured)\n", state->packet_limit);
        
        // Stop capture
        state->running = 0;
        if (state->capture_ctx) {
            capture_stop(state->capture_ctx);
        }
        if (state->mmap_ctx) {
            state->mmap_ctx->running = 0;
        }
    }
}

// Initialize application
int init_application(app_state_t *state, config_t *config) {
    memset(state, 0, sizeof(app_state_t));
    state->running = 1;
    state->packet_limit = config->packet_count;
    
    // Initialize statistics
    state->stats_ctx = stats_init();
    if (!state->stats_ctx) {
        fprintf(stderr, "Failed to initialize statistics\n");
        return ERROR;
    }
    
    // Initialize stream tracker if requested
    if (config->enable_stream_reassembly) {
        state->stream_tracker = stream_tracker_init();
        if (!state->stream_tracker) {
            fprintf(stderr, "Failed to initialize stream tracker\n");
            return ERROR;
        }
        stream_tracker_set_callback(state->stream_tracker, stream_data_callback, config);
        
        if (config->verbose) {
            printf("TCP stream reassembly enabled\n");
        }
    }
    
    // Initialize anomaly detector if requested
    if (config->enable_anomaly_detection) {
        state->detector_ctx = detector_init();
        if (!state->detector_ctx) {
            fprintf(stderr, "Failed to initialize anomaly detector\n");
            return ERROR;
        }
        detector_set_alert_callback(state->detector_ctx, alert_callback, config);
        
        if (config->verbose) {
            printf("Anomaly detection enabled\n");
        }
    }
    
    // Initialize display
    if (!config->quiet) {
        state->display_ctx = display_init(config->display_mode, config->use_colors);
        if (!state->display_ctx) {
            fprintf(stderr, "Failed to initialize display\n");
            return ERROR;
        }
    }
    
    // Initialize PCAP writer
    if (config->output_file) {
        state->pcap_ctx = pcap_writer_open(config->output_file);
        if (!state->pcap_ctx) {
            fprintf(stderr, "Failed to open PCAP file: %s\n", config->output_file);
            return ERROR;
        }
        if (config->verbose) {
            printf("Writing packets to: %s\n", config->output_file);
        }
    }
    
    // Initialize logger
    if (config->log_file) {
        state->logger_ctx = logger_open(config->log_file, config->log_format);
        if (!state->logger_ctx) {
            fprintf(stderr, "Failed to open log file: %s\n", config->log_file);
            return ERROR;
        }
        if (config->verbose) {
            printf("Logging packets to: %s (format: %d)\n", config->log_file, config->log_format);
        }
    }
    
    // Initialize filter
    if (config->filter_expr) {
        state->filter_ctx = filter_compile(config->filter_expr, 1);
        if (!state->filter_ctx) {
            fprintf(stderr, "Failed to compile filter: %s\n", config->filter_expr);
            return ERROR;
        }
        if (config->verbose) {
            printf("Using BPF filter: %s\n", config->filter_expr);
        }
    }
    
    // Initialize capture
    if (config->use_mmap) {
        state->mmap_ctx = mmap_capture_init(config->interface);
        if (!state->mmap_ctx) {
            fprintf(stderr, "Failed to initialize mmap capture on %s\n", config->interface);
            return ERROR;
        }
        if (config->verbose) {
            printf("Using memory-mapped capture on interface: %s\n", config->interface);
        }
    } else {
        state->capture_ctx = capture_init(config->interface, config->promiscuous);
        if (!state->capture_ctx) {
            fprintf(stderr, "Failed to initialize capture on %s\n", config->interface);
            return ERROR;
        }
        
        // Attach filter
        if (state->filter_ctx) {
            if (filter_attach(state->capture_ctx->sockfd, state->filter_ctx) != SUCCESS) {
                fprintf(stderr, "Warning: Failed to attach BPF filter\n");
            }
        }
        
        if (config->verbose) {
            printf("Capturing on interface: %s (promiscuous: %s)\n", 
                   config->interface, config->promiscuous ? "yes" : "no");
        }
    }
    
    return SUCCESS;
}

// Cleanup application
void cleanup_application(app_state_t *state) {
    if (!state) return;
    
    // Stop capture
    if (state->capture_ctx) {
        capture_cleanup(state->capture_ctx);
        state->capture_ctx = NULL;
    }
    
    if (state->mmap_ctx) {
        mmap_capture_cleanup(state->mmap_ctx);
        state->mmap_ctx = NULL;
    }
    
    // Close outputs
    if (state->pcap_ctx) {
        pcap_writer_close(state->pcap_ctx);
        state->pcap_ctx = NULL;
    }
    
    if (state->logger_ctx) {
        logger_close(state->logger_ctx);
        state->logger_ctx = NULL;
    }
    
    // Cleanup display
    if (state->display_ctx) {
        display_cleanup(state->display_ctx);
        state->display_ctx = NULL;
    }
    
    // Cleanup filter
    if (state->filter_ctx) {
        filter_destroy(state->filter_ctx);
        state->filter_ctx = NULL;
    }
    
    // Cleanup analysis
    if (state->stream_tracker) {
        stream_tracker_cleanup(state->stream_tracker);
        state->stream_tracker = NULL;
    }
    
    if (state->detector_ctx) {
        detector_cleanup(state->detector_ctx);
        state->detector_ctx = NULL;
    }
    
    // Cleanup statistics
    if (state->stats_ctx) {
        stats_cleanup(state->stats_ctx);
        state->stats_ctx = NULL;
    }
}

// Main capture loop
int run_capture(app_state_t *state, const config_t *config) {
    printf("\n");
    printf("====================================\n");
    printf("  Packet Sniffer - Capture Started\n");
    printf("====================================\n");
    if (config->packet_count > 0) {
        printf("Capturing %d packets...\n", config->packet_count);
    } else {
        printf("Capturing packets (Press Ctrl+C to stop)...\n");
    }
    if (config->enable_stream_reassembly) {
        printf("TCP Stream Reassembly: ENABLED\n");
    }
    if (config->enable_anomaly_detection) {
        printf("Anomaly Detection: ENABLED\n");
    }
    printf("\n");
    
    // Start capture
    if (state->capture_ctx) {
        if (capture_start(state->capture_ctx) != SUCCESS) {
            fprintf(stderr, "Failed to start capture\n");
            return ERROR;
        }
    }

    // Run capture loop - will stop automatically when:
    // 1. Packet limit is reached (checked in process_packet)
    // 2. User presses Ctrl+C (signal handler sets running = 0)
    // 3. Error occurs
    
    int ret;
    
    if (state->mmap_ctx) {
        ret = mmap_capture_loop(state->mmap_ctx, process_packet, state);
    } else {
        ret = capture_loop(state->capture_ctx, process_packet, state);
    }
    
    if (ret != SUCCESS && state->running) {
        // Only report error if we're still supposed to be running
        // (if running=0, we stopped intentionally)
        fprintf(stderr, "Capture loop error\n");
        return ERROR;
    }
    
    return SUCCESS;
}

// Print final statistics
void print_final_stats(app_state_t *state, const config_t *config) {
    printf("\n");
    printf("====================================\n");
    printf("  Capture Summary\n");
    printf("====================================\n");
    
    if (state->stats_ctx) {
        if (config->show_stats) {
            stats_print_detailed(state->stats_ctx, stdout);
        } else {
            stats_print_summary(state->stats_ctx, stdout);
        }
    }
    
    if (state->capture_ctx) {
        uint64_t captured, dropped, bytes;
        capture_get_stats(state->capture_ctx, &captured, &dropped, &bytes);
        
        if (dropped > 0) {
            printf("Warning: %lu packets dropped by kernel\n", dropped);
        }
    }
    
    if (state->pcap_ctx) {
        uint64_t packets, bytes;
        pcap_writer_get_stats(state->pcap_ctx, &packets, &bytes);
        printf("Wrote %lu packets (%.2f MB) to PCAP file\n", 
               packets, bytes / (1024.0 * 1024.0));
    }
    
    if (state->logger_ctx) {
        printf("Logged %lu packets to file\n", state->logger_ctx->packets_logged);
    }
    
    if (state->detector_ctx) {
        printf("\nSecurity Alerts: %lu total\n", state->detector_ctx->total_alerts);
        if (state->detector_ctx->total_alerts > 0) {
            printf("  Port Scans: %lu\n", state->detector_ctx->alerts_by_type[ALERT_PORT_SCAN]);
            printf("  SYN Floods: %lu\n", state->detector_ctx->alerts_by_type[ALERT_SYN_FLOOD]);
            printf("  ARP Spoofing: %lu\n", state->detector_ctx->alerts_by_type[ALERT_ARP_SPOOF]);
        }
    }
}

// Free config strings
void free_config(config_t *config) {
    if (config->interface) free(config->interface);
    if (config->filter_expr) free(config->filter_expr);
    if (config->output_file) free(config->output_file);
    if (config->log_file) free(config->log_file);
}

int main(int argc, char **argv) {
    config_t config;
    app_state_t state;
    
    // Parse arguments
    if (parse_arguments(argc, argv, &config) != SUCCESS) {
        return EXIT_FAILURE;
    }
    
    // Check root privileges
    if (geteuid() != 0) {
        fprintf(stderr, "Error: This program requires root privileges\n");
        fprintf(stderr, "Please run with sudo or as root\n");
        free_config(&config);
        return EXIT_FAILURE;
    }
    
    // Initialize application
    if (init_application(&state, &config) != SUCCESS) {
        cleanup_application(&state);
        free_config(&config);
        return EXIT_FAILURE;
    }
    
    // Set global state for signal handler
    g_app_state = &state;
    
    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Run capture
    int ret = run_capture(&state, &config);
    
    // Print statistics
    print_final_stats(&state, &config);
    
    // Cleanup
    cleanup_application(&state);
    free_config(&config);
    
    printf("\nCapture complete. Exiting.\n");
    
    return (ret == SUCCESS) ? EXIT_SUCCESS : EXIT_FAILURE;
}