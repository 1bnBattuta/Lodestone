#ifndef LOGGER_H
#define LOGGER_H

#include "../utils/common.h"
#include "../utils/packet.h"
#include <stdio.h>

// Log formats
typedef enum {
    LOG_FORMAT_TEXT,      // Human-readable text
    LOG_FORMAT_CSV,       // Comma-separated values
    LOG_FORMAT_JSON,      // JSON format
    LOG_FORMAT_XML        // XML format
} log_format_t;

typedef struct {
    FILE *file;
    char filename[256];
    log_format_t format;
    uint64_t packets_logged;
    int initialized;
} logger_ctx_t;

// Logger functions
logger_ctx_t* logger_open(const char *filename, log_format_t format);
void logger_close(logger_ctx_t *ctx);
int logger_write_packet(logger_ctx_t *ctx, const packet_t *pkt, uint64_t pkt_num);
int logger_write_header(logger_ctx_t *ctx);
int logger_write_footer(logger_ctx_t *ctx);

#endif