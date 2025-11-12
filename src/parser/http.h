#ifndef HTTP_H
#define HTTP_H

#include "parser.h"
#include "../utils/common.h"
#include "../utils/packet.h"

// HTTP method types
typedef enum {
    HTTP_METHOD_GET,
    HTTP_METHOD_POST,
    HTTP_METHOD_PUT,
    HTTP_METHOD_PATCH,
    HTTP_METHOD_DELETE,
    HTTP_METHOD_HEAD,
    HTTP_METHOD_OPTIONS,
    HTTP_METHOD_CONNECT,
    HTTP_METHOD_TRACE
} http_method_t;

typedef struct {
    http_method_t method;
    char uri[512];
    char version[16];
    char host[256];
    char user_agent[256];
    int content_length;
} http_request_t;

typedef struct {
    char version[16];
    int status_code;
    char status_msg[128];
    char content_type[128];
    int content_length;
} http_response_t;

int is_http_packet(const packet_t *pkt);
int parse_http_request(const uint8_t *data, size_t len, http_request_t *req);
int parse_http_response(const uint8_t *data, size_t len, http_response_t *resp);
const char* http_method_to_string(http_method_t method);

#endif