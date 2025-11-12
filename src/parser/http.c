#include "http.h"
#include <stdio.h>
#include <ctype.h>
#include <string.h>

// This parser works only with http1.X because (using string messages)
int is_http_packet(const packet_t *pkt) {
    if (!pkt->tcp_hdr || !pkt->payload || pkt->payload_len < 4) {
        return 0;
    }
    
    uint16_t src_port = ntohs(pkt->tcp_hdr->source);
    uint16_t dst_port = ntohs(pkt->tcp_hdr->dest);
    
    // Check HTTP ports
    if (src_port != 80 && dst_port != 80 && 
        src_port != 8080 && dst_port != 8080) {
        return 0;
    }
    
    // Check for HTTP signature in payload
    const char *payload = (const char*)pkt->payload;
    
    // HTTP request methods
    if (strncmp(payload, "GET ", 4) == 0 ||
        strncmp(payload, "POST ", 5) == 0 ||
        strncmp(payload, "PUT ", 4) == 0 ||
        strncmp(payload, "PATCH ", 6) == 0 ||
        strncmp(payload, "DELETE ", 7) == 0 ||
        strncmp(payload, "HEAD ", 5) == 0 ||
        strncmp(payload, "OPTIONS ", 8) == 0 ||
        strncmp(payload, "CONNECT ", 8) == 0 ||
        strncmp(payload, "TRACE ", 6) == 0) {
        return 1;
    }
    
    // HTTP response
    if (strncmp(payload, "HTTP/", 5) == 0) {
        return 1;
    }
    
    return 0;
}

int parse_http_request(const uint8_t *data, size_t len, http_request_t *req) {
    if (!data || !req || len < 14) { // Minimum: "GET / HTTP/1.0"
        return PARSE_ERROR;
    }
    
    memset(req, 0, sizeof(http_request_t));
    
    const char *payload = (const char*)data;
    const char *line_end = strstr(payload, "\r\n");
    if (!line_end) {
        line_end = strstr(payload, "\n");
        if (!line_end) return PARSE_ERROR;
    }
    
    // Parse request line
    char request_line[512];
    size_t line_len = line_end - payload;
    if (line_len >= sizeof(request_line)) {
        line_len = sizeof(request_line) - 1;
    }
    memcpy(request_line, payload, line_len);
    request_line[line_len] = '\0';
    
    // Extract method
    char method[16];
    if (sscanf(request_line, "%15s %511s %15s", method, req->uri, req->version) != 3) {
        return PARSE_ERROR;
    }
    
    // Determine method type
    if (strcmp(method, "GET") == 0) req->method = HTTP_METHOD_GET;
    else if (strcmp(method, "POST") == 0) req->method = HTTP_METHOD_POST;
    else if (strcmp(method, "PUT") == 0) req->method = HTTP_METHOD_PUT;
    else if (strcmp(method, "DELETE") == 0) req->method = HTTP_METHOD_DELETE;
    else if (strcmp(method, "HEAD") == 0) req->method = HTTP_METHOD_HEAD;
    else if (strcmp(method, "OPTIONS") == 0) req->method = HTTP_METHOD_OPTIONS;
    else if (strcmp(method, "PATCH") == 0) req->method = HTTP_METHOD_PATCH;
    else if (strcmp(method, "CONNECT") == 0) req->method = HTTP_METHOD_CONNECT;
    else if (strcmp(method, "TRACE") == 0) req->method = HTTP_METHOD_TRACE;
    
    // Parse headers
    const char *header_start = line_end + 2; // Skip \r\n
    const char *header_end = strstr(header_start, "\r\n\r\n");
    if (!header_end) {
        header_end = strstr(header_start, "\n\n");
    }
    
    if (header_end) {
        const char *line = header_start;
        while (line < header_end) {
            const char *next_line = strstr(line, "\r\n");
            if (!next_line) next_line = strstr(line, "\n");
            if (!next_line) break;
            
            // Extract header name and value
            const char *colon = strchr(line, ':');
            if (colon && colon < next_line) {
                char header_name[64];
                size_t name_len = colon - line;
                if (name_len >= sizeof(header_name)) {
                    name_len = sizeof(header_name) - 1;
                }
                memcpy(header_name, line, name_len);
                header_name[name_len] = '\0';
                
                // Skip colon and whitespace
                const char *value = colon + 1;
                while (value < next_line && isspace(*value)) value++;
                
                size_t value_len = next_line - value;
                
                // Parse specific headers
                if (strcasecmp(header_name, "Host") == 0) {
                    if (value_len >= sizeof(req->host)) {
                        value_len = sizeof(req->host) - 1;
                    }
                    memcpy(req->host, value, value_len);
                    req->host[value_len] = '\0';
                }
                else if (strcasecmp(header_name, "User-Agent") == 0) {
                    if (value_len >= sizeof(req->user_agent)) {
                        value_len = sizeof(req->user_agent) - 1;
                    }
                    memcpy(req->user_agent, value, value_len);
                    req->user_agent[value_len] = '\0';
                }
                else if (strcasecmp(header_name, "Content-Length") == 0) {
                    char len_str[16];
                    if (value_len >= sizeof(len_str)) {
                        value_len = sizeof(len_str) - 1;
                    }
                    memcpy(len_str, value, value_len);
                    len_str[value_len] = '\0';
                    req->content_length = atoi(len_str);
                }
            }
            
            line = next_line + 2; // Skip \r\n
        }
    }
    
    return PARSE_SUCCESS;
}

int parse_http_response(const uint8_t *data, size_t len, http_response_t *resp) {
    if (!data || !resp || len < 12) { // Minimum: "HTTP/1.0 200"
        return PARSE_ERROR;
    }
    
    memset(resp, 0, sizeof(http_response_t));
    
    const char *payload = (const char*)data;
    const char *line_end = strstr(payload, "\r\n");
    if (!line_end) {
        line_end = strstr(payload, "\n");
        if (!line_end) return PARSE_ERROR;
    }
    
    // Parse status line
    char status_line[256];
    size_t line_len = line_end - payload;
    if (line_len >= sizeof(status_line)) {
        line_len = sizeof(status_line) - 1;
    }
    memcpy(status_line, payload, line_len);
    status_line[line_len] = '\0';
    
    // Extract version and status code
    if (sscanf(status_line, "%15s %d", resp->version, &resp->status_code) != 2) {
        return PARSE_ERROR;
    }
    
    // Extract status message
    const char *msg_start = strchr(status_line, ' '); // Skip version
    if (msg_start) {
        msg_start = strchr(msg_start + 1, ' '); // Skip status code
        if (msg_start) {
            msg_start++; // Skip space
            strncpy(resp->status_msg, msg_start, sizeof(resp->status_msg) - 1);
            resp->status_msg[sizeof(resp->status_msg) - 1] = '\0';
        }
    }
    
    // Parse headers
    const char *header_start = line_end + 2;
    const char *header_end = strstr(header_start, "\r\n\r\n");
    if (!header_end) {
        header_end = strstr(header_start, "\n\n");
    }
    
    if (header_end) {
        const char *line = header_start;
        while (line < header_end) {
            const char *next_line = strstr(line, "\r\n");
            if (!next_line) next_line = strstr(line, "\n");
            if (!next_line) break;
            
            const char *colon = strchr(line, ':');
            if (colon && colon < next_line) {
                char header_name[64];
                size_t name_len = colon - line;
                if (name_len >= sizeof(header_name)) {
                    name_len = sizeof(header_name) - 1;
                }
                memcpy(header_name, line, name_len);
                header_name[name_len] = '\0';
                
                const char *value = colon + 1;
                while (value < next_line && isspace(*value)) value++;
                
                size_t value_len = next_line - value;
                
                // Parse specific headers
                if (strcasecmp(header_name, "Content-Type") == 0) {
                    if (value_len >= sizeof(resp->content_type)) {
                        value_len = sizeof(resp->content_type) - 1;
                    }
                    memcpy(resp->content_type, value, value_len);
                    resp->content_type[value_len] = '\0';
                }
                else if (strcasecmp(header_name, "Content-Length") == 0) {
                    char len_str[16];
                    if (value_len >= sizeof(len_str)) {
                        value_len = sizeof(len_str) - 1;
                    }
                    memcpy(len_str, value, value_len);
                    len_str[value_len] = '\0';
                    resp->content_length = atoi(len_str);
                }
            }
            
            line = next_line + 2;
        }
    }
    
    return PARSE_SUCCESS;
}

const char* http_method_to_string(http_method_t method) {
    switch (method) {
        case HTTP_METHOD_GET: return "GET";
        case HTTP_METHOD_POST: return "POST";
        case HTTP_METHOD_PUT: return "PUT";
        case HTTP_METHOD_DELETE: return "DELETE";
        case HTTP_METHOD_HEAD: return "HEAD";
        case HTTP_METHOD_OPTIONS: return "OPTIONS";
        case HTTP_METHOD_PATCH: return "PATCH";
        case HTTP_METHOD_CONNECT: return "CONNECT";
        case HTTP_METHOD_TRACE: return "TRACE";
        default: return "UNKNOWN";
    }
}