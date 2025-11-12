#include "logger.h"
#include "../parser/ethernet.h"
#include "../parser/ip.h"
#include <time.h>
#include <arpa/inet.h>
#include <string.h>

logger_ctx_t* logger_open(const char *filename, log_format_t format) {
    if (!filename) return NULL;
    
    logger_ctx_t *ctx = (logger_ctx_t*)malloc(sizeof(logger_ctx_t));
    if (!ctx) {
        perror("malloc");
        return NULL;
    }
    
    memset(ctx, 0, sizeof(logger_ctx_t));
    strncpy(ctx->filename, filename, sizeof(ctx->filename) - 1);
    ctx->format = format;
    
    // Open file
    ctx->file = fopen(filename, "w");
    if (!ctx->file) {
        perror("fopen");
        free(ctx);
        return NULL;
    }
    
    // Write format-specific header
    logger_write_header(ctx);
    ctx->initialized = 1;
    
    return ctx;
}

void logger_close(logger_ctx_t *ctx) {
    if (!ctx) return;
    
    if (ctx->file) {
        logger_write_footer(ctx);
        fflush(ctx->file);
        fclose(ctx->file);
    }
    
    free(ctx);
}

int logger_write_header(logger_ctx_t *ctx) {
    if (!ctx || !ctx->file) return ERROR;
    
    switch (ctx->format) {
        case LOG_FORMAT_CSV:
            fprintf(ctx->file, "packet_num,timestamp,src_mac,dst_mac,ethertype,");
            fprintf(ctx->file, "src_ip,dst_ip,protocol,src_port,dst_port,length,payload_len\n");
            break;
            
        case LOG_FORMAT_JSON:
            fprintf(ctx->file, "{\n  \"packets\": [\n");
            break;
            
        case LOG_FORMAT_XML:
            fprintf(ctx->file, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
            fprintf(ctx->file, "<packets>\n");
            break;
            
        case LOG_FORMAT_TEXT:
        default:
            fprintf(ctx->file, "Packet Capture Log\n");
            fprintf(ctx->file, "==================\n\n");
            break;
    }
    
    return SUCCESS;
}

int logger_write_footer(logger_ctx_t *ctx) {
    if (!ctx || !ctx->file) return ERROR;
    
    switch (ctx->format) {
        case LOG_FORMAT_JSON:
            fprintf(ctx->file, "\n  ]\n}\n");
            break;
            
        case LOG_FORMAT_XML:
            fprintf(ctx->file, "</packets>\n");
            break;
            
        case LOG_FORMAT_TEXT:
        case LOG_FORMAT_CSV:
        default:
            break;
    }
    
    return SUCCESS;
}

static void escape_json_string(const char *input, char *output, size_t output_len) {
    size_t j = 0;
    for (size_t i = 0; input[i] && j < output_len - 2; i++) {
        if (input[i] == '"' || input[i] == '\\') {
            output[j++] = '\\';
        }
        output[j++] = input[i];
    }
    output[j] = '\0';
}

int logger_write_packet(logger_ctx_t *ctx, const packet_t *pkt, uint64_t pkt_num) {
    if (!ctx || !ctx->file || !pkt) return ERROR;
    
    FILE *f = ctx->file;
    
    // Timestamp
    char timestamp[64];
    time_t sec = pkt->timestamp.tv_sec;
    struct tm *tm = localtime(&sec);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm);
    
    switch (ctx->format) {
        case LOG_FORMAT_CSV: {
            fprintf(f, "%lu,", pkt_num);
            fprintf(f, "%s.%06ld,", timestamp, pkt->timestamp.tv_usec);
            
            if (pkt->eth_hdr) {
                char src_mac[18], dst_mac[18];
                format_mac(pkt->eth_hdr->ether_shost, src_mac, sizeof(src_mac));
                format_mac(pkt->eth_hdr->ether_dhost, dst_mac, sizeof(dst_mac));
                fprintf(f, "%s,%s,0x%04x,", src_mac, dst_mac, ntohs(pkt->eth_hdr->ether_type));} else {
                fprintf(f, ",,,");
            }
            
            // IPv4
            if (pkt->ip_version == 4 && pkt->ip_hdr) {
                char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &pkt->ip_hdr->saddr, src_ip, sizeof(src_ip));
                inet_ntop(AF_INET, &pkt->ip_hdr->daddr, dst_ip, sizeof(dst_ip));
                fprintf(f, "4,%s,%s,%u,", src_ip, dst_ip, pkt->ip_hdr->protocol);
            }
            // IPv6
            else if (pkt->ip_version == 6 && pkt->ip6_hdr) {
                char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &pkt->ip6_hdr->ip6_src, src_ip, sizeof(src_ip));
                inet_ntop(AF_INET6, &pkt->ip6_hdr->ip6_dst, dst_ip, sizeof(dst_ip));
                fprintf(f, "6,%s,%s,%u,", src_ip, dst_ip, pkt->ip6_hdr->ip6_nxt);
            } else {
                fprintf(f, ",,,,");
            }
            
            if (pkt->tcp_hdr) {
                fprintf(f, "%u,%u,", ntohs(pkt->tcp_hdr->source), ntohs(pkt->tcp_hdr->dest));
            } else if (pkt->udp_hdr) {
                fprintf(f, "%u,%u,", ntohs(pkt->udp_hdr->source), ntohs(pkt->udp_hdr->dest));
            } else {
                fprintf(f, ",,");
            }
            
            fprintf(f, "%zu,%zu\n", pkt->length, pkt->payload_len);
            break;
        }
        
        case LOG_FORMAT_JSON: {
            if (ctx->packets_logged > 0) {
                fprintf(f, ",\n");
            }
            
            fprintf(f, "    {\n");
            fprintf(f, "      \"packet_num\": %lu,\n", pkt_num);
            fprintf(f, "      \"timestamp\": \"%s.%06ld\",\n", timestamp, pkt->timestamp.tv_usec);
            fprintf(f, "      \"length\": %zu,\n", pkt->length);
            fprintf(f, "      \"ip_version\": %u", pkt->ip_version);

            if (pkt->eth_hdr) {
                char src_mac[18], dst_mac[18];
                format_mac(pkt->eth_hdr->ether_shost, src_mac, sizeof(src_mac));
                format_mac(pkt->eth_hdr->ether_dhost, dst_mac, sizeof(dst_mac));
                
                fprintf(f, "      \"ethernet\": {\n");
                fprintf(f, "        \"src_mac\": \"%s\",\n", src_mac);
                fprintf(f, "        \"dst_mac\": \"%s\",\n", dst_mac);
                fprintf(f, "        \"ethertype\": \"0x%04x\"\n", ntohs(pkt->eth_hdr->ether_type));
                fprintf(f, "      }");
            }
            
            if (pkt->ip_version == 4 && pkt->ip_hdr) {
                char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &pkt->ip_hdr->saddr, src_ip, sizeof(src_ip));
                inet_ntop(AF_INET, &pkt->ip_hdr->daddr, dst_ip, sizeof(dst_ip));
                
                fprintf(f, ",\n");
                fprintf(f, "      \"ipv4\": {\n");
                fprintf(f, "        \"src_ip\": \"%s\",\n", src_ip);
                fprintf(f, "        \"dst_ip\": \"%s\",\n", dst_ip);
                fprintf(f, "        \"protocol\": %u,\n", pkt->ip_hdr->protocol);
                fprintf(f, "        \"ttl\": %u\n", pkt->ip_hdr->ttl);
                fprintf(f, "      }");
            } else if (pkt->ip_version == 6 && pkt->ip6_hdr) {
                char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &pkt->ip6_hdr->ip6_src, src_ip, sizeof(src_ip));
                inet_ntop(AF_INET6, &pkt->ip6_hdr->ip6_dst, dst_ip, sizeof(dst_ip));
                
                fprintf(f, ",\n");
                fprintf(f, "      \"ipv6\": {\n");
                fprintf(f, "        \"src_ip\": \"%s\",\n", src_ip);
                fprintf(f, "        \"dst_ip\": \"%s\",\n", dst_ip);
                fprintf(f, "        \"next_header\": %u,\n", pkt->ip6_hdr->ip6_nxt);
                fprintf(f, "        \"hop_limit\": %u\n", pkt->ip6_hdr->ip6_hlim);
                fprintf(f, "      }");
            }
            
            if (pkt->tcp_hdr) {
                fprintf(f, "      \"tcp\": {\n");
                fprintf(f, "        \"src_port\": %u,\n", ntohs(pkt->tcp_hdr->source));
                fprintf(f, "        \"dst_port\": %u,\n", ntohs(pkt->tcp_hdr->dest));
                fprintf(f, "        \"seq\": %u,\n", ntohl(pkt->tcp_hdr->seq));
                fprintf(f, "        \"ack\": %u,\n", ntohl(pkt->tcp_hdr->ack_seq));
                fprintf(f, "        \"flags\": {\n");
                fprintf(f, "          \"fin\": %d,\n", pkt->tcp_hdr->fin);
                fprintf(f, "          \"syn\": %d,\n", pkt->tcp_hdr->syn);
                fprintf(f, "          \"rst\": %d,\n", pkt->tcp_hdr->rst);
                fprintf(f, "          \"psh\": %d,\n", pkt->tcp_hdr->psh);
                fprintf(f, "          \"ack\": %d,\n", pkt->tcp_hdr->ack);
                fprintf(f, "          \"urg\": %d\n", pkt->tcp_hdr->urg);
                fprintf(f, "        }\n");
                fprintf(f, "      }");
                
                if (pkt->payload_len > 0) {
                    fprintf(f, ",");
                }
                fprintf(f, "\n");
            } else if (pkt->udp_hdr) {
                fprintf(f, "      \"udp\": {\n");
                fprintf(f, "        \"src_port\": %u,\n", ntohs(pkt->udp_hdr->source));
                fprintf(f, "        \"dst_port\": %u,\n", ntohs(pkt->udp_hdr->dest));
                fprintf(f, "        \"length\": %u\n", ntohs(pkt->udp_hdr->len));
                fprintf(f, "      }");
                
                if (pkt->payload_len > 0) {
                    fprintf(f, ",");
                }
                fprintf(f, "\n");
            } else if (pkt->icmp_hdr) {
                fprintf(f, "      \"icmp\": {\n");
                fprintf(f, "        \"type\": %u,\n", pkt->icmp_hdr->type);
                fprintf(f, "        \"code\": %u\n", pkt->icmp_hdr->code);
                fprintf(f, "      }");
                
                if (pkt->payload_len > 0) {
                    fprintf(f, ",");
                }
                fprintf(f, "\n");
            } else if (pkt->icmp6_hdr) {
                fprintf(f, ",\n");
                fprintf(f, "      \"icmpv6\": {\n");
                fprintf(f, "        \"type\": %u,\n", pkt->icmp6_hdr->icmp6_type);
                fprintf(f, "        \"code\": %u\n", pkt->icmp6_hdr->icmp6_code);
                fprintf(f, "      }");
            }

            
            if (pkt->payload_len > 0) {
                fprintf(f, "      \"payload_length\": %zu\n", pkt->payload_len);
            }
            
            fprintf(f, "    }");
            break;
        }
        
        case LOG_FORMAT_XML: {
            fprintf(f, "  <packet num=\"%lu\">\n", pkt_num);
            fprintf(f, "    <timestamp>%s.%06ld</timestamp>\n", timestamp, pkt->timestamp.tv_usec);
            fprintf(f, "    <length>%zu</length>\n", pkt->length);
            
            if (pkt->eth_hdr) {
                char src_mac[18], dst_mac[18];
                format_mac(pkt->eth_hdr->ether_shost, src_mac, sizeof(src_mac));
                format_mac(pkt->eth_hdr->ether_dhost, dst_mac, sizeof(dst_mac));
                
                fprintf(f, "    <ethernet>\n");
                fprintf(f, "      <src_mac>%s</src_mac>\n", src_mac);
                fprintf(f, "      <dst_mac>%s</dst_mac>\n", dst_mac);
                fprintf(f, "      <ethertype>0x%04x</ethertype>\n", ntohs(pkt->eth_hdr->ether_type));
                fprintf(f, "    </ethernet>\n");
            }
            
            if (pkt->ip_version == 4 && pkt->ip_hdr) {
                char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &pkt->ip_hdr->saddr, src_ip, sizeof(src_ip));
                inet_ntop(AF_INET, &pkt->ip_hdr->daddr, dst_ip, sizeof(dst_ip));
                
                fprintf(f, "    <ipv4>\n");
                fprintf(f, "      <src_ip>%s</src_ip>\n", src_ip);
                fprintf(f, "      <dst_ip>%s</dst_ip>\n", dst_ip);
                fprintf(f, "      <protocol>%u</protocol>\n", pkt->ip_hdr->protocol);
                fprintf(f, "      <ttl>%u</ttl>\n", pkt->ip_hdr->ttl);
                fprintf(f, "    </ipv4>\n");
            } else if (pkt->ip_version == 6 && pkt->ip6_hdr) {
                char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &pkt->ip6_hdr->ip6_src, src_ip, sizeof(src_ip));
                inet_ntop(AF_INET6, &pkt->ip6_hdr->ip6_dst, dst_ip, sizeof(dst_ip));
                
                fprintf(f, "    <ipv6>\n");
                fprintf(f, "      <src_ip>%s</src_ip>\n", src_ip);
                fprintf(f, "      <dst_ip>%s</dst_ip>\n", dst_ip);
                fprintf(f, "      <next_header>%u</next_header>\n", pkt->ip6_hdr->ip6_nxt);
                fprintf(f, "      <hop_limit>%u</hop_limit>\n", pkt->ip6_hdr->ip6_hlim);
                fprintf(f, "    </ipv6>\n");
            }
            
            if (pkt->tcp_hdr) {
                fprintf(f, "    <tcp>\n");
                fprintf(f, "      <src_port>%u</src_port>\n", ntohs(pkt->tcp_hdr->source));
                fprintf(f, "      <dst_port>%u</dst_port>\n", ntohs(pkt->tcp_hdr->dest));
                fprintf(f, "      <seq>%u</seq>\n", ntohl(pkt->tcp_hdr->seq));
                fprintf(f, "      <ack>%u</ack>\n", ntohl(pkt->tcp_hdr->ack_seq));
                fprintf(f, "      <flags>\n");
                fprintf(f, "        <fin>%d</fin>\n", pkt->tcp_hdr->fin);
                fprintf(f, "        <syn>%d</syn>\n", pkt->tcp_hdr->syn);
                fprintf(f, "        <rst>%d</rst>\n", pkt->tcp_hdr->rst);
                fprintf(f, "        <psh>%d</psh>\n", pkt->tcp_hdr->psh);
                fprintf(f, "        <ack>%d</ack>\n", pkt->tcp_hdr->ack);
                fprintf(f, "        <urg>%d</urg>\n", pkt->tcp_hdr->urg);
                fprintf(f, "      </flags>\n");
                fprintf(f, "    </tcp>\n");
            } else if (pkt->udp_hdr) {
                fprintf(f, "    <udp>\n");
                fprintf(f, "      <src_port>%u</src_port>\n", ntohs(pkt->udp_hdr->source));
                fprintf(f, "      <dst_port>%u</dst_port>\n", ntohs(pkt->udp_hdr->dest));
                fprintf(f, "      <length>%u</length>\n", ntohs(pkt->udp_hdr->len));
                fprintf(f, "    </udp>\n");
            } else if (pkt->icmp_hdr) {
                fprintf(f, "    <icmp>\n");
                fprintf(f, "      <type>%u</type>\n", pkt->icmp_hdr->type);
                fprintf(f, "      <code>%u</code>\n", pkt->icmp_hdr->code);
                fprintf(f, "    </icmp>\n");
            } else if (pkt->icmp6_hdr) {
                fprintf(f, "    <icmpv6>\n");
                fprintf(f, "      <type>%u</type>\n", pkt->icmp6_hdr->icmp6_type);
                fprintf(f, "      <code>%u</code>\n", pkt->icmp6_hdr->icmp6_code);
                fprintf(f, "    </icmpv6>\n");
            }
            
            if (pkt->payload_len > 0) {
                fprintf(f, "    <payload_length>%zu</payload_length>\n", pkt->payload_len);
            }
            
            fprintf(f, "  </packet>\n");
            break;
        }
        
        case LOG_FORMAT_TEXT:
        default: {
            fprintf(f, "Packet #%lu - %s.%06ld\n", pkt_num, timestamp, pkt->timestamp.tv_usec);
            fprintf(f, "Length: %zu bytes\n", pkt->length);
            
            if (pkt->eth_hdr) {
                char src_mac[18], dst_mac[18];
                format_mac(pkt->eth_hdr->ether_shost, src_mac, sizeof(src_mac));
                format_mac(pkt->eth_hdr->ether_dhost, dst_mac, sizeof(dst_mac));
                fprintf(f, "Ethernet: %s -> %s (Type: 0x%04x)\n", 
                        src_mac, dst_mac, ntohs(pkt->eth_hdr->ether_type));
            }
            
            if (pkt->ip_version == 4 && pkt->ip_hdr) {
                char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &pkt->ip_hdr->saddr, src_ip, sizeof(src_ip));
                inet_ntop(AF_INET, &pkt->ip_hdr->daddr, dst_ip, sizeof(dst_ip));
                fprintf(f, "IPv4: %s -> %s (Protocol: %u, TTL: %u)\n",
                        src_ip, dst_ip, pkt->ip_hdr->protocol, pkt->ip_hdr->ttl);
            } else if (pkt->ip_version == 6 && pkt->ip6_hdr) {
                char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &pkt->ip6_hdr->ip6_src, src_ip, sizeof(src_ip));
                inet_ntop(AF_INET6, &pkt->ip6_hdr->ip6_dst, dst_ip, sizeof(dst_ip));
                fprintf(f, "IPv6: [%s] -> [%s] (Next Header: %u, Hop Limit: %u)\n",
                        src_ip, dst_ip, pkt->ip6_hdr->ip6_nxt, pkt->ip6_hdr->ip6_hlim);
            }
            
            if (pkt->tcp_hdr) {
                fprintf(f, "TCP: Port %u -> %u (Seq: %u, Ack: %u)\n",
                        ntohs(pkt->tcp_hdr->source), ntohs(pkt->tcp_hdr->dest),
                        ntohl(pkt->tcp_hdr->seq), ntohl(pkt->tcp_hdr->ack_seq));
            } else if (pkt->udp_hdr) {
                fprintf(f, "UDP: Port %u -> %u (Length: %u)\n",
                        ntohs(pkt->udp_hdr->source), ntohs(pkt->udp_hdr->dest),
                        ntohs(pkt->udp_hdr->len));
            } else if (pkt->icmp_hdr) {
                fprintf(f, "ICMP: Type %u, Code %u\n",
                        pkt->icmp_hdr->type, pkt->icmp_hdr->code);
            } else if (pkt->icmp6_hdr) {
                fprintf(f, "ICMPv6: Type %u, Code %u\n",
                        pkt->icmp6_hdr->icmp6_type, pkt->icmp6_hdr->icmp6_code);
            }
            
            if (pkt->payload_len > 0) {
                fprintf(f, "Payload: %zu bytes\n", pkt->payload_len);
            }
            
            fprintf(f, "\n");
            break;
        }
    }
    
    ctx->packets_logged++;
    return SUCCESS;
}