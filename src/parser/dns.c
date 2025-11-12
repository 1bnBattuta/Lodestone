#include "dns.h"
#include <stdio.h>
#include <ctype.h>
#include <string.h>

int is_dns_packet(const packet_t *pkt) {
    if (!pkt->udp_hdr) return 0;
    
    uint16_t src_port = ntohs(pkt->udp_hdr->source);
    uint16_t dst_port = ntohs(pkt->udp_hdr->dest);
    
    return (src_port == 53 || dst_port == 53);
}

int parse_dns_header(const uint8_t *data, size_t len, struct dns_header *hdr) {
    if (len < sizeof(struct dns_header)) {
        return PARSE_TRUNCATED;
    }
    
    memcpy(hdr, data, sizeof(struct dns_header));
    
    // Convert from network byte order
    hdr->id = ntohs(hdr->id);
    hdr->flags = ntohs(hdr->flags);
    hdr->qdcount = ntohs(hdr->qdcount);
    hdr->ancount = ntohs(hdr->ancount);
    hdr->nscount = ntohs(hdr->nscount);
    hdr->arcount = ntohs(hdr->arcount);
    
    return PARSE_SUCCESS;
}

int extract_dns_name(const uint8_t *dns_data, size_t dns_len,
                     const uint8_t *name_ptr, char *output, size_t output_len,
                     size_t *bytes_read) {
    size_t pos = 0;
    const uint8_t *ptr = name_ptr;
    const uint8_t *original_ptr = name_ptr;
    int jumped = 0;
    int max_jumps = 5;
    int jumps = 0;
    
    if (bytes_read) *bytes_read = 0;
    
    while (ptr < dns_data + dns_len && *ptr != 0) {
        // Check for pointer (compression)
        if ((*ptr & 0xC0) == 0xC0) {
            if (ptr + 1 >= dns_data + dns_len) {
                return PARSE_ERROR;
            }
            
            if (!jumped) {
                // Only count bytes for the first pointer encountered
                if (bytes_read) {
                    *bytes_read = (ptr - original_ptr) + 2;
                }
                jumped = 1;
            }
            
            // Extract pointer offset (14-bit offset)
            uint16_t offset = ((ptr[0] & 0x3F) << 8) | ptr[1];
            
            if (offset >= dns_len) {
                return PARSE_ERROR;
            }
            
            ptr = dns_data + offset;
            
            if (++jumps > max_jumps) {
                return PARSE_ERROR; // Prevent infinite loops
            }
            continue;
        }
        
        // Regular label
        uint8_t label_len = *ptr++;
        
        // Label length must be <= 63 (6 bits)
        if (label_len > 63) {
            return PARSE_ERROR;
        }
        
        if (label_len == 0) {
            break; // End of name
        }
        
        if (ptr + label_len > dns_data + dns_len) {
            return PARSE_ERROR;
        }
        
        // Check output buffer space
        if (pos + label_len + 1 >= output_len) {
            return PARSE_ERROR;
        }
        
        // Add dot separator (except for first label)
        if (pos > 0) {
            output[pos++] = '.';
        }
        
        // Copy label
        memcpy(output + pos, ptr, label_len);
        pos += label_len;
        ptr += label_len;
    }
    
    output[pos] = '\0';
    
    // If we didn't jump, calculate bytes read
    if (!jumped && bytes_read) {
        *bytes_read = (ptr - original_ptr) + 1; // +1 for null terminator
    }
    
    return PARSE_SUCCESS;
}

int parse_dns_packet(const uint8_t *data, size_t len, dns_packet_t *dns_pkt) {
    if (!data || !dns_pkt || len < sizeof(struct dns_header)) {
        return PARSE_ERROR;
    }
    
    memset(dns_pkt, 0, sizeof(dns_packet_t));
    
    // Parse header
    if (parse_dns_header(data, len, &dns_pkt->header) != PARSE_SUCCESS) {
        return PARSE_ERROR;
    }
    
    const uint8_t *ptr = data + sizeof(struct dns_header);
    size_t remaining = len - sizeof(struct dns_header);
    
    // Allocate space for questions
    if (dns_pkt->header.qdcount > 0) {
        dns_pkt->questions = (dns_question_t*)calloc(dns_pkt->header.qdcount, 
                                                      sizeof(dns_question_t));
        if (!dns_pkt->questions) {
            return PARSE_ERROR;
        }
    }
    
    // Parse questions
    for (uint16_t i = 0; i < dns_pkt->header.qdcount; i++) {
        if (remaining < 1) {
            dns_packet_destroy(dns_pkt);
            return PARSE_TRUNCATED;
        }
        
        size_t name_bytes = 0;
        if (extract_dns_name(data, len, ptr, dns_pkt->questions[i].name, 
                           sizeof(dns_pkt->questions[i].name), &name_bytes) != PARSE_SUCCESS) {
            dns_packet_destroy(dns_pkt);
            return PARSE_ERROR;
        }
        
        ptr += name_bytes;
        remaining -= name_bytes;
        
        // Parse QTYPE and QCLASS
        if (remaining < 4) {
            dns_packet_destroy(dns_pkt);
            return PARSE_TRUNCATED;
        }
        
        dns_pkt->questions[i].qtype = (ptr[0] << 8) | ptr[1];
        dns_pkt->questions[i].qclass = (ptr[2] << 8) | ptr[3];
        
        ptr += 4;
        remaining -= 4;
        
        dns_pkt->question_count++;
    }
    
    // Allocate space for answers
    if (dns_pkt->header.ancount > 0) {
        dns_pkt->answers = (dns_answer_t*)calloc(dns_pkt->header.ancount,
                                                  sizeof(dns_answer_t));
        if (!dns_pkt->answers) {
            dns_packet_destroy(dns_pkt);
            return PARSE_ERROR;
        }
    }
    
    // Parse answers
    for (uint16_t i = 0; i < dns_pkt->header.ancount; i++) {
        if (remaining < 1) {
            dns_packet_destroy(dns_pkt);
            return PARSE_TRUNCATED;
        }
        
        size_t name_bytes = 0;
        if (extract_dns_name(data, len, ptr, dns_pkt->answers[i].name,
                           sizeof(dns_pkt->answers[i].name), &name_bytes) != PARSE_SUCCESS) {
            dns_packet_destroy(dns_pkt);
            return PARSE_ERROR;
        }
        
        ptr += name_bytes;
        remaining -= name_bytes;
        
        // Parse TYPE, CLASS, TTL, RDLENGTH
        if (remaining < 10) {
            dns_packet_destroy(dns_pkt);
            return PARSE_TRUNCATED;
        }
        
        dns_pkt->answers[i].rtype = (ptr[0] << 8) | ptr[1];
        dns_pkt->answers[i].rclass = (ptr[2] << 8) | ptr[3];
        dns_pkt->answers[i].ttl = (ptr[4] << 24) | (ptr[5] << 16) | (ptr[6] << 8) | ptr[7];
        dns_pkt->answers[i].rdlength = (ptr[8] << 8) | ptr[9];
        
        ptr += 10;
        remaining -= 10;
        
        // Validate RDLENGTH
        if (dns_pkt->answers[i].rdlength > remaining) {
            dns_packet_destroy(dns_pkt);
            return PARSE_TRUNCATED;
        }
        
        // Store pointer to RDATA (no copy for performance)
        dns_pkt->answers[i].rdata = (uint8_t*)ptr;
        
        ptr += dns_pkt->answers[i].rdlength;
        remaining -= dns_pkt->answers[i].rdlength;
        
        dns_pkt->answer_count++;
    }
    
    return PARSE_SUCCESS;
}

void dns_packet_destroy(dns_packet_t *dns_pkt) {
    if (!dns_pkt) return;
    
    if (dns_pkt->questions) {
        free(dns_pkt->questions);
        dns_pkt->questions = NULL;
    }
    
    if (dns_pkt->answers) {
        free(dns_pkt->answers);
        dns_pkt->answers = NULL;
    }
    
    dns_pkt->question_count = 0;
    dns_pkt->answer_count = 0;
}

const char* dns_type_to_string(uint16_t qtype) {
    switch (qtype) {
        case DNS_TYPE_A: return "A";
        case DNS_TYPE_NS: return "NS";
        case DNS_TYPE_CNAME: return "CNAME";
        case DNS_TYPE_SOA: return "SOA";
        case DNS_TYPE_PTR: return "PTR";
        case DNS_TYPE_MX: return "MX";
        case DNS_TYPE_TXT: return "TXT";
        case DNS_TYPE_AAAA: return "AAAA";
        default: return "UNKNOWN";
    }
}

const char* dns_class_to_string(uint16_t qclass) {
    switch (qclass) {
        case DNS_CLASS_IN: return "IN";
        case DNS_CLASS_CS: return "CS";
        case DNS_CLASS_CH: return "CH";
        case DNS_CLASS_HS: return "HS";
        default: return "UNKNOWN";
    }
}