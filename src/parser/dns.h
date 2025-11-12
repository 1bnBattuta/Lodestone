#ifndef DNS_H
#define DNS_H

#include "parser.h"
#include "../utils/common.h"
#include "../utils/packet.h"

// DNS header structure
struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;  // Question count
    uint16_t ancount;  // Answer count
    uint16_t nscount;  // Authority count
    uint16_t arcount;  // Additional count
} __attribute__((packed));

// DNS flags
#define DNS_QR_MASK 0x8000      // Query/Response
#define DNS_OPCODE_MASK 0x7800  // Operation code
#define DNS_AA_MASK 0x0400      // Authoritative answer
#define DNS_TC_MASK 0x0200      // Truncated
#define DNS_RD_MASK 0x0100      // Recursion desired
#define DNS_RA_MASK 0x0080      // Recursion available
#define DNS_RCODE_MASK 0x000F   // Response code

// DNS record types
#define DNS_TYPE_A 1
#define DNS_TYPE_NS 2
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_SOA 6
#define DNS_TYPE_PTR 12
#define DNS_TYPE_MX 15
#define DNS_TYPE_TXT 16
#define DNS_TYPE_AAAA 28

// DNS classes
#define DNS_CLASS_IN 1      // Internet
#define DNS_CLASS_CS 2      // CSNET
#define DNS_CLASS_CH 3      // CHAOS
#define DNS_CLASS_HS 4      // Hesiod

typedef struct {
    char name[256];
    uint16_t qtype;
    uint16_t qclass;
} dns_question_t;

typedef struct {
    char name[256];
    uint16_t rtype;
    uint16_t rclass;
    uint32_t ttl;
    uint16_t rdlength;
    uint8_t *rdata;
} dns_answer_t;

typedef struct {
    struct dns_header header;
    dns_question_t *questions;
    dns_answer_t *answers;
    int question_count;
    int answer_count;
} dns_packet_t;

int is_dns_packet(const packet_t *pkt);
int parse_dns_header(const uint8_t *data, size_t len, struct dns_header *hdr);
int parse_dns_packet(const uint8_t *data, size_t len, dns_packet_t *dns_pkt);
int extract_dns_name(const uint8_t *dns_data, size_t dns_len, 
                     const uint8_t *name_ptr, char *output, size_t output_len,
                     size_t *bytes_read);
const char* dns_type_to_string(uint16_t qtype);
const char* dns_class_to_string(uint16_t qclass);
void dns_packet_destroy(dns_packet_t *dns_pkt);

// Helper to check DNS flags
static inline int dns_is_query(uint16_t flags) {
    return !(flags & DNS_QR_MASK);
}

static inline int dns_is_response(uint16_t flags) {
    return (flags & DNS_QR_MASK) != 0;
}

static inline uint8_t dns_get_opcode(uint16_t flags) {
    return (flags & DNS_OPCODE_MASK) >> 11;
}

static inline uint8_t dns_get_rcode(uint16_t flags) {
    return flags & DNS_RCODE_MASK;
}

#endif