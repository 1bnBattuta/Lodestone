#ifndef CHECKSUM_H
#define CHECKSUM_H

#include "common.h"
#include <arpa/inet.h> // for htons function

uint16_t checksum_ip(const uint8_t *data, size_t len);
uint16_t checksum_tcp_udp(const uint8_t *data, size_t len, 
                          uint32_t src_ip, uint32_t dst_ip, uint8_t protocol);

#endif