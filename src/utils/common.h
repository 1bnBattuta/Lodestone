#define __USE_MISC

#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

// Return codes
#define SUCCESS 0
#define ERROR -1

// Common macros
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

// Protocol numbers (from IP header)
#define PROTO_ICMP 1
#define PROTO_TCP 6
#define PROTO_UDP 17

// Ethernet types
#define ETH_TYPE_IP 0x0800
#define ETH_TYPE_ARP 0x0806
#define ETH_TYPE_IPV6 0x86DD

#endif