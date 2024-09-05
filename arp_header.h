#pragma once

#include <cstdint>

#define ETH_P_ALL 0x0003
#define ETH_P_ARP 0x0806
#define ARP_REQUEST 1
#define ARP_REPLY 2

struct arp_header {
  uint16_t hw_type;
  uint16_t proto_type;
  uint8_t hw_size;
  uint8_t proto_size;
  uint16_t opcode;
  uint8_t sender_mac[6];
  uint8_t sender_ip[4];
  uint8_t target_mac[6];
  uint8_t target_ip[4];
} __attribute__((packed));
