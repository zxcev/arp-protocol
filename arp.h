#pragma once

#include <linux/if_ether.h>
#include <stdint.h>

#define ETH_P_ALL 0x0003
// #define ETH_P_ARP 0x0806
#define ARP_REQUEST 1
#define ARP_REPLY 2

struct ether_hdr_t {
  uint8_t hdst[ETH_ALEN]; /* destination mac address */
  uint8_t hsrc[ETH_ALEN]; /* source mac address */
  uint16_t ether_type;    /* ethernet frame type, ARP, IPv4, IPv6, ... */
} __attribute__((packed));

struct arp_hdr_t {
  uint16_t htype; /* hardware type */
  uint16_t ptype; /* protocol type */
  uint8_t hlen;   /* length of a hardware address */
  uint8_t plen;   /* length of a specific protocol address */
  uint16_t op;    /* arp operation code */
  uint8_t sha[6]; /* sender hardware address */
  uint8_t spa[4]; /* sender protocol address */
  uint8_t tha[6]; /* target hardware address */
  uint8_t tpa[4]; /* target protocol address */
} __attribute__((packed));
