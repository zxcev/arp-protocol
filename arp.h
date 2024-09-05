#include <arpa/inet.h>
#include <cstdint>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define ETH_P_ALL 0x0003
#define ETH_P_ARP 0x0806
#define ARP_REQUEST 1
#define ARP_REPLY 2

struct arp_hdr_t {
  uint16_t htype; /* hardware type */
  uint16_t ptype; /* protocol type */
  uint8_t hlen;   /* length of a hardware address */
  uint8_t plen;   /* length of a specific protocol address */
  uint16_t op;    /* arp operation code */
} __attribute__((packed));

struct ether_hdr_t {
  struct arp_hdr_t arp_hdr; /* fixed arp header */
  uint8_t sha[6];           /* sender hardware address */
  uint8_t spa[4];           /* sender protocol address */
  uint8_t tha[6];           /* target hardware address */
  uint8_t tpa[4];           /* target protocol address */
} __attribute__((packed));
