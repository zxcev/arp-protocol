#include "print_addr.h"
#include <stdio.h>

void print_mac(uint8_t *mac) {
  printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3],
         mac[4], mac[5]);
}

void print_ip(uint8_t *ip) {
  printf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
}
