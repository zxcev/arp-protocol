#include <arpa/inet.h>
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

void print_mac(uint8_t *mac) {
  printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3],
         mac[4], mac[5]);
}

void print_ip(uint8_t *ip) {
  printf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
}

void print_arp_packet(struct arp_header *arp, int length) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  struct tm *tm = localtime(&ts.tv_sec);

  printf("%02d:%02d:%02d.%06ld ARP, ", tm->tm_hour, tm->tm_min, tm->tm_sec,
         ts.tv_nsec / 1000);

  if (ntohs(arp->opcode) == ARP_REQUEST) {
    printf("Request who-has ");
    print_ip(arp->target_ip);
    printf(" tell ");
    print_ip(arp->sender_ip);
  } else if (ntohs(arp->opcode) == ARP_REPLY) {
    printf("Reply ");
    print_ip(arp->sender_ip);
    printf(" is-at ");
    print_mac(arp->sender_mac);
    printf(" tell ");
    print_ip(arp->target_ip);
  } else {
    printf("Unknown operation (%d)", ntohs(arp->opcode));
  }

  printf(", length %d\n", length);
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
    exit(1);
  }

  int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (sock_raw == -1) {
    perror("socket");
    exit(1);
  }

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, argv[1], IFNAMSIZ - 1);
  if (ioctl(sock_raw, SIOCGIFINDEX, &ifr) < 0) {
    perror("ioctl");
    close(sock_raw);
    exit(1);
  }

  struct sockaddr_ll sll;
  memset(&sll, 0, sizeof(sll));
  sll.sll_family = AF_PACKET;
  sll.sll_ifindex = ifr.ifr_ifindex;
  sll.sll_protocol = htons(ETH_P_ALL);

  if (bind(sock_raw, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
    perror("bind");
    close(sock_raw);
    exit(1);
  }

  unsigned char *buffer = (unsigned char *)malloc(65536);
  struct ethhdr *eth = (struct ethhdr *)buffer;
  struct arp_header *arp =
      (struct arp_header *)(buffer + sizeof(struct ethhdr));

  printf("Listening for ARP packets on %s...\n", argv[1]);

  while (1) {
    int data_size = recvfrom(sock_raw, buffer, 65536, 0, NULL, NULL);
    if (data_size < 0) {
      perror("recvfrom");
      close(sock_raw);
      free(buffer);
      exit(1);
    }

    if (ntohs(eth->h_proto) == ETH_P_ARP) {
      print_arp_packet(arp, data_size - sizeof(struct ethhdr));
    }
  }

  close(sock_raw);
  free(buffer);
  return 0;
}
