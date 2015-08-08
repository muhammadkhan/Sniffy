#include <stdio.h>
#include <stdlib.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

#include "packet.h"
#include "printing.h"

int icmp = 0, igmp = 0, tcp = 0, udp = 0, misc = 0, total = 0;

typedef void (*print_func)(FILE*, unsigned char*, int);
typedef struct iphdr* iphdr_t;

print_func printing_function(iphdr_t iph){
  switch(iph->protocol){
  case 1: /* ICMP */
    icmp++;
    return print_icmp_packet;
  case 2: /* IGMP */
    igmp++;
    return NULL;
  case 6: /* TCP */
    tcp++;
    return print_tcp_packet;
  case 17: /* UDP */
    udp++;
    return print_udp_packet;
  default: /* Some other protocol type */
    misc++;
    return NULL;
  }
}

void process_packet (FILE* log, unsigned char* buffer, int size){
  print_func f;
  iphdr_t iph = (iphdr_t)(buffer + sizeof(struct ethhdr));
  total++;
  f = printing_function(iph);
  if(f != NULL)
    f(log, buffer, size);
  printf("TCP: %d\n UDP: %d\n ICMP: %d\n IGMP: %d\n Misc.:%d\n TOTAL:%d\n\n", tcp, udp, icmp, igmp, misc, total);
}
