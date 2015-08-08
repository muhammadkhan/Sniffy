#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>

#include "printing.h"

typedef struct iphdr* iphdr_t;
typedef struct icmphdr* icmphdr_t;
typedef struct tcphdr*  tcphdr_t;
typedef struct udphdr*  udphdr_t;

/* Not exposed in printing.h */
void print_ethernet_header(FILE* log, unsigned char* buffer, int size){
  struct ethhdr* eth = (struct ethhdr*)buffer;

  fprintf(log, "\n");
  fprintf(log, "===ETHERNET HEADER===\n");
  fprintf(log, "    -> Destination Addr. : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",
	  eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
	  eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
  fprintf(log, "    -> Source Addr. : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",
	  eth->h_source[0], eth->h_source[1], eth->h_source[2],
	  eth->h_source[3], eth->h_source[4], eth->h_source[5]);
  fprintf(log, "    -> Protocol : %u\n", (unsigned short)eth->h_proto);
}

void print_ip_header(FILE* log, unsigned char* buffer, int size){
  struct sockaddr_in source, dest;
  unsigned short iphdr_len;
  iphdr_t iph;
  print_ethernet_header(log, buffer, size);
  iph = (iphdr_t)(buffer + sizeof(struct ethhdr));
  iphdr_len = iph->ihl*4;
  memset(&source, 0, sizeof(source));
  memset(&dest, 0, sizeof(dest));
  source.sin_addr.s_addr = iph->saddr;
  dest.sin_addr.s_addr = iph->daddr;

  fprintf(log, "\n");
  fprintf(log, "===IP HEADER===\n");
  fprintf(log, "   -> IP Version        : %d\n", (unsigned int)iph->version);
  fprintf(log, "   -> IP Header Length  : %d DWORDS (%d bytes)\n", (unsigned int)iph->ihl, ((unsigned int)(iph->ihl))*4);
  fprintf(log, "   -> Type Of Service   : $d\n", (unsigned int)iph->tos);
  fprintf(log, "   -> IP Total Length   : %d bytes (size of packet)\n", ntohs(iph->tot_len));
  fprintf(log, "   -> Identification    : %d\n", ntohs(iph->id));
  fprintf(log, "   -> TTL               : %d\n", (unsigned int)ntohs(iph->ttl));
  fprintf(log, "   -> Protocol          : %d\n", (unsigned int)ntohs(iph->protocol));
  fprintf(log, "   -> Checksum          : %d\n", ntohs(iph->check));
  fprintf(log, "   -> Source IP         : %s\n", inet_ntoa(source.sin_addr));
  fprintf(log, "   -> Destination IP    : %s\n", inet_ntoa(dest.sin_addr));
}

void print_icmp_packet(FILE* log, unsigned char* buffer, int size){
  unsigned short iphdr_len;
  int header_size;
  icmphdr_t icmph;
  iphdr_t iph = (iphdr_t)(buffer + sizeof(struct ethhdr));
  iphdr_len = iph->ihl*4;
  icmph = (icmphdr_t)(buffer + iphdr_len + sizeof(struct ethhdr));
  header_size = sizeof(struct ethhdr) + iphdr_len + sizeof(icmph);
  fprintf(log, "\n\n*******************ICMP PACKET********************\n");
  print_ip_header(log, buffer, size);
  fprintf(log, "\n");
  fprintf(log, "===ICMP HEADER===\n");
  fprintf(log, "   -> Type        : %d", (unsigned int)icmph->type);
  if((unsigned int)(icmph->type) == 11)
    fprintf(log, "   (TTL Expired)\n");
  else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
    fprintf(log, "   (ICMP Echo Reply)\n");
  fprintf(log, "   -> Code        : %d\n", (unsigned int)icmph->code);
  fprintf(log, "   -> Checksum    : %d\n", ntohs(icmph->checksum));
  fprintf(log, "\n");
  
  fprintf(log, "===IP HEADER===\n");
  print_data(log, buffer, iphdr_len);
  fprintf(log, "===ICMP HEADER==\n");
  print_data(log, buffer + iphdr_len, sizeof(icmph));
  fprintf(log, "===DATA PAYLOAD===\n");
  print_data(log, buffer + header_size, (size - header_size));
  fprintf(log, "\n\n################################################\n");
}

void print_tcp_packet(FILE* log, unsigned char* buffer, int size){
  unsigned short iphdr_len;
  int header_size;
  tcphdr_t tcph;
  iphdr_t iph = (iphdr_t)(buffer + sizeof(struct ethhdr));
  iphdr_len = iph->ihl*4;
  tcph = (tcphdr_t)(buffer + iphdr_len + sizeof(struct ethhdr));
  header_size = sizeof(struct ethhdr) + iphdr_len + tcph->doff*4;
  fprintf(log, "\n\n********************TCP PACKET********************\n");
  print_ip_header(log, buffer, size);
  fprintf(log, "\n");
  fprintf(log, "===TCP HEADER====\n");
  fprintf(log, "   -> Source Port          : %u\n", ntohs(tcph->source));
  fprintf(log, "   -> Destination Port     : %u\n", ntohs(tcph->dest));
  fprintf(log, "   -> Sequence Number      : %u\n", ntohl(tcph->seq));
  fprintf(log, "   -> Acknowledge Number   : %u\n", ntohl(tcph->ack_seq));
  fprintf(log, "   -> Header Length        : %d DWORDS (%d bytes)\n", (unsigned int)tcph->doff, (unsigned int)tcph->doff*4);
  fprintf(log, "   -> Urgent Flag          : %d\n", (unsigned int)tcph->urg);
  fprintf(log, "   -> Acknowledgement Flag : %d\n", (unsigned int)tcph->ack);
  fprintf(log, "   -> Push Flag            : %d\n", (unsigned int)tcph->psh);
  fprintf(log, "   -> Reset Flag           : %d\n", (unsigned int)tcph->rst);
  fprintf(log, "   -> Synchronize Flag     : %d\n", (unsigned int)tcph->syn);
  fprintf(log, "   -> Finish Flag          : %d\n", (unsigned int)tcph->fin);
  fprintf(log, "   -> Window               : %d\n", ntohs(tcph->window));
  fprintf(log, "   -> Checksum             : %d\n", ntohs(tcph->check));
  fprintf(log, "   -> Urgent Pointer       : %d\n", tcph->urg_ptr);
  fprintf(log, "\n");
  fprintf(log, "===================DATA DUMP========================\n");
  fprintf(log, "\n");
  fprintf(log, "===IP HEADER===\n");
  print_data(log, buffer, iphdr_len);
  fprintf(log, "===TCP HEADER===\n");
  print_data(log, buffer + iphdr_len, tcph->doff*4);
  fprintf(log, "===DATA PAYLOAD===\n");
  print_data(log, buffer + header_size, (size - header_size));
  fprintf(log, "\n\n################################################\n");
}

void print_udp_packet(FILE* log, unsigned char* buffer, int size){
  unsigned short iphdr_len;
  int header_size;
  udphdr_t udph;
  iphdr_t iph = (iphdr_t)(buffer + sizeof(struct ethhdr));
  iphdr_len = iph->ihl*4;
  udph = (udphdr_t)(buffer + iphdr_len + sizeof(struct ethhdr));
  header_size = sizeof(struct ethhdr) + iphdr_len + sizeof(udph);
  fprintf(log, "\n\n********************UDP PACKET********************\n");
  print_ip_header(log, buffer, size);
  fprintf(log, "\n");
  fprintf(log, "===UDP HEADER====\n");
  fprintf(log, "   -> Source Port          : %u\n", ntohs(udph->source));
  fprintf(log, "   -> Destination Port     : %u\n", ntohs(udph->dest));
  fprintf(log, "   -> UDP Length           : %d\n", ntohs(udph->len));
  fprintf(log, "   -> UDP Checksum         : %d\n", ntohs(udph->check));
  fprintf(log, "\n");
  fprintf(log, "===IP HEADER===\n");
  print_data(log, buffer, iphdr_len);
  fprintf(log, "===UDP HEADER===\n");
  print_data(log, buffer + iphdr_len, sizeof(udph));
  fprintf(log, "===DATA PAYLOAD===\n");
  print_data(log, buffer + header_size, (size - header_size));
  fprintf(log, "\n\n################################################\n");
}

void print_data(FILE* log, unsigned char* data, int size){
  int i,j;
  for(i = 0; i < size; i++){
    if(i != 0 && i % 16 == 0){
      /* one line, hex printing */
      fprintf(log, "       ");
      for(j = i - 16; j < i; j++){
	if(data[j] >= 32 && data[j] <= 128)
	  /* number of alphabet letter */
	  fprintf(log, "%c", (unsigned char)data[j]);
	else
	  /* print a dot if it's not a number or letter */
	  fprintf(log, ".");
      }
      fprintf(log, "\n");
    }

    if(i % 16 == 0)
      fprintf(log, "    ");
    fprintf(log, " %02X", (unsigned int)data[i]);

    if(i == size - 1){
      /* printing last spaces */
      for(j = 0; j < 15 - i%16; j++)
	fprintf(log, "   ");
      fprintf(log, "          ");
      for(j = i - i%16; j <= i; j++){
	if(data[j] >= 32 && data[j] <= 128)
	  fprintf(log, "%c", (unsigned char)data[j]);
	else
	  fprintf(log, ".");
      }
      fprintf(log, "\n");
    }
  }
}
