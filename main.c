#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>

#include "packet.h"
#include "printing.h"

#define BUFFER_SIZE 65536

int main(int argc, char** argv){
  FILE* log;
  int saddr_size, data_size, sock_raw;
  struct sockaddr saddr;
  unsigned char* buffer = (unsigned char*)malloc(BUFFER_SIZE);
  log = fopen(argv[1], "w");
  if(log == NULL)
    printf("Error creating '%s' file.\n", argv[1]);
  printf("===Starting Sniffy==\n");
  sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if(sock_raw < 0){
    perror("SOCKET ERROR");
    return 1;
  }

  while(1){
    saddr_size = sizeof(saddr);
    data_size = recvfrom(sock_raw, buffer, BUFFER_SIZE, 0, &saddr, (socklen_t*)&saddr_size);
    if(data_size < 0)
      printf("recvfrom error: could not get packets\n");
    process_packet(log, buffer, data_size);
  }
  close(sock_raw);
  free(buffer);
  printf("===Sniffy Finished===\n");
  return 0;
}
