#ifndef _PACKET_H
#define _PACKET_H

#include <stdio.h>
#include <netinet/ip.h>

void process_packet(FILE*, unsigned char*, int);

#endif /* _PACKET_H */
