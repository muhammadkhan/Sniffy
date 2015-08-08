#ifndef _PRINTING_H
#define _PRINTING_H

#include <stdio.h>

void print_ip_header(FILE*, unsigned char*, int);

void print_icmp_packet(FILE*, unsigned char*, int);

void print_tcp_packet(FILE*, unsigned char*, int);

void print_udp_packet(FILE*, unsigned char*, int);

void print_data(FILE*, unsigned char*, int);

#endif /* _PRINTING_H */
