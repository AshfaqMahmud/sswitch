#ifndef UTILS_H
#define UTILS_H

#include <netinet/if_ether.h>

void print_mac(const unsigned char *mac);
void print_packet_info(const struct ether_header *eth);

#endif
