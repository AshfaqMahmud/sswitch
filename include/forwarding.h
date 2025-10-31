#ifndef FORWARDING_H
#define FORWARDING_H

#include <pcap.h>

void forward_packet(pcap_t *dest_handle, const u_char *packet, int length);

#endif
