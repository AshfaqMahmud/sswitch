#ifndef FORWARDING_H
#define FORWARDING_H

#include <pcap.h>

void forward_packet(pcap_t *dest_handle, const u_char *packet, int length);
// destination handle is the handle defined in capture.h using pcap.h
// that handle is opaque type
// an example of handle:
// pcap_t *handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
// packet is a string of character
// length of packet

#endif
