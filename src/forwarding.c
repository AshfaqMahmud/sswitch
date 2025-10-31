#include "../include/forwarding.h"
#include <stdio.h>

void forward_packet(pcap_t *dest_handle, const u_char *packet, int length)
{
    if (pcap_sendpacket(dest_handle, packet, length) != 0)
    {
        fprintf(stderr, "Error forwarding packet: %s\n", pcap_geterr(dest_handle));
    }
}
