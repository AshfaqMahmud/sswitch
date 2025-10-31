#include "../include/capture.h"
#include "../include/forwarding.h"
#include "../include/mac_table.h"
#include "../include/utils.h"
#include <netinet/ether.h>
#include <string.h>
#include <stdio.h>

static Interface *ifaces;
static int iface_count;

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet)
{
    int in_port = *(int *)user;
    const struct ether_header *eth = (struct ether_header *)packet;

    // Learn source MAC
    mac_table_add((struct ether_addr *)eth->ether_shost, in_port);

    // Lookup destination
    int out_port = mac_table_lookup((struct ether_addr *)eth->ether_dhost);

    print_packet_info(eth);

    if (out_port == -1)
    {
        // Flood
        printf("Unknown dest -> Flooding\n");
        for (int i = 0; i < iface_count; i++)
        {
            if (i != in_port)
                forward_packet(ifaces[i].handle, packet, header->len);
        }
    }
    else if (out_port != in_port)
    {
        // Forward
        printf("Forwarding to port %d\n", out_port);
        forward_packet(ifaces[out_port].handle, packet, header->len);
    }

    mac_table_print();
}

void start_capture(Interface *interfaces, int num_interfaces)
{
    ifaces = interfaces;
    iface_count = num_interfaces;

    for (int i = 0; i < num_interfaces; i++)
    {
        int *port_id = malloc(sizeof(int));
        *port_id = i;
        pcap_loop(interfaces[i].handle, 0, packet_handler, (u_char *)port_id);
    }
}
