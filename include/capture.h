#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap.h>

typedef struct
{
    //  pcap_t is opaque type, meaning no need to know
    // It’s a pointer because pcap_open_live() returns a pointer to an allocated handle.
    pcap_t *handle;     // handle is connection between the NI and libpcap and it is pointer bcz libpcap just takes a reference
    int id;             // Port ID or internal port number of switch like eth0 or eth1, not port of socket
    char name[16];      // name of the port like eth or wlan or anything
} Interface;            // Interface means network interface

void start_capture(Interface *interfaces, int num_interfaces);      // num_interfaces is the total port number of switch

#endif
