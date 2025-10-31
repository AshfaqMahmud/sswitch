#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap.h>

typedef struct
{
    pcap_t *handle;
    int id; // Port ID
    char name[16];
} Interface;

void start_capture(Interface *interfaces, int num_interfaces);

#endif
