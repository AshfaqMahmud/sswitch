#include "../include/capture.h"
#include "../include/mac_table.h"
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    Interface ifaces[2];
    mac_table_init();

    char *iface_names[2] = {"veth0", "veth1"};

    for (int i = 0; i < 2; i++)
    {
        snprintf(ifaces[i].name, sizeof(ifaces[i].name), "%s", iface_names[i]);
        ifaces[i].handle = pcap_open_live(ifaces[i].name, BUFSIZ, 1, 1000, errbuf);
        if (!ifaces[i].handle)
        {
            fprintf(stderr, "Failed to open %s: %s\n", iface_names[i], errbuf);
            exit(1);
        }
        ifaces[i].id = i;
    }

    printf("Software switch running on %s and %s...\n", iface_names[0], iface_names[1]);
    start_capture(ifaces, 2);

    for (int i = 0; i < 2; i++)
        pcap_close(ifaces[i].handle);

    return 0;
}
