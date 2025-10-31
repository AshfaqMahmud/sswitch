#ifndef MAC_TABLE_H
#define MAC_TABLE_H

#include <netinet/ether.h>

#define MAX_MAC_ENTRIES 1024

typedef struct
{
    struct ether_addr mac;
    int port; // 0 for veth0, 1 for veth1, etc.
} MacEntry;

void mac_table_init();
void mac_table_add(const struct ether_addr *mac, int port);
int mac_table_lookup(const struct ether_addr *mac);
void mac_table_print();

#endif
