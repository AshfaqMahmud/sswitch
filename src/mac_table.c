#include "../include/mac_table.h"
#include <string.h>
#include <stdio.h>

static MacEntry table[MAX_MAC_ENTRIES];
static int entry_count = 0;

void mac_table_init()
{
    memset(table, 0, sizeof(table));
    entry_count = 0;
}

void mac_table_add(const struct ether_addr *mac, int port)
{
    // Check if it already exists
    for (int i = 0; i < entry_count; i++)
    {
        if (memcmp(&table[i].mac, mac, sizeof(struct ether_addr)) == 0)
        {
            table[i].port = port;
            return;
        }
    }
    if (entry_count < MAX_MAC_ENTRIES)
    {
        table[entry_count].mac = *mac;
        table[entry_count].port = port;
        entry_count++;
    }
}

int mac_table_lookup(const struct ether_addr *mac)
{
    for (int i = 0; i < entry_count; i++)
    {
        if (memcmp(&table[i].mac, mac, sizeof(struct ether_addr)) == 0)
            return table[i].port;
    }
    return -1; // Unknown
}

void mac_table_print()
{
    printf("\n--- MAC Table ---\n");
    for (int i = 0; i < entry_count; i++)
    {
        printf("%02x:%02x:%02x:%02x:%02x:%02x -> Port %d\n",
               table[i].mac.ether_addr_octet[0],
               table[i].mac.ether_addr_octet[1],
               table[i].mac.ether_addr_octet[2],
               table[i].mac.ether_addr_octet[3],
               table[i].mac.ether_addr_octet[4],
               table[i].mac.ether_addr_octet[5],
               table[i].port);
    }
    printf("-----------------\n");
}
