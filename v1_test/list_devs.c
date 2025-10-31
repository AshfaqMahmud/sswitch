#include <pcap.h>
#include <stdio.h>

struct ethhdr
{
    unsigned char dst[6];
    unsigned char src[6];
    unsigned short ethertype;
};

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    const struct ethhdr *eth = (struct ethhdr *)packet;
    printf("Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->src[0], eth->src[1], eth->src[2],
           eth->src[3], eth->src[4], eth->src[5]);
    printf("Packet captured: length= %d bytes, timestamp= %ld\n", header->len, header->ts.tv_sec);
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;

    // print all devices in the system

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    for(pcap_if_t *d = alldevs; d; d = d->next) {
        printf("Device: %s\n", d->name);
    }

    pcap_freealldevs(alldevs);


    // packet capture of device
    pcap_t *handle = pcap_open_live("wlp0s20f3", BUFSIZ, 1, 1000, errbuf);
    if(!handle) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 1;
    }

    pcap_loop(handle, 10, packet_handler, NULL);
    pcap_close(handle);
    return 0;
}