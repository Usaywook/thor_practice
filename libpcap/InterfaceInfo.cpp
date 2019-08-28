#include <stdio.h>
#include <pcap.h>
// pcap_findalldevs : allocate memmory
// pcap_freealldevs : return memory
int main(void) {
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i = 0;

    char errbuf[PCAP_ERRBUF_SIZE]; // PCAP_ERRBUF_SIZE = 256

    if (pcap_findalldevs(&alldevs, errbuf) < 0) {
        printf("pcap_findalldevs error\n");
        return 1;
    }

    if (!alldevs) {
        printf("%s\n", errbuf);
    }

    for (d=alldevs; d; d=d->next) {
        printf("%p : %d. %s", d, ++i, d->name);

        if (d->description) printf(" (%s)", d->description);
        printf("\n");
    }

    pcap_freealldevs(alldevs);

    return 0;
}