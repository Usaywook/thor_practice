#include </home/usaywook/Documents/thordrive/WpdPack/Include/pcap/pcap.h>

int main() {

    const char *pcap_v;
    pcap_v = pcap_lib_version();

    printf("Libpcap Version: %s \n", pcap_v);

    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
   	dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }

    printf("Device: %s\n", dev);
    return 0;
}