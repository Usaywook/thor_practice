#include <stdio.h>
#include <string.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <pcap.h>
'''
 pcap_open_live : open device to capture packet
 pcap_loop : assign handler function when packet was received
 original form of pcap handler : typedef void (*pcap_handler)(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
 pcap_pkthdr structor : 
    struct pcap_pkthdr {
        struct timeval ts;  /* time stamp */
        bpf_u_int32 caplen; /* length of portion present */
        bpf_u_int32 len;  /* length this packet (off wire) */
    }; 
'''
void packet_handler(u_char *param,
  const struct pcap_pkthdr *header, const u_char *pkt_data) {
  printf("caplen : %d\n", header->caplen);
  printf("len : %d\n", header->len);
}

int main(int argc, char **argv) {
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_if_t *d;
    struct pcap_addr *a;
    int i = 0;
    int no;

    if (pcap_findalldevs(&alldevs, errbuf) < 0) {
        printf("pcap_findalldevs error\n");
        return 1;
    }

    for (d=alldevs; d; d=d->next) {
        printf("%d :  %s\n", ++i, (d->description)?(d->description):(d->name));
    }

    printf("number : ");
    scanf("%d", &no);

    if (!(no > 0 && no <= i)) {
        printf("number error\n");
        return 1;
    }

    for (d=alldevs, i=0; d; d=d->next) {
        if (no == ++i)  break;
    }

    if (!(adhandle= pcap_open_live(d->name, 65536, 1, 1000, errbuf))) {
        printf("pcap_open_live error %s\n", d->name);
        pcap_freealldevs(alldevs);
        return -1;
    }

    pcap_freealldevs(alldevs);

    pcap_loop(adhandle, 0, packet_handler, NULL);

    pcap_close(adhandle);

    return 0;
}