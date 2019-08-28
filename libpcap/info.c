#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>     //libpcap 헤더 포험
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <string.h>

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0
#define CAPSIZ 65536

// IP 헤더 구조체
struct ip *iph;

// TCP 헤더 구조체
struct tcphdr *tcph;

// UDP 헤더 구조체
struct udphdr *udph;

// pack_pkthder 구조체는  패킷의 헤더 정보로 패킷 다룰때 사용되는 정보
// packet는 data
void callback(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    static int count = 1;
    struct ether_header *ep;
    unsigned short ether_type;    
    int chcnt =0;
    int length=pkthdr->len; // libpcap이 capture 한 packet 의 길이

    struct tm *ltime;
    char timestr[16];
    u_short sport,dport;
    time_t local_tv_sec;    

    /* convert the timestamp to readable format */
    local_tv_sec = pkthdr->ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime( timestr, sizeof(timestr), "%H:%M:%S", ltime);

    /* print timestamp and length of the packet */
    printf("================================================\n");
    printf("%s.%.6ld total len:%d \n", timestr, pkthdr->ts.tv_usec, length);    

    // 이더넷 헤더를 가져온다. 
    ep = (struct ether_header *)packet;

    // IP 헤더를 가져오기 위해서 
    // 이더넷 헤더 크기만큼 offset 한다.   
    packet += sizeof(struct ether_header);

    // 프로토콜 타입을 알아낸다. Ethernet 길이는 14로 고정
    ether_type = ntohs(ep->ether_type);

    // 만약 IP 패킷이라면 
    if (ether_type == ETHERTYPE_IP)
    {
        // IP 헤더에서 데이타 정보를 출력한다 IP길이는 20 고정 
        iph = (struct ip *)packet;      
        printf("=================Ip Layer=======================\n"); 
        printf("IP 패킷\n");
        printf("Version     : %d\n", iph->ip_v);
        printf("Header Len  : %d\n", iph->ip_hl);
        printf("Ident       : %d\n", ntohs(iph->ip_id));
        printf("TTL         : %d\n", iph->ip_ttl); 
        printf("Src Address : %s\n", inet_ntoa(iph->ip_src));
        printf("Dst Address : %s\n", inet_ntoa(iph->ip_dst));

        // 만약 TCP 데이타 라면
        // TCP 정보를 출력한다. 
        if (iph->ip_p == IPPROTO_TCP)
        {   
            printf("=============Session Layer(TCP)===================\n"); 
            tcph = (struct tcphdr *)(packet + iph->ip_hl * 4);
            printf("Src Port : %d\n" , ntohs(tcph->source));
            printf("Dst Port : %d\n" , ntohs(tcph->dest));
        }
        else if (iph->ip_p == IPPROTO_UDP)
        {
            printf("=============Session Layer(UDP)===================\n");
            // /* retireve the position of the udp header */            
            udph = (struct udphdr *)(packet + iph->ip_hl * 4);            
            printf("Src Port    : %d\n" , ntohs( udph->uh_sport ));
            printf("Dst Port    : %d\n" , ntohs( udph->uh_dport ));
            printf("Udp length : %d\n" , ntohs(udph->uh_ulen));
        }            
        // Packet 데이타 (udp or tcp)를 출력한다. 
        // Ethernet 헤더 부터 출력한다.
        packet -= sizeof(struct ether_header);  
        while(length--)
        {
            printf("%02x", *(packet++)); 
            if ((++chcnt % 16) == 0) 
                printf("\n");
        }
        pcap_dump(user, pkthdr, packet);        
    }
    // IP 패킷이 아니라면 
    else
    {
        printf("NONE IP 패킷\n");        
    }
    printf("\n\n");
}

int main(int argc, char **argv)
{
    char *dev;    // 사용중인 네트웍 디바이스 이름 
    char *net;    // 네트웍 어드레스 
    char *mask;   // 네트웍 mask 어드레스 
    int ret;      // 네트웍 디바이스에 대한 mask 번호
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 netp;  // ip 
    bpf_u_int32 maskp; // submet mask
    struct in_addr net_addr, mask_addr;

    pcap_t *pcd; // packet capture descriptor
    struct bpf_program fp;
    // char packet_filter[] = "port 80";    

    pcap_dumper_t *df;

    // 네트웍 디바이스 이름을 얻어온다. 
    dev = pcap_lookupdev(errbuf);    

    //메모리 할당
    // if(pcap_findalldevs(dev, errbuf) == -1)
    // {
    //     fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
    //     exit(1);
    // }


    // 에러가 발생했을경우 
    if(dev == NULL)
    {
        printf("%s\n",errbuf);
        exit(1);
    }

    // 네트웍 디바이스 이름 출력 
    printf("DEV: %s\n",dev);

    // 네트웍 디바이스 이름 dev 에 대한 
    // mask, ip 정보 얻어오기   
    ret = pcap_lookupnet(dev,&netp,&maskp,errbuf);

    if(ret == -1)
    {
        printf("%s\n",errbuf);
        exit(1);
    }

    // 네트웍 어드레스를 점박이 3형제 스타일로
    net_addr.s_addr = netp;
    net = inet_ntoa(net_addr);

    if(net == NULL)
    {
        perror("inet_ntoa");
        exit(1);
    }

    printf("NET: %s\n",net);

    // 마찬가지로 mask 어드레스를 점박이 3형제 스타일로
    mask_addr.s_addr = maskp;
    mask = inet_ntoa(mask_addr);
  
    if(mask == NULL)
    {
        perror("inet_ntoa");
        exit(1);
    }
  
    printf("MASK: %s\n",mask);    
    printf("=======================\n");
    // printf("%d\n", CAPSIZ);
    // 메모리 반환
    // pcap_freealldevs(dev);

    // 네트워크의 패킷들을 보기위해 필요한 packet capture descriptor를 얻는다.
    pcd = pcap_open_live(dev, CAPSIZ,  NONPROMISCUOUS, -1, errbuf);
    if (pcd == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }

    // 컴파일 옵션을 준다.
    // packet_filter <-> argv[2]
    if (pcap_compile(pcd, &fp, argv[2], 1, netp) == -1) 
    {
        printf("compile error\n");    
        exit(1);
    }
    // 컴파일 옵션대로 패킷필터 룰을 세팅한다. 
    if (pcap_setfilter(pcd, &fp) == -1)
    {
        printf("setfilter error\n");
        exit(0);    
    }

    // 지정된 횟수만큼 패킷캡쳐를 한다. 
    // pcap_setfilter 을 통과한 패킷이 들어올경우 
    // callback 함수를 호출하도록 한다.
    df = pcap_dump_open(pcd,argv[3]);
    if (df == NULL)
    {
        printf("fail dump_open\n");
        printf("%s\n",errbuf);
        exit(1); 
    }
    pcap_loop(pcd, atoi(argv[1]), callback, (u_char *)df); 

    pcap_dump_close(df);
    pcap_close(pcd);
    return 0;
}