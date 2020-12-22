#include "handler.h"

int main(int argc, char **argv){
    
    pcap_t *pcap_file;
    char errbuf[PCAP_ERRBUF_SIZE];
    char filename[100];

    if(argc > 1){
        strcpy(filename, argv[1]);
    }else{
        printf("invalid input argument!\n");
        exit(0);
    }

    pcap_file = pcap_open_offline(filename, errbuf);
    if(pcap_file == NULL){
        printf("pcap_open_offline() failed!\n"); 
        exit(0);
    }

    struct pcap_pkthdr *pkt_header;
    struct ether_header *ethernet_header;
    struct ip *ip_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    struct tm *ltime;
    char time_info[50];

    const u_char *pkt_data;
    time_t local_tv_sec;
    int res;

    while((res = pcap_next_ex(pcap_file, &pkt_header, &pkt_data)) >= 0){
        if(res == 0){
            printf("pcap time out!\n!");
            break;
        }

        local_tv_sec = pkt_header->ts.tv_sec;
        ltime = localtime(&local_tv_sec);
        strftime(time_info, sizeof(time_info), "%Y %x %X, %A", ltime);
        printf("\n----------Packet_Start----------\n");
        printf("Packet_Time: %s\n", time_info);
        printf("Packet_length: %u\n", pkt_header->len);
        printf("Packet_Capture_length: %u\n", pkt_header->caplen);

        uint16_t ethernet_protocol_ID;
        uint8_t ip_protocol_ID;

        //ethernet info
        ethernet_header = (struct ether_header *)pkt_data;
        ethernet_protocol_ID = ethernet_handler(ethernet_header);
        
        //ip info
	//printf("number of ethernet type: %hx\n", ethernet_protocol_ID);
        if(ethernet_protocol_ID == ETHERTYPE_IP){
            ip_header = (struct ip *)(pkt_data + ETHER_HDR_LEN);
            ip_protocol_ID = ip_handler(ip_header);
            //tcp udp protocol
	    if(ip_protocol_ID == IPPROTO_TCP){
	        tcp_header = (struct tcphdr *)(pkt_data + ETHER_HDR_LEN + ((ip_header->ip_hl) << 2));
		tcp_handler(tcp_header);
	    }else if(ip_protocol_ID == IPPROTO_UDP){
	        udp_header = (struct udphdr *)(pkt_data + ETHER_HDR_LEN + ((ip_header->ip_hl) << 2));
		udp_handler(udp_header);
	    }
        }else if(ethernet_protocol_ID == ETHERTYPE_ARP){
            printf("========== ARP protocol ==========\n");
        }else if(ethernet_protocol_ID == ETHERTYPE_REVARP){
            printf("========== RARP protocol ==========\n");
        }else{
	    printf("========== protocol not supported ==========\n");
	}
	printf("----------Packet End----------\n");
    }
    return 0;
}
