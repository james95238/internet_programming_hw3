#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<time.h>
#include<pcap/pcap.h>
#include<unistd.h>
#include<netinet/in.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>
#include<net/ethernet.h>
#include<sys/types.h>
#include<arpa/inet.h>

#define MAC_ADDR_LEN 18 

char* mac_ntoa(u_char *mac_addr){
    static char mac_addr_str[MAC_ADDR_LEN];
    
    sprintf(mac_addr_str, "%02x:%02x:%02x:%02x:%02x:%02x", mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
    return mac_addr_str;    
}

uint16_t ethernet_handler(struct ether_header *ethernet_header){
    char src_MAC_addr[MAC_ADDR_LEN] = {0};
    char dst_MAC_addr[MAC_ADDR_LEN] = {0};
        
    strncpy(src_MAC_addr, mac_ntoa(ethernet_header->ether_shost), MAC_ADDR_LEN);
    strncpy(dst_MAC_addr, mac_ntoa(ethernet_header->ether_dhost), MAC_ADDR_LEN);
    printf("MAC src address: %s\n", src_MAC_addr);
    printf("MAC dst address: %s\n", dst_MAC_addr);
    return ntohs(ethernet_header->ether_type);
}

void pkt_data_analyze(u_char *pkt_data){
    struct ether_header *ethernet_header;
    ethernet_header = (struct ether_header *)pkt_data;
    ethernet_handler(ethernet_header);
}

uint8_t ip_handler(struct ip *ip_header){
    char src_ip_addr[INET_ADDRSTRLEN], dst_ip_addr[INET_ADDRSTRLEN];
    unsigned int header_length;
    unsigned int version;
    unsigned short total_length;
    unsigned short service_type;
    unsigned short fragment_offset;
    unsigned short identification;
    unsigned short checksum;
    uint8_t ttl;
    uint8_t protocol;

    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip_addr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip_addr, INET_ADDRSTRLEN);
    header_length = ip_header->ip_hl;
    version = ip_header->ip_v;
    total_length = ip_header->ip_len;
    service_type = ip_header->ip_tos;
    identification = ip_header->ip_id;
    fragment_offset = ip_header->ip_off;
    checksum = ip_header->ip_sum;
    ttl = ip_header->ip_ttl;
    protocol = ip_header->ip_p;
    
    printf("========== IP Protocol ==========\n");
    printf("version: %d | ip_header_length: %d | type of service: %d | total_length: %d\n", version, header_length, service_type, total_length);
    printf("identification: %d | fragment offset: %d\n", identification, fragment_offset);
    printf("ttl: %d | protocol: %d | header checksum: %d\n", ttl, protocol, checksum);
    printf("src ip address: %s\n", src_ip_addr);
    printf("dst ip address: %s\n", dst_ip_addr);
    printf("========== IP Protocol ==========\n");
    
    return protocol;
}

void tcp_handler(struct tcphdr *tcp_header){
    u_short src_port, dst_port;

    src_port = tcp_header->th_sport;
    dst_port = tcp_header->th_dport;
    printf("========== TCP Protocol ==========\n");
    printf("Src Port: %hu, Dst Port: %hu\n", src_port, dst_port);
    printf("========== TCP Protocol ==========\n");
}

void udp_handler(struct udphdr *udp_header){
    u_short src_port, dst_port;

    src_port = udp_header->uh_sport;
    dst_port = udp_header->uh_dport;
    printf("========== UDP Protocol ==========\n");
    printf("Src Port: %hu, Dst Port: %hu\n", src_port, dst_port);
    printf("========== UDP Protocol ==========\n");
}



