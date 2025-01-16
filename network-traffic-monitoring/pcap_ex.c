#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

int total_net_flows = 0;
int tcp_net_flows = 0;
int udp_net_flows = 0;
int total_packets = 0;
int tcp_packets = 0;
int udp_packets = 0;
int tcp_bytes = 0;
int udp_bytes = 0;

FILE *fp;

pcap_t *handle;

typedef struct net_flow {
  char src_adr[INET6_ADDRSTRLEN];
  char dst_adr[INET6_ADDRSTRLEN];
  unsigned char prtcl;
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t prev_seq_num;
  struct net_flow *next;
} net_flow;

net_flow *head = NULL;

int list_net_flows(char *src_adr, char *dst_adr, unsigned char prtcl, uint16_t src_port, uint16_t dst_port, uint32_t seq_num) {
  if (head == NULL) {
    head = (net_flow *)malloc(sizeof(net_flow));
    if (head == NULL) {
      printf("Memory allocation failure.\n");
      exit(EXIT_FAILURE);
    }
    strcpy(head->src_adr, src_adr);
    strcpy(head->dst_adr, dst_adr);
    head->prtcl = prtcl;
    head->src_port = src_port;
    head->dst_port = dst_port;
    head->prev_seq_num = seq_num;
    head->next = NULL;
  }
  else {
    net_flow *curr = head;
    while (curr->next != NULL) {
      if (strcmp(curr->src_adr, src_adr) == 0 && 
          strcmp(curr->dst_adr, dst_adr) == 0 &&
          curr->prtcl == prtcl &&
          curr->src_port == src_port &&
          curr->dst_port == dst_port) {
        if (prtcl == IPPROTO_TCP && seq_num <= curr->prev_seq_num)
          return 2; // Net flow exists and the packet is a retransmission
        else if (prtcl == IPPROTO_TCP && seq_num > curr->prev_seq_num)
          curr->prev_seq_num = seq_num;
        return 1; // Net flow exists
      }
      curr = curr->next;
    }
    if (strcmp(curr->src_adr, src_adr) == 0 && 
        strcmp(curr->dst_adr, dst_adr) == 0 &&
        curr->prtcl == prtcl &&
        curr->src_port == src_port &&
        curr->dst_port == dst_port) {
      if (prtcl == IPPROTO_TCP && seq_num <= curr->prev_seq_num)
        return 2; // Net flow exists and the packet is a retransmission
      else if (prtcl == IPPROTO_TCP && seq_num > curr->prev_seq_num)
        curr->prev_seq_num = seq_num;
      return 1; // Net flow exists
    }
    
    net_flow *new_node = (net_flow *)malloc(sizeof(net_flow));
    if (new_node == NULL) {
      printf("Memory allocation failure.\n");
      exit(EXIT_FAILURE);
    }
    strcpy(new_node->src_adr, src_adr);
    strcpy(new_node->dst_adr, dst_adr);
    new_node->prtcl = prtcl;
    new_node->src_port = src_port;
    new_node->dst_port = dst_port;
    new_node->next = NULL;

    curr->next = new_node;
  }
  return 0; // Net flow did not exist, so it was added to the list
}

void stop_capturing(int signum) { // This function is called when Ctrl+C is pressed
  pcap_breakloop(handle);
  pcap_close(handle);
}

void print_stats() {
  total_net_flows = tcp_net_flows + udp_net_flows;
  printf(
    "\nTotal number of network flows captured: %d\n" // This does not include network flows that are not TCP or UDP
    "Number of TCP network flows captured: %d\n"
    "Number of UDP network flows captured: %d\n"
    "Total number of packets received: %d\n" // This includes packets that are not TCP or UDP
    "Total number of TCP packets received: %d\n"
    "Total number of UDP packets received: %d\n"
    "Total bytes of TCP packets received: %d\n"
    "Total bytes of UDP packets received: %d\n",
    total_net_flows, tcp_net_flows, udp_net_flows, total_packets,
    tcp_packets, udp_packets, tcp_bytes, udp_bytes);
}

void decodeIPv4packet(const u_char *packet_body, char *filter){
  int port = -1;
  if (filter != NULL) {
    sscanf(filter, "port %d", &port);
  }
  int rtns_flag = 0;
  struct ip *ip_header; 
  ip_header = (struct ip *)(packet_body + sizeof(struct ether_header)); // The ethernet header is always 14 bytes as defined by standards
  char src_adr[INET_ADDRSTRLEN];
  char dst_adr[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(ip_header->ip_src), src_adr, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &(ip_header->ip_dst), dst_adr, INET_ADDRSTRLEN);
  if (ip_header->ip_p == IPPROTO_TCP) {
    struct tcphdr *tcp_header = (struct tcphdr *)(packet_body + sizeof(struct ether_header) + (ip_header->ip_hl * 4));
    uint16_t src_port = ntohs(tcp_header->th_sport);
    uint16_t dst_port = ntohs(tcp_header->th_dport);
    int payload_length = ntohs(ip_header->ip_len) - (ip_header->ip_hl * 4) - (tcp_header->th_off * 4);
    int ret = list_net_flows(src_adr, dst_adr, ip_header->ip_p, src_port, dst_port, ntohl(tcp_header->th_seq));
    if (ret == 0)
      tcp_net_flows++;
    else if (ret == 2)
      rtns_flag = 1;
    if (port == -1 || port == src_port || port == dst_port) {
      if (rtns_flag)
        fprintf(fp, "Retransmitted\n");
      fprintf(fp, "Source IPv4 Adress: %s\n", src_adr);
      fprintf(fp, "Destination IPv4 Adress: %s\n", dst_adr);
      fprintf(fp, "Protocol: TCP\n");
      fprintf(fp, "Source port: %u\n", src_port);
      fprintf(fp, "Destination port: %u\n", dst_port);
      fprintf(fp, "TCP header length: %u\n", tcp_header->th_off * 4);
      fprintf(fp, "TCP payload length: %d\n\n", payload_length);
    }
    tcp_packets++;
    tcp_bytes += ntohs(ip_header->ip_len) - (ip_header->ip_hl * 4);
  }
  else if (ip_header->ip_p == IPPROTO_UDP){
    struct udphdr *udp_header = (struct udphdr *)(packet_body + sizeof(struct ether_header) + (ip_header->ip_hl * 4));
    uint16_t src_port = ntohs(udp_header->uh_sport);
    uint16_t dst_port = ntohs(udp_header->uh_dport);
    int payload_length = ntohs(udp_header->uh_ulen) - 8;
    int ret = list_net_flows(src_adr, dst_adr, ip_header->ip_p, src_port, dst_port, 0);
    if (ret == 0)
      udp_net_flows++;
    if (port == -1 || port == src_port || port == dst_port) {
      fprintf(fp, "Source IPv4 Adress: %s\n", src_adr);
      fprintf(fp, "Destination IPv4 Adress: %s\n", dst_adr);
      fprintf(fp, "Protocol: UDP\n");
      fprintf(fp, "Source port: %u\n", src_port);
      fprintf(fp, "Destination port: %u\n", dst_port);
      fprintf(fp, "UDP header length: 8\n"); //UDP header length is always 8
      fprintf(fp, "UDP payload length: %d\n\n", payload_length);
    }
    udp_packets++;
    udp_bytes += ntohs(udp_header->uh_ulen);
  }
  // Else not a TCP or UDP packet
}

void decodeIPv6packet(const u_char *packet_body, char *filter) {
  int port = -1;
  if (filter != NULL) {
    sscanf(filter, "port %d", &port);
  }
  int rtns_flag = 0;
  struct ip6_hdr *ip6_header;
  ip6_header = (struct ip6_hdr *)(packet_body + sizeof(struct ether_header)); // The ethernet header is always 14 bytes as defined by standards
  char src_adr[INET6_ADDRSTRLEN];
  char dst_adr[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_adr, INET6_ADDRSTRLEN);
  inet_ntop(AF_INET6, &(ip6_header->ip6_dst), src_adr, INET6_ADDRSTRLEN);

  if (ip6_header->ip6_nxt == IPPROTO_TCP) {
    struct tcphdr *tcp_header = (struct tcphdr *)(packet_body + sizeof(struct ether_header) + sizeof(struct ip6_hdr)); // The IPv6 header is always 40 bytes as defined by standards
    uint16_t src_port = ntohs(tcp_header->th_sport);
    uint16_t dst_port = ntohs(tcp_header->th_dport);
    int payload_length = ntohs(ip6_header->ip6_plen) - (tcp_header->th_off * 4);
    int ret = list_net_flows(src_adr, dst_adr, ip6_header->ip6_nxt, src_port, dst_port, ntohl(tcp_header->th_seq));
    if (ret == 0)
      tcp_net_flows++;
    else if (ret == 2)
      rtns_flag = 1;
    if (port == -1 || port == src_port || port == dst_port) {
      if (rtns_flag)
        fprintf(fp, "Retransmitted\n");
      fprintf(fp, "Source IPv6 Adress: %s\n", src_adr);
      fprintf(fp, "Destination IPv6 Adress: %s\n", dst_adr);
      fprintf(fp, "Protocol: TCP\n");
      fprintf(fp, "Source port: %u\n", src_port);
      fprintf(fp, "Destination port: %u\n", dst_port);
      fprintf(fp, "TCP header length: %u\n", tcp_header->th_off * 4);
      fprintf(fp, "TCP payload length: %d\n\n", payload_length);
    }
    tcp_packets++;
    tcp_bytes += ntohs(ip6_header->ip6_plen);
  }
  else if (ip6_header->ip6_nxt == IPPROTO_UDP){
    struct udphdr *udp_header = (struct udphdr *)(packet_body + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
    uint16_t src_port = ntohs(udp_header->uh_sport);
    uint16_t dst_port = ntohs(udp_header->uh_dport);
    int payload_length = ntohs(udp_header->uh_ulen) - 8;
    int ret = list_net_flows(src_adr, dst_adr, ip6_header->ip6_nxt, src_port, dst_port, 0);
    if (ret == 0)
      udp_net_flows++;
    if (port == -1 || port == src_port || port == dst_port) {
      fprintf(fp, "Source IPv6 Adress: %s\n", src_adr);
      fprintf(fp, "Destination IPv6 Adress: %s\n", dst_adr);
      fprintf(fp, "Protocol: UDP\n");
      fprintf(fp, "Source port: %u\n", src_port);
      fprintf(fp, "Destination port: %u\n", dst_port);
      fprintf(fp, "UDP header length: 8\n"); //UDP header length is always 8
      fprintf(fp, "UDP payload length: %d\n\n", payload_length);
    }
    udp_packets++;
    udp_bytes += ntohs(udp_header->uh_ulen);
  }
  // Else not a TCP or UDP packet
}

void my_packet_handler(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body) {
  total_packets++;
  char *filter = (char *)args;
  struct ether_header *eth_header = (struct ether_header *)packet_body;
  if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) //0x0800 IPv4
    decodeIPv4packet(packet_body, filter);
  else if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6) //0x86dd IPv6
    decodeIPv6packet(packet_body, filter);
  // Else not an IPv4 or IPv6 packet
}

void online_capturing(char *interface, char *filter) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevsp;
  int exists = 0;

  if (pcap_findalldevs(&alldevsp, errbuf) < 0) {
      fprintf (stderr, "%s", errbuf);
      exit(EXIT_FAILURE);
    }
  while(alldevsp != NULL) {
      // printf("%s\n", alldevsp->name);
      if(strcmp(interface, alldevsp->name) == 0) {
        exists = 1;
      }
      alldevsp = alldevsp->next;
  }
  if(!exists) {
    printf("This interface does not exist.");
    exit(EXIT_FAILURE);
  }

  handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf (stderr, "%s", errbuf);
    exit(EXIT_FAILURE);
  }

  fp = fopen("log.txt", "a");

  signal(SIGINT, stop_capturing);

  pcap_loop(handle, -1, my_packet_handler, (u_char *)filter);

  print_stats();

  fclose(fp);
}

void offline_capturing(char *file, char *filter) {
  char errbuf[PCAP_ERRBUF_SIZE]; 

  handle = pcap_open_offline(file, errbuf);
  if (handle == NULL) {
    fprintf (stderr, "%s", errbuf);
    exit(EXIT_FAILURE);
  }

  fp = stdout;

  pcap_loop(handle, -1, my_packet_handler, (u_char *)filter);

  print_stats();
}

void usage() {
  printf(
      "\n"
      "usage:\n"
      "\tsudo ./pcap_ex \n"
      "Options:\n"
      "-i <interface>, Select the network interface name (e.g., wlp4s0)\n"
      "-i <interface> -f <filter>, Apply port filter (e.g., \"port 8080\")\n"
      "-r <file>, Select the packet capture file name (e.g., test_pcap_5mins.pcap)\n" 
      "-r <file> -f <filter>, Apply port filter (e.g., \"port 8080\")\n"
      "-h, Help message\n\n");
}

int main(int argc, char *argv[]) {
  if (argc == 3) {
    if (strcmp(argv[1], "-i") == 0)
      online_capturing(argv[2], NULL);
    else if (strcmp(argv[1], "-r") == 0)
      offline_capturing(argv[2], NULL);
    else {
      printf("Invalid input. Use -h for help.\n");
      exit(EXIT_FAILURE);
    }
  }
  else if (argc == 5) {
    if (strcmp(argv[1], "-i") == 0 && strcmp(argv[3], "-f") == 0)
      online_capturing(argv[2], argv[4]);
    else if (strcmp(argv[1], "-r") == 0 && strcmp(argv[3], "-f") == 0)
      offline_capturing(argv[2], argv[4]);
    else {
      printf("Invalid input. Use -h for help.\n");
      exit(EXIT_FAILURE);
    }
  }
  else if (argc == 2 && strcmp(argv[1], "-h") == 0)
    usage();
  else {
    printf("Invalid input. Use -h for help.\n");
    exit(EXIT_FAILURE);
  }
  return 0;
}
