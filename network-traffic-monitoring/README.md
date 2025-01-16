For this assignment, we created a networking monitoring tool, based on the C programming
language. The tool is capable of capturing packets in two modes (online and offline), 
decode the TCP/UDP ones that follow the IPv4/IPv6 protocol and print their info, and will
also print certain statistics as soon as the capturing is terminated (by pressing Ctrl+C).

The user can also apply a port filter, limiting the printed packets to only those that use 
this port, either as a source or a destination. However, the final statistics are not 
filtered, because the structure of the transport layer header depends on the specific protocol 
in use. Non TCP or UDP protocols may have varying header formats, including the position and 
size of the ports' fields.


Q: Find where the payload is in memory.
A: In order to calculate the payload location in memory, we have to get past the ethernet, 
   IP, and TCP/UDP layer, by taking into consideration the size of those elements, based on 
   the packet's IP version (IPv4/IPv6), and protocol.

Q: Can you tell if an incoming TCP packet is a retransmission? If yes, how? If not, why?
A: Yes. For an incoming packet to be a retransmission of a previous one, they need to 
   belong to the same network flow and the new one must have a sequence number less than
   or equal to the sequence number of the previous one. In practice, the implementation 
   of marking packets as retransmissions accurately is more complicated, because we need 
   to evaluate multiple additional factors, such as their acknowledgment numbers and TCP 
   flags, timing information, etc.

Q: Can you tell if an incoming UDP packet is a retransmission? If yes, how? If not, why?
A: No. UDP is a connectionless protocol and so we can’t detect lost packets. Therefore, 
   retransmission of the lost packets is not possible.


Program execution examples:
sudo ./pcap_ex -i eth0 (save the packets in log.txt)
sudo ./pcap_ex -i eth0 -f "port 8080"
sudo ./pcap_ex -r test_pcap_5mins.pcap (print the outputs in terminal)
sudo ./pcap_ex -r test_pcap_5mins.pcap -f "port 8080"
sudo ./pcap_ex -h 
