For this assignment we used Snort-3, an IDS/IPS solution, to run a set of rules that will produce 
an alert when the scanned traffic matches them.

We implemented the following tasks: 

● Report any icmp connection attempt in test_pcap_5mins.pcap  
For this task, the Snort rule simply detects any icmp connections, regardless of the source and
destination addresses.  
For the given file, Snort produces 34 alerts.

● Find all packets which contain “hello” string in test_pcap_5mins.pcap  
For this task, the Snort rule detects packets that contain the "hello" string, using the "content"
option, for any ip protocol.  
For the given file, Snort produces 2 alerts.

● Report all traffic between non root ports (port number > 1024)  
For this task, the Snort rule detects packets between non root ports using the ":" (range) operator, next
to the number 1025 (meaning greater than or equal to 1025), on the port component of the header.  
For the given file, Snort produces ~9145 alerts.

● Create a rule that will detect ssh brute force attacks in sshguess.pcap file  
  ○ A brute force attempt can be realized as 10 attempts within 10 minutes  
For this task, the Snort rule detects client request packets destined to the port 22, the default SSH port, 
keeping the ones that are established TCP connections and contain the "SSH" string, in the first 4 bytes. It
also uses the "detection_filter" option, which is used to require multiple rule hits before generating 
an event. In this case, it is used to detect 10 hits within 10 minutes (600 seconds).  
For the given file, Snort produces 1 alert

● Setup the community rules (run snort with associated snort.conf) and report any clear
indicator of malicious traffic in test_pcap_5mins.pcap  
  ○ Some community rules clearly state the exploit detected  
For the given file, Snort produces 102 alerts

Alert messages:

-INDICATOR-SCAN UPnP service discover attempt  
This event indicates that an attempt has been made to scan a host, suggesting that the system might be 
affected by malware. Symptoms do not guarantee an infection; the network configuration may not be affected 
by malware, but showing indicators as a result of a normal function. There have been known false positives.

-PROTOCOL-ICMP Time-To-Live Exceeded in Transit  
This event is generated when a routing device detects that a packet has exceeded the maximum number of 
allowable hops. This may be an indication of an attacker attempting a traceroute of a host in your network. 
There have been known false positives.

-POLICY-SOCIAL Microsoft MSN user search  
This event is generated when activity relating to network chat clients is detected, implying policy violation. 
Use of chat clients to communicate with unknown external sources may be against the policy of many organizations.
There have been no known false positives.

-POLICY-SOCIAL Microsoft MSN message  
This event is generated when network traffic that indicates MSN messenger is being used, implying possible 
policy violation. The use of MSN messenger may be prohibited by corporate policy in some network environments. 
There have been no known false positives.

-PROTOCOL-SNMP public access udp & PROTOCOL-SNMP request udp  
Snort has detected traffic that may indicate the presence of the snmp protocol or vulnerabilities in the snmp 
protocol on the network. There have been no known false positives.

-PROTOCOL-ICMP L3retriever Ping  
Snort alerted on Internet Control Message Protocol (ICMP) traffic, which allows hosts to send error messages 
about interruptions in traffic. Administrators can use ICMP to perform diagnostics and troubleshooting, but 
the protocol can also be used by attackers to gain information on a network. There have been no known false 
positives.

-PROTOCOL-ICMP PING  
The rule looks for PING traffic coming into the network that doesn't follow the normal format of a PING. 
There have been no known false positives.


-PROTOCOL-ICMP Echo Reply  
This event is generated when a network host generates an ICMP Echo Reply in response to an ICMP Echo Request 
message. There have been no known false positives.
