This script is responsible for creating a simple adblock mechanism. It rejects connections from specific 
domain names or IPv4/IPv6 addresses using iptables/ip6tables.

To run the script, you need to grant exetutable privilidges to the .sh file, by chanigng its mode,
using chmod +x adblock.sh. Then, in order to run it, type in the command sudo bash adblock.sh,
followed by one of the options below:

  -domains        Configure adblock rules based on the domain names of 'domainNames.txt' file.  
  -ips            Configure adblock rules based on the IP addresses of 'IPAddresses.txt' file.  
  -save           Save rules to 'adblockRules' file.  
  -load           Load rules from 'adblockRules' file.  
  -list           List current rules.  
  -reset          Reset rules to default settings (i.e. accept all).  
  -help           Display this help and exit.  

The adblocker will block incoming packets from a list of domains/IPs given by the user. In practice,
the mechanism might fail to block certain ads, due to various factors, such as:

-Ad networks may have a large number of IP addresses, and blocking only a few of them might not be 
sufficient to block all ads. Also, recklessly blocking all IPs from certain domains may block 
legitimate services that share the same IP addresses.

-Some ad servers use dynamic IP addresses, which means they can change their IP addresses frequently. 
Blocking a specific IP may not be effective if the ad server switches to a different IP, and so the 
user will need to run the script again.

-Ads can be delivered through JavaScript or embedded directly into the webpage. Such cases cannot be
handled by our adblocker.
