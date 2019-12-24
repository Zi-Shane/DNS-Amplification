# Imports
from scapy.all import *
from pprint import pprint
import operator

# Parameters
interface = "eno2"                      # `Interface you want to use
dns_source = "192.168.100.1"                 # IP of that interface
dns_destination = ["8.8.8.8"]   # List of DNS Server IPs

time_to_live = 128                                                                 # IP TTL 
query_name = "dnssec-tools.org"                                                          # DNS Query Name
query_type = ["A"] # DNS Query Types
# query_type = ["ANY", "A","AAAA","CNAME","MX","NS","PTR","CERT","SRV","TXT", "SOA"] # DNS Query Types

# Initialise variables
results = []
packet_number=0

# Loop through all query types then all DNS servers
for i in range(0,len(query_type)):
    for j in range(0, len(dns_destination)):
        packet_number += 1

        # Craft the DNS query packet with scapy
        packet_dns = IP(src=dns_source, dst=dns_destination[j], ttl=time_to_live) / UDP() / DNS(rd=1, qd=DNSQR(qname=query_name, qtype=query_type[i]))
        packet_dnssec = IP(src=dns_source, dst=dns_destination[j], ttl=time_to_live) / UDP() / DNS(rd=1, ad=1, qd=DNSQR(qname=query_name, qtype=query_type[i]),ar=DNSRROPT())
        # print(hexdump(packet))
        # packet.show()

        # Sending the packet
        try:
            query_dns = sr1(packet_dns,iface=interface,verbose=False, timeout=8)
            print("Packet dns #{} sent!".format(packet_number))
            query_dnssec = sr1(packet_dnssec,iface=interface,verbose=False, timeout=8)
            print("Packet dnssec #{} sent!".format(packet_number))
        except:
            print("Error sending packet #{}".format(packet_number))
        
        # Creating dictionary with received information
        try:
            result_dict_dns = {
                'query_dns_type': "dns",
                'dns_destination':dns_destination[j],
                'query_type':query_type[i],
                'query_size':len(packet_dns),
                'response_size':len(query_dns),
                'amplification_factor': ( len(query_dns) / len(packet_dns) ),
                'packet_number':packet_number
            }
            result_dict_dnssec = {
                'query_dns_type': "dnssec",
                'dns_destination':dns_destination[j],
                'query_type':query_type[i],
                'query_size':len(packet_dnssec),
                'response_size':len(query_dnssec),
                'amplification_factor': ( len(query_dnssec) / len(packet_dnssec) ),
                'packet_number':packet_number
            }
            results.append(result_dict_dns)
            results.append(result_dict_dnssec)
        except:
            pass

# Sort dictionary by the amplification factor
results.sort(key=operator.itemgetter('amplification_factor'),reverse=True)

# Print results
pprint(results)
