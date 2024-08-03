#Basic packet sniffer
# from scapy.all import sniff

#Define a callback function that will be called for each captured packet
#def packet_callback(packet):
# print(packet.summary())

#start sniffing on network interface
#sniff(prn=packet_callback, count=50)


#Analyzing the packets

#from scapy.all import sniff, IP

#def packet_callback(packet):
    #if packet.haslayer(IP):
        #ip_layer = packet.getlayer(IP)
       # print(f"source: {ip_layer.src}, Destination: {ip_layer.dst}, protocol:{ip_layer.proto}")

#sniff(prn=packet_callback, count=10)


#Saving and Reading Packets
from scapy.all import sniff, IP, wrpcap, rdpcap

packets = sniff(count=10)
wrpcap("packets.pcap", packets)

# Read packets from a file
saved_packets = rdpcap("packets.pcap")
for packet in saved_packets:
    print(packet.summary())