
"""
created on Thu Jan 12 07:31:55 2023

@author: ejuli_000
"""

"""
goals -> replicate wireshark to help learn how pcapture files work
long term -> build user input/interface. display graphs. 
"""

from scapy.all import *

def open_pcap_file(file_name):
    packet_file = rdpcap(file_name)
    print("pcap file opened")
    print(len(packet_file))


from scapy.utils import RawPcapReader 
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP

def printPacket(file_name):
       for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
            print(pkt_data)

def IPv4only(file_name, out): 
    count = 0
    input_packet = PcapReader(file_name)
    output_packet = PcapWriter('output_file.pcap', append=True) #change output file -> based on user input
    
    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
        ether_pkt = Ether(pkt_data)
        if 'type' in ether_pkt.fields:
            if ether_pkt.type == 0x0800: 
                time.sleep(1)
                packet = input_packet.read_packet()
                output_packet.write(packet)
                count += 1
                print(count)

"""def EthernetBroadCast(file_name, out)
    count = 0
    input_packet = PcapReader(file_name)
    output_packet = PcapWriter('output_file.pcap', append=True) #change output file -> based on user input
    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
  """          





##IPv4only('example-01.pcap')
printPacket('example-01.pcap')

    
