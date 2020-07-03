#!/usr/bin/python3.3
#Sniffs only incoming TCP packet

import socket, sys
import struct

def ethernet_frame(data):
    dest_mac, src_mac, proto= struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto),data[14:]

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

#create an INET, STREAMing socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
except:
    print ('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
    sys.exit()

# receive a packet
espacio='\t |-'
while True:
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    raw_data, addr = conn.recvfrom(65536)
    dest_mac, src_mac, eth_proto, data=ethernet_frame(raw_data)
    print('\tEthernet Header')
    print(espacio, 'Destination Address :', dest_mac)
    print(espacio, 'Source Address :',src_mac)
    print(espacio, 'Protocol :',eth_proto)

    packet = s.recvfrom(65565)
    #packet string from tuple
    packet = packet[0]

    #take first 20 characters for the ip header
    ip_header = packet[0:20]

    #now unpack them :)
    iph = struct.unpack('!BBHHHBBH4s4s' , ip_header)
   
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    iph_length = ihl * 4
    ip_tos = iph[1] # char
    ip_len = iph[2] # short int
    ip_id = iph[3]  # short int
    ip_off = iph[4] # short int
    #------------------
    ip_ttl = iph[5] #char
    ip_p = iph[6]   #char
    ip_sum = iph[7] #shor int

    s_addr = socket.inet_ntoa(iph[8])
    d_addr = socket.inet_ntoa(iph[9])
    
    print("\tIP Header")
    print(espacio,'IP Version : ' + str(version) )
    print(espacio,'IP Header Length (IHL) : ' , ihl, 'DWORDS or',str(ihl*32//8) ,'bytes')
    print(espacio,'Type of Service (TOS): ',str(ip_tos))
    print(espacio,'IP Total Length: ',ip_len, ' DWORDS ',str(ip_len*32//8) ,'bytes')
    print(espacio,'Identification: ',ip_id)
    print(espacio,'flags: ',ip_off)
    print(espacio,'TTL : ' + str(ip_ttl))
    print(espacio,'Protocol : ' + str(ip_p) )
    print(espacio,'Chksum: ',ip_sum)
    print(espacio,'Source Address IP : ' + str(s_addr) )
    print(espacio,'Destination Address IP: ' + str(d_addr))
    print("")

    tcp_header = packet[iph_length:iph_length+20]
    tcph = struct.unpack('!HHLLBBHHH' , tcp_header)
    source_port = tcph[0]   # uint16_t
    dest_port = tcph[1]     # uint16_t
    sequence = tcph[2]      # uint32_t
    acknowledgement = tcph[3]   # uint32_t
    doff_reserved = tcph[4]     # uint8_t
    tcph_length = doff_reserved >> 4

    tcph_flags = tcph[5]            #uint8_t
    tcph_window_size = tcph[6]      #uint16_t
    tcph_checksum = tcph[7]         #uint16_t
    tcph_urgent_pointer = tcph[8]   #uint16_t
    
    print("\tTCP Header")
    
    print(espacio,"Source Port:",source_port)
    print(espacio,"Destination Port:",dest_port)
    print(espacio,"Sequence Number:",sequence)
    print(espacio,"Acknowledge Number:",acknowledgement)
    print(espacio,"Header Length:",tcph_length,'DWORDS or ',str(tcph_length*32//8) ,'bytes')

    print(espacio,"Urgent Flag:",(tcph_flags & 32)>>5)

    print(espacio,"Acknowledgement Flag:",(tcph_flags & 16)>>4)
    print(espacio,"Push Flag:",(tcph_flags & 8)>>3)
    print(espacio,"Reset Flag:",(tcph_flags & 4)>>2)
    print(espacio,"Synchronise Flag:",(tcph_flags & 2)>>1)
    print(espacio,"Finish Flag:",(tcph_flags & 1))

    print(espacio,"Window Size:",tcph_window_size)
    print(espacio,"Checksum:",tcph_checksum)
    print(espacio,"Urgent Pointer:",tcph_urgent_pointer)
    print("")

    h_size = iph_length + tcph_length * 4
    data_size = len(packet) - h_size

    #get data from the packet
    data = packet[h_size:]
    
    print('Diego Gorostiaga Marin')
    print('Paralelo A')

