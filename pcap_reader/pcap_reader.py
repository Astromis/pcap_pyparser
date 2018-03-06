from __future__ import division
import descriptions
import os.path
import datetime

def reverse(list):
    list.reverse()
    return list
    
def read_file_header(data):
    #extract file header
    offset = 14
    file_header = map(lambda x: hex(ord(x))[2:],data[:24])
    for i in range(len(file_header)):
        if len(file_header[i]) == 1:
            file_header[i] = '0'+file_header[i]
            
    #write parts of file header
    magic_num = ''.join(file_header[:4])
    if magic_num == 'a1b2c3d4': #big endian
        end = 0
        data_link_type_num = ''.join(file_header[20:24])
        file_hdr_dict ={'big_little_ver' : ''.join(file_header[4:8]),
        'gmt_timezone' : ''.join(file_header[8:12]),
        'accuracy_timestamps' : ''.join(file_header[12:16]),
        'size_packet' : ''.join(file_header[16:20]),
        'data_link_type' : descriptions.links_type[int(data_link_type_num,16)]
        }
    elif magic_num == 'd4c3b2a1': #little endian
        end = 1
        data_link_type_num = ''.join(reverse(file_header[20:24]))
        file_hdr_dict ={'big_little_ver' : ''.join(reverse(file_header[4:8])),
        'gmt_timezone' : ''.join(reverse(file_header[8:12])),
        'accuracy_timestamps' : ''.join(reverse(file_header[12:16])),
        'size_packet' : ''.join(reverse(file_header[16:20])),
        'data_link_type' : descriptions.links_type[int(data_link_type_num,16)]
        }
    else:
        print "Eror reading fike. Wrong magic number."
        exit(1)
    if data_link_type_num == 'LINKTYPE_RAW':
        offset = 0
    
    return file_hdr_dict, end, offset

    
def table_of_packets(file,end):
    #read packet headers and create table of packets as a dictionary, where key column is a number of packet
    #and value is a tuple with next structure (time, absolut value of begin data, absolut value of end data)
    
    pointer_on_begin_hdr = 24 # begin of packet header
    len_file = os.path.getsize(file.name) # length of data
    t_of_packets = []
    time_counter = 0
    tmp_time = 0

    while pointer_on_begin_hdr < len_file:
         
        file.seek(pointer_on_begin_hdr)
        data = file.read(16)
        packet_header = map(lambda x: hex(ord(x))[2:],data)
        
        for j in range(len(packet_header)):
            if len(packet_header[j]) == 1:
                packet_header[j] = '0'+packet_header[j]
        if end == 0: #if big endian
            #write parts of packet header        
            timestamp = int(''.join(reverse(packet_header[:4])),16)

            time = time_counter + int('0x' + ''.join(packet_header[4:8]),16)/1000000
            
            len_data = ''.join(packet_header[8:12])
            len_packet = ''.join(packet_header[12:16]) 
            if tmp_time > time:
                time_counter += 1
                time +=1
            else:
                tmp_time = time
        elif end == 1: #if ltittle endian
            timestamp = int(''.join(reverse(packet_header[:4])),16)
            time = int('0x' + ''.join(packet_header[4:8]),16)/1000000
            len_data = ''.join(reverse(packet_header[8:12]))
            len_packet = ''.join(reverse(packet_header[12:16]))
            if tmp_time > time:
                time_counter += 1
                time +=1
            else:
                tmp_time = time
        t_of_packets.append( (time, pointer_on_begin_hdr +16, pointer_on_begin_hdr +16+int(len_data,16)) )
        pointer_on_begin_hdr += int(len_data,16)+16
    t_of_packets.sort(key=lambda x: x[0])
    return t_of_packets

