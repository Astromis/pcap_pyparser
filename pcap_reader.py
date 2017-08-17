f = open('test_file.pcap','r+b')
data = f.read()

def read_file_header(data):
    #extract file header
    file_header = map(lambda x: hex(ord(x))[2:],data[:24])
    for i in range(len(file_header)):
        if len(file_header[i]) == 1:
            file_header[i] = '0'+file_header[i]
            
    #write parts of file header
    magic_num = ''.join(file_header[:4])
    if magic_num != 'a1b2c3d4': # Note: pay attention to this condition if function return nothing
        return 0
    big_little_ver = ''.join(file_header[4:8])
    gmt_timezone = ''.join(file_header[8:12])
    accuracy_timestamps = ''.join(file_header[12:16])
    size_packet = ''.join(file_header[16:20])
    data_link_type = ''.join(file_header[20:24])
    return data_link_type
    
def table_of_packets(data):
    #create table of packets as a dictionary, where key column is a number of packet
    #and value is a tuple with next structure (time, absolut value of begin data, absolut value of end data)
    
    pointer_on_begin_hdr = 24 # begin of packet header
    len_file = len(data) # length of data
    packet_counter = 0
    table_of_packets = {}
    while pointer_on_begin_hdr < len_file:
        packet_counter += 1
        packet_header = map(lambda x: hex(ord(x))[2:],data[pointer_on_begin_hdr:pointer_on_begin_hdr+16])
        
        for j in range(len(packet_header)):
            if len(packet_header[j]) == 1:
                packet_header[j] = '0'+packet_header[j]
        print packet_header
        #write parts of packet header        
        timestamp = ''.join(packet_header[:4])
        time = ''.join(packet_header[4:8])
        len_data = magic_num = ''.join(packet_header[8:12])
        len_packet = magic_num = ''.join(packet_header[12:16]) # difference between len_data and len_packet ???
        
        table_of_packets[packet_counter] = (time, pointer_on_begin_hdr +16, pointer_on_begin_hdr +16+int(len_data,16))
        pointer_on_begin_hdr += int(len_data,16)+16
    return table_of_packets
    
print table_of_packets
for i in range(table_of_packets[1][1],table_of_packets[1][2]):
    print hex(ord(data[i]))
f.close()