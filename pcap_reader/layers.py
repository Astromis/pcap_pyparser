import descriptions

def eth_layer(data):
    # first 13 bytes of packet data
    data = map(lambda x: hex(ord(x))[2:],data)
    for i in range(len(data)):
        if len(data[i]) == 1:
            data[i] = '0'+data[i]
    eth_dict = {'mac_dst' : ':'.join(data[0:6]),
        'mac_src' : ':'.join(data[6:12]),
    }
    try: 
        eth_dict['type'] = descriptions.types_proto_upper_eth[int(''.join(data[12:14]),16)]
    except KeyError:
        eth_dict['type'] = '0'
    return eth_dict
    
def ip_layer(data):
    data = map(lambda x: hex(ord(x))[2:],data)
    for i in range(len(data)):
        if len(data[i]) == 1:
            data[i] = '0'+data[i]
    options = 0
    len_hdr = (int(data[0],16)&0xf)*4
    if len_hdr != 20:
        pass
        #options = (int(''.join(data[20:len_hdr]),16)&0xf)*4
        options = int(''.join(data[20:len_hdr]),16)
    ip_layer_dict = {'version' : int(data[0],16)>>4,
    'len_hdr' : len_hdr, 
    'type_of_service' : data[1], # add table
    'total_len' : int(''.join(data[2:4]),16),
    'identification' : int(''.join(data[4:6]),16),
    'flags' : int(''.join(data[6:8]),16)>>13, #add table
    'fragment_offset' : int(''.join(data[6:8]),16)&0x1FFF,
    'ttl' : int(data[8],16),
    'protocol' : descriptions.types_proto_upper_ip[int(data[9],16)],
    'checksum_ip' : int(''.join(data[10:12]),16),
    'ip_src' : '.'.join(map(lambda x: str(int(x,16)),data[12:16])),
    'ip_dst' : '.'.join(map(lambda x: str(int(x,16)),data[16:20])),
    'options' : options
    }
    return ip_layer_dict

def transport_layer(data, protocol):
    #parse TCP or UDP
    data = map(lambda x: hex(ord(x))[2:],data)
    counter = 0
    for i in range(len(data)):
        if len(data[i]) == 1:
            data[i] = '0'+data[i]
    if protocol == "TCP":
        len_hdr = (int(''.join(data[12:14]),16)>>12)*4
        len_data = len(data[len_hdr:])
        for i in data[len_hdr:]:
            if i == '00':
               counter +=1
        if counter == len_data:
            len_data = 0
            
        transport_dict = {
            'src_port' : int(''.join(data[0:2]),16),
            'dst_port' : int(''.join(data[2:4]),16),
            'seq_num' : int(''.join(data[4:8]),16),
            'ack_num' : int(''.join(data[8:12]),16),
            'len_hdr' : len_hdr,
            'reserv_and_flags' : int(''.join(data[12:14]),16)&0xfff,
            'window_size' : int(''.join(data[14:16]),16),
            'checksum_tcp' : int(''.join(data[16:18]),16),
            'urgent' : int(''.join(data[18:20]),16),
            'options' : data[20:len_hdr],
            'data' : ''.join(map(lambda x: chr(int(x,16)),data[len_hdr:]))#len_data#
            }
        return transport_dict

        
    elif protocol == 'UDP':
        transport_dict = {
            'src_port' : int(''.join(data[0:2]),16),
            'dst_port' : int(''.join(data[2:4]),16),
            'datagramm_len' : int(''.join(data[4:6]),16),
            'checksum_udp' : int(''.join(data[6:8]),16),
            'len_hdr' : 8,
            'data' : ''.join(map(lambda x: chr(int(x,16)),data[8:]))#len(data[8:])#
        }
        return transport_dict
