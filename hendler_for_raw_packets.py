def handler_for_raw_packets(string):
    #input of function is a first 28 byte for UDP/IP, 
    #cuz IP has len 20 and UDP has len 16, after that data are located.
    #make this function universal(for TCP and UDP)    
    into_number = map(lambda x:ord(x),string)
    ip_ver = into_number[0]>>4
    #if ip_ver != 4 or ip_ver != 6:
    #    raise ProtocolError(Exception)
    if into_number[9] == 17:
        up_proto = 'UDP'
    else:
        up_proto ='-'
    ip_src = '.'.join(map(lambda x: str(x),into_number[12:16]))
    ip_dst = '.'.join(map(lambda x: str(x),into_number[16:20]))
    port_src = int('0x'+hex(into_number[20])[2:]+hex(into_number[21])[2:],16)
    port_dst = int('0x'+hex(into_number[22])[2:]+hex(into_number[23])[2:],16)
    return [ip_ver,up_proto, ip_src,ip_dst, port_src,port_dst]
    
