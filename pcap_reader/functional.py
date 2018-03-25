from __future__ import division
from layers import *
from pcap_reader import *
import numpy as np

def assemble_packeges(table, file):
    net_paths = {}
    index_session = -1
    list_packets = []
    len_table = len(table.keys())  
    for i in range(1,len_table):
        table_val = table.pop(i)
        file.seek(table_val[1])
        data = file.read(table_val[2]-table_val[1])
        eth_lay = eth_layer(data[:14])
        
        if eth_lay['type'] != 'IPv4':
            continue
        ip_hdr_len = (ord(data[14])&0xf)*4
        ip_lay = ip_layer(data[14:14+ip_hdr_len])
        if  (ip_lay['protocol'] != 'TCP') and (ip_lay['protocol'] != 'UDP'):
            continue
        
        transport_lay = transport_layer(data[14+ip_hdr_len:],ip_lay['protocol'])
        #need to my reserch. Delete it condition if need full represent
        if transport_lay['data'] == 0:
            continue
        
        packet = {'number' : table_val[3],
            'time':table_val[0],
            'eth_lay' : eth_lay,
            'ip_lay' : ip_lay,
            'transport_lay' : transport_lay,
            'index_session' : 0,
            'side' : ''
            }
        net_path_str = ip_lay['ip_src']+'.'+str(transport_lay['src_port'])+'-'+ip_lay['ip_dst']+'.'+str(transport_lay['dst_port'])
        inv_net_path_str = ip_lay['ip_dst']+'.'+str(transport_lay['dst_port'])+'-'+ip_lay['ip_src']+'.'+str(transport_lay['src_port'])
        if (inv_net_path_str in net_paths.keys()) == True:
            packet['side']='serv'
            packet['index_session'] = net_paths[inv_net_path_str]
        else:
            packet['side']='client'
            try:
                packet['index_session'] = net_paths[net_path_str]
            except KeyError:
                index_session +=1
                net_paths[net_path_str] = index_session
                packet['index_session'] = index_session
        try:
            list_packets.append(packet)
        except MemoryError:
            return list_packets
    return list_packets

def packet_generator(f):

    net_paths = {}
    eth_lay = {}

    file_hdr, end, offset = read_file_header(f.read(24))
     
    table = table_of_packets(f,end)
    
    for i in table:
        table_val = i
        f.seek(table_val[1])
        data = f.read(table_val[2]-table_val[1])
        if file_hdr['data_link_type'] != 'LINKTYPE_RAW':
            eth_lay = eth_layer(data[:offset])
        if len(eth_lay.keys()) != 0:
            if eth_lay['type'] != 'IPv4':
                continue
        ip_hdr_len = (ord(data[offset])&0xf)*4
        ip_lay = ip_layer(data[offset:offset+ip_hdr_len])
        if  (ip_lay['protocol'] != 'TCP') and (ip_lay['protocol'] != 'UDP'):
            continue
        
        transport_lay = transport_layer(data[offset+ip_hdr_len:],ip_lay['protocol'])
        
        packet = {'number' : table.index(i)+1,
            'time':table_val[0],
            'eth_lay' : eth_lay,
            'ip_lay' : ip_lay,
            'transport_lay' : transport_lay,
            'index_session' : 0,
            'side' : ''
            }

        net_path_str = ip_lay['ip_src']+'.'+str(transport_lay['src_port'])+'-'+ip_lay['ip_dst']+'.'+str(transport_lay['dst_port'])
        inv_net_path_str = ip_lay['ip_dst']+'.'+str(transport_lay['dst_port'])+'-'+ip_lay['ip_src']+'.'+str(transport_lay['src_port'])
        if (inv_net_path_str in net_paths.keys()) == True:
            packet['side']='serv'
            net_paths[inv_net_path_str].append(packet)
        else:
            packet['side']='client'
            try:
                net_paths[net_path_str].append(packet)
            except KeyError:
                net_paths[net_path_str] = []
                net_paths[net_path_str].append(packet)
        yield packet

def fprint(packet):
    print 'General packet info:'
    print '\tNumber of packet: %d' % packet['number']
    print '\tCapture time: %s' % packet['time']
    print '\tSide: %s' % packet['side']
    print '\tSession index: %d' % packet['index_session']
    print 
    print 'Ethernet layer:'
    print '\tSource MAC-addres: %s' %packet['eth_lay']['mac_src']
    print '\tDestination MAC-addres: %s' %packet['eth_lay']['mac_dst']
    print '\tProtocol of next layer: %s' %packet['eth_lay']['type']
    print 
    print 'IP Layer:'
    if packet['eth_lay']['type'] == 'IPv4':
        print '\tHeader lenght: %s' % packet['ip_lay']['len_hdr']  
        print '\tType of service: %s' % packet['ip_lay']['type_of_service'] 
        print '\tTotal lenght: %s' % packet['ip_lay']['total_len']  
        print '\tIdentification: %s' % packet['ip_lay']['identification'] 
        print '\tFlags: %s' % packet['ip_lay']['flags'] 
        print '\tFragment offset: %s' % packet['ip_lay']['fragment_offset'] 
        print '\tTTL: %s' % packet['ip_lay']['ttl'] 
        print '\tTransport protocol: %s' % packet['ip_lay']['protocol']  
        print '\tChecksum: %s' % packet['ip_lay']['checksum_ip'] 
        print '\tSource IP addres: %s' % packet['ip_lay']['ip_src'] 
        print '\tDestination IP addres: %s' % packet['ip_lay']['ip_dst'] 
        print '\tOptions: %s' % packet['ip_lay']['options']
        print 
    else:
        print 'Impossible to print information about %s protocol' % packet['eth_lay']['type']
        print '-------------------------'
    if packet['ip_lay']['protocol']  == 'TCP':
        print 'Transport layer(TCP):'
        print '\tSource port: %s' % packet['transport_lay']['src_port']
        print '\tDestinaton port: %s' % packet['transport_lay']['dst_port'] 
        print '\tSequence number: %s' % packet['transport_lay']['seq_num'] 
        print '\tAcknowlegment number: %s' % packet['transport_lay']['ack_num']
        print '\tHeader lenght: %s' % packet['transport_lay']['len_hdr'] 
        print '\tFalgs and reservse: %s' % packet['transport_lay']['reserv_and_flags'] 
        print '\tWindow size: %s' % packet['transport_lay']['window_size'] 
        print '\tChecksum: %s' % packet['transport_lay']['checksum_tcp'] 
        print '\tUrgent: %s' % packet['transport_lay']['urgent']
        print '\tOptions: %s' % packet['transport_lay']['options'] 
        print '\tData: %s' % packet['transport_lay']['data']
    elif packet['ip_lay']['protocol']  == 'UDP':
        print 'Transport layer(UDP):' 
        print '\tSource port: %s' % packet['transport_lay']['src_port']
        print '\tDestinaton port: %s' % packet['transport_lay']['dst_port']
        print '\tChecksum: %s' % packet['transport_lay']['checksum_udp']
        print '\tDatagramm lenght: %s' % packet['transport_lay']['datagramm_len'] 
        print '\tHeader lenght: %s' % packet['transport_lay']['len_hdr']
        print '\tData: %s' % packet['transport_lay']['data']
        print '-------------------------'
    else:
        print 'Impossible to print information about %s protocol' % packet['ip_lay']['protocol']
        print '-------------------------'

