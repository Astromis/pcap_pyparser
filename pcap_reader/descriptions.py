links_type = {	1:'LINKTYPE_ETHERNET',
	3:'LINKTYPE_AX25',
	6:'LINKTYPE_IEEE802_5',
	7:'LINKTYPE_ARCNET_BSD',
	8:'LINKTYPE_SLIP',
	9:'LINKTYPE_PPP',
	10:'LINKTYPE_FDDI',
	50:'LINKTYPE_PPP_HDLC',
	51:'LINKTYPE_PPP_ETHER',
	100:'LINKTYPE_ATM_RFC1483',
	101:'LINKTYPE_RAW',
	104:'LINKTYPE_C_HDLC',
	105:'LINKTYPE_IEEE802_11',
	107:'LINKTYPE_FRELAY',
	108:'LINKTYPE_LOOP',
	113:'LINKTYPE_LINUX_SLL',
	114:'LINKTYPE_LTALK',
	117:'LINKTYPE_PFLOG',
	119:'LINKTYPE_IEEE802_11_PRISM',
	122:'LINKTYPE_IP_OVER_FC',
	123:'LINKTYPE_SUNATM',
	127:'LINKTYPE_IEEE802_11_RADIOTAP',
	129:'LINKTYPE_ARCNET_LINUX',
	138:'LINKTYPE_APPLE_IP_OVER_IEEE1394',
	139:'LINKTYPE_MTP2_WITH_PHDR',
	140:'LINKTYPE_MTP2',
	141:'LINKTYPE_MTP3',
	142:'LINKTYPE_SCCP',
	143:'LINKTYPE_DOCSIS',
	144:'LINKTYPE_LINUX_IRDA',
	#147-162:'LINKTYPE_USER0-LINKTYPE-USER15', #Reserved for private use; see above. Create handler for this instance
	163:'LINKTYPE_IEEE802_11_AVS',
	165:'LINKTYPE_BACNET_MS_TP',
	166:'LINKTYPE_PPP_PPPD',
	169:'LINKTYPE_GPRS_LLC',
	170:'LINKTYPE_GPF_T',
	171:'LINKTYPE_GPF_F',
	177:'LINKTYPE_LINUX_LAPD',
	187:'LINKTYPE_BLUETOOTH_HCI_H4',
	189:'LINKTYPE_USB_LINUX',
	192:'LINKTYPE_PPI',
	195:'LINKTYPE_IEEE802_15_4',
	196:'LINKTYPE_SITA',
	197:'LINKTYPE_ERF',
	201:'LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR',
	202:'LINKTYPE_AX25_KISS',
	203:'LINKTYPE_LAPD',
	204:'LINKTYPE_PPP_WITH_DIR',
	205:'LINKTYPE_C_HDLC_WITH_DIR',
	206:'LINKTYPE_FRELAY_WITH_DIR',
	209:'LINKTYPE_IPMB_LINUX',
	215:'LINKTYPE_IEEE802_15_4_NONASK_PHY',
	220:'LINKTYPE_USB_LINUX_MMAPPED',
	224:'LINKTYPE_FC_2',
	225:'LINKTYPE_FC_2_WITH_FRAME_DELIMS',
	226:'LINKTYPE_IPNET',
	227:'LINKTYPE_CAN_SOCKETCAN',
	228:'LINKTYPE_IPV4',
	229:'LINKTYPE_IPV6',
	230:'LINKTYPE_IEEE802_15_4_NOFCS',
	231:'LINKTYPE_DBUS',
	235:'LINKTYPE_DVB_CI',
	236:'LINKTYPE_MUX27010',
	237:'LINKTYPE_STANAG_5066_D_PDU',
	239:'LINKTYPE_NFLOG',
	240:'LINKTYPE_NETANALYZER',
	241:'LINKTYPE_NETANALYZER_TRANSPARENT',
	242:'LINKTYPE_IPOIB',
	243:'LINKTYPE_MPEG_2_TS',
	244:'LINKTYPE_NG40',
	245:'LINKTYPE_NFC_LLCP',
	247:'LINKTYPE_INFINIBAND',
	248:'LINKTYPE_SCTP',
	249:'LINKTYPE_USBPCAP',
	250:'LINKTYPE_RTAC_SERIAL',
	251:'LINKTYPE_BLUETOOTH_LE_LL',
	253:'LINKTYPE_NETLINK',
	254:'LINKTYPE_BLUETOOTH_LINUX_MONITOR',
	255:'LINKTYPE_BLUETOOTH_BREDR_BB',
	256:'LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR',
	257:'LINKTYPE_PROFIBUS_DL',
	258:'LINKTYPE_PKTAP',
	259:'LINKTYPE_EPON',
	260:'LINKTYPE_IPMI_HPM_2',
	261:'LINKTYPE_ZWAVE_R1_R2',
	262:'LINKTYPE_ZWAVE_R3',
	263:'LINKTYPE_WATTSTOPPER_DLM',
	264:'LINKTYPE_ISO_14443',
	265:'LINKTYPE_RDS',
	266:'LINKTYPE_USB_DARWIN',
	268:'LINKTYPE_SDLC'
}
types_proto_upper_eth = { 0x86dd: 'IPv6',
    0x800: "IPv4",
    0x806: "ARP"
}
types_proto_upper_ip = {0:'IP',
1:'ICMP',
2:'IGMP',
3:'GGP',
4:'IP-ENCAP',
5:'ST2',
6:'TCP',
7:'CBT',
8:'EGP',
9:'IGP',
10:'BBN-RCC-MON',
11:'NVP-II',
12:'PUP',
13:'ARGUS',
14:'EMCON',
15:'XNET',
16:'CHAOS',
17:'UDP',
18:'MUX',
19:'DCN-MEAS',
20:'HMP',
21:'PRM',
22:'XNS-IDP',
23:'TRUNK-1',
24:'TRUNK-2',
25:'LEAF-1',
26:'LEAF-2',
27:'RDP',
28:'IRTP',
29:'ISO-TP4',
30:'NETBLT',
31:'MFE-NSP',
32:'MERIT-INP',
33:'SEP',
34:'3PC',
35:'IDPR',
36:'XTP',
37:'DDP',
38:'IDPR-CMTP',
39:'TP++',
40:'IL',
41:'IPV6',
42:'SDRP',
43:'IPV6-ROUTE',
44:'IPV6-FRAG',
45:'IDRP',
46:'RSVP',
47:'GRE',
48:'MHRP',
49:'BNA',
50:'ESP',
51:'AH',
52:'I-NLSP',
53:'SWIPE',
54:'NARP',
55:'MOBILE',
56:'TLSP',
57:'SKIP',
58:'IPV6-ICMP',
59:'IPV6-NONXT',
60:'IPV6-OPTS',
62:'CFTP',
64:'SAT-EXPAK',
65:'KRYPTOLAN',
66:'RVD',
67:'IPPC',
69:'SAT-MON',
70:'VISA',
71:'IPCV',
72:'CPNX',
73:'CPHB',
74:'WSN',
75:'PVP',
76:'BR-SAT-MON',
77:'SUN-ND',
78:'WB-MON',
79:'WB-EXPAK',
80:'ISO-IP',
81:'VMTP',
82:'SECURE-VMTP',
83:'VINES',
84:'TTP',
85:'NSFNET-IGP',
86:'DGP',
87:'TCF',
88:'EIGRP',
89:'OSPFIGP',
90:'Sprite-RPC',
91:'LARP',
92:'MTP',
93:'AX.25',
94:'IPIP',
95:'MICP',
96:'SCC-SP',
97:'ETHERIP',
98:'ENCAP',
100:'GMTP',
101:'IFMP',
102:'PNNI',
103:'PIM',
104:'ARIS',
105:'SCPS',
106:'QNX',
107:'A/N',
108:'IPComp',
109:'SNP',
110:'Compaq-Peer',
111:'IPX-in-IP',
112:'VRRP',
113:'PGM',
115:'L2TP',
116:'DDX',
117:'IATP',
118:'ST',
119:'SRP',
120:'UTI',
121:'SMP',
122:'SM',
123:'PTP',
124:'ISIS',
125:'FIRE',
126:'CRTP',
127:'CRUDP',
128:'SSCOPMCE',
129:'IPLT',
130:'SPS',
131:'PIPE',
132:'SCTP',
133:'FC',
254:'DIVERT'
}