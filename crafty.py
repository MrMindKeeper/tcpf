import socket
import argparse
import struct
import binascii

# Ethernet Header
argParser = argparse.ArgumentParser(description='Packet header details. This tool only support IPv4 at the moment.')
argParser.add_argument('-smac','--smac',metavar="Source_MAC_Address",type=str, help="Source MAC Address")
argParser.add_argument('-dmac','--dmac',metavar="Destination_MAC_Address",type=str, help="Destination MAC Address")
argParser.add_argument('-ipv','--ipv',metavar="Internet_Protocol_Version",type=str, help="Internet Protocol Version")

# IP Header
argParser.add_argument('-ver','--ver',metavar="Version",type=str, help="Version")
argParser.add_argument('-ihl','--ihl',metavar="Header_Length",type=str, help="Header Length")
argParser.add_argument('-tos','--tos',metavar="Type_of_Service",type=str, help="Type of Service")
argParser.add_argument('-tl','--tl',metavar="Total_Length",type=str, help="Total Length")
argParser.add_argument('-id','--id',metavar="Identification",type=str, help="Identification")
argParser.add_argument('-flag','--flag',metavar="IP_Header_FLags",type=str, help="IP Header Flags")
argParser.add_argument('-fo','--fo',metavar="Fragment_Offset",type=str, help="Fragment Offset")
argParser.add_argument('-ttl','--ttl',metavar="Time_To_Live",type=str, help="Time To Live")
argParser.add_argument('-protocol','--protocol',metavar="Protocol_code_in_decimal",type=str, help="Protocol code in decimal")
argParser.add_argument('-hc','--hc',metavar="IP_Header_Checksum",type=str, help="IP Header Checksum")
argParser.add_argument('-s','--s',metavar="Source_IP_Address",type=str, help="Source IP Address")
argParser.add_argument('-d','--d',metavar="Destination_IP_Address",type=str, help="Destination IP Address")

# IP Protocol Header
argParser.add_argument('-sp','--sp',metavar="Source_Port",type=str, help="Source Port")
argParser.add_argument('-dp','--dp',metavar="Destination_Port",type=str, help="Destination Port")
argParser.add_argument('-l','--l',metavar="Length",type=str, help="Protocol header length+Data")
argParser.add_argument('-ch','--ch',metavar="Checksum",type=str, help="Checksum")
argParser.add_argument('-data','--data',metavar="Data",type=str, help="Data")

# Others
argParser.add_argument('-v','--v', action="store_true",help="Verbose, print everything")
args = argParser.parse_args()

def argHandler(args, protocol):
    pEthernetSrc = ""
    pEthernetDst = ""
    pEthernetIPv = ""

    if(args.smac == None):
        pEthernetSrc = "00:00:00:00:00:00"
    elif(len(args.smac) != 17):
        print("[-] Source MAC address is not valid")
        return -1
    else:
        pEthernetSrc = args.smac

    if(args.dmac == None):
        pEthernetDst = "00:00:00:00:00:00"
    elif(len(args.dmac) != 17):
        print("[-] Destination MAC address is not valid")
        return -1
    else:
        pEthernetDst = args.dmac

    if(args.ipv == None):
        pEthernetIPv = "4"
    elif(len(args.ipv) != 1):
        print("[-] Internet Protocol Version is not valid")
        return -1
    else:
        pEthernetIPv = args.ipv
        
    EthernetHeader = parseEthernetHeader([pEthernetSrc, pEthernetDst, pEthernetIPv])
    IPHeader = parseIPHeader(args, protocol)
    protocolHeader = parseProtocolHeader(args)
    craftPacket(EthernetHeader, IPHeader, protocolHeader)

def parseEthernetHeader(ethernet):
    sourceMac = ""

    macChars = ethernet[0].replace(":", "")
    smacChars = bytes.fromhex(macChars)
    
    macChars = ethernet[1].replace(":", "")
    dmacChars = bytes.fromhex(macChars)
    
    IPversion = ""
    if(ethernet[2] == "4"):
        IPversion = b"\x08\x00"

    return [smacChars, dmacChars, IPversion]

def parseIPHeader(args, protocol):
    #--ver --ihl --tos --tl
    ipVersion = '4';
    if(args.ver == None):
        ipVersion = '4'
    elif(len(args.ver) == 1):
        ipVersion = args.ver

    ipHeaderLen = '5'
    if(args.ihl == None):
        ipHeaderLen = '5'
    elif(len(args.ihl) == 1):
        ipHeaderLen = args.ihl
    else:
        print("[-] Invalid IHL entered")
        return -1

    IPvIHL = ipVersion+ipHeaderLen

    ipHeaderTos = '00'
    if(args.tos == None):
        ipHeaderTos = '00'
    elif(int(args.tos) <= 4095):
        ipHeaderTos = hex(int(args.tos))
        ipHeaderTos = ipHeaderTos[2:]
        if(len(ipHeaderTos) == 1):
            ipHeaderTos = "0"+ipHeaderTos
    else:
        print('[-] Invalid TOS entered')
        return -1

    ipHeaderTL = "0021"
    if(args.tl == None):
        if(protocol == "UDP"):
            ipHeaderTL = "0021"
    elif(len(args.tl)>5):
        print("[-] Invalid Total Length entered")
        return -1
    elif(int(args.tl) > 65535):
        print("[-] Invalid Total Length entered")
        return -1
    else:
        ipHeaderTL = hex(int(args.tl))
        ipHeaderTL = ipHeaderTL[2:]
        if(len(ipHeaderTL) != 4):
            for i in range(1, 4):
                ipHeaderTL = "0"+ipHeaderTL
                if(len(ipHeaderTL) != 4):
                    continue
                else:
                    break;


    #IPvIHL + ipHeaderTos + ipHeaderTL
    
    
    # --id --flag --fo
    # IP Header Identification Handler
    ipHeaderId = "abcd"
    if(args.id == None):
        ipHeaderId = "abcd"
    elif(int(args.id) > int(65535)):
        print("[-] Invalid IP Header ID")
        return -1
    elif(len(args.id) > 5):
        print("[-] Invalid IP Header ID")
        return -1
    else:
        ipHeaderId = hex(int(args.id))
        ipHeaderId = ipHeaderId[2:]
        if(len(ipHeaderId) != 4):
            for i in range(1, 4):
                ipHeaderId = "0"+ipHeaderId
                if(len(ipHeaderId) != 4):
                    continue
                else:
                    break;

    # IP Header Flags handler
    ipHeaderFlag = "0"
    if(args.flag == None):
        ipHeaderFlag = "0"
    elif(len(args.flag) != 1):
        print("[-] Invalid IP Header Flag")
        return -1
    elif(int(args.flag) > 8):
        print("[-] Invalid IP Header Flag")
        return -1
    else:
        ipHeaderFlag = hex(int(args.flag))
        ipHeaderFlag = ipHeaderFlag[2:]
    
    #IP Header Fragment Offset Handler
    ipHeaderOffset = "000"
    if(args.fo == None):
        ipHeaderOffset = "000"
    elif(len(args.fo) > 4):
        print("[-] Invalid Header Fragment Offset")
        return -1
    elif(int(args.fo) > 4095):
        print("[-] Invalid Header Fragment Offset")
        return -1
    else:
        ipHeaderOffset = hex(int(args.fo))
        ipHeaderOffset = ipHeaderOffset[2:]
        if(len(ipHeaderOffset) != 3):
            for i in range(1, 3):
                ipHeaderOffset = "0"+ipHeaderOffset
                if(len(ipHeaderOffset) != 3):
                    continue
                else:
                    break;
    #IPvIHL + ipHeaderTos + ipHeaderTL + ipHeaderId + ipHeaderFlag + ipHeaderOffset
    # ttl, protocol, hc
    # TTL 1 byte
    # Header TTL Handler
    ipHeaderTTL = "40"
    if(args.ttl== None):
        ipHeaderTTL = "40"
    elif(len(args.ttl) > 3):
        print("[-] Invalid Time To Live")
        return -1
    elif(int(args.ttl) > 255):
        print("[-] Invalid Time To Live")
        return -1
    else:
        ipHeaderTTL = hex(int(args.ttl))
        ipHeaderTTL = ipHeaderTTL[2:]
        if(len(ipHeaderTTL) != 2):
            for i in range(1, 2):
                ipHeaderTTL = "0"+ipHeaderTTL
                if(len(ipHeaderTTL) != 2):
                    continue
                else:
                    break;

    # IP Header protocol Handler
    ipHeaderProtocol = "11"
    if(args.protocol == None):
        ipHeaderProtocol = "11"
        protocol = "UDP"
    elif(len(args.protocol) > 2):
        print("[-] Invalid Protocol")
        return -1
    elif(int(args.protocol) > 255):
        print("[-] Invalid Protocol")
        return -1
    else:
        ipHeaderProtocol = hex(int(args.protocol))
        ipHeaderProtocol = ipHeaderProtocol[2:]
        if(len(ipHeaderProtocol) != 2):
            for i in range(1, 2):
                ipHeaderProtocol = "0"+ipHeaderProtocol
                if(len(ipHeaderProtocol) != 2):
                    continue
                else:
                    break;

    # IP Header Checksum Handler
    ipHeaderChecksum = "a6ec"
    if(args.hc == None):
        ipHeaderChecksum = "a6ec"
    elif(len(args.hc) > 5):
        print("[-] Invalid header checksum")
        return -1
    elif(int(args.hc) > 65535):
        print("[-] Invalid header checksum")
        return -1
    else:
        ipHeaderChecksum = hex(int(args.hc))
        ipHeaderChecksum = ipHeaderChecksum[2:]
        if(len(ipHeaderChecksum) != 4):
            for i in range(1, 4):
                ipHeaderChecksum = "0"+ipHeaderChecksum
                if(len(ipHeaderCheckum) != 4):
                    continue
                else:
                    break;


    # -s -d
    # IP Header Source IP address Handler
    ipHeaderSource = "127.0.0.1"
    if(args.s == None):
        ipHeaderSource = "127.0.0.1"
    elif(len(args.s) > 15):
        print("[-] Invalid IP Address")
        return -1
    else:
        ipHeaderSource = str(args.s)
   
    ipHeaderSourceIP = ""
    inByte = ""
    if("." in ipHeaderSource):
        sourceParts = ipHeaderSource.split(".")
        for part in sourceParts:
            ipByte = hex(int(part))
            ipByte = ipByte[2:]
            if(len(ipByte) != 2):
                for i in range(1, 2):
                    ipByte = "0"+ipByte
                    if(len(ipByte) != 2):
                        continue
                    else:
                        ipHeaderSourceIP = ipHeaderSourceIP+ipByte
                        break
            else:
                ipHeaderSourceIP = ipHeaderSourceIP+ipByte
    

    # IP Header Destination IP address Handler
    ipHeaderDestination = "127.0.0.1"
    if(args.d == None):
        ipHeaderDestination = "127.0.0.1"
    elif(len(args.d) > 15):
        print("[-] Invalid IP Address")
        return -1
    else:
        ipHeaderDestination = str(args.d)
   
    ipHeaderDestinationIP = ""
    inByte = ""
    if("." in ipHeaderDestination):
        destinationParts = ipHeaderDestination.split(".")
        for part in destinationParts:
            ipByte = hex(int(part))
            ipByte = ipByte[2:]
            if(len(ipByte) != 2):
                for i in range(1, 2):
                    ipByte = "0"+ipByte
                    if(len(ipByte) != 2):
                        continue
                    else:
                        ipHeaderDestinationIP = ipHeaderDestinationIP+ipByte
                        break
            else:
                ipHeaderDestinationIP = ipHeaderDestinationIP+ipByte
    
    ipHeader = bytes.fromhex(IPvIHL+ipHeaderTos+ipHeaderTL+ipHeaderId+ipHeaderFlag+ipHeaderOffset+ipHeaderTTL+ipHeaderProtocol+ipHeaderChecksum+ipHeaderSourceIP+ipHeaderDestinationIP)
    return ipHeader

def parseProtocolHeader(args):
    sourcePort = "0050"
    # --sp --dp --l --ch --data
    
    # Source Port Handler
    if(args.sp == None):
        sourcePort="0050"
    elif(len(args.sp) > 5):
        print("[-] Invalid source port")
        return -1
    elif(int(args.sp) > 65535):
        print("[-] Invalid source port")
        return -1
    else:
        sourcePort = hex(int(args.sp))
        sourcePort = sourcePort[2:]
        if(len(sourcePort) != 4):
            for i in range(1, 4):
                sourcePort = "0"+sourcePort
                if(len(sourcePort) != 4):
                    continue
                else:
                    break;

    # Destination Port Handler
    destinationPort = "0050"
    if(args.dp == None):
        destinationPort="0050"
    elif(len(args.dp) > 5):
        print("[-] Invalid destination port")
        return -1
    elif(int(args.dp) > 65535):
        print("[-] Invalid destination port")
        return -1
    else:
        destinationPort = hex(int(args.dp))
        destinationPort = destinationPort[2:]
        if(len(destinationPort) != 4):
            for i in range(1, 4):
                destinationPort = "0"+destinationPort
                if(len(destinationPort) != 4):
                    continue
                else:
                    break;

    # Protocol Header Length
    protocolHeaderLength = "000d"
    if(args.l == None):
        protocolHeaderLength="000d"
    elif(len(args.l) > 5):
        print("[-] Invalid Length")
        return -1
    elif(int(args.l) > 65535):
        print("[-] Invalid Length")
        return -1
    else:
        protocolHeaderLength = hex(int(args.l))
        protocolHeaderLength = protocolHeaderLength[2:]
        if(len(protocolHeaderLength) != 4):
            for i in range(1, 4):
                protocolHeaderLength = "0"+protocolHeaderLength
                if(len(protocolHeaderLength) != 4):
                    continue
                else:
                    break;
    

    # Protocol Header Checksum
    protocolHeaderChecksum = "0000"
    if(args.ch == None):
        protocolHeaderChecksum="0000"
    elif(len(args.ch) > 5):
        print("[-] Invalid Header Checksum")
        return -1
    elif(int(args.ch) > 65535):
        print("[-] Invalid Header Checksum")
        return -1
    else:
        protocolHeaderChecksum = hex(int(args.ch))
        protocolHeaderChecksum = protocolHeaderChecksum[2:]
        if(len(protocolHeaderChecksum) != 4):
            for i in range(1, 4):
                protocolHeaderChecksum = "0"+protocolHeaderChecksum
                if(len(protocolHeaderChecksum) != 4):
                    continue
                else:
                    break;
    
    data = "48656c6c6f"
    if(args.data == None):
        data = data
    else:
        data = args.data
        data = data.encode('utf-8').hex()
    protocolHeader = bytes.fromhex(sourcePort+destinationPort+protocolHeaderLength+protocolHeaderChecksum+data)
    print(protocolHeader)
    return protocolHeader

def craftPacket(EthernetHeader, IPHeader, ProtocolHeader):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind(("eth0", 0))
     
    ethernet = b''
    for p in EthernetHeader:
        ethernet = ethernet+p

    if(args.v):
        print('\t Ethernet Header: '+str(ethernet))
        print('\t IP Header      : '+str(IPHeader))
        print('\t Protocol Header: '+str(ProtocolHeader))
    
    packet = ethernet + IPHeader + ProtocolHeader
    s.send(packet)


protocol = "UDP"
argHandler(args, protocol)
