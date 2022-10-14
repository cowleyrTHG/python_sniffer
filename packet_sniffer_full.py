import sys
import binascii
import socket

socket.socket()

# Taken from https://www.codeproject.com/Tips/612847/Generate-a-quick-and-easy-custom-pcap-file-using-P

#Custom "Hello World!"" Packet
message =  ('48 65 6C 6C 6F' #Hello
            '20 57 6F 72 6C 64 21') # World!

#Global header for pcap 2.4
pcap_global_header =   ('D4 C3 B2 A1'   
                        '02 00'         #File format major revision (i.e. pcap <2>.4)  
                        '04 00'         #File format minor revision (i.e. pcap 2.<4>)   
                        '00 00 00 00'     
                        '00 00 00 00'     
                        'FF FF 00 00'     
                        '01 00 00 00')

# pcap packet header that must preface every packet
# Gives some metadata about the packet
pcap_packet_header =   ('CA FE BA BE'   #Epoch time in seconds
                        '01 00 00 00'   #Milliseconds
                        'XX XX XX XX'   #Frame Size (little endian) 
                        'YY YY YY YY')  #Frame Size (little endian)

eth_header =   ('00 00 00 00 00 00'     #Source Mac    
                '00 00 00 00 00 00'     #Dest Mac  
                '08 00')                #Protocol (0x0800 = IP)

ip_header =    ('45'                    #IP version and header length (multiples of 4 bytes)   
                '00'                      
                'XX XX'                 #Length - will be calculated and replaced later
                '00 00'                 #ID number
                '40'                    #Flags
                '00'                    #Fragment offset
                '40'                    #TTL
                '11'                    #Protocol (0x11 = UDP)
                'YY YY'                 #Checksum - will be calculated and replaced later
                '7F 00 00 01'           #Source IP (Default: 127.0.0.1)         
                '7F 00 00 01')          #Dest IP (Default: 127.0.0.1) 

udp_header =   ('80 01'                 #Dest Port 32769
                '00 15'                 #Source Port 21
                'YY YY'                 #Length - will be calculated and replaced later        
                '00 00')
                
def getByteLength(str1):
    # Return the length of the hex string in bytes
    return int(len(''.join(str1.split())) / 2)

def writeByteStringToFile(bytestring, filename):
    bytelist = bytestring.split()  
    bytes = binascii.a2b_hex(''.join(bytelist))
    bitout = open(filename, 'wb')
    bitout.write(bytes)

def generatePCAP(message, pcapfile): 

    udp_len = getByteLength(message) + getByteLength(udp_header)
    udp = udp_header.replace('YY YY',"%04x"%udp_len)

    ip_len = udp_len + getByteLength(ip_header)
    ip = ip_header.replace('XX XX',"%04x"%ip_len)
    checksum = ip_checksum(ip.replace('YY YY', '00 00'))
    ip = ip.replace('YY YY',"%04x"%checksum)
    
    pcap_len = ip_len + getByteLength(eth_header)
    hex_str = "%08x"%pcap_len
    reverse_hex_str = hex_str[6:] + hex_str[4:6] + hex_str[2:4] + hex_str[:2]
    pcaph = pcap_packet_header.replace('XX XX XX XX',reverse_hex_str)
    pcaph = pcaph.replace('YY YY YY YY',reverse_hex_str)

    bytestring = pcap_global_header + pcaph + eth_header + ip + udp + message
    writeByteStringToFile(bytestring, pcapfile)

#Splits the string into a list of tokens every n characters
def splitN(str1,n):
    return [str1[start:start+n] for start in range(0, len(str1), n)]

#Calculates and returns the IP checksum based on the given IP Header
def ip_checksum(iph):

    #split into bytes    
    words = splitN(''.join(iph.split()),4)

    csum = 0;
    for word in words:
        csum += int(word, base=16)

    csum += (csum >> 16)
    csum = csum & 0xFFFF ^ 0xFFFF

    return csum



if __name__ == "__main__":

    if len(sys.argv) > 2:
            print('usage: pcapgen.py output_file')
            exit(0)

    if sys.argv[1]:
        generatePCAP(message, sys.argv[1])
    else:
        print("Please specify an output file.")
        exit(0)
