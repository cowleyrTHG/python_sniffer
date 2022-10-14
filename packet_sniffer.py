from scapy.all import wrpcap, sniff

if __name__ == "__main__":
    a = sniff(count=1000, iface="en0")
    a[0].show()
    a.summary()
    wrpcap("test.pcap", a)
    

