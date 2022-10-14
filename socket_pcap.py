import socket

if __name__ == "__main__":

    ETH_P_ALL = 3
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind(('en0', 0))