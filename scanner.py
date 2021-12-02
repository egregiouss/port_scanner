import argparse
import socket
import struct
import time
from multiprocessing.dummy import Pool
from random import randint

from scapy.config import conf
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr, sr1
from scapy.supersocket import L3RawSocket
from scapy.volatile import RandShort

ID = randint(1, 65535)
DNS_PACK = struct.pack("!HHHHHH", ID, 256, 1, 0, 0, 0) + b"\x06google\x03com\x00\x00\x01\x00\x01"
UDP_PACKS = {
    'HTTP': b'GET / HTTP/1.1',
    "DNS": DNS_PACK,
    "ECHO": b"ping"
}


def get_input_parameters():
    parser = argparse.ArgumentParser(
        description="TCP/UDP Scanner"
    )
    parser.add_argument("ip_address", type=str, help="ip address")
    parser.add_argument(
        "--timeout",
        type=int,
        default=2,
        help="таймаут ожидания ответа (по умолчанию 2с)",
    )
    parser.add_argument(
        '-v', '--verbose', action="store_true", help="подробный режим"
    )
    parser.add_argument('-g', '--guess', action="store_true")
    parser.add_argument('ports', metavar='PORT', type=str, nargs='+',
                        help='ports....')
    return parser.parse_args()


def scan_tcp(args):
    port, ip, is_verbose, is_guess, timeout = args
    start_time = time.perf_counter()
    conf.L3socket = L3RawSocket
    port = int(port)
    src_port = RandShort()  # Randomize source port numbers
    packet = IP(dst=ip) / TCP(sport=src_port, dport=port, flags='S')

    resp = sr1(packet, timeout=timeout, verbose=0)
    elapsed = ''
    proto = ''
    if is_verbose:
        elapsed = time.perf_counter() - start_time
    if (resp == None):
        pass
    elif resp.haslayer(TCP):
        if (resp.getlayer(TCP).flags == 0x12):  # We got a SYN-ACK
            sr(IP(dst=ip) / TCP(sport=src_port, dport=port, flags='AR'), timeout=1, verbose=0)
            if is_guess:
                proto = resp.sprintf("%TCP.sport%")
                if proto == "domain":
                    proto = "DNS"
                if proto == "echo":
                    proto = "ECHO"
                else:
                    proto = proto.upper()
            print("TCP {} {} {}".format(port, str(round(elapsed * 1000, 3)), proto))


def scan_ports(ip, ports, is_verbose, is_guess, timeout):
    pool_tcp = Pool(256)
    udp_ports = []
    pool_udp = Pool(256)
    tcp_ports = []
    for port in ports['udp']:
        udp_ports.append((ip, port, is_guess, timeout))
    pool_udp.map(scan_udp, udp_ports)
    for port in ports['tcp']:
        tcp_ports.append((port, ip, is_verbose, is_guess, timeout))
    pool_tcp.map(scan_tcp, tcp_ports)


def parse_args(args):
    ip = args.ip_address
    ports = {'udp': set(), 'tcp': set()}
    for port_info in args.ports:
        proto = port_info[:3]
        for i in port_info[4:].split(','):
            if "-" in i:
                start = int(i.split("-")[0])
                end = int(i.split("-")[1])
                ports[proto].update(range(start, end + 1))
            else:
                ports[proto].update([i])
    return ports, ip, args.timeout, args.verbose, args.guess


def scan_udp(args):
    ip, port, is_guess, timeout = args
    proto = ''
    sock = socket.socket(
        socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    for i in UDP_PACKS:
        try:
            address = (ip, int(port))
            sock.sendto(UDP_PACKS[i], address)
            data, _ = sock.recvfrom(1024)
            if is_guess:
                proto = check_pack(data, ID, UDP_PACKS[i])
            if data:
                if proto is None:
                    proto = '-'
                else:
                    print("UDP", port, proto)
                    break
        except socket.timeout as error:
            pass
    sock.close()


def check_pack(pack, pack_id, was_send):
    if pack[:4].startswith(b"HTTP"):
        return "HTTP"
    elif struct.pack("!H", pack_id) in pack:
        return "DNS"
    elif was_send == pack:
        return "ECHO"
    else:
        return None


def main():
    args = get_input_parameters()
    ports, ip, timeout, is_verbose, is_guess = parse_args(args)
    scan_ports(ip, ports, is_verbose, is_guess, timeout)


if __name__ == '__main__':
    main()
