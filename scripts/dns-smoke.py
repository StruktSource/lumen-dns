#!/usr/bin/env python3
"""Send one bounded DNS query over UDP or TCP and require a valid response."""
import argparse
import secrets
import socket
import struct


def query(name, identifier):
    labels = b''.join(bytes([len(part)]) + part.encode('ascii') for part in name.split('.'))
    return struct.pack('!HHHHHH', identifier, 0x0100, 1, 0, 0, 0) + labels + b'\0\0\1\0\1'


def receive_exact(stream, size):
    data = b''
    while len(data) < size:
        chunk = stream.recv(size - len(data))
        if not chunk:
            raise RuntimeError('DNS TCP response ended early')
        data += chunk
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True)
    parser.add_argument('--port', type=int, default=53)
    parser.add_argument('--protocol', choices=['udp', 'tcp'], required=True)
    parser.add_argument('--name', default='health.lumen.invalid')
    args = parser.parse_args()
    identifier = secrets.randbelow(65536)
    packet = query(args.name, identifier)
    sock_type = socket.SOCK_DGRAM if args.protocol == 'udp' else socket.SOCK_STREAM
    addresses = socket.getaddrinfo(args.host, args.port, type=sock_type)
    if not addresses:
        raise RuntimeError('DNS target has no address')
    family, kind, proto, _, address = addresses[0]
    with socket.socket(family, kind, proto) as client:
        client.settimeout(5)
        if args.protocol == 'udp':
            client.sendto(packet, address)
            response, _ = client.recvfrom(4096)
        else:
            client.connect(address)
            client.sendall(struct.pack('!H', len(packet)) + packet)
            size = struct.unpack('!H', receive_exact(client, 2))[0]
            if size > 4096:
                raise RuntimeError('DNS TCP response is too large')
            response = receive_exact(client, size)
    if len(response) < 12 or struct.unpack('!H', response[:2])[0] != identifier or response[2] & 0x80 == 0:
        raise RuntimeError('invalid DNS response')
    print(f'{args.protocol.upper()} DNS response OK ({len(response)} bytes)')


if __name__ == '__main__':
    main()
