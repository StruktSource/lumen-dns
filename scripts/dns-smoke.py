#!/usr/bin/env python3
"""Send one bounded DNS query over UDP or TCP and require a valid response."""
import argparse
import secrets
import socket
import struct
import time


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


def exchange(args, packet):
    sock_type = socket.SOCK_DGRAM if args.protocol == 'udp' else socket.SOCK_STREAM
    addresses = socket.getaddrinfo(args.host, args.port, type=sock_type)
    if not addresses:
        raise RuntimeError('DNS target has no address')
    family, kind, proto, _, address = addresses[0]
    with socket.socket(family, kind, proto) as client:
        client.settimeout(args.timeout)
        if args.protocol == 'udp':
            client.sendto(packet, address)
            response, _ = client.recvfrom(4096)
            return response
        client.connect(address)
        client.sendall(struct.pack('!H', len(packet)) + packet)
        size = struct.unpack('!H', receive_exact(client, 2))[0]
        if size > 4096:
            raise RuntimeError('DNS TCP response is too large')
        return receive_exact(client, size)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True)
    parser.add_argument('--port', type=int, default=53)
    parser.add_argument('--protocol', choices=['udp', 'tcp'], required=True)
    parser.add_argument('--name', default='health.lumen.invalid')
    parser.add_argument('--attempts', type=int, default=5, help='tries before failing; UDP and fresh pod networking can drop the first packet')
    parser.add_argument('--timeout', type=float, default=3.0, help='seconds per attempt')
    args = parser.parse_args()
    last_error = None
    for attempt in range(1, max(args.attempts, 1) + 1):
        identifier = secrets.randbelow(65536)
        try:
            response = exchange(args, query(args.name, identifier))
        except (OSError, RuntimeError) as error:  # timeouts and resets are OSError
            last_error = error
            print(f'attempt {attempt}/{args.attempts} failed: {error}', flush=True)
            time.sleep(1)
            continue
        if len(response) < 12 or struct.unpack('!H', response[:2])[0] != identifier or response[2] & 0x80 == 0:
            raise RuntimeError('invalid DNS response')
        print(f'{args.protocol.upper()} DNS response OK ({len(response)} bytes)')
        return
    raise SystemExit(f'DNS {args.protocol.upper()} check failed after {args.attempts} attempts: {last_error}')


if __name__ == '__main__':
    main()
