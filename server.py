import pickle
import socket
import os
import sys


class HTTP_response:
    accept = False
    status = 0
    message = ""

    def __init__(self, port):
        con = Connection()
        con.connect(port)
        self.accept = True
        con.send_pkt(to_bytes(self))
        con.recv_pkt()
        req = from_bytes(con.received_pkts.pop())
        if req.method == "POST":
            con.received_pkts.append(req.message)
            con.recv_pkts()
            if os.path.isdir(req.destination):
                self.status = 200
                con.send_pkt(to_bytes(self))
                con.close()
                with open(req.destination + "/" + req.filename, 'a') as f:
                    for line in con.received_pkts:
                        f.write(line + "\n")
            else:
                self.status = 404
                con.send_pkt(to_bytes(self))
        else:
            if os.path.exists(req.destination + "/" + req.filename):
                self.status = 200
                lines = []
                with open(req.destination + "/" + req.filename, 'r') as f:
                    for line in f:
                        lines.append(line)
                i = 0
                while i < len(lines) and sys.getsizeof(self.message + lines[i]) < 750:
                    self.message += lines[i]
                    i += 1
                con.send_pkt(to_bytes(self))
                lines = lines[i:]
                result = combine_strings(lines)
                con.send_file(result)
                con.close()
            else:
                self.status = 404
                con.send_pkt(to_bytes(self))
                con.recv_pkt()
                con.close()


class HTTP_request:

    def __init__(self, address, method, directory, filename, message, destination):
        self.address = address
        self.method = method
        self.directory = directory
        self.filename = filename
        self.message = message
        self.destination = destination


class Connection:
    received_pkts = []
    address = 0
    send = True
    receive = True

    def __init__(self):
        self.received_pkts = []
        self.seq_num = 0
        self.ack_num = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        #self.sock.settimeout(1)  # set timeout to 1 second

    def connect(self, port):
        server_address = ('localhost', port)
        self.sock.bind(server_address)
        while True:
            syn_packet, address = self.sock.recvfrom(1024)
            syn_packet = from_bytes(syn_packet)
            self.address = address
            if not syn_packet.is_corrupt():
                if syn_packet.flags & 0xC0 == 0b10000000:
                    self.sock.settimeout(1)
                    print(syn_packet.data)
                    synack_packet = Packet(0, 0, 'SYNACK Pckt', 0b11000000)
                    passes = 0
                    while passes < 3:
                        try:
                            self.sock.sendto(to_bytes(synack_packet), self.address)
                            ack_packet, address = self.sock.recvfrom(1024)
                            ack_packet = from_bytes(ack_packet)
                            if not ack_packet.is_corrupt():
                                if ack_packet.flags & 0xC0 == 0b01000000:
                                    print(ack_packet.data)
                                    break
                                else:
                                    raise Exception("Wrong connection")
                            else:
                                raise Exception("Wrong connection")
                        except socket.timeout:
                            passes += 1
                            pass
                    break
                else:
                    raise Exception("Wrong connection")
            else:
                raise Exception("Wrong connection")

    def send_pkt(self, data):
        if self.send:
            packet = Packet(self.seq_num, self.ack_num, data, 0)
            passes = 0
            while True:
                try:
                    self.sock.sendto(to_bytes(packet), self.address)
                    ack_packet, address = self.sock.recvfrom(1024)
                    ack_packet = from_bytes(ack_packet)
                    print("seq", self.seq_num)
                    if not ack_packet.is_corrupt():
                        if ack_packet.ack_num == (self.seq_num + 1) % 2:
                            self.seq_num += 1
                            self.seq_num %= 2
                            # Acknowledgment received, move on to the next packet
                            break
                        else:
                            pass
                    else:
                        raise Exception("Corrupt Packet")
                except socket.timeout:
                    if passes < 3:
                        passes += 1
                        pass
                    else:
                        raise Exception("No ACK received")

    def recv_pkts(self):
        if self.receive:
            while True:
                packet, address = self.sock.recvfrom(1024)
                packet = from_bytes(packet)
                if not packet.is_corrupt():
                    if packet.seq_num == self.ack_num and packet.flags & 0xE0 == 0b00100000:
                        finack_pkt = Packet(self.seq_num, self.ack_num, '', 0b01100000)
                        self.sock.sendto(to_bytes(finack_pkt), self.address)
                        self.receive = False
                        self.handle_close()
                        break
                    elif packet.seq_num == self.ack_num:
                        self.ack_num += 1
                        self.ack_num = self.ack_num % 2
                        print(self.ack_num)
                        ack_packet = Packet(0, self.ack_num, '', 0b01000000)
                        self.sock.sendto(to_bytes(ack_packet), self.address)
                        self.received_pkts.append(packet.data)
                        pass
                    else:
                        ack_packet = Packet(0, (packet.seq_num + 1) % 2, '', 0b01000000)
                        self.sock.sendto(to_bytes(ack_packet), self.address)

    def recv_pkt(self):
        if self.receive:
            while True:
                packet, address = self.sock.recvfrom(1024)
                packet = from_bytes(packet)
                if not packet.is_corrupt():
                    if packet.seq_num == self.ack_num and packet.flags & 0xE0 == 0b00100000:
                        finack_pkt = Packet(self.seq_num, self.ack_num, '', 0b01100000)
                        self.sock.sendto(to_bytes(finack_pkt), self.address)
                        self.receive = False
                        self.handle_close()
                        break
                    elif packet.seq_num == self.ack_num:
                        self.ack_num += 1
                        self.ack_num = self.ack_num % 2
                        print(self.ack_num)
                        ack_packet = Packet(0, self.ack_num, '', 0b01000000)
                        self.sock.sendto(to_bytes(ack_packet), self.address)
                        self.received_pkts.append(packet.data)
                        break
                    else:
                        ack_packet = Packet(0, (packet.seq_num + 1) % 2, '', 0b01000000)
                        self.sock.sendto(to_bytes(ack_packet), self.address)

    def send_file(self, lines):
        if self.send:
            for line in lines:
                self.send_pkt(line)

    def close(self):
        # send FIN packet
        fin_pkt = Packet(self.seq_num, self.ack_num, '', 0b00100000)
        passes = 0
        while True:
            try:
                self.sock.sendto(to_bytes(fin_pkt), self.address)
                finack_packet, address = self.sock.recvfrom(1024)
                finack_packet = from_bytes(finack_packet)
                if not finack_packet.is_corrupt():
                    if finack_packet.flags & 0xE0 == 0b01100000:
                        # FIN-ACK packet received
                        self.send = False
                        self.handle_close()
                        self.recv_pkts()
                        break
                    else:
                        raise Exception("Wrong connection")
                else:
                    raise Exception("Corrupt Packet")
            except socket.timeout:
                if passes < 3:
                    passes += 1
                    pass
                else:
                    raise Exception("No ACK received")

    def handle_close(self):
        if not self.send and not self.receive:
            self.sock.close()
            print("Connection closed")


class Packet:
    def __init__(self, seq_num, ack_num, data, flags):
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.data = data
        self.flags = flags
        self.len = len(data)
        self.checksum = self.calculate_checksum(data)

    def calculate_checksum(self, data):
        if isinstance(data, str):
            data = data.encode()
        if len(data) % 2 == 1:
            data += b'\x00'  # append null byte to make even length
        checksum = 0
        for i in range(0, len(data), 2):
            chunk = (data[i] << 8) + data[i + 1]
            checksum += chunk
            checksum = (checksum & 0xffff) + (checksum >> 16)
        return ~checksum & 0xffff

    def is_corrupt(self):
        data = self.data
        if isinstance(data, str):
            data = data.encode()
        if len(data) % 2 == 1:
            data += b'\x00'  # append null byte to make even length
        checksum = 0
        for i in range(0, len(data), 2):
            chunk = (data[i] << 8) + data[i + 1]
            checksum += chunk
            checksum = (checksum & 0xffff) + (checksum >> 16)
        checksum = ~checksum & 0xffff
        return not checksum == self.checksum


def to_bytes(obj):
    return pickle.dumps(obj)


def from_bytes(bytes_packet):
    return pickle.loads(bytes_packet)


def combine_strings(strings):
    result = []
    current = ""
    for s in strings:
        if len(current.encode()) + len(s.encode()) > 900:
            result.append(current)
            current = ""
        current += s
    if current:
        result.append(current)
    return result


serve = HTTP_response(8000)
