import pickle
import socket
import sys


class HTTP_response:
    accept = False
    status = 0
    message = ""


class HTTP_request:

    def __init__(self, address, method, directory, filename, message, destination):
        self.address = address
        self.method = method
        self.directory = directory
        self.filename = filename
        self.message = message
        self.destination = destination
        self.request()

    def request(self):
        con = Connection(self.address)
        con.recv_pkt()
        res = from_bytes(con.received_pkts.pop())
        if res.accept:
            if self.method == "POST":
                lines = []
                with open(self.directory + "/" + self.filename, 'r') as f:
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
                con.recv_pkt()
                stat = from_bytes(con.received_pkts.pop())
                if stat.status == 200:
                    print("Status 200 OK")
                else:
                    print("Status 404 NOT FOUND")
                con.recv_pkt()
            else:
                con.send_pkt(to_bytes(self))
                con.recv_pkt()
                stat = from_bytes(con.received_pkts.pop())
                if stat.status == 200:
                    print("Status 200 OK")
                    con.recv_pkts()
                    with open(self.directory + "/" + self.filename, 'a') as f:
                        for line in con.received_pkts:
                            f.write(line+"\n")

                else:
                    print("Status 404 NOT FOUND")
                con.close()
        else:
            print("Connection Not Accepted")


class Connection:
    received_pkts = []
    send = True
    receive = True

    def __init__(self, address):
        self.received_pkts = []
        self.address = address
        self.seq_num = 0
        self.ack_num = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(1)  # set timeout to 1 second
        self._connect()

    def _connect(self):
        # send SYN packet
        syn_pkt = Packet(self.seq_num, self.ack_num, 'Syn Pckt', 0b10000000)
        self.sock.sendto(to_bytes(syn_pkt), self.address)
        while True:
            synack_packet, address = self.sock.recvfrom(1024)
            synack_packet = from_bytes(synack_packet)
            if not synack_packet.is_corrupt():
                if synack_packet.flags & 0xC0 == 0b11000000:
                    print(synack_packet.data)
                    ack_packet = Packet(0, 0, 'Ack Pckt', 0b01000000)
                    self.sock.sendto(to_bytes(ack_packet), self.address)
                    break
                else:
                    raise Exception("Wrong connection")
            else:
                raise Exception("Wrong connection")

    def send_pkt(self, data):
        if self.send:
            self.sock.settimeout(1)
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
            self.sock.settimeout(3)
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
            self.sock.settimeout(3)
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
        self.sock.settimeout(3)
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
            try:
                self.sock.close()
            except Exception as e:
                pass
            print("Connection closed")

    def pack_crrpt(self, packet):
        packet.checksum += 3
        packet.checksum = (packet.checksum & 0xffff) + (packet.checksum >> 16)

    def lose_one_ack(self, data):
        if self.send:
            self.sock.settimeout(1)
            packet = Packet(self.seq_num, self.ack_num, data, 0)
            passes = 0
            while True:
                try:
                    self.sock.sendto(to_bytes(packet), self.address)
                    if passes == 0:
                        _, _ = self.sock.recvfrom(1024)
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

    def crrpt_one_pack(self):
        if self.receive:
            self.sock.settimeout(1.5)
            passes = 0
            while True:
                packet, address = self.sock.recvfrom(1024)
                packet = from_bytes(packet)
                if passes == 0:
                    self.pack_crrpt(packet)
                    passes += 1
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

    def lose_first_pack(self):
        if self.receive:
            self.sock.settimeout(1.5)
            while True:
                _, _ = self.sock.recvfrom(1024)
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


HTTP_request(('localhost', 8000), "GET", "src", "alice.txt", "", "dest")
