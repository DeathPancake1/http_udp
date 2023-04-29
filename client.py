import pickle
import socket


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
        self.sock.sendto(syn_pkt.to_bytes(), self.address)
        while True:
            synack_packet, address = self.sock.recvfrom(1024)
            synack_packet = Packet.from_bytes(synack_packet)
            if not synack_packet.is_corrupt():
                if synack_packet.flags & 0xC0 == 0b11000000:
                    print(synack_packet.data)
                    ack_packet = Packet(0, 0, 'Ack Pckt', 0b01000000)
                    self.sock.sendto(ack_packet.to_bytes(), self.address)
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
                    self.sock.sendto(packet.to_bytes(), self.address)
                    ack_packet, address = self.sock.recvfrom(1024)
                    ack_packet = Packet.from_bytes(ack_packet)
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

    def recv_pkt(self):
        if self.receive:
            while True:
                packet, address = self.sock.recvfrom(1024)
                packet = Packet.from_bytes(packet)
                if not packet.is_corrupt():
                    if packet.seq_num == self.ack_num and packet.flags & 0xE0 == 0b00100000:
                        finack_pkt = Packet(self.seq_num, self.ack_num, '', 0b01100000)
                        self.sock.sendto(finack_pkt.to_bytes(), self.address)
                        self.receive = False
                        self.handle_close()
                        break
                    elif packet.seq_num == self.ack_num:
                        self.ack_num += 1
                        self.ack_num = self.ack_num % 2
                        print(self.ack_num)
                        ack_packet = Packet(0, self.ack_num, '', 0b01000000)
                        self.sock.sendto(ack_packet.to_bytes(), self.address)
                        self.received_pkts.append(packet.data)
                        pass
                    else:
                        ack_packet = Packet(0, (packet.seq_num + 1) % 2, '', 0b01000000)
                        self.sock.sendto(ack_packet.to_bytes(), self.address)

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
                self.sock.sendto(fin_pkt.to_bytes(), self.address)
                finack_packet, address = self.sock.recvfrom(1024)
                finack_packet = Packet.from_bytes(finack_packet)
                if not finack_packet.is_corrupt():
                    if finack_packet.flags & 0xE0 == 0b01100000:
                        # FIN-ACK packet received
                        self.send = False
                        self.handle_close()
                        self.recv_pkt()
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


class Packet:
    def __init__(self, seq_num, ack_num, data, flags):
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.data = data
        self.flags = flags
        self.len = len(data)
        self.checksum = self.calculate_checksum(data)

    def calculate_checksum(self, data):
        data = self.data
        if len(data) % 2 == 1:
            data += '\x00'  # append null byte to make even length
        checksum = 0
        for i in range(0, len(data), 2):
            chunk = (ord(data[i]) << 8) + ord(data[i + 1])
            checksum += chunk
            checksum = (checksum & 0xffff) + (checksum >> 16)
        return ~checksum & 0xffff  # 1's complement

    def is_corrupt(self):
        data = self.data
        if len(data) % 2 == 1:
            data += '\x00'  # append null byte to make even length
        checksum = 0
        for i in range(0, len(data), 2):
            chunk = (ord(data[i]) << 8) + ord(data[i + 1])
            checksum += chunk
            checksum = (checksum & 0xffff) + (checksum >> 16)
        checksum = ~checksum & 0xffff
        return not checksum == self.checksum

    def to_bytes(self):
        return pickle.dumps(self)

    @staticmethod
    def from_bytes(bytes_packet):
        return pickle.loads(bytes_packet)


#new_con = Connection(('localhost', 9999))
#new_con.send_pkt("Hello")
#new_con.send_pkt("Hello2")
#new_con.send_pkt("Hello3")
#new_con.close()
new_con = Connection(('localhost', 9999))
new_con.recv_pkt()
new_con.close()
print(new_con.received_pkts)