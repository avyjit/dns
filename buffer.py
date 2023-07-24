import struct
from dataclasses import dataclass

DNS_QNAME_MAX_JUMPS = 5
DNS_POINTER_MASK = 0xC0
DNS_POINTER_OFFSET_MASK = 0x3FFF
DNS_MAX_NAME_LENGTH = 255

@dataclass
class Buffer:
    buf: bytes = b""
    offset: int = 0

    def unpack(self, fmt):
        values = struct.unpack_from(fmt, self.buf, self.offset)
        self.offset += struct.calcsize(fmt)
        return values

    def peek(self, fmt):
        return struct.unpack_from(fmt, self.buf, self.offset)

    def seek(self, offset):
        self.offset = offset

    def get(self, pos):
        return self.buf[pos]

    def get_range(self, start: int, length: int):
        end = start + length
        assert end <= len(self), "Buffer out of range"
        assert end <= 512, "Packet length exceeds 512 bytes"

        return self.buf[start:end]

    def pos(self):
        return self.offset

    def __len__(self):
        return len(self.buf)

    def read_qname(self):
        qname = ""

        pos = self.pos()
        jumped = False
        max_jumps = 5
        jumps_performed = 0

        delim = ""
        while True:
            assert jumps_performed < max_jumps, "Too many jumps in DNS name"
            length = self.get(pos)

            if length & DNS_POINTER_MASK == DNS_POINTER_MASK:

                if not jumped:
                    self.seek(pos + 2)

                b2 = self.get(pos + 1)
                offset = ((length ^ DNS_POINTER_MASK) << 8) | b2
                pos = offset
                jumped = True
                jumps_performed += 1

                continue
            else:
                pos += 1
                if length == 0:
                    break

                qname += delim
                qname += self.get_range(pos, length).decode("utf-8")
                delim = "."
                pos += length
        
        if not jumped:
            # try off by one also
            self.seek(pos)
        
        return qname


    def write_byte(self, byte: int):
        self.buf += struct.pack("!B", byte)

    def write(self, fmt: str, *vals):
        self.buf += struct.pack(fmt, *vals)

    def write_qname(self, qname: str):
        if qname is None:
            qname = ""

        for label in qname.split("."):
            length = len(label)
            assert length <= 63, "Label exceeds 63 characters"

            self.write("!B", length)
            raw_bytes = label.encode("utf-8")
            self.buf += raw_bytes

        self.write("!B", 0)
