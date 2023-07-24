import struct
from dataclasses import dataclass

DNS_QNAME_MAX_JUMPS = 5


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
        num_jumps = 0

        delim = ""

        while True:
            assert (
                num_jumps < DNS_QNAME_MAX_JUMPS
            ), "Too many jumps in DNS qname parsing"

            # Read a single byte indicating length of next segment
            (length,) = self.peek("!B")

            if length & 0xC0 == 0xC0:
                if not jumped:
                    self.seek(self.pos() + 2)

                b2 = self.get(pos + 1)
                pos = ((length ^ 0xC0) << 8) + b2

                jumped = True
                num_jumps += 1

                continue

            else:
                pos += 1

                # The qname is terminated by a zero-length segment
                if length == 0:
                    self.seek(pos)
                    break

                qname += delim
                qname += self.get_range(pos, length).decode("utf-8").lower()

                delim = "."
                pos += length
                self.seek(pos)

            # if not jumped:
            #     self.seek(pos)

        return qname

    def write_byte(self, byte: int):
        self.buf += struct.pack("!B", byte)

    def write(self, fmt: str, *vals):
        self.buf += struct.pack(fmt, *vals)

    def write_qname(self, qname: str):
        for label in qname.split("."):
            length = len(label)
            assert length <= 63, "Label exceeds 63 characters"

            self.write("!B", length)
            raw_bytes = label.encode("utf-8")
            self.buf += raw_bytes

        self.write("!B", 0)
