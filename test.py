import ipaddress
import pprint
from dataclasses import asdict, dataclass
from enum import IntEnum
from typing import List, Union

from buffer import Buffer


class ResultCode(IntEnum):
    NOERROR = 0
    FORMERR = 1
    SERVFAIL = 2
    NXDOMAIN = 3
    NOTIMP = 4
    REFUSED = 5


class QueryType(IntEnum):
    UNKNOWN = 0
    A = 1


@dataclass
class DnsHeader:
    id: int  # 16 bits

    recursion_desired: bool  # 1 bit
    truncated_message: bool  # 1 bit
    authoritative_answer: bool  # 1 bit
    opcode: int  # 4 bits
    response: bool  # 1 bit

    rescode: ResultCode  # 4 bits
    checking_disabled: bool  # 1 bit
    authed_data: bool  # 1 bit
    z: bool  # 1 bit
    recursion_available: bool  # 1 bit

    questions: int  # 16 bits
    answers: int  # 16 bits
    authoritative_entries: int  # 16 bits
    resource_entries: int  # 16 bits

    @classmethod
    def parse(cls, buf: Buffer):
        assert len(buf) >= 12, "Packet header must be atleast 12 bytes"
        (id, flags, questions, answers, auth, res) = buf.unpack("!HHHHHH")

        # a represents the first 8 bits of the flags
        # b represents the last 8 bits of the flags
        # flags is 16 bits long
        a, b = flags >> 8, flags & 0xFF

        recursion_desired = (a & (1 << 0)) > 0
        truncated_message = (a & (1 << 1)) > 0
        authoritative_answer = (a & (1 << 2)) > 0
        opcode = (a >> 3) & 0x0F
        response = (a & (1 << 7)) > 0

        rescode = ResultCode(b & 0x0F)
        checking_disabled = (b & (1 << 4)) > 0
        authed_data = (b & (1 << 5)) > 0
        z = (b & (1 << 6)) > 0
        recursion_available = (b & (1 << 7)) > 0

        return cls(
            id=id,
            recursion_desired=recursion_desired,
            truncated_message=truncated_message,
            authoritative_answer=authoritative_answer,
            opcode=opcode,
            response=response,
            rescode=rescode,
            checking_disabled=checking_disabled,
            authed_data=authed_data,
            z=z,
            recursion_available=recursion_available,
            questions=questions,
            answers=answers,
            authoritative_entries=auth,
            resource_entries=res,
        )

    def __str__(self):
        return f"DnsHeader {pprint.pformat(asdict(self))}"

    def write(self, buf: Buffer):
        buf.write("!H", self.id)
        buf.write(
            "!B",
            (
                (self.recursion_desired << 0)
                | (self.truncated_message << 1)
                | (self.authoritative_answer << 2)
                | (self.opcode << 3)
                | (self.response << 7)
            ),
        )

        buf.write(
            "!B",
            (
                (self.rescode << 0)
                | (self.checking_disabled << 4)
                | (self.authed_data << 5)
                | (self.z << 6)
                | (self.recursion_available << 7)
            ),
        )

        buf.write(
            "!HHHH",
            self.questions,
            self.answers,
            self.authoritative_entries,
            self.resource_entries,
        )


@dataclass
class DnsQuestion:
    name: str
    qtype: QueryType

    @classmethod
    def parse(cls, buf: Buffer):
        name = buf.read_qname()
        (qtype, _) = buf.unpack("!HH")
        return cls(name=name, qtype=QueryType(qtype))

    def __str__(self):
        return f"DnsQuestion {pprint.pformat(asdict(self))}"

    def write(self, buf: Buffer):
        buf.write_qname(self.name)
        buf.write("!HH", self.qtype, 1)


@dataclass
class DnsRecordUnknown:
    domain: str
    qtype: int  # 16 bits
    length: int  # 16 bits
    ttl: int  # 32 bits

    def write(self, buf: Buffer):
        print("Writing unknown record")
        buf.write_qname(self.domain)
        buf.write("!HHIH", self.qtype, 1, self.ttl, self.length)


@dataclass
class DnsRecordA:
    domain: str
    addr: ipaddress.IPv4Address
    ttl: int  # 32 bits

    def write(self, buf: Buffer):
        buf.write_qname(self.domain)
        buf.write("!HHIH", QueryType.A, 1, self.ttl, 4)
        buf.write("!I", int(self.addr))


DnsRecord = Union[DnsRecordUnknown, DnsRecordA]

@dataclass
class DnsRecordTest:
    domain_name: str
    record_type: int
    record_class: int
    ttl: int
    rdlength: int
    rdata: bytes

    @classmethod
    def parse(cls, buf: Buffer):
        domain_name = buf.read_qname()

        # Unpack the remaining fields (Type, Class, TTL, RDLENGTH)
        (record_type, record_class, ttl, rdlength) = buf.unpack("!HHIH")

        # Read the RDATA based on the RDLENGTH
        rdata = buf.get_range(buf.pos(), rdlength)

        # Update the buffer offset to point to the next record (if any)
        buf.seek(buf.pos() + rdlength)

        return cls(
            domain_name=domain_name,
            record_type=record_type,
            record_class=record_class,
            ttl=ttl,
            rdlength=rdlength,
            rdata=rdata,
        )

def parse_dns_record(buf: Buffer) -> DnsRecord:
    print("offset before parsing dns record = ", buf.offset)
    domain = buf.read_qname()
    print("offset after parsing domain = ", buf.offset)
    (qtype,) = buf.unpack("!H")
    try:
        qtype = QueryType(qtype)
    except ValueError:
        print("Unknown query type: ", qtype)
        qtype = QueryType.UNKNOWN

    _ = buf.unpack("!H")  # class
    (ttl,) = buf.unpack("!I")
    (length,) = buf.unpack("!H")

    if qtype == QueryType.A:
        (addr,) = buf.unpack("!I")
        addr = ipaddress.ip_address(addr)
        return DnsRecordA(domain=domain, addr=addr, ttl=ttl)

    else:
        return DnsRecordUnknown(domain=domain, qtype=qtype, length=length, ttl=ttl)


@dataclass
class DnsPacket:
    header: DnsHeader
    questions: List[DnsQuestion]
    answers: List[DnsRecord]
    authoritative_entries: List[DnsRecord]
    resource_entries: List[DnsRecord]

    @classmethod
    def parse(cls, buf: Buffer):
        questions = []
        answers = []
        authoritative_entries = []
        resource_entries = []

        header = DnsHeader.parse(buf)
        print(f"offset after parsing header = {buf.offset}")
        for _ in range(header.questions):
            questions.append(DnsQuestion.parse(buf))
        
        print(f"offset after parsing questions = {buf.offset}")

        for _ in range(header.answers):
            answers.append(parse_dns_record(buf))
        
        print(f"offset after parsing answers = {buf.offset}")

        for _ in range(header.authoritative_entries):
            authoritative_entries.append(parse_dns_record(buf))
        
        print(f"offset after parsing authoritative = {buf.offset}")

        for _ in range(header.resource_entries):
            resource_entries.append(parse_dns_record(buf))
        
        print(f"offset after parsing resource = {buf.offset}")

        return cls(
            header=header,
            questions=questions,
            answers=answers,
            authoritative_entries=authoritative_entries,
            resource_entries=resource_entries,
        )

    def write(self, buf: Buffer):
        self.header.write(buf)
        for question in self.questions:
            question.write(buf)

        for answer in self.answers:
            answer.write(buf)

        for auth in self.authoritative_entries:
            auth.write(buf)

        for resource in self.resource_entries:
            resource.write(buf)

def ipos(array, *index):
    """ Visually indicate where the index is in an array """
    def bfmt(x):
        return repr(chr(x))[1:-1] if x >= 32 and x <= 126 else f"\\x{x:02x}"
    
    return "".join(
        [
            bfmt(array[i])
            if i not in index
            #else f"\033[1;31;40m{str(i)}\033[0;37;40m"
            else f"\033[31;1;4m{bfmt(array[i])}\033[0m"
            for i in range(len(array))
        ]
    )

with open("r1.pkt", "rb") as f:
    buf = Buffer(f.read())

packet = DnsPacket.parse(buf)
pprint.pprint(packet)
print(f"Buffer total length = {len(buf)}")
print(f"Buffer offset after parsing = {buf.offset}")

print(ipos(buf.buf, 28, 12))

print(buf.buf)

