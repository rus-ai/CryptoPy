import collections
from enum import IntEnum


class Numbers(IntEnum):
    Boolean = 0x01
    Integer = 0x02
    BitString = 0x03
    OctetString = 0x04
    Null = 0x05
    ObjectIdentifier = 0x06
    Enumerated = 0x0a
    UTF8String = 0x0c
    Sequence = 0x10
    Set = 0x11
    PrintableString = 0x13
    IA5String = 0x16
    UTCTime = 0x17
    GeneralizedTime = 0x18
    UnicodeString = 0x1e


class Types(IntEnum):
    Constructed = 0x20
    Primitive = 0x00


class Classes(IntEnum):
    Universal = 0x00
    Application = 0x40
    Context = 0x80
    Private = 0xc0


tag_to_string_map = {
    Numbers.Boolean: "BOOLEAN",
    Numbers.Integer: "INTEGER",
    Numbers.BitString: "BIT STRING",
    Numbers.OctetString: "OCTET STRING",
    Numbers.Null: "NULL",
    Numbers.ObjectIdentifier: "OBJECT",
    Numbers.PrintableString: "PRINTABLESTRING",
    Numbers.IA5String: "IA5STRING",
    Numbers.UTCTime: "UTCTIME",
    Numbers.GeneralizedTime: "GENERALIZED TIME",
    Numbers.Enumerated: "ENUMERATED",
    Numbers.Sequence: "SEQUENCE",
    Numbers.Set: "SET"
}

cls_to_string_map = {
    Classes.Universal: "U",
    Classes.Application: "A",
    Classes.Context: "C",
    Classes.Private: "P"
}

Tag = collections.namedtuple('Tag', 'nr typ cls')


def tag_to_string(id):
    if id in tag_to_string_map:
        return tag_to_string_map[id]
    return '{:#02x}'.format(id)


def class_to_string(cls):
    if cls in cls_to_string_map:
        return cls_to_string_map[cls]
    raise ValueError('Illegal class: {:#02x}'.format(cls))


class Asn1Sequence:
    def __init__(self, data):
        if not isinstance(data, bytes):
            raise Exception('Expecting bytes instance.')
        self.m_stack = [[0, bytes(data)]]
        self.m_tag = None
        self.tag = self._read_tag()
        self.length = self._read_length()
        self.value = self._read_value(self.length)

    def __repr__(self):
        typ = "Constructed"
        if self.tag.typ == Types.Primitive:
            typ = "Primitive"
        return f"[{class_to_string(self.tag.cls)}] {tag_to_string(self.tag.nr)} " \
               f"({typ})"

    def _read_tag(self):
        byte = self._read_byte()
        cls = byte & 0xc0
        typ = byte & 0x20
        nr = byte & 0x1f
        if nr == 0x1f:
            nr = 0
            while True:
                byte = self._read_byte()
                nr = (nr << 7) | (byte & 0x7f)
                if not byte & 0x80:
                    break
        return Tag(nr=nr, typ=typ, cls=cls)

    def _read_length(self):
        byte = self._read_byte()
        if byte & 0x80:
            count = byte & 0x7f
            if count == 0x7f:
                raise Exception('ASN1 syntax error')
            bytes_data = self._read_bytes(count)
            length = 0
            for byte in bytes_data:
                length = (length << 8) | int(byte)
            try:
                length = int(length)
            except OverflowError:
                pass
        else:
            length = byte
        return length

    def _read_value(self, length):
        return self._read_bytes(length)

    def _read_byte(self):
        index, input_data = self.m_stack[-1]
        try:
            byte = input_data[index]
        except IndexError:
            raise Exception('Premature end of input.')
        self.m_stack[-1][0] += 1
        return byte

    def _read_bytes(self, count):
        index, input_data = self.m_stack[-1]
        bytes_data = input_data[index:index + count]
        if len(bytes_data) != count:
            raise Exception('Premature end of input.')
        self.m_stack[-1][0] += count
        return bytes_data

