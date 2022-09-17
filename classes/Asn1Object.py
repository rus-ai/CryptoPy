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


def tag_to_string(tag):
    if tag in tag_to_string_map:
        return tag_to_string_map[tag]
    return '{:#02x}'.format(tag)


def cls_to_string(tag_class):
    if tag_class in cls_to_string_map:
        return cls_to_string_map[tag_class]
    raise ValueError('Illegal class: {:#02x}'.format(tag_class))


class Asn1Object:
    def __init__(self, data, intent=0, encoding="utf-8"):
        if not isinstance(data, bytes):
            raise Exception('Expecting bytes instance.')
        self.intent = intent
        self.encoding = encoding
        self.m_stack = [[0, bytes(data)]]
        self.m_tag = None
        self.tag = self._read_tag()
        self.length = self._read_length()
        self.value = self._read_value(self.length)
        index, remains_data = self.m_stack[-1]
        self.remains = remains_data[index:]
        self.children = []
        if self.tag.typ == Types.Constructed:
            child_asn1 = Asn1Object(self.value, intent + 1)
            self.children.append(child_asn1)
            while child_asn1.remains:
                child_asn1 = Asn1Object(child_asn1.remains, intent + 1)
                self.children.append(child_asn1)
        else:
            try:
                child_asn1 = Asn1Object(self.value[1:], intent + 1)
                self.children.append(child_asn1)
                while child_asn1.remains:
                    child_asn1 = Asn1Object(child_asn1.remains, intent + 1)
                    self.children.append(child_asn1)
            except:
                self._decode_primitive()

    def __repr__(self):
        typ = "Constructed"
        value = ""
        children = ""
        if self.tag.typ == Types.Primitive:
            typ = "Primitive"
            if hasattr(self, "repr_value"):
                value = " = " + str(self.repr_value)
        for child_asn1 in self.children:
            children += str(child_asn1)
        return "    "*self.intent + \
               f"[{cls_to_string(self.tag.cls)}] {tag_to_string(self.tag.nr)} " \
               f"({typ}){value}\n{children}"

    def _decode_primitive(self):
        if self.tag.nr in (Numbers.PrintableString, Numbers.IA5String,
                           Numbers.UTF8String, Numbers.UTCTime,
                           Numbers.GeneralizedTime):
            self.repr_value = self._decode_printable_string(self.value)
        elif self.tag.nr == Numbers.ObjectIdentifier:
            self.repr_value = self._decode_object_identifier(self.value)
        elif self.tag.nr == Numbers.BitString:
            self.repr_value = self._decode_bitstring(self.value)
        elif self.tag.nr in (Numbers.Integer, Numbers.Enumerated):
            self.repr_value = self._decode_integer(self.value)
        elif self.tag.nr == Numbers.Boolean:
            self.repr_value = self._decode_boolean(self.value)
        elif self.tag.nr in (Numbers.Integer, Numbers.Enumerated):
            self.repr_value = self._decode_integer(self.value)
        elif self.tag.nr == Numbers.OctetString:
            self.repr_value = self._decode_octet_string(self.value)
        elif self.tag.nr == Numbers.Null:
            self.repr_value = self._decode_null(self.value)
        else:
            self.repr_value = str(self.value)

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

    @staticmethod
    def _decode_boolean(bytes_data):
        if len(bytes_data) != 1:
            raise Exception('ASN1 syntax error')
        if bytes_data[0] == 0:
            return "False"
        return "True"

    @staticmethod
    def _decode_integer(bytes_data):
        values = [int(b) for b in bytes_data]
        if len(values) > 1 and (values[0] == 0xff and values[1] & 0x80 or values[0] == 0x00 and not (values[1] & 0x80)):
            raise Exception('ASN1 syntax error')
        negative = values[0] & 0x80
        if negative:
            for i in range(len(values)):
                values[i] = 0xff - values[i]
            for i in range(len(values) - 1, -1, -1):
                values[i] += 1
                if values[i] <= 0xff:
                    break
                assert i > 0
                values[i] = 0x00
        value = 0
        for val in values:
            value = (value << 8) | val
        if negative:
            value = -value
        try:
            value = int(value)
        except OverflowError:
            pass
        return value

    @staticmethod
    def _decode_octet_string(bytes_data):
        return bytes_data.hex()

    @staticmethod
    def _decode_null(bytes_data):
        return bytes_data.hex()

    @staticmethod
    def _decode_object_identifier(bytes_data):
        result = []
        value = 0
        for i in range(len(bytes_data)):
            byte = int(bytes_data[i])
            if value == 0 and byte == 0x80:
                raise Exception('ASN1 syntax error')
            value = (value << 7) | (byte & 0x7f)
            if not byte & 0x80:
                result.append(value)
                value = 0
        if len(result) == 0 or result[0] > 1599:
            raise Exception('ASN1 syntax error')
        result = [result[0] // 40, result[0] % 40] + result[1:]
        result = list(map(str, result))
        return str('.'.join(result))

    def _decode_printable_string(self, bytes_data):
        return bytes_data.decode(self.encoding)

    @staticmethod
    def _decode_bitstring(bytes_data):  # type: (bytes) -> str
        if len(bytes_data) == 0:
            raise Exception('ASN1 syntax error')

        num_unused_bits = bytes_data[0]
        if not (0 <= num_unused_bits <= 7):
            raise Exception('ASN1 syntax error')

        if num_unused_bits == 0:
            return bytes_data[1:]

        remaining = bytearray(bytes_data[1:])
        bitmask = (1 << num_unused_bits) - 1
        removed_bits = 0

        for i in range(len(remaining)):
            byte = int(remaining[i])
            remaining[i] = (byte >> num_unused_bits) | (removed_bits << num_unused_bits)
            removed_bits = byte & bitmask

        return bytes(remaining).hex() + f" (Unused bits: {num_unused_bits})"
