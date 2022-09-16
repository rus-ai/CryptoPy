import binascii
import sys
import modules.asn1 as asn1

tag_id_to_string_map = {
    asn1.Numbers.Boolean: "BOOLEAN",
    asn1.Numbers.Integer: "INTEGER",
    asn1.Numbers.BitString: "BIT STRING",
    asn1.Numbers.OctetString: "OCTET STRING",
    asn1.Numbers.Null: "NULL",
    asn1.Numbers.ObjectIdentifier: "OBJECT",
    asn1.Numbers.PrintableString: "PRINTABLESTRING",
    asn1.Numbers.IA5String: "IA5STRING",
    asn1.Numbers.UTCTime: "UTCTIME",
    asn1.Numbers.GeneralizedTime: "GENERALIZED TIME",
    asn1.Numbers.Enumerated: "ENUMERATED",
    asn1.Numbers.Sequence: "SEQUENCE",
    asn1.Numbers.Set: "SET"
}

class_id_to_string_map = {
    asn1.Classes.Universal: "U",
    asn1.Classes.Application: "A",
    asn1.Classes.Context: "C",
    asn1.Classes.Private: "P"
}

object_id_to_string_map = {
    "1.2.643.2.2.36.0": "cryptopro-XchA",
    "1.2.643.2.2.37.2.1": "private-keys",
    "1.2.643.2.2.37.3.10": "Expiration???",
    "1.2.643.7.1.1.2.2": "Hash???",
    "1.2.643.7.1.1.6.1": "Elliptic-curve Diffie–Hellman 256",
}


def tag_id_to_string(identifier):
    """Return a string representation of a ASN.1 id."""
    if identifier in tag_id_to_string_map:
        return tag_id_to_string_map[identifier]
    return '{:#02x}'.format(identifier)


def class_id_to_string(identifier):
    """Return a string representation of an ASN.1 class."""
    if identifier in class_id_to_string_map:
        return class_id_to_string_map[identifier]
    raise ValueError('Illegal class: {:#02x}'.format(identifier))


def object_identifier_to_string(identifier):
    if identifier in object_id_to_string_map:
        return object_id_to_string_map[identifier]
    return identifier


def value_to_string(tag_number, value):
    if tag_number == asn1.Numbers.ObjectIdentifier:
        return object_identifier_to_string(value)
    elif isinstance(value, bytes):
        return '0x' + str(binascii.hexlify(value).upper())
    elif isinstance(value, str):
        return value
    else:
        return repr(value)


def pretty_print(input_stream, output_stream, indent=0):
    while not input_stream.eof():
        tag = input_stream.peek()
        if tag.typ == asn1.Types.Primitive:
            tag, value = input_stream.read()
            output_stream.write(' ' * indent)
            output_stream.write('[{}] {}: {}\n'.format(class_id_to_string(tag.cls), tag_id_to_string(tag.nr), value_to_string(tag.nr, value)))
        elif tag.typ == asn1.Types.Constructed:
            output_stream.write(' ' * indent)
            output_stream.write('[{}] {}\n'.format(class_id_to_string(tag.cls), tag_id_to_string(tag.nr)))
            input_stream.enter()
            pretty_print(input_stream, output_stream, indent + 2)
            input_stream.leave()


def print_keyfile(binary):
    decoder = asn1.Decoder()
    decoder.start(binary)
    output_file = sys.stdout
    pretty_print(decoder, output_file)
