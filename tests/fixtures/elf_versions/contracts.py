"""Make load-time version contracts observable independently of relocations.

All imports in the contract consumer become unversioned, while its valid
VERNEED declarations stay intact. A provider still advertising VERS_1 but
renaming VERS_2 to LOST_2 must be rejected for a strong requirement. The same
missing declaration is permitted when weak, or when the provider is entirely
unversioned. The host probe checks these semantics, not a synthetic oracle.
"""
import pathlib
import struct
import sys


def elf_hash(name):
    result = 0
    for byte in name:
        result = (result << 4) + byte
        high = result & 0xF0000000
        result ^= high >> 24
        result &= ~high
    return result


class Image:
    def __init__(self, data):
        self.data = bytearray(data)
        assert self.data[:6] == b"\x7fELF\x02\x01"
        offset = self.u64(32)
        width, count = struct.unpack_from("<HH", self.data, 54)
        assert width == 56
        self.headers = [struct.unpack_from("<IIQQQQQQ", self.data, offset + i * width)
                        for i in range(count)]
        self.tags = {}
        dynamic = next(header for header in self.headers if header[0] == 2)
        for offset in range(dynamic[2], dynamic[2] + dynamic[5], 16):
            tag, value = struct.unpack_from("<qQ", self.data, offset)
            if tag == 0:
                break
            self.tags[tag] = value

    def u16(self, offset):
        return struct.unpack_from("<H", self.data, offset)[0]

    def u32(self, offset):
        return struct.unpack_from("<I", self.data, offset)[0]

    def u64(self, offset):
        return struct.unpack_from("<Q", self.data, offset)[0]

    def offset(self, address):
        return next(header[2] + address - header[3] for header in self.headers
                    if header[0] == 1 and header[3] <= address < header[3] + header[5])

    def name(self, offset):
        start = self.offset(self.tags[5]) + offset
        return bytes(self.data[start:self.data.index(0, start)])

    def unversion_imports(self):
        # The original consumer's relocations identify every imported slot.
        versym = self.offset(self.tags[0x6FFFFFF0])
        for address, size in ((7, 8), (23, 2)):
            if address not in self.tags:
                continue
            start = self.offset(self.tags[address])
            for offset in range(start, start + self.tags[size], 24):
                index = self.u64(offset + 8) >> 32
                if index:
                    struct.pack_into("<H", self.data, versym + index * 2, 1)

    def weaken_missing_requirement(self):
        offset = self.offset(self.tags[0x6FFFFFFE])
        found = 0
        for _ in range(self.tags[0x6FFFFFFF]):
            aux = offset + self.u32(offset + 8)
            for _ in range(self.u16(offset + 2)):
                if self.name(self.u32(aux + 8)) == b"VERS_2":
                    struct.pack_into("<H", self.data, aux + 4, 2)
                    found += 1
                aux += self.u32(aux + 12)
            offset += self.u32(offset + 12)
        assert found == 1

    def rename_definition(self):
        offset = self.offset(self.tags[0x6FFFFFFC])
        found = 0
        for _ in range(self.tags[0x6FFFFFFD]):
            aux = offset + self.u32(offset + 12)
            name = self.u32(aux)
            if self.name(name) == b"VERS_2":
                start = self.offset(self.tags[5]) + name
                self.data[start:start + 6] = b"LOST_2"
                struct.pack_into("<I", self.data, offset + 8, elf_hash(b"LOST_2"))
                found += 1
            offset += self.u32(offset + 16)
        assert found == 1

    def write(self, path, sectionless):
        data = bytearray(self.data)
        if sectionless:
            struct.pack_into("<Q", data, 40, 0)
            struct.pack_into("<HHH", data, 58, 0, 0, 0)
        path.write_bytes(data)


def main(root):
    original = root / "full"
    missing = Image((original / "libversions.so").read_bytes())
    missing.rename_definition()
    plain = Image((original / "plain_provider.so").read_bytes())
    consumer = Image((original / "consumer.so").read_bytes())
    consumer.unversion_imports()
    weak = Image(consumer.data)
    weak.weaken_missing_requirement()
    for form in ("full", "sectionless"):
        for case, provider, client in (("strong", missing, consumer), ("weak", missing, weak),
                                       ("unversioned", plain, consumer)):
            directory = root / form / ("contract_" + case)
            directory.mkdir(parents=True, exist_ok=True)
            provider.write(directory / "libversions.so", form == "sectionless")
            client.write(directory / "contract.so", form == "sectionless")


if __name__ == "__main__":
    main(pathlib.Path(sys.argv[1]))
