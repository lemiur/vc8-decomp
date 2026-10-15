"""Bounded i386 COFF discovery. VC8 /GL containers are deliberately not COFF.

The plain discovery object is never used as candidate byte provenance.
"""
from dataclasses import dataclass
from pathlib import Path
import struct


@dataclass(frozen=True)
class Symbol:
    name: str
    value: int
    section: int
    kind: int
    storage: int

    @property
    def is_function(self):
        return self.section > 0 and bool(self.kind & 0x20)


def read_symbols(path):
    data = Path(path).read_bytes()
    if len(data) < 20:
        raise ValueError('truncated COFF header')
    machine, sections, _, table, count, optional, _ = struct.unpack_from('<HHIIIHH', data)
    if machine != 0x14c or optional or 20 + sections * 40 > len(data):
        raise ValueError('not a standard i386 COFF object (LTCG containers unsupported)')
    strings = table + count * 18
    if table < 20 or strings + 4 > len(data):
        raise ValueError('COFF symbol table outside file')
    string_size = struct.unpack_from('<I', data, strings)[0]
    if string_size < 4 or strings + string_size > len(data):
        raise ValueError('COFF string table outside file')
    result = []
    index = 0
    while index < count:
        at = table + index * 18
        name = data[at:at + 8]
        if name[:4] == b'\0' * 4:
            offset = struct.unpack_from('<I', name, 4)[0]
            if not 4 <= offset < string_size:
                raise ValueError('COFF name offset outside string table')
            start = strings + offset
            end = data.find(b'\0', start, strings + string_size)
            if end < 0:
                raise ValueError('unterminated COFF name')
            name = data[start:end]
        else:
            name = name.rstrip(b'\0')
        value, section, kind, storage, aux = struct.unpack_from('<IhHBB', data, at + 8)
        if index + aux >= count:
            raise ValueError('COFF auxiliary records outside symbol table')
        result.append(Symbol(name.decode('latin-1'), value, section, kind, storage))
        index += 1 + aux
    return result


def function_symbols(path):
    return [symbol.name for symbol in read_symbols(path) if symbol.is_function]
