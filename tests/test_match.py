import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import coff
import ltcg
import match


class MatchContracts(unittest.TestCase):
    def source(self, text):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        path = Path(temp.name) / 'unit.cpp'
        path.write_text(text, encoding='utf-8')
        return path

    def test_annotations_keep_layout_and_ignore_comment_braces(self):
        path = self.source('// FUNCTION: cl 0x401000\n// SYMBOL: _real\nint real(int n) {\n /* } */ return n;\n}\n')
        annotation, = match.parse_annotations(path)
        self.assertEqual((annotation.line, annotation.start, annotation.end), (1, 3, 5))
        self.assertEqual(annotation.symbol, '_real')
        self.assertEqual(match.discover_symbol(annotation, ['_real']), '_real')

    def test_unbalanced_or_duplicate_annotations_rejected(self):
        for body in ('// FUNCTION: cl 0x401000\nint f() {',
                     '// FUNCTION: cl 0x401000\nint f() {}\n// FUNCTION: cl 0x401000\nint g() {}'):
            with self.assertRaises(ValueError):
                match.parse_annotations(self.source(body))

    def test_ambiguous_decorated_symbol_does_not_guess(self):
        annotation = match.Annotation('cl', 1, 1, 1, 2, 'f', None)
        with self.assertRaises(ValueError):
            match.discover_symbol(annotation, ['?f@A@@QAEXXZ', '?f@B@@QAEXXZ'])

    def test_coff_names_and_truncation(self):
        path = self.source('')
        header = struct.pack('<HHIIIHH', 0x14c, 0, 0, 20, 1, 0, 0)
        symbol = b'_real\0\0\0' + struct.pack('<IhHBB', 0, 1, 0x20, 2, 0)
        data = header + symbol + struct.pack('<I', 4)
        path.write_bytes(data)
        self.assertEqual(coff.function_symbols(path), ['_real'])
        path.write_bytes(data[:-1])
        with self.assertRaises(ValueError):
            coff.read_symbols(path)
        path.write_bytes(b'\0' * 40)
        with self.assertRaises(ValueError):
            coff.read_symbols(path)

    def test_map_retains_aliases_and_data(self):
        path = self.source(' 0001:00000000 _f 10001000 f candidate.obj\n 0002:00000000 _global 10002000 candidate.obj\n')
        symbols = ltcg.read_map(path)
        self.assertEqual([(s.name, s.va, s.is_function) for s in symbols], [('_f', 0x10001000, True), ('_global', 0x10002000, False)])

    def test_decoder_orders_internal_external_and_absolute_references(self):
        code = b'\xe8\x0b\x00\x00\x00\x75\xf9\xa1\x00\x20\x00\x10\xc3'

        class Image:
            def read_va(self, va, size):
                return code[va - 0x10001000:va - 0x10001000 + size]

            def base_relocations(self):
                return [{'va': 0x10001008, 'type': 3, 'width': 4}]

        symbols = [ltcg.MapSymbol('_callee', 0x10001010, 1, 16, True, 'a.obj')]
        refs = ltcg.scan_referents(Image(), 0x10001000, len(code), symbols)
        self.assertEqual([(r['offset'], r['kind']) for r in refs], [(1, 'rel32'), (6, 'rel8'), (8, 'abs32')])
        self.assertEqual(refs[1]['identity'], 'self+0x0')
        self.assertFalse(refs[2]['resolved'])

    def test_decoder_rejects_truncation_and_unsupported_relocation(self):
        class Image:
            def read_va(self, va, size):
                return b'\xe8'[:size]

            def base_relocations(self):
                return []

        with self.assertRaises(ValueError):
            ltcg.scan_referents(Image(), 0x1000, 1)
        Image.base_relocations = lambda self: [{'va': 0x1000, 'type': 7, 'width': None}]
        with self.assertRaises(ValueError):
            ltcg.scan_referents(Image(), 0x1000, 1)

    def test_build_rejects_reusing_nonempty_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'config').mkdir()
            (root / 'config/project.json').write_text(json.dumps({'toolchain_root': 'unused', 'binaries': {'cl': {}}}))
            (root / 'out').mkdir()
            (root / 'out/stale.dll').write_bytes(b'stale')
            with self.assertRaisesRegex(ValueError, 'empty'):
                match.build(root, 'cl', root / 'out')
            self.assertEqual((root / 'out/stale.dll').read_bytes(), b'stale')

    def test_registry_combines_descriptors_and_rejects_duplicate_addresses(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'config').mkdir()
            entry = {'binary': 'cl', 'symbol': '_f', 'retail_va': '0x401000'}
            descriptor = {'schema_version': 1, 'candidates': [entry]}
            (root / 'config/cl-candidates.json').write_text(json.dumps(descriptor))
            self.assertEqual(match.registry_entries(root, 'cl'), [entry])
            entry2 = dict(entry, symbol='_g')
            (root / 'config/gate-allow.json').write_text(json.dumps({'schema_version': 1, 'candidates': [entry2]}))
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                match.registry_entries(root, 'cl')


if __name__ == '__main__':
    unittest.main()
