import json
import hashlib
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
    def test_gl_mode_states_one_switch_only(self):
        self.assertEqual(match.gl_flags(['/nologo', '/GL', '/MD'], False), ['/nologo', '/MD'])
        self.assertEqual(match.gl_flags(['/nologo', '/gl-', '/MD'], True), ['/nologo', '/MD'])
        self.assertEqual(match.gl_flags(['/nologo', '/MD'], True), ['/nologo', '/MD'])

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

    def test_shared_entry_alias_binding_resolves_only_an_exact_map_alias_set(self):
        code = b'\xe8\x0b\x00\x00\x00\xc3'

        class Image:
            def read_va(self, va, size):
                return code[va - 0x10001000:va - 0x10001000 + size]

            def base_relocations(self):
                return []

        entry = ltcg.MapSymbol('__chkstk', 0x10001010, 1, 16, True, 'msvcrt:chkstk.obj')
        data = ltcg.MapSymbol('__alloca_probe', 0x10001010, 1, 16, False, 'msvcrt:chkstk.obj')
        binding = {'kind': 'entry-alias', 'va': '0x40bd30', 'size': 43,
                   'bytes_sha256': 'f8675b4976f7b8efc0bd917aebab734d11ca90222d20bcd2a166ce9914ed2b6e',
                   'aliases': ['__alloca_probe', '__chkstk'],
                   'evidence': 'synthetic test binding'}
        refs = ltcg.scan_referents(Image(), 0x10001000, len(code), [entry, data],
                                   {'entry-alias:__alloca_probe|__chkstk': binding})
        self.assertEqual(refs[0]['identity'], 'entry-alias:__alloca_probe|__chkstk')
        self.assertTrue(refs[0]['resolved'])
        self.assertEqual(refs[0]['aliases'], ['__alloca_probe', '__chkstk'])
        self.assertEqual((refs[0]['size'], refs[0]['bytes_sha256']),
                         (43, binding['bytes_sha256']))

        wrong = dict(binding, aliases=['__alloca_probe', '__chkstk64'])
        refs = ltcg.scan_referents(Image(), 0x10001000, len(code), [entry, data],
                                   {'entry-alias:__alloca_probe|__chkstk64': wrong})
        self.assertIsNone(refs[0]['identity'])
        self.assertFalse(refs[0]['resolved'])

        refs = ltcg.scan_referents(Image(), 0x10001000, len(code), [entry, data])
        self.assertIsNone(refs[0]['identity'])
        self.assertFalse(refs[0]['resolved'])

        with self.assertRaisesRegex(ValueError, 'ambiguous entry-alias'):
            ltcg.scan_referents(Image(), 0x10001000, len(code), [entry, data],
                                {'entry-alias:__alloca_probe|__chkstk': binding, 'other': dict(binding)})

    def test_single_map_alias_is_never_promoted_to_a_shared_entry(self):
        code = b'\xe8\x0b\x00\x00\x00\xc3'

        class Image:
            def read_va(self, va, size):
                return code[va - 0x10001000:va - 0x10001000 + size]

            def base_relocations(self):
                return []

        symbols = [ltcg.MapSymbol('__chkstk', 0x10001010, 1, 16, True, 'msvcrt:chkstk.obj')]
        binding = {'kind': 'entry-alias', 'va': '0x40bd30', 'size': 43,
                   'bytes_sha256': '0f' * 32, 'aliases': ['__alloca_probe', '__chkstk'],
                   'evidence': 'synthetic test binding'}
        refs = ltcg.scan_referents(Image(), 0x10001000, len(code), symbols,
                                   {'entry-alias:__alloca_probe|__chkstk': binding})
        self.assertEqual(refs[0]['identity'], '__chkstk')
        self.assertTrue(refs[0]['resolved'])

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

    def test_comparison_resolves_exact_referent_instead_of_masking(self):
        candidate = {'candidate_va': 0x10001000, 'retail_va': 0x401000}
        code = b'\xa1\x00\x20\x00\x10\xc3'
        source = [{'offset': 1, 'width': 4, 'kind': 'abs32', 'target': 0x10002000, 'identity': '_global'}]
        retail = [{'offset': 1, 'width': 4, 'kind': 'abs32', 'target': 0x41a020}]
        bindings = {'_global': {'va': '0x41a020', 'evidence': 'independent storage identity'}}
        self.assertEqual(match.relocate_for_comparison(candidate, code, source, retail, bindings), b'\xa1\x20\xa0\x41\x00\xc3')
        with self.assertRaisesRegex(ValueError, 'unresolved'):
            match.relocate_for_comparison(candidate, code, source, retail, {})
        bindings['_global']['va'] = '0x41a024'
        with self.assertRaisesRegex(ValueError, 'differs'):
            match.relocate_for_comparison(candidate, code, source, retail, bindings)

    def test_comparison_rejects_same_mask_with_different_ordered_sites(self):
        source = [{'offset': 1, 'width': 4, 'kind': 'rel32', 'target': 0x1000, 'identity': 'self+0x0'}]
        retail = [dict(source[0], offset=2)]
        with self.assertRaisesRegex(ValueError, 'encoding differs'):
            match.relocate_for_comparison({'candidate_va': 0x1000, 'retail_va': 0x2000}, b'\xe8\0\0\0\0', source, retail, {})

    def test_import_identity_comes_from_actual_pe_slot_instead_of_map_alias(self):
        code = b'\xff\x25\x00\x20\x00\x10'

        class Image:
            def read_va(self, va, size):
                return code[va - 0x10001000:va - 0x10001000 + size]

            def base_relocations(self):
                return []

            def import_records(self):
                return [{'va': 0x10002000, 'identity': 'msvcr80.dll!free'}]

        aliases = [ltcg.MapSymbol('__imp__free', 0x10002000, 2, 0, False, 'msvcrt.lib')]
        refs = ltcg.scan_referents(Image(), 0x10001000, len(code), aliases)
        self.assertEqual(refs[0]['identity'], 'msvcr80.dll!free')

    def test_literal_identity_requires_exact_bounded_content(self):
        code = b'\xa1\x00\x20\x00\x10\xc3'
        payload = b'CONOUT$\0'

        class Image:
            def read_va(self, va, size):
                data, start = (code, 0x10001000) if va < 0x10002000 else (payload, 0x10002000)
                if not start <= va <= va + size <= start + len(data):
                    raise ValueError('not file-backed')
                return data[va - start:va - start + size]

            def base_relocations(self):
                return []

        digest = hashlib.sha256(payload).hexdigest()
        key = 'literal:sha256:' + digest
        binding = {key: {'kind': 'literal', 'size': len(payload), 'bytes_sha256': digest}}
        refs = ltcg.scan_referents(Image(), 0x10001000, len(code), bindings=binding)
        self.assertEqual(refs[0]['identity'], key)
        binding[key]['bytes_sha256'] = '0' * 64
        refs = ltcg.scan_referents(Image(), 0x10001000, len(code), bindings=binding)
        self.assertIsNone(refs[0]['identity'])

    def test_fixed_base_index_operand_is_a_reference_without_pe_fixups(self):
        code = b'\x8b\x04\x85\x00\x20\x00\x10\xc3'

        class Image:
            def read_va(self, va, size):
                return code[va - 0x10001000:va - 0x10001000 + size]

            def base_relocations(self):
                return []

        refs = ltcg.scan_referents(Image(), 0x10001000, len(code))
        self.assertEqual([(r['offset'], r['kind'], r['target']) for r in refs], [(3, 'abs32', 0x10002000)])

    def test_immediate_virtual_bss_pointer_remains_an_unresolved_referent(self):
        code = b'\x68\x20\x20\x00\x10\xc3'

        class Image:
            sections = [{'va': 0x10002000, 'vsize': 0x100, 'rawsize': 0}]

            def read_va(self, va, size):
                if not 0x10001000 <= va <= va + size <= 0x10001000 + len(code):
                    raise ValueError('not file-backed')
                return code[va - 0x10001000:va - 0x10001000 + size]

            def base_relocations(self):
                return []

        refs = ltcg.scan_referents(Image(), 0x10001000, len(code))
        self.assertEqual([(r['offset'], r['kind'], r['target'], r['resolved']) for r in refs], [(1, 'abs32', 0x10002020, False)])

    def test_struct_base_address_and_offset_zero_memory_have_distinct_identities(self):
        code = b'\x68\x00\x20\x00\x10\xc7\x05\x00\x20\x00\x10\x0c\0\0\0\x8d\x05\x00\x20\x00\x10\xc3'

        class Image:
            sections = [{'va': 0x10002000, 'vsize': 12, 'rawsize': 0}]

            def read_va(self, va, size):
                if not 0x10001000 <= va <= va + size <= 0x10001000 + len(code):
                    raise ValueError('not file-backed')
                return code[va - 0x10001000:va - 0x10001000 + size]

            def base_relocations(self):
                return []

        witness = {'path': 'layout.json', 'sha256': 'a' * 64}
        bindings = {'_attrs': {'kind': 'symbol', 'size': 12, 'layout_witness': witness},
                    'member:_attrs.nLength': {'kind': 'member', 'base_identity': '_attrs',
                        'offset': 0, 'size': 4, 'layout_witness': witness}}
        symbols = [ltcg.MapSymbol('_attrs', 0x10002000, 2, 0, False, 'source.obj')]
        refs = ltcg.scan_referents(Image(), 0x10001000, len(code), symbols, bindings)
        self.assertEqual([r['identity'] for r in refs], ['_attrs', 'member:_attrs.nLength', '_attrs'])
        bindings['member:_attrs.nLength']['size'] = 1
        refs = ltcg.scan_referents(Image(), 0x10001000, len(code), symbols, bindings)
        self.assertEqual([r['identity'] for r in refs], ['_attrs', None, '_attrs'])


if __name__ == '__main__':
    unittest.main()
