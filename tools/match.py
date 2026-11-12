"""Fresh VC8 builds (/GL + /LTCG unless the adapter says otherwise) and bounded retail comparisons.

Only gate.py can admit compiled bytes. MAP-derived spans are explicitly
unverified. This harness never manufactures definitions for missing callees.
"""
import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
import uuid

from coff import function_symbols
import ltcg
from matchlib import ADAPTER_DEFAULTS, adapter_of, annotation_pattern, unit_gl

ROOT = Path(__file__).resolve().parents[1]
SYMBOL = re.compile(r'^\s*//\s*SYMBOL:\s*(\S+)\s*$', re.M)
COMMENT_OR_STRING = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', re.S)


@dataclass
class Annotation:
    binary: str
    retail_va: int
    line: int
    start: int
    end: int
    source_name: str | None
    symbol: str | None


def parse_annotations(path, adapter=ADAPTER_DEFAULTS):
    text = Path(path).read_text(encoding='utf-8-sig')
    clean = COMMENT_OR_STRING.sub(lambda m: ''.join('\n' if c == '\n' else ' ' for c in m[0]), text)
    function = adapter['annotation']['function']
    markers = [marker for marker in annotation_pattern(adapter).finditer(text)
               if marker.groupdict().get('kind', function) == function]
    result = []
    seen = set()
    for index, marker in enumerate(markers):
        limit = markers[index + 1].start() if index + 1 < len(markers) else len(text)
        opening = clean.find('{', marker.end(), limit)
        if opening < 0:
            raise ValueError('FUNCTION annotation has no body at line %d' % (text.count('\n', 0, marker.start()) + 1))
        depth = 1
        closing = opening + 1
        while closing < limit and depth:
            depth += (clean[closing] == '{') - (clean[closing] == '}')
            closing += 1
        if depth:
            raise ValueError('unbalanced FUNCTION body')
        declaration = clean[marker.end():opening]
        names = re.findall(r'([A-Za-z_$][\w$]*)\s*\(', declaration)
        names = [name for name in names if name not in ('__declspec', '__attribute__', 'throw')]
        symbol = SYMBOL.search(text, marker.end(), opening)
        binary, va = marker['binary'], int(marker['va'], 16)
        if (binary, va) in seen:
            raise ValueError('duplicate FUNCTION address %s %#x' % (binary, va))
        seen.add((binary, va))
        declaration_start = marker.end() + len(declaration) - len(declaration.lstrip())
        result.append(Annotation(binary, va, text.count('\n', 0, marker.start()) + 1,
                                 text.count('\n', 0, declaration_start) + 1,
                                 text.count('\n', 0, closing) + 1,
                                 names[0] if names else None, symbol[1] if symbol else None))
    return result


def integer(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def read_json(path, fallback=None):
    return json.loads(Path(path).read_text(encoding='utf-8-sig')) if Path(path).is_file() else fallback


def discover_symbol(annotation, symbols):
    if annotation.symbol:
        if annotation.symbol not in symbols:
            raise ValueError('explicit symbol is not defined by discovery object: ' + annotation.symbol)
        return annotation.symbol
    name = annotation.source_name
    choices = [symbol for symbol in symbols if symbol == '_' + str(name) or
               re.fullmatch(r'_' + re.escape(str(name)) + r'@\d+', symbol) or
               symbol.startswith('?' + str(name) + '@')]
    if len(choices) != 1:
        raise ValueError('cannot uniquely bind annotation at line %d to COFF symbol; add // SYMBOL: decorated-name' % annotation.line)
    return choices[0]


def registry_entries(root, binary):
    entries = []
    seen = set()
    for path in (root / 'config' / 'gate-allow.json', root / 'config' / (binary + '-candidates.json')):
        registry = read_json(path, {})
        if path.is_file() and registry.get('schema_version') != 1:
            raise ValueError('unsupported candidate registry schema: ' + str(path))
        for entry in registry.get('candidates', []):
            if entry.get('binary') != binary:
                continue
            key = (entry['symbol'], integer(entry['retail_va']))
            if key in seen or any(old['symbol'] == key[0] or integer(old['retail_va']) == key[1] for old in entries):
                raise ValueError('duplicate candidate symbol or retail address across registries')
            seen.add(key)
            entries.append(entry)
    return entries


def load_settings(root, binary):
    project = read_json(root / 'config' / 'project.json')
    if not project or binary not in project.get('binaries', {}):
        raise ValueError('binary is not configured: ' + binary)
    settings = dict(project['binaries'][binary])
    settings.update(read_json(root / 'config' / (binary + '.json'), {}))
    settings['adapter'] = adapter_of(project)
    return project, settings


def registry_referents(root, binary):
    bindings = {}
    for path in (root / 'config/gate-allow.json', root / 'config' / (binary + '-candidates.json')):
        registry = read_json(path, {})
        for name, record in registry.get('referents', {}).get(binary, {}).items():
            if name in bindings and bindings[name] != record:
                raise ValueError('conflicting referent identity binding: ' + name)
            bindings[name] = record
    return bindings


def source_path(root, path):
    path = Path(path)
    return path.resolve() if path.is_absolute() else (root / path).resolve()


def gl_flags(flags, gl):
    """Strip the opposite whole-program switch so the argv states one /GL mode only."""
    opposite = '/GL-' if gl else '/GL'
    return [flag for flag in flags if flag.lower() != opposite.lower()]


def compile_unit(source, output, toolroot, flags, env, commands, compiler, gl=True):
    argv = [str(toolroot / 'bin' / compiler), '/nologo', '/c', '/showIncludes'] + gl_flags(flags, gl)
    argv += ['/GL' if gl else '/GL-', '/Fo' + str(output), str(source)]
    result = ltcg.run_command(argv, output.parent, env, commands, [output])
    if not output.is_file():
        raise RuntimeError('successful compilation produced no object')
    includes = []
    for line in (result.stdout + result.stderr).splitlines():
        match = re.match(r'\s*Note: including file:\s*(.+)', line)
        if match:
            includes.append(Path(match[1].strip()).resolve())
    return includes


def build(root, binary, output_dir=None, manifest_path=None, build_id=None, units=None, toolchain_name=None):
    project, settings = load_settings(root, binary)
    adapter = settings['adapter']
    build_id = build_id or str(uuid.uuid4())
    out = Path(output_dir).resolve() if output_dir else root / 'build' / binary / build_id
    if out.exists() and any(out.iterdir()):
        raise ValueError('output directory must be empty for a fresh build: ' + str(out))
    out.mkdir(parents=True, exist_ok=True)
    destination = Path(manifest_path).resolve() if manifest_path else out / 'manifest.json'
    toolroot = Path(project['toolchain_root'])
    env = ltcg.tool_environment(toolroot)
    toolchain_config = root / 'config' / 'toolchains.json'
    toolchain = None
    if toolchain_name and not toolchain_config.is_file():
        raise ValueError('explicit toolchain selection requires config/toolchains.json')
    if toolchain_config.is_file():
        from probe_toolchain import load_toolchain, toolchain_environment
        toolchain = load_toolchain(toolchain_name or settings.get('toolchain', 'sp1'), toolchain_config)
        toolroot = Path(toolchain['bin']).parent
        env = toolchain_environment(toolchain)
    configured_flags = settings.get('flags', {})
    flags = settings.get('compile_flags', configured_flags.get('compile', ['/O2', '/MD', '/Gy', '/GF', '/GS']))
    link_flags = settings.get('link_flags', configured_flags.get('link', []))
    tools = [toolroot / 'bin' / name for name in adapter['toolchain_core']]
    manifest = {'schema_version': 1, 'binary': binary, 'build_id': build_id,
                'toolchain_name': toolchain_name or settings.get('toolchain', 'sp1'),
                'status': 'building', 'source_inputs': [], 'toolchain': [], 'commands': [],
                'artifacts': [], 'candidates': [], 'limitations': [
                    'Standalone LTCG context does not prove retail custom calling conventions.',
                    'MAP-derived function ends are unverified and cannot be admitted.',
                    'Compile flags remain provisional until configured from probes.']}
    inputs = {}

    def add_input(path):
        path = Path(path).resolve()
        digest = ltcg.sha256(path)
        old = inputs.get(str(path))
        if old and old != digest:
            raise ValueError('input changed during build: ' + str(path))
        inputs[str(path)] = digest

    def add_artifact(path, kind):
        manifest['artifacts'].append({'path': str(Path(path).resolve()), 'sha256': ltcg.sha256(path), 'kind': kind})

    try:
        if toolchain:
            for tool in toolchain.get('files', []):
                path = Path(tool['path']).resolve()
                digest = ltcg.sha256(path)
                if digest != tool['sha256']:
                    raise ValueError('toolchain pin mismatch: ' + str(path))
                manifest['toolchain'].append({'path': str(path), 'sha256': digest})
            if not manifest['toolchain']:
                raise ValueError('configured toolchain has no pinned inputs')
            add_input(toolchain_config)
        else:
            manifest['limitations'].append('Toolchain inventory not configured; gate admission unavailable.')
            for tool in tools:
                manifest['toolchain'].append({'path': str(tool.resolve()), 'sha256': ltcg.sha256(tool)})
        add_input(root / 'config' / 'project.json')
        for config in (root / 'config' / (binary + '.json'), root / 'config' / 'gate-allow.json',
                       root / 'config' / (binary + '-candidates.json')):
            if config.exists():
                add_input(config)
        selected = [source_path(root, unit) for unit in units] if units else sorted(
            path for path in (root / 'matching' / binary).rglob('*') if path.suffix.lower() in ('.c', '.cpp', '.cxx'))
        entries = registry_entries(root, binary)
        bindings = registry_referents(root, binary)
        for number, source in enumerate(selected):
            annotations = [annotation for annotation in parse_annotations(source, adapter) if annotation.binary == binary]
            if not annotations:
                continue
            group = out / ('unit-%03d' % number)
            group.mkdir()
            add_input(source)
            source_entries = [entry for entry in entries if source_path(root, entry['unit']) == source]
            for annotation in annotations:
                allowed = [entry for entry in source_entries if integer(entry['retail_va']) == annotation.retail_va]
                if len(allowed) > 1:
                    raise ValueError('duplicate registry address')
                if allowed:
                    if annotation.symbol and annotation.symbol != allowed[0]['symbol']:
                        raise ValueError('annotation and registry symbols disagree')
                    annotation.symbol = allowed[0]['symbol']
            dependencies = {source_path(root, path) for entry in source_entries for path in entry.get('dependencies', [])}
            dependencies.update(source_path(root, path) for path in settings.get('dependencies', {}).get(source.relative_to(root).as_posix(), []))
            objects = []
            group_link_flags = list(link_flags)
            group_gl = False
            discovery_symbols = []
            for index, unit in enumerate([source] + sorted(dependencies - {source})):
                add_input(unit)
                unit_flags = list(flags)
                unit_options = settings.get('units', {}).get(unit.relative_to(root).as_posix(), {})
                gl = unit_gl(adapter, settings, unit.relative_to(root).as_posix())
                group_gl = group_gl or gl
                removed = {flag.lower() for flag in unit_options.get('remove_compile_flags', [])}
                unit_flags = [flag for flag in unit_flags if flag.lower() not in removed]
                unit_flags.extend(unit_options.get('compile_flags', []))
                group_link_flags.extend(flag for flag in unit_options.get('link_flags', []) if flag not in group_link_flags)
                if unit.suffix.lower() != '.c' and not any(flag.lower().startswith('/eh') for flag in unit_flags):
                    unit_flags.append('/EHsc')
                plain = group / ('discovery-%03d.obj' % index)
                for include in compile_unit(unit, plain, toolroot, unit_flags, env, manifest['commands'],
                                            adapter['compiler'], gl=False):
                    add_input(include)
                if index == 0:
                    discovery_symbols = function_symbols(plain)
                add_artifact(plain, 'discovery-object-not-candidate')
                obj = group / ('source-%03d.obj' % index)
                for include in compile_unit(unit, obj, toolroot, unit_flags, env, manifest['commands'],
                                            adapter['compiler'], gl):
                    if str(include) not in inputs:
                        raise ValueError('candidate compile introduced an input absent from discovery: ' + str(include))
                    add_input(include)
                objects.append(obj)
                add_artifact(obj, 'ltcg-object' if gl else 'object')
            roots = [discover_symbol(annotation, discovery_symbols) for annotation in annotations]
            roots += [name for entry in source_entries for name in entry.get('roots', [])]
            image_path, map_path = ltcg.link(toolroot, objects, roots, group, env, manifest['commands'], group_link_flags,
                                             ltcg=group_gl, base_flags=adapter['link_flags'], linker=adapter['linker'])
            add_artifact(image_path, 'linked-image')
            add_artifact(map_path, 'linker-map')
            from matchlib import PEImage
            image = PEImage(image_path)
            map_symbols = ltcg.read_map(map_path)
            for annotation, symbol in zip(annotations, roots):
                matches = [item for item in map_symbols if item.name == symbol]
                if len(matches) != 1:
                    raise ValueError('root does not identify one linked function: ' + symbol)
                start = matches[0].va
                allowed = next((entry for entry in source_entries if integer(entry['retail_va']) == annotation.retail_va), None)
                boundary = allowed.get('boundary', {}) if allowed else {}
                size = integer(allowed['size']) if allowed else None
                if size is None:
                    ends = [item.va for item in map_symbols if item.va > start and item.section == matches[0].section]
                    size = min(ends) - start if ends else 0
                    boundary = {'status': 'unverified', 'evidence': 'next MAP symbol; includes possible padding' if ends else 'no end boundary'}
                if size < 0 or size > 16 * 1024 * 1024:
                    raise ValueError('invalid extraction size')
                code = image.read_va(start, size) if size else b''
                refs = []
                ref_status = 'unresolved'
                ref_error = None
                try:
                    if size:
                        refs = ltcg.scan_referents(image, start, size, map_symbols, bindings)
                        ref_status = 'verified' if all(ref['resolved'] for ref in refs) else 'unresolved'
                except (ValueError, ImportError) as error:
                    ref_error = str(error)
                manifest['candidates'].append({'symbol': symbol, 'retail_va': annotation.retail_va,
                    'candidate_va': start, 'size': size, 'boundary': boundary,
                    'source_span': {'start': annotation.start, 'end': annotation.end},
                    'annotation_line': annotation.line, 'image_path': str(image_path),
                    'image_sha256': ltcg.sha256(image_path), 'bytes_sha256': hashlib.sha256(code).hexdigest(),
                    'source_path': str(source), 'source_sha256': ltcg.sha256(source),
                    'function_source_sha256': hashlib.sha256('\n'.join(source.read_text(encoding='utf-8-sig').splitlines()[annotation.start - 1:annotation.end]).encode('utf-8')).hexdigest(),
                    'referents': refs, 'referents_status': ref_status, 'referents_error': ref_error,
                    'rule_status': 'pending', 'compile_context': 'standalone-%s-with-real-dependencies' % ('ltcg' if group_gl else 'link')})
        for path, digest in inputs.items():
            if ltcg.sha256(path) != digest:
                raise ValueError('input changed during build: ' + path)
        for tool in manifest['toolchain']:
            if ltcg.sha256(tool['path']) != tool['sha256']:
                raise ValueError('toolchain changed during build: ' + tool['path'])
        manifest['status'] = 'built'
    except Exception as error:
        manifest['status'] = 'failed'
        manifest['error'] = str(error)
        raise
    finally:
        manifest['source_inputs'] = [{'path': path, 'sha256': digest} for path, digest in sorted(inputs.items())]
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    return manifest, destination


def compare_candidates(manifest, root, binary):
    from matchlib import PEImage
    project, settings = load_settings(root, binary)
    retail_path = settings.get('path') or str(Path(project['toolchain_root']) / 'bin' / settings['filename'])
    retail = PEImage(retail_path)
    bindings = registry_referents(root, binary)
    results = []
    for candidate in manifest['candidates']:
        size = candidate['size']
        image = PEImage(candidate['image_path'])
        ours = image.read_va(candidate['candidate_va'], size) if size else b''
        theirs = retail.read_va(candidate['retail_va'], size) if size else b''
        normalized = ours
        referents_status = 'unresolved'
        comparison_error = None
        if size:
            try:
                source_refs = ltcg.scan_referents(image, candidate['candidate_va'], size,
                    ltcg.read_map(Path(candidate['image_path']).with_suffix('.map')), bindings)
                retail_refs = ltcg.scan_referents(retail, candidate['retail_va'], size)
                normalized = relocate_for_comparison(candidate, ours, source_refs, retail_refs, bindings)
                referents_status = 'resolved'
            except (ValueError, ImportError) as error:
                comparison_error = str(error)
                referents_status = 'mismatch' if 'differs' in str(error) else 'unresolved'
        equal = sum(a == b for a, b in zip(normalized, theirs))
        exact = bool(size) and normalized == theirs and referents_status == 'resolved'
        results.append({'symbol': candidate['symbol'], 'retail_va': candidate['retail_va'],
                        'observed_at': datetime.now(timezone.utc).isoformat(),
                        'source_path': candidate['source_path'], 'source_sha256': candidate['source_sha256'],
                        'function_source_sha256': candidate['function_source_sha256'],
                        'build_id': manifest['build_id'], 'size': size,
                        'score': 100.0 * equal / size if size else None,
                        'score_kind': 'resolved-referents' if referents_status == 'resolved' else 'raw-bytes',
                        'raw_bytes_equal': bool(size) and ours == theirs,
                        'bytes_exact': exact,
                        'boundary_status': candidate['boundary'].get('status', 'unverified'),
                        'referents_status': referents_status, 'comparison_error': comparison_error, 'rule_status': 'pending',
                        'status': 'MATCH-PENDING' if exact else 'DIFF' if size else 'UNRESOLVED'})
    return results


def relocate_for_comparison(candidate, code, source_refs, retail_refs, bindings):
    """Diagnostic relocation only after ordered encodings and identities agree.

    These bytes are never spliced by this tool. The gate repeats every check
    independently and additionally verifies rules and complete image identity.
    """
    shape = lambda refs: [(ref['offset'], ref['width'], ref['kind']) for ref in refs]
    if shape(source_refs) != shape(retail_refs):
        raise ValueError('ordered referent encoding differs from retail')
    adjusted = bytearray(code)
    for source, retail in zip(source_refs, retail_refs):
        identity = source.get('identity')
        if identity and identity.startswith('self+0x'):
            offset = int(identity[7:], 16)
            if not 0 <= offset < len(code) or source['target'] != candidate['candidate_va'] + offset:
                raise ValueError('internal reference identity differs from candidate')
            target = candidate['retail_va'] + offset
        else:
            record = bindings.get(identity)
            if not record or not record.get('evidence'):
                raise ValueError('unresolved retail identity: ' + str(identity))
            target = integer(record['va'])
        if target != retail['target']:
            raise ValueError('ordered referent target differs from retail: ' + str(identity))
        offset, width = source['offset'], source['width']
        value = target if source['kind'] == 'abs32' else target - (candidate['retail_va'] + offset + width)
        if source['kind'] != 'abs32' and not -(1 << (width * 8 - 1)) <= value < 1 << (width * 8 - 1):
            raise ValueError('relative target cannot be encoded at retail address')
        adjusted[offset:offset + width] = (value & ((1 << (width * 8)) - 1)).to_bytes(width, 'little')
    return bytes(adjusted)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['build', 'match', 'diff'])
    parser.add_argument('--binary', required=True)
    parser.add_argument('--unit', action='append')
    parser.add_argument('--function')
    parser.add_argument('--output-dir')
    parser.add_argument('--manifest')
    parser.add_argument('--build-id')
    parser.add_argument('--toolchain', help='isolated toolchains.json selection, e.g. sp1 or rtm')
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args(argv)
    try:
        root = args.root.resolve()
        if args.command == 'match' and not args.unit:
            parser.error('match requires --unit')
        units = args.unit
        if args.command == 'diff':
            if not args.function:
                parser.error('diff requires --function')
            units = [entry['unit'] for entry in registry_entries(root, args.binary) if entry['symbol'] == args.function]
            if not units:
                parser.error('function has no configured unit in gate-allow.json')
        manifest, path = build(root, args.binary, args.output_dir, args.manifest, args.build_id, units, args.toolchain)
        print('Built %d candidate(s); manifest: %s' % (len(manifest['candidates']), path))
        if args.command != 'build':
            results = compare_candidates(manifest, root, args.binary)
            (path.parent / 'comparison.json').write_text(json.dumps(results, indent=2) + '\n', encoding='utf-8')
            for result in results:
                if args.command == 'diff' and result['symbol'] != args.function:
                    continue
                print('%s %s size=%d score=%s boundary=%s referents=%s' % (
                    result['status'], result['symbol'], result['size'], result['score'],
                    result['boundary_status'], result['referents_status']))
                if args.command == 'diff':
                    candidate = next(item for item in manifest['candidates'] if item['symbol'] == result['symbol'])
                    print_diff(root, args.binary, candidate)
        return 0
    except (OSError, ValueError, RuntimeError, ImportError, KeyError) as error:
        print('ERROR: ' + str(error), file=sys.stderr)
        return 1


def print_diff(root, binary, candidate):
    from matchlib import PEImage
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    project, settings = load_settings(root, binary)
    retail = PEImage(settings.get('path') or Path(project['toolchain_root']) / 'bin' / settings['filename'])
    ours = PEImage(candidate['image_path']).read_va(candidate['candidate_va'], candidate['size'])
    theirs = retail.read_va(candidate['retail_va'], candidate['size'])
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    left = list(decoder.disasm(theirs, candidate['retail_va']))
    right = list(decoder.disasm(ours, candidate['candidate_va']))
    print('RETAIL'.ljust(52) + 'CANDIDATE (first 24 instructions)')
    for index in range(min(24, max(len(left), len(right)))):
        def format_instruction(items):
            if index >= len(items):
                return ''
            ins = items[index]
            return '%08x %-8s %s' % (ins.address, ins.mnemonic, ins.op_str)
        print(format_instruction(left).ljust(52) + format_instruction(right))


if __name__ == '__main__':
    sys.exit(main())
