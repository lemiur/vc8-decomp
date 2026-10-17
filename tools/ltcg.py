"""VC8 /GL + /LTCG candidate linker and evidence extraction.

No retail code or synthetic stub bytes are linked. Missing real dependencies are
link failures. Keeping roots standard-convention is an experiment, not evidence
that retail's whole-program custom calling conventions have been reproduced.
"""
from dataclasses import dataclass
from pathlib import Path
import hashlib
import os
import re
import subprocess


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


@dataclass(frozen=True)
class MapSymbol:
    name: str
    va: int
    section: int
    offset: int
    is_function: bool
    object_name: str


MAP_LINE = re.compile(r'^\s*([\da-fA-F]{4}):([\da-fA-F]{8})\s+(\S+)\s+([\da-fA-F]{8,16})\s+(?:(f)\s+)?(?:i\s+)?(.+?)\s*$')


def read_map(path):
    result = []
    for line in Path(path).read_text(encoding='latin-1').splitlines():
        match = MAP_LINE.match(line)
        if match and int(match[1], 16):
            result.append(MapSymbol(match[3], int(match[4], 16), int(match[1], 16),
                                    int(match[2], 16), bool(match[5]), match[6]))
    return result


def tool_environment(root):
    root = Path(root)
    env = dict(os.environ)
    env['PATH'] = os.pathsep.join([str(root / 'bin'), str(root.parent / 'Common7' / 'IDE'), env.get('PATH', '')])
    env['INCLUDE'] = os.pathsep.join(str(p) for p in (root / 'include', root / 'PlatformSDK' / 'include') if p.exists())
    env['LIB'] = os.pathsep.join(str(p) for p in (root / 'lib', root / 'PlatformSDK' / 'lib') if p.exists())
    # Ambient CL/LINK options would make the command's recorded flags incomplete.
    for key in ('CL', '_CL_', 'LINK', '_LINK_'):
        env.pop(key, None)
    return env


def run_command(argv, cwd, env, commands, produced=()):
    try:
        completed = subprocess.run([str(a) for a in argv], cwd=cwd, env=env,
                                   capture_output=True, text=True, errors='replace', timeout=120)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError('compiler/linker timed out after 120 seconds') from error
    output = completed.stdout + completed.stderr
    log = Path(cwd) / ('command-%02d.log' % len(commands))
    log.write_text(output, encoding='utf-8')
    commands.append({'argv': [str(a) for a in argv], 'cwd': str(Path(cwd).resolve()),
                     'returncode': completed.returncode, 'log_path': str(log.resolve()),
                     'log_sha256': sha256(log),
                     'produced': [str(Path(path).resolve()) for path in produced]})
    if completed.returncode:
        raise RuntimeError('command failed (%s):\n%s' % (completed.returncode, '\n'.join(output.splitlines()[-35:])))
    return completed


def link(toolchain_root, objects, roots, out_dir, env, commands, flags=(), ltcg=True,
         base_flags=('/OPT:NOREF,NOICF',), linker='link.exe'):
    """Link a candidate DLL; base_flags are the project adapter's link_flags."""
    out_dir = Path(out_dir)
    image = out_dir / 'candidate.dll'
    mapfile = out_dir / 'candidate.map'
    argv = [str(Path(toolchain_root) / 'bin' / linker), '/nologo', '/DLL', '/NOENTRY']
    argv += ['/LTCG'] if ltcg else []
    argv += ['/MACHINE:X86', '/INCREMENTAL:NO', *base_flags, '/MANIFEST:NO',
             '/OUT:' + str(image), '/MAP:' + str(mapfile)]
    argv += ['/INCLUDE:' + root for root in sorted(set(roots))]
    argv += list(flags) + [str(obj) for obj in objects] + ['kernel32.lib']
    run_command(argv, out_dir, env, commands, [image, mapfile])
    if not image.is_file() or not mapfile.is_file():
        raise RuntimeError('successful link did not produce fresh image and MAP')
    return image, mapfile


def scan_referents(image, va, size, symbols=(), bindings=None):
    """Independent decoder inputs are public; all targets remain evidence records.

    Return ordered external and internal branches plus HIGHLOW/absolute memory
    references. Fail closed on undecoded bytes or unsupported PE relocations.
    """
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_GRP_JUMP, CS_GRP_CALL, CS_OP_IMM, CS_OP_MEM
    code = image.read_va(va, size)
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True
    refs = {}
    relocation_sites = set()
    decoded_word_sites = set()
    memory_accesses = {}
    names = {}
    for symbol in symbols:
        names.setdefault(symbol.va, []).append(symbol.name)
    imports = {}
    for record in getattr(image, 'import_records', lambda: [])():
        imports.setdefault(record['va'], set()).add(record['identity'])

    def add(offset, width, kind, target):
        identity = 'self+0x%x' % (target - va) if va <= target < va + size else None
        aliases = names.get(target, [])
        if identity is None:
            imported = imports.get(target, set())
            if len(imported) == 1:
                identity = next(iter(imported))
            elif not imported:
                literals = []
                for key, binding in (bindings or {}).items():
                    if binding.get('kind') != 'literal':
                        continue
                    length = binding.get('size', 0)
                    if not isinstance(length, int) or not 0 < length <= 65536:
                        continue
                    try:
                        data = image.read_va(target, length)
                    except ValueError:
                        continue
                    if hashlib.sha256(data).hexdigest() == binding.get('bytes_sha256'):
                        literals.append(key)
                if len(literals) == 1:
                    identity = literals[0]
                elif not literals and len(aliases) == 1:
                    identity = aliases[0]
        record = {'offset': offset, 'width': width, 'kind': kind,
                  'target': target, 'identity': identity, 'resolved': identity is not None}
        old = refs.get(offset)
        if old is not None and old != record:
            raise ValueError('conflicting reference encodings at offset %#x' % offset)
        refs[offset] = record

    for relocation in image.base_relocations():
        site = relocation['va']
        width = relocation.get('width')
        if va <= site < va + size:
            if relocation['type'] != 3 or width != 4 or site + 4 > va + size:
                raise ValueError('unsupported or partial PE relocation in candidate')
            add(site - va, 4, 'abs32', int.from_bytes(image.read_va(site, 4), 'little'))
            relocation_sites.add(site - va)
    decoded = 0
    for ins in decoder.disasm(code, va):
        off = ins.address - va
        if off != decoded:
            raise ValueError('instruction decoding gap')
        decoded += ins.size
        if ins.imm_size == 4:
            decoded_word_sites.add(off + ins.imm_offset)
        if ins.disp_size == 4:
            decoded_word_sites.add(off + ins.disp_offset)
        branch = ins.group(CS_GRP_JUMP) or ins.group(CS_GRP_CALL)
        if branch and ins.operands and ins.operands[0].type == CS_OP_IMM:
            width = ins.imm_size
            if width not in (1, 4):
                raise ValueError('unsupported relative branch width')
            add(off + ins.imm_offset, width, 'rel%d' % (width * 8), ins.operands[0].imm & 0xffffffff)
        for operand in ins.operands:
            if operand.type == CS_OP_MEM and ins.disp_size == 4:
                memory_accesses[off + ins.disp_offset] = {
                    'width': operand.size, 'dynamic': bool(operand.mem.base or operand.mem.index),
                    'address_only': ins.mnemonic == 'lea'}
            if operand.type == CS_OP_MEM and not operand.mem.base:
                if ins.disp_size != 4:
                    raise ValueError('unsupported absolute memory operand width')
                add(off + ins.disp_offset, 4, 'abs32', operand.mem.disp & 0xffffffff)
            elif not branch and operand.type == CS_OP_IMM and ins.imm_size == 4:
                target = operand.imm & 0xffffffff
                try:
                    readable = len(image.read_va(target, 1)) == 1
                except ValueError:
                    readable = any(section['va'] <= target < section['va'] +
                                   max(section['vsize'], section['rawsize'])
                                   for section in getattr(image, 'sections', []))
                if readable:
                    add(off + ins.imm_offset, 4, 'abs32', target)
    if decoded != size:
        raise ValueError('candidate span contains undecoded bytes')
    if relocation_sites - decoded_word_sites:
        raise ValueError('PE relocation is not a decoded four-byte operand')
    ordered = [refs[offset] for offset in sorted(refs)]
    for ref in ordered:
        access = memory_accesses.get(ref['offset'])
        if ref['kind'] != 'abs32' or not access or access['address_only']:
            continue
        matches = []
        for identity, binding in (bindings or {}).items():
            if binding.get('kind') != 'member' or access['dynamic']:
                continue
            base_identity = binding.get('base_identity')
            base = (bindings or {}).get(base_identity, {})
            offset = binding.get('offset', -1)
            field_size, base_size = binding.get('size', 0), base.get('size', 0)
            if not all(isinstance(value, int) for value in (offset, field_size, base_size)):
                continue
            if not (0 <= offset and 0 < access['width'] <= field_size and offset + field_size <= base_size):
                continue
            witness = base.get('layout_witness')
            if not witness or binding.get('layout_witness') != witness:
                continue
            if set(names.get(ref['target'] - offset, [])) == {base_identity}:
                matches.append(identity)
        if len(matches) > 1:
            raise ValueError('ambiguous typed member identity')
        if matches:
            ref['identity'], ref['resolved'] = matches[0], True
        elif (bindings or {}).get(ref['identity'], {}).get('layout_witness'):
            # A struct's first field shares its base address. Memory access is
            # not proof of a whole-object identity; require the named field.
            ref['identity'], ref['resolved'] = None, False
    if any(a['offset'] + a['width'] > b['offset'] for a, b in zip(ordered, ordered[1:])):
        raise ValueError('overlapping reference operands')
    return ordered
