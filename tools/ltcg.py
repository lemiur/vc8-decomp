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


def link(toolchain_root, objects, roots, out_dir, env, commands, flags=()):
    out_dir = Path(out_dir)
    image = out_dir / 'candidate.dll'
    mapfile = out_dir / 'candidate.map'
    argv = [str(Path(toolchain_root) / 'bin' / 'link.exe'), '/nologo', '/DLL', '/NOENTRY',
            '/LTCG', '/MACHINE:X86', '/INCREMENTAL:NO', '/OPT:NOREF,NOICF', '/MANIFEST:NO',
            '/OUT:' + str(image), '/MAP:' + str(mapfile)]
    argv += ['/INCLUDE:' + root for root in sorted(set(roots))]
    argv += list(flags) + [str(obj) for obj in objects] + ['kernel32.lib']
    run_command(argv, out_dir, env, commands, [image, mapfile])
    if not image.is_file() or not mapfile.is_file():
        raise RuntimeError('successful link did not produce fresh image and MAP')
    return image, mapfile


def scan_referents(image, va, size, symbols=()):
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
    names = {}
    for symbol in symbols:
        names.setdefault(symbol.va, []).append(symbol.name)

    def add(offset, width, kind, target):
        identity = 'self+0x%x' % (target - va) if va <= target < va + size else None
        aliases = names.get(target, [])
        if identity is None and len(aliases) == 1:
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
            if operand.type == CS_OP_MEM and not operand.mem.base and not operand.mem.index:
                if ins.disp_size != 4:
                    raise ValueError('unsupported absolute memory operand width')
                add(off + ins.disp_offset, 4, 'abs32', operand.mem.disp & 0xffffffff)
            elif not branch and operand.type == CS_OP_IMM and ins.imm_size == 4:
                target = operand.imm & 0xffffffff
                try:
                    readable = len(image.read_va(target, 1)) == 1
                except ValueError:
                    readable = False
                if readable:
                    add(off + ins.imm_offset, 4, 'abs32', target)
    if decoded != size:
        raise ValueError('candidate span contains undecoded bytes')
    if relocation_sites - decoded_word_sites:
        raise ValueError('PE relocation is not a decoded four-byte operand')
    ordered = [refs[offset] for offset in sorted(refs)]
    if any(a['offset'] + a['width'] > b['offset'] for a, b in zip(ordered, ordered[1:])):
        raise ValueError('overlapping reference operands')
    return ordered
