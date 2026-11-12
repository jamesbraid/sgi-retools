#!/usr/bin/env python3
"""Non-MIPS facts checked against hand-assembled instruction and ELF sequences."""
import contextlib
import io
import inspect
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hostfacts


def arm_dp(opcode, rn=0, rd=15, rm=1, immediate=None, flags=False, condition=14, shift=0):
    word=(condition<<28)|(opcode<<21)|(int(flags)<<20)|(rn<<16)|(rd<<12)
    word|=(1<<25)|immediate if immediate is not None else shift|rm
    return struct.pack('<I',word).hex()


def arm_elf(code='04109fe5000091e51eff2fe100000000', relocations=(), rela=False,
            thumb=False, mappings=(), symbol_size=None, copy_size=8, elf_type=3,
            dynamic=False, dynamic_changes=None, hide_relocations=False):
    """Assemble a small ELF32 file with separate executable and writable loads."""
    code = bytes.fromhex(code)
    names = b'\0entry\0external\0alias\0object\0undefined_function\0'
    symbols = [bytes(16)]
    for address, mode in mappings:
        at = len(names); names += ('$'+mode).encode()+b'\0'
        symbols.append(struct.pack('<IIIBBH', at, address, 0, 0, 0, 1))
    first_global = len(symbols)
    size = symbol_size if symbol_size is not None else len(code)-4
    symbols.append(struct.pack('<IIIBBH', 1, 0x2000+thumb, size, 0x12, 0, 1))
    external = len(symbols)
    symbols.append(struct.pack('<IIIBBH', 7, 0, copy_size, 0x11, 0, 0))
    symbols.append(struct.pack('<IIIBBH', 16, 0x2000+thumb, size, 0x12, 0, 1))
    symbols.append(struct.pack('<IIIBBH', 22, 0x2000, 4, 0x11, 0, 1))
    symbols.append(struct.pack('<IIIBBH', 29, 0, 0, 0x12, 0, 0))
    rel = b''
    for kind, site in relocations:
        info = ((0 if kind in (0, 23) else external) << 8) | kind
        rel += struct.pack('<IIi' if rela else '<II', site, info, -4) if rela else struct.pack('<II', site, info)
    shnames = b'\0.text\0.data\0.strtab\0.symtab\0.rel.dyn\0.shstrtab\0'
    nameat = lambda n: shnames.index(n.encode()+b'\0')
    raw = bytearray(0x190)
    raw[0x100:0x100+len(code)] = code
    raw[0x180:0x190] = struct.pack('<IIII', 7, 8, 9, 10)
    tags = {}
    if dynamic:
        tags = {7 if rela else 17:0x4000, 8 if rela else 18:len(rel), 9 if rela else 19:12 if rela else 8,
                6:0x5000, 11:16, 5:0x6000, 10:len(names)}
        for key, value in (dynamic_changes or {}).items():
            if value is None:tags.pop(key, None)
            else:tags[key]=value
        raw += b''.join(struct.pack('<II',k,v)for k,v in tags.items())+bytes(8)
    dynamic_size = len(raw)-0x190
    strings = len(raw); raw += names
    while len(raw) % 4: raw += b'\0'
    syms = len(raw); raw += b''.join(symbols)
    relpos = len(raw); raw += rel
    shstr = len(raw); raw += shnames
    while len(raw) % 4: raw += b'\0'
    shoff = len(raw)
    sections = [(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
                (nameat('.text'), 1, 6, 0x2000, 0x100, len(code), 0, 0, 4, 0),
                (nameat('.data'), 1, 3, 0x3000, 0x180, 16, 0, 0, 4, 0),
                (nameat('.strtab'), 3, 2 if dynamic else 0, 0x6000 if dynamic else 0, strings, len(names), 0, 0, 1, 0),
                (nameat('.symtab'), 11 if dynamic else 2, 2 if dynamic else 0, 0x5000 if dynamic else 0, syms, 16*len(symbols), 3, first_global, 4, 16),
                (nameat('.rel.dyn'), 1 if hide_relocations else 4 if rela else 9, 2, 0x4000 if dynamic else 0, relpos, len(rel), 4, 0, 4, 12 if rela else 8),
                (nameat('.shstrtab'), 3, 0, 0, shstr, len(shnames), 0, 0, 1, 0)]
    for section in sections: raw += struct.pack('<10I', *section)
    ident = b'\x7fELF'+bytes([1, 1, 1, 0])+bytes(8)
    raw[:52] = ident+struct.pack('<HHIIIIIHHHHHH', elf_type, 40, 1, 0x2000+thumb,
                                52, shoff, 0, 52, 32, 6 if dynamic else 2, 40, 7, 6)
    raw[52:84] = struct.pack('<8I', 1, 0x100, 0x2000, 0x2000, len(code), len(code), 5, 0x80)
    raw[84:116] = struct.pack('<8I', 1, 0x180, 0x3000, 0x3000, 16+dynamic_size, max(64,16+dynamic_size), 6, 0x80)
    if dynamic:
        loads = [(1,relpos,0x4000,0x4000,len(rel),len(rel),4,4),
                 (1,syms,0x5000,0x5000,16*len(symbols),16*len(symbols),4,4),
                 (1,strings,0x6000,0x6000,len(names),len(names),4,1),
                 (2,0x190,0x3010,0x3010,dynamic_size,dynamic_size,6,4)]
        for n, load in enumerate(loads):raw[116+n*32:148+n*32]=struct.pack('<8I',*load)
    return bytes(raw)


class FirmwareFacts(unittest.TestCase):
    def test_arm_unknown_alu_pc_write_stops_literal_fallthrough(self):
        fs,_=self.analyze('arm','0cf08ae20700a0e31eff2fe1')
        self.assertEqual(fs['blocks'][0]['kind'],'jump')
        self.assertIsNone(fs['blocks'][0]['target'])
        self.assertEqual(fs['blocks'][0]['successors'],[])
        self.assertEqual(fs['coverage']['unresolved_transfers'],['0x1000'])
        self.assertEqual(fs['exits'],[])
        self.assertEqual(fs['unreached'],['0x1004','0x1008'])
        self.assertFalse(any(c['value']=='0x7'for c in fs['constants']))

    def test_arm_computed_pc_target_join_does_not_leave_orphan_effects(self):
        fs,_=self.analyze('arm','0000a0e300f18fe0000081e50100a0e3fbffffea')
        self.assertEqual([b['first']for b in fs['blocks']],['0x1000','0x1004'])
        self.assertEqual(fs['blocks'][1]['successors'],[])
        self.assertIsNone(fs['blocks'][1]['target'])
        self.assertFalse(any(c['address']=='0x100c'for c in fs['constants']))
        self.assertEqual(fs['unreached'],['0x1008','0x100c','0x1010'])
        fs,_=self.analyze('arm','0000a0e3000051e300f18f001eff2fe10100a0e3faffffea')
        self.assertEqual([b['first']for b in fs['blocks']],['0x1000','0x1004','0x1008','0x100c'])
        self.assertEqual(fs['exits'][0]['value'],'0x0')
        self.assertFalse(any(c['address']=='0x1010'for c in fs['constants']))

    def test_arm_explicit_alu_pc_destinations_are_transfers_not_returns(self):
        cases=[arm_dp(op,rn=0,rm=1)for op in (0,1,2,3,4,5,6,7,12,14)]
        cases += [arm_dp(15,rm=0),arm_dp(13,rm=14,shift=1<<7),arm_dp(13,rm=14,flags=True),arm_dp(2,rn=14,immediate=0,flags=True)]
        for code in cases:
            with self.subTest(code=code):
                fs,_=self.analyze('arm',code+'0700a0e31eff2fe1')
                self.assertEqual(fs['blocks'][0]['kind'],'jump')
                self.assertEqual(fs['blocks'][0]['successors'],[])
                self.assertEqual(fs['exits'],[])

    def test_arm_conditional_pc_write_keeps_only_the_nonexecuted_path(self):
        fs,text=self.analyze('arm','000050e3'+arm_dp(4,rn=10,immediate=12,condition=0)+'0700a0e31eff2fe1')
        b=next(b for b in fs['blocks']if b['first']=='0x1004')
        self.assertEqual(b['kind'],'conditional')
        self.assertIsNone(b['target'])
        self.assertEqual(b['successors'],[{'kind':'falls through','block':'B2'}])
        self.assertEqual(b['taken_when'],'r0 == 0x0')
        self.assertEqual(b['falls_through_when'],'r0 != 0x0')
        self.assertEqual(fs['exits'][0]['value'],'0x7')
        self.assertIn('0x1004',fs['coverage']['unresolved_transfers'])
        fs,_=self.analyze('arm','000050e3'+arm_dp(4,rn=10,immediate=12,condition=0,flags=True)+'0000001a0700a0e31eff2fe1')
        b=next(b for b in fs['blocks']if b['first']=='0x1008')
        self.assertEqual(b['taken_when'],'r0 != 0x0')

    def test_arm_pc_source_and_coprocessor_flag_forms_do_not_become_jumps(self):
        cases=[arm_dp(op,rn=15,rd=0,rm=0,flags=True)for op in (8,9,10,11)]
        cases += ['10ff11ee','00f080e5','008080e8']
        for code in cases:
            with self.subTest(code=code):
                fs,_=self.analyze('arm',code+'0700a0e31eff2fe1')
                self.assertEqual(fs['blocks'][0]['kind'],'normal')
                self.assertEqual(fs['exits'][0]['value'],'0x7')

    def test_arm_aligned_add_sub_pc_targets_skip_intervening_effects(self):
        fs,_=self.analyze('arm','04f08fe2000081e56300a0e30700a0e31eff2fe1')
        self.assertEqual(fs['blocks'][0]['target'],'0x100c')
        self.assertEqual(fs['blocks'][0]['successors'],[{'kind':'taken','block':'B3'}])
        self.assertFalse(any(a['address']=='0x1004'for a in fs['accesses']))
        self.assertEqual(fs['exits'][0]['value'],'0x7')
        fs,_=self.analyze('arm',arm_dp(2,rn=15,immediate=4)+'0700a0e31eff2fe1')
        self.assertEqual(fs['blocks'][0]['target'],'0x1004')
        self.assertEqual(fs['blocks'][0]['kind'],'jump')
        fs,_=self.analyze('arm','0ca09fe50cf08ae2000081e50700a0e31eff2fe100100000')
        self.assertEqual(next(b for b in fs['blocks']if b['first']=='0x1004')['target'],'0x100c')
        self.assertEqual(fs['exits'][0]['value'],'0x7')

    def test_arm_carry_flags_alignment_and_unknown_shift_do_not_invent_targets(self):
        cases=[arm_dp(5,rn=15,immediate=0),arm_dp(4,rn=15,immediate=0,flags=True),
               arm_dp(4,rn=15,immediate=1),arm_dp(4,rn=15,rm=0,shift=2<<7)]
        for code in cases:
            with self.subTest(code=code):
                fs,_=self.analyze('arm',code+'0700a0e31eff2fe1')
                self.assertEqual(fs['blocks'][0]['kind'],'jump')
                self.assertIsNone(fs['blocks'][0]['target'])
                self.assertEqual(fs['exits'],[])

    def test_arm_alu_pc_write_does_not_acquire_a_manual_call(self):
        fs,_=self.analyze('arm','0fe0a0e10cf08ae20700a0e31eff2fe1')
        b=next(b for b in fs['blocks']if b['first']=='0x1004')
        self.assertEqual(b['kind'],'jump')
        self.assertEqual(b['successors'],[])
        self.assertEqual(fs['calls'],[])
        for code in ('0ef0a0e1','1eff2fe1'):
            fs,_=self.analyze('arm',code)
            self.assertEqual(fs['blocks'][0]['kind'],'return')

    def test_thumb_add_pc_uses_unaligned_data_pc_and_preserves_thumb_state(self):
        fs,_=self.analyze('thumb','0420874401606320c04607207047')
        b=next(b for b in fs['blocks']if b['first']=='0x1002')
        self.assertEqual(b['target'],'0x100a')
        self.assertEqual(b['kind'],'jump')
        self.assertFalse(any(a['address']=='0x1004'for a in fs['accesses']))
        self.assertEqual(fs['exits'][0]['value'],'0x7')
        fs,_=self.analyze('thumb','874407207047')
        self.assertEqual(fs['blocks'][0]['kind'],'jump')
        self.assertIsNone(fs['blocks'][0]['target'])
        self.assertEqual(fs['exits'],[])

    def test_arm_elf_pc_control_never_maps_a_runtime_integer_by_coincidence(self):
        _,_,fs=self.elf_facts(arm_elf('04f08fe2000081e56300a0e30700a0e31eff2fe1',symbol_size=20))
        self.assertEqual(fs['blocks'][0]['target'],'0x200c')
        self.assertEqual(fs['blocks'][0].get('target_coordinate_basis'),'linked ELF virtual address')
        self.assertEqual(fs['exits'][0]['value'],'0x7')
        _,_,fs=self.elf_facts(arm_elf('0ca09fe50cf08ae2000081e50700a0e31eff2fe100200000',symbol_size=20))
        b=next(b for b in fs['blocks']if b['first']=='0x2004')
        self.assertIsNone(b['target'])
        self.assertEqual(b['successors'],[])
        self.assertEqual(fs['exits'],[])

    def test_arm_thumb_computed_pc_arithmetic_wraps_at_32_bits(self):
        for arch,load,code,site,target in [('arm',0xfffffff8,'00f08fe20700a0e3','0xfffffff8','0x0'),
                                         ('thumb',0xfffffffa,'022087440720','0xfffffffc','0x2')]:
            with self.subTest(arch=arch):
                with tempfile.TemporaryDirectory()as directory:
                    path=os.path.join(directory,'image')
                    with open(path,'wb')as stream:stream.write(bytes.fromhex(code))
                    r=hostfacts.routine_for(path,hex(load),size=len(bytes.fromhex(code)),flat=True,load=load,arch=arch);fs=r.facts()
                b=next(b for b in fs['blocks']if b['first']==site)
                self.assertEqual(b['target'],target)
                self.assertEqual(b['kind'],'jump')
                self.assertEqual(fs['exits'],[])

    def test_arm_extracted_load_image_remains_flat_without_elf_opt_in(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'load.bin')
            with open(path, 'wb') as stream: stream.write(arm_elf())
            image = hostfacts.FirmwareImage(path, 'arm', 0x2000)
            self.assertEqual(image.kind, 'flat')
            self.assertEqual(image.read(0x2000, 4), b'\x7fELF')

    def elf_image(self, raw, arch='arm', load=0x2000, **kwargs):
        self.assertIn('elf', inspect.signature(hostfacts.FirmwareImage).parameters)
        d = tempfile.TemporaryDirectory(); self.addCleanup(d.cleanup)
        p = os.path.join(d.name, 'image.elf')
        with open(p, 'wb') as stream: stream.write(raw)
        return hostfacts.FirmwareImage(p, arch, load, elf=True, **kwargs)

    def elf_facts(self, raw, arch='arm', size=None):
        image = self.elf_image(raw, arch)
        self.assertEqual(image.kind, 'elf')
        name, addr, size, source = image.find('entry', size)
        routine = hostfacts.FirmwareRoutine(image, name, addr, size, source)
        return image, routine, routine.facts()

    def test_arm_elf_maps_loads_and_defined_function_symbols(self):
        image = self.elf_image(arm_elf())
        self.assertEqual(image.kind, 'elf')
        self.assertEqual(image.read(0x2000, 4).hex(), '04109fe5')
        self.assertIsNone(image.read(0x2010, 1))
        self.assertIsNone(image.read(0x3010, 1))
        self.assertEqual(image.find('entry', None)[1:3], (0x2000, 12))
        self.assertEqual(image.find('alias', None)[1:3], (0x2000, 12))
        self.assertIsNone(image.name_at(0x2000))
        for name in ('external', 'object', 'undefined_function'):
            with self.assertRaises(ValueError): image.find(name, None)

    def test_arm_elf_relocated_zero_literal_never_becomes_absolute_zero(self):
        for rela in (False, True):
            with self.subTest(rela=rela):
                _, _, fs = self.elf_facts(arm_elf(relocations=[(2, 0x200c)], rela=rela))
                dereference = next(a for a in fs['accesses'] if a['address'] == '0x2004')
                self.assertNotIn('absolute', dereference)
                self.assertEqual(fs['exits'][0]['value'], '?')
                self.assertTrue(any('relocation' in w for w in fs['warnings']))

    def test_arm_elf_unreached_relocated_pool_does_not_block_body(self):
        _, _, fs = self.elf_facts(arm_elf(relocations=[(23, 0x200c)], symbol_size=16))
        self.assertIn('0x200c', fs['unreached'])
        self.assertEqual(len(fs['exits']), 1)
        self.assertNotIn('absolute', next(a for a in fs['accesses'] if a['address']=='0x2004'))

    def test_arm_elf_genuine_readonly_zero_and_nonzero_remain_constants(self):
        for value in (0, 7):
            code = '00009fe51eff2fe1'+struct.pack('<I', value).hex()
            _, _, fs = self.elf_facts(arm_elf(code))
            self.assertEqual(fs['exits'][0]['value'], hex(value))

    def test_arm_elf_writable_initial_word_is_not_a_runtime_constant(self):
        _, _, fs = self.elf_facts(arm_elf('f80f9fe51eff2fe1', symbol_size=8))
        self.assertNotEqual(fs['exits'][0]['value'], '0x7')

    def test_arm_elf_relocation_partial_overlap_and_copy_extent(self):
        image = self.elf_image(arm_elf(relocations=[(2, 0x200c)]))
        self.assertEqual(image.kind, 'elf')
        for start, width in ((0x200c, 1), (0x200d, 2), (0x200b, 2)):
            self.assertIsNone(image.read_constant(start, width))
        image = self.elf_image(arm_elf(relocations=[(20, 0x3000)], elf_type=2, copy_size=8))
        self.assertIsNone(image.read_constant(0x3004, 4))
        self.assertEqual(image.relocations[0]['size'], 8)
        image = self.elf_image(arm_elf('04109fe5000091e51eff2fe10000000007000000',
                                      relocations=[(20,0x200c)],elf_type=2,copy_size=8,symbol_size=12))
        self.assertIsNone(image.read_constant(0x2010,4))
        for copy_size, elf_type in ((0,2),(8,3)):
            with self.subTest(copy_size=copy_size,elf_type=elf_type),self.assertRaises(ValueError):
                self.elf_image(arm_elf(relocations=[(20,0x3000)],copy_size=copy_size,elf_type=elf_type))

    def test_arm_elf_none_relocation_does_not_taint(self):
        _, _, fs = self.elf_facts(arm_elf('00009fe51eff2fe100000000', relocations=[(0, 0x2008)]))
        self.assertEqual(fs['exits'][0]['value'], '0x0')

    def test_arm_elf_reached_relocated_opcode_cannot_build_a_cfg(self):
        image = self.elf_image(arm_elf(relocations=[(2, 0x2000)]))
        self.assertEqual(image.kind, 'elf')
        name, addr, size, source = image.find('entry', None)
        routine = hostfacts.FirmwareRoutine(image, name, addr, size, source)
        with self.assertRaisesRegex(ValueError, 'relocation-dependent instruction'):
            routine.facts()

    def test_arm_elf_rejects_unknown_relocations_and_bad_sites(self):
        for kind, site in ((255, 0x200c), (2, 0x5000), (2, 0x200e)):
            with self.subTest(kind=kind, site=site), self.assertRaises(ValueError):
                self.elf_image(arm_elf(relocations=[(kind, site)]))

    def test_arm_elf_checks_load_offset_architecture_and_endianness(self):
        for kwargs in ({'load': 0}, {'offset': 1}, {'arch': 'x86-32'}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError): self.elf_image(arm_elf(), **kwargs)
        raw = bytearray(arm_elf()); raw[5] = 2
        with self.assertRaises(ValueError): self.elf_image(bytes(raw))
        raw = bytearray(arm_elf()); raw[4] = 2
        with self.assertRaises(ValueError): self.elf_image(bytes(raw))

    def test_arm_elf_thumb_symbol_and_mapping_modes_are_checked(self):
        raw = arm_elf('00207047', thumb=True, symbol_size=4, mappings=[(0x2000, 't')])
        _, _, fs = self.elf_facts(raw, 'thumb')
        self.assertEqual(fs['exits'][0]['value'], '0x0')
        image = self.elf_image(raw)
        with self.assertRaisesRegex(ValueError, 'mode'): image.find('entry', None)
        image = self.elf_image(arm_elf(mappings=[(0x2000, 'a'), (0x2004, 't')]))
        self.assertEqual(image.kind, 'elf')
        name, addr, size, source = image.find('entry', None)
        with self.assertRaisesRegex(ValueError, 'mode'):
            hostfacts.FirmwareRoutine(image, name, addr, size, source).facts()

    def test_arm_elf_reports_linked_coordinates_and_unknown_runtime_base(self):
        _, routine, fs = self.elf_facts(arm_elf())
        self.assertEqual(fs['routine']['coordinate_basis'], 'linked ELF virtual addresses')
        self.assertEqual(fs['routine']['runtime_load_base'], 'unknown')
        self.assertIn('runtime load base unknown', hostfacts.render(routine, fs))

    def test_arm_elf_taint_reaches_calls_conditions_returns_and_indirect_targets(self):
        _, _, fs = self.elf_facts(arm_elf('08009fe50d0000eb1eff2fe10000a0e100000000',
                                        relocations=[(2,0x2010)], symbol_size=12))
        self.assertEqual(fs['calls'][0]['args'][0]['value'], '?')
        _, _, fs = self.elf_facts(arm_elf('10009fe5000050e30000000a1eff2fe11eff2fe10000a0e100000000',
                                        relocations=[(23,0x2018)], symbol_size=20))
        branch = next(b for b in fs['blocks'] if 'taken_when' in b)
        self.assertEqual(branch['taken_when'], '? == 0x0')
        self.assertTrue(all(e['value']=='?' for e in fs['exits']))
        self.assertFalse(any(c['register']=='r0' for c in fs['constants']))
        _, _, fs = self.elf_facts(arm_elf('04309fe533ff2fe11eff2fe100000000', relocations=[(2,0x200c)]))
        self.assertIsNone(fs['calls'][0]['target'])
        self.assertIsNone(fs['calls'][0]['callee'])

    def test_arm_elf_rejects_malformed_load_and_symbol_mapping(self):
        raw = bytearray(arm_elf()); struct.pack_into('<I', raw, 52+20, 4)
        with self.assertRaises(ValueError): self.elf_image(bytes(raw))
        raw = bytearray(arm_elf()); struct.pack_into('<I', raw, 84+8, 0x2000)
        with self.assertRaises(ValueError): self.elf_image(bytes(raw))
        raw = bytearray(arm_elf()); struct.pack_into('<I', raw, 52+24, 4)
        image = self.elf_image(bytes(raw))
        with self.assertRaises(ValueError): image.find('entry', None)

    def test_arm_elf_cli_and_routine_api_require_unambiguous_input_mode(self):
        self.assertIn('elf', inspect.signature(hostfacts.routine_for).parameters)
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'image.elf')
            with open(path, 'wb') as stream: stream.write(arm_elf())
            with self.assertRaises(ValueError):
                hostfacts.routine_for(path, 'entry', flat=True, load=0x2000, arch='arm', elf=True)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                hostfacts.main([path,'entry','--arch','arm','--elf','--load','0x2000','--json'])
            import json
            self.assertEqual(json.loads(output.getvalue())['routine']['kind'], 'elf')

    def test_arm_elf_numeric_entry_respects_containing_thumb_function(self):
        image = self.elf_image(arm_elf('0020012070477047', thumb=True, symbol_size=8))
        with self.assertRaisesRegex(ValueError, 'mode'): image.find('0x2004', 4)

    def test_arm_elf_reports_only_relocations_relevant_to_selected_routine(self):
        _, routine, fs = self.elf_facts(arm_elf(relocations=[(2,0x200c),(21,0x3000)]))
        self.assertEqual([r['address'] for r in fs['relocations']], ['0x200c'])
        self.assertIn('ELF relocation-dependent places (1)', hostfacts.render(routine, fs))

    def test_arm_elf_dynamic_tables_must_have_complete_matching_metadata(self):
        for rela in (False, True):
            _, _, fs = self.elf_facts(arm_elf(relocations=[(2,0x200c)],rela=rela,dynamic=True))
            self.assertNotIn('absolute', next(a for a in fs['accesses']if a['address']=='0x2004'))
        cases = [(True, {}), (False, {18:None}), (False, {19:4}),
                 (False, {18:16}), (False, {17:0x4004}),
                 (False, {6:0x5004}), (False, {5:0x6001}),
                 (False, {36:0x4000,35:8,37:4}), (False,{0x60000011:0x4000})]
        for hidden, changes in cases:
            with self.subTest(hidden=hidden,changes=changes), self.assertRaises(ValueError):
                self.elf_image(arm_elf(relocations=[(2,0x200c)],dynamic=True,
                                       hide_relocations=hidden,dynamic_changes=changes))

    def test_arm_elf_unreviewed_named_dynamic_extensions_are_rejected(self):
        with self.assertRaisesRegex(ValueError,'DT_GNU_CONFLICT'):
            self.elf_image(arm_elf(relocations=[(2,0x200c)],dynamic=True,
                                   dynamic_changes={0x6ffffef8:0x4000}))
        with self.assertRaises(ValueError):
            self.elf_image(arm_elf(relocations=[(23,0x200c)],dynamic=True,
                                   dynamic_changes={0x6ffffffa:2}))

    def test_arm_elf_accepted_dynamic_records_always_taint_their_places(self):
        for rela in (False,True):
            for kind in (2,23):
                for info in (0,1,3,6):
                    for flags in (0,2):
                        for strings_allocated in (False,True):
                            with self.subTest(rela=rela,kind=kind,info=info,flags=flags,strings_allocated=strings_allocated):
                                raw=bytearray(arm_elf(relocations=[(kind,0x200c)],rela=rela,dynamic=True,dynamic_changes={22:0}))
                                shoff=struct.unpack_from('<I',raw,32)[0]
                                struct.pack_into('<I',raw,shoff+5*40+28,info)
                                struct.pack_into('<I',raw,shoff+5*40+8,flags)
                                struct.pack_into('<I',raw,shoff+3*40+8,2 if strings_allocated else 0)
                                try:image=self.elf_image(bytes(raw))
                                except ValueError:
                                    self.assertIn(info,(3,6))
                                    continue
                                self.assertTrue(image.relocation_overlap(0x200c,4))
                                name,addr,size,source=image.find('entry',None)
                                fs=hostfacts.FirmwareRoutine(image,name,addr,size,source).facts()
                                self.assertNotIn('absolute',next(a for a in fs['accesses']if a['address']=='0x2004'))
                                self.assertEqual(fs['exits'][0]['value'],'?')

    def test_arm_elf_dynamic_validation_requires_the_consumed_taint_to_remain(self):
        image=self.elf_image(arm_elf(relocations=[(2,0x200c)],dynamic=True,dynamic_changes={22:0}))
        image.relocations.clear()
        with self.assertRaises(ValueError):image.check_dynamic_relocations(list(image.elf.iter_sections()))

    def test_arm_elf_relative_count_checks_the_actual_prefix_types(self):
        for rela in (False,True):
            counttag=0x6ffffff9 if rela else 0x6ffffffa
            for first in (0,2):
                with self.subTest(rela=rela,first=first),self.assertRaises(ValueError):
                    self.elf_image(arm_elf(relocations=[(first,0x200c),(23,0x3000)],rela=rela,dynamic=True,dynamic_changes={22:0,counttag:1}))
            image=self.elf_image(arm_elf(relocations=[(23,0x200c),(0,0x3000)],rela=rela,dynamic=True,dynamic_changes={22:0,counttag:1}))
            self.assertTrue(image.relocation_overlap(0x200c,4))
            with self.subTest(rela=rela,second_prefix=True),self.assertRaises(ValueError):
                self.elf_image(arm_elf(relocations=[(23,0x200c),(0,0x3000)],rela=rela,dynamic=True,dynamic_changes={22:0,counttag:2}))

    def test_arm_elf_none_and_empty_relative_count_controls_remain_valid(self):
        for rela in (False,True):
            counttag=0x6ffffff9 if rela else 0x6ffffffa
            for count in (None,0):
                changes={22:0}if count is None else{22:0,counttag:count}
                _,_,fs=self.elf_facts(arm_elf(relocations=[(0,0x200c)],rela=rela,dynamic=True,dynamic_changes=changes))
                self.assertEqual(next(a for a in fs['accesses']if a['address']=='0x2004')['absolute'],'0x0')
                image=self.elf_image(arm_elf(rela=rela,dynamic=True,dynamic_changes=changes))
                self.assertEqual(image.relocations,[])
            with self.subTest(rela=rela,empty_positive=True),self.assertRaises(ValueError):
                self.elf_image(arm_elf(rela=rela,dynamic=True,dynamic_changes={22:0,counttag:1}))

    def test_arm_elf_nonruntime_sections_and_conflicting_count_hints(self):
        raw=bytearray(arm_elf(relocations=[(2,0x200c)]));shoff=struct.unpack_from('<I',raw,32)[0]
        struct.pack_into('<I',raw,shoff+5*40+28,6);struct.pack_into('<I',raw,shoff+5*40+8,0)
        image=self.elf_image(bytes(raw));self.assertEqual(image.relocations,[])
        for rela in (False,True):
            counttag=0x6ffffff9 if rela else 0x6ffffffa
            raw=bytearray(arm_elf(relocations=[(0,0x200c)],rela=rela,dynamic=True,dynamic_changes={22:0,counttag:1,0x6ffffffe:0}))
            struct.pack_into('<I',raw,0x190+9*8,counttag)
            with self.subTest(rela=rela),self.assertRaises(ValueError):self.elf_image(bytes(raw))

    def test_arm_elf_missing_sections_cannot_hide_dynamic_relocations(self):
        raw = bytearray(arm_elf(relocations=[(2,0x200c)],dynamic=True))
        struct.pack_into('<I',raw,32,0);struct.pack_into('<HH',raw,48,0,0)
        with self.assertRaises(ValueError):self.elf_image(bytes(raw))

    def test_arm_elf_empty_dynamic_relocation_table_needs_no_mapped_bytes(self):
        try:
            _, _, fs = self.elf_facts(arm_elf('00009fe51eff2fe100000000',dynamic=True))
        except ValueError as error:
            self.fail('a valid empty relocation table was rejected: '+str(error))
        self.assertEqual(fs['exits'][0]['value'], '0x0')

    def test_arm_elf_zero_sized_function_requires_an_explicit_extent(self):
        image = self.elf_image(arm_elf(symbol_size=0))
        with self.assertRaisesRegex(ValueError, 'ELF.*--size'):image.find('entry',None)
        self.assertEqual(image.find('entry',12)[1:3],(0x2000,12))

    def test_arm_elf_nonallocated_function_cannot_name_a_runtime_callee(self):
        raw = bytearray(arm_elf());shoff=struct.unpack_from('<I',raw,32)[0]
        struct.pack_into('<I',raw,shoff+40+8,4)
        syms=struct.unpack_from('<I',raw,shoff+4*40+16)[0];raw[syms+3*16+12]=0x11
        image=self.elf_image(bytes(raw))
        self.assertNotIn('entry',image.symbols)
        self.assertIsNone(image.name_at(0x2000))

    def test_arm_elf_mapping_markers_require_mapping_symbol_attributes(self):
        for info, size in ((0x10,0),(2,0),(0,4)):
            raw=bytearray(arm_elf(mappings=[(0x2000,'a')]));shoff=struct.unpack_from('<I',raw,32)[0]
            syms=struct.unpack_from('<I',raw,shoff+4*40+16)[0]
            raw[syms+16+12]=info;struct.pack_into('<I',raw,syms+16+8,size)
            with self.subTest(info=info,size=size),self.assertRaises(ValueError):self.elf_image(bytes(raw))

    def test_arm_elf_dynamic_indirect_constant_does_not_name_a_linked_function(self):
        for elf_type in (3,2):
            raw=bytearray(arm_elf('04309fe533ff2fe11eff2fe100200000',elf_type=elf_type))
            shoff=struct.unpack_from('<I',raw,32)[0];syms=struct.unpack_from('<I',raw,shoff+4*40+16)[0]
            raw[syms+3*16+12]=0x11
            _,_,fs=self.elf_facts(bytes(raw))
            self.assertEqual(fs['calls'][0]['target'],'0x2000')
            self.assertIsNone(fs['calls'][0]['callee'])
            self.assertEqual(fs['calls'][0].get('target_coordinate_basis'),'runtime constant')
            self.assertEqual(fs['exits'][0]['value'],'ret(runtime 0x2000)')

    def test_arm_elf_dynamic_pc_values_remain_load_bias_relative(self):
        _,_,fs=self.elf_facts(arm_elf('00402de90fe0a0e10e00a0e10080bde8',symbol_size=16))
        self.assertNotEqual(fs['exits'][0]['value'],'0x200c')
        self.assertIn('ELF load bias',fs['exits'][0]['value'])
        self.assertFalse(any(c['register']in('lr','r0')for c in fs['constants']))
        _,_,fs=self.elf_facts(arm_elf())
        literal=next(a for a in fs['accesses']if a['address']=='0x2000')
        self.assertEqual(literal['linked_address'],'0x200c')
        self.assertNotIn('absolute',literal)
        self.assertIn('ELF load bias',literal['origin'])
        self.assertEqual(next(a for a in fs['accesses']if a['address']=='0x2004')['absolute'],'0x0')

    def test_arm_elf_direct_calls_keep_linked_target_identity(self):
        raw=bytearray(arm_elf('feffffeb1eff2fe1',symbol_size=8))
        shoff=struct.unpack_from('<I',raw,32)[0];syms=struct.unpack_from('<I',raw,shoff+4*40+16)[0];raw[syms+3*16+12]=0x11
        _,_,fs=self.elf_facts(bytes(raw))
        self.assertEqual(fs['calls'][0]['callee'],'entry')
        self.assertEqual(fs['calls'][0].get('target_coordinate_basis'),'linked ELF virtual address')
        _,_,fs=self.elf_facts(arm_elf('0e0000eb1eff2fe1',symbol_size=8))
        self.assertEqual(fs['exits'][0]['value'],'ret(linked ELF 0x2040)')

    def test_arm_elf_pc_relative_indirect_call_keeps_local_identity(self):
        raw=bytearray(arm_elf('00402de90fe0a0e10c304ee233ff2fe10080bde8',symbol_size=20))
        shoff=struct.unpack_from('<I',raw,32)[0];syms=struct.unpack_from('<I',raw,shoff+4*40+16)[0];raw[syms+3*16+12]=0x11
        _,_,fs=self.elf_facts(bytes(raw))
        self.assertEqual(fs['calls'][0]['callee'],'entry')
        self.assertEqual(fs['calls'][0].get('target_coordinate_basis'),'linked ELF virtual address')

    def test_arm_elf_data_addresses_and_scalar_returns_do_not_mix_domains(self):
        _,routine,fs=self.elf_facts(arm_elf('04109fe5000091e51eff2fe100200000'))
        access=next(a for a in fs['accesses']if a['address']=='0x2004')
        self.assertEqual(access['absolute'],'0x2000')
        self.assertEqual(access['coordinate_basis'],'runtime constant')
        self.assertNotIn('sym(',hostfacts.render(routine,fs))
        _,_,fs=self.elf_facts(arm_elf('00009fe51eff2fe100200000'))
        self.assertEqual(fs['exits'][0]['value'],'0x2000')
        _,routine,fs=self.elf_facts(arm_elf('04108fe2000091e51eff2fe107000000'))
        access=next(a for a in fs['accesses']if a['address']=='0x2004')
        self.assertNotIn('absolute',access)
        self.assertEqual(access['linked_address'],'0x200c')
        self.assertIn('ELF load bias',access['origin'])
        self.assertIn('coordinate_basis=ELF load-bias-relative',hostfacts.render(routine,fs))

    def test_arm_elf_pc_provenance_wraps_in_the_32_bit_address_domain(self):
        image=self.elf_image(arm_elf())
        self.assertEqual(hostfacts.facts.Render(image)(image.code_value(0x100000004)),
                         'ELF load bias (unknown)+4')

    def test_arm_elf_callee_identity_requires_matching_execution_state(self):
        for opcode, mode, name in [('0a0000fa','thumb','alias'),('0a0000eb','arm',None)]:
            with self.subTest(opcode=opcode):
                code=opcode+'1eff2fe1'+'0000a0e1'*10+'0b207047'
                raw=bytearray(arm_elf(code,symbol_size=8));shoff=struct.unpack_from('<I',raw,32)[0]
                syms=struct.unpack_from('<I',raw,shoff+4*40+16)[0];struct.pack_into('<II',raw,syms+3*16+4,0x2031,4)
                _,_,fs=self.elf_facts(bytes(raw))
                self.assertEqual(fs['calls'][0]['callee'],name)
                self.assertEqual(fs['calls'][0].get('target_arch'),mode)

    def test_arm_elf_pc_relative_thumb_pointer_retains_interworking_bit(self):
        code='00402de90fe0a0e125308ee233ff2fe10080bde8'+'0000a0e1'*7+'0b207047'
        raw=bytearray(arm_elf(code,symbol_size=20));shoff=struct.unpack_from('<I',raw,32)[0]
        syms=struct.unpack_from('<I',raw,shoff+4*40+16)[0];struct.pack_into('<II',raw,syms+3*16+4,0x2031,4)
        _,_,fs=self.elf_facts(bytes(raw));call=fs['calls'][0]
        self.assertEqual(call['callee'],'alias')
        self.assertEqual(call.get('target_arch'),'thumb')
        self.assertEqual(call['target'],'0x2031')
        self.assertEqual(call.get('instruction_target'),'0x2030')

    def test_arm_elf_reached_mode_switch_cannot_be_decoded_in_wrong_mode(self):
        raw = bytearray(arm_elf('0000a0e100207047',symbol_size=4))
        shoff = struct.unpack_from('<I',raw,32)[0]
        syms = struct.unpack_from('<I',raw,shoff+4*40+16)[0]
        struct.pack_into('<II',raw,syms+3*16+4,0x2005,4)
        image = self.elf_image(bytes(raw));name,addr,size,source=image.find('entry',8)
        with self.assertRaisesRegex(ValueError,'mode'):
            hostfacts.FirmwareRoutine(image,name,addr,size,source).facts()

    def analyze(self, arch, code, **kwargs):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, 'blob')
            with open(p, 'wb') as f:
                f.write(bytes.fromhex(code))
            r = hostfacts.routine_for(p, '0x1000', size=len(bytes.fromhex(code)),
                                      flat=True, load=0x1000, arch=arch, **kwargs)
            fs = r.facts(False)
            return fs, hostfacts.render(r, fs)

    def test_x86_direction_changes_preserve_registers_flags_and_stack(self):
        # mov eax,7; cmp eax,8; cld/std; je +1; ret; ret.
        for direction in ('fc', 'fd'):
            with self.subTest(direction=direction):
                fs, text = self.analyze('x86-32', 'b80700000083f808' +
                                       direction + '7401c3c3')
                self.assertEqual([e['value'] for e in fs['exits']], ['0x7', '0x7'])
                self.assertIn('taken when 0x7 == 0x8', text)
                self.assertEqual(fs['warnings'], [])
                fs, _ = self.analyze('x86-32', '6a07' + direction + 'e800000000c3')
                self.assertEqual(fs['calls'][0]['args'][0]['value'], '0x7')

    def test_x86_string_output_reports_per_transfer_accesses(self):
        # mov edx,0x123403f8; mov esi,0x2000; mov ecx,3; cld;
        # rep outsw; mov eax,esi; ret.
        fs, text = self.analyze('x86-32',
            'baf8033412be00200000b903000000fcf3666f89f0c3')
        transfers = [a for a in fs['accesses'] if a['address'] == '0x1010']
        self.assertEqual([(a['kind'], a['width']) for a in transfers],
                         [('load', 2), ('store', 2)])
        memory, port = transfers
        self.assertEqual((memory.get('segment'), memory.get('segment_offset')), ('ds', '0x2000'))
        self.assertNotIn('absolute', memory)
        self.assertEqual((port['space'], port['absolute'], port['value']),
                         ('io', '0x3f8', '?'))
        self.assertTrue(all(a['iterations'] == '0x3' for a in transfers))
        self.assertEqual([a['stride'] for a in transfers], [2, 0])
        self.assertIn('per transfer; normal completion', text)
        self.assertIn('iterations=0x3', text)
        self.assertIn('segment=ds offset=0x2000 base unknown', text)
        self.assertEqual(fs['exits'][0]['value'], '0x2006')

    def test_x86_string_input_uses_es_and_invalidates_saved_memory(self):
        # push 7; mov edx,0x20; mov edi,0x2000; std; insb;
        # mov eax,edi; call next; ret.
        fs, _ = self.analyze('x86-32',
            '6a07ba20000000bf00200000fd6c89f8e800000000c3')
        transfers = [a for a in fs['accesses'] if a['address'] == '0x100d']
        self.assertEqual([(a['kind'], a['width']) for a in transfers],
                         [('load', 1), ('store', 1)])
        port, memory = transfers
        self.assertEqual((port['space'], port['absolute']), ('io', '0x20'))
        self.assertEqual((memory.get('segment'), memory.get('segment_offset'), memory.get('stride')),
                         ('es', '0x2000', -1))
        self.assertNotIn('absolute', memory)
        self.assertEqual(fs['calls'][0]['args'][0]['value'], '?')

    def test_x86_zero_repeat_count_preserves_index_and_saved_stack(self):
        # push 7; xor ecx,ecx; rep insd; mov eax,edi; call next; ret.
        fs, _ = self.analyze('x86-32', '6a0731c9f36d89f8e800000000c3')
        self.assertEqual([a for a in fs['accesses'] if a['address'] == '0x1004'], [])
        self.assertEqual(fs['calls'][0]['args'][0]['value'], '0x7')
        fs, _ = self.analyze('x86-32', 'bf0020000031c9f36d89f8c3')
        self.assertEqual(fs['exits'][0]['value'], '0x2000')

    def test_x86_unknown_repeat_count_is_conditional_and_finishes_at_zero(self):
        # cld; rep outsb; mov eax,ecx; ret.
        fs, text = self.analyze('x86-32', 'fcf36e89c8c3')
        transfers = [a for a in fs['accesses'] if a['address'] == '0x1001']
        self.assertEqual(len(transfers), 2)
        self.assertTrue(all(a['iterations'] == 'ecx' and a['condition'] == 'ecx != 0x0'
                            for a in transfers))
        self.assertEqual(fs['exits'][0]['value'], '0x0')
        self.assertIn('when ecx != 0x0', text)

    def test_x86_unknown_direction_does_not_invent_updated_index(self):
        # mov esi,0x2000; outsb; mov eax,esi; ret.
        fs, _ = self.analyze('x86-32', 'be002000006e89f0c3')
        memory = next((a for a in fs['accesses'] if a['kind'] == 'load'), {})
        self.assertIsNone(memory.get('stride'))
        self.assertEqual(fs['exits'][0]['value'], '?')

    def test_x86_string_direction_is_merged_and_clobbered_by_calls(self):
        # cmp eax,0; je std; cld; jmp outsb; std; outsb; mov eax,esi; ret.
        fs, _ = self.analyze('x86-32', '83f8007403fceb01fd6e89f0c3')
        self.assertTrue(all(a.get('stride') in (None, 0) for a in fs['accesses']))
        self.assertEqual(fs['exits'][0]['value'], '?')
        # cld; call next; outsb; mov eax,esi; ret.
        fs, _ = self.analyze('x86-32', 'fce8000000006e89f0c3')
        self.assertEqual(fs['exits'][0]['value'], '?')

    def test_x86_string_address_size_controls_count_index_and_wrap(self):
        # mov esi,0x1234fffe; mov ecx,0xabcd0002; cld;
        # address-size-16 rep outsw; mov eax,esi; ret.
        fs, _ = self.analyze('x86-32',
            'befeff3412b90200cdabfc67f3666f89f0c3')
        transfers = [a for a in fs['accesses'] if a['address'] == '0x100b']
        self.assertEqual(transfers[0].get('iterations'), '0x2')
        self.assertEqual(transfers[0].get('count_register'), 'cx')
        self.assertEqual(transfers[0].get('address_bits'), 16)
        self.assertEqual(fs['exits'][0]['value'], '0x12340002')
        # In 16-bit code address-size-32 uses ESI/ECX, operand size stays word.
        fs, _ = self.analyze('x86-16',
            '66be0020000066b902000000fc67f36f6689f0c3')
        transfers = [a for a in fs['accesses'] if a['mnemonic'] == 'rep outsw']
        self.assertEqual((transfers[0].get('count_register'), transfers[0].get('address_bits')),
                         ('ecx', 32))
        self.assertEqual(fs['exits'][0]['value'], '0x2004')

    def test_x86_string_transfer_width_is_independent_of_address_size(self):
        for arch, prefix, width in (('x86-16', '', 2), ('x86-16', '66', 4),
                                    ('x86-32', '', 4), ('x86-32', '66', 2)):
            for opcode in ('6d', '6f'):
                with self.subTest(arch=arch, prefix=prefix, opcode=opcode):
                    fs, _ = self.analyze(arch, 'fc' + prefix + opcode + 'c3')
                    self.assertEqual([a['width'] for a in fs['accesses']], [width, width])

    def test_x86_string_segment_override_remains_unknown(self):
        # mov esi,0x2000; cld; fs outsb; ret.
        fs, text = self.analyze('x86-32', 'be00200000fc646ec3')
        memory = next((a for a in fs['accesses'] if a['kind'] == 'load'), {})
        self.assertEqual((memory.get('segment'), memory.get('segment_offset')), ('fs', '0x2000'))
        self.assertNotIn('absolute', memory)
        self.assertIn('unknown effective address', text)

    def test_x86_truncated_string_prefix_has_no_transfer(self):
        for code in ('f3', 'f366', 'f36766'):
            with self.subTest(code=code):
                fs, _ = self.analyze('x86-32', code)
                self.assertEqual(fs['accesses'], [])

    def test_x86_repne_string_io_is_not_modelled_as_rep(self):
        fs, _ = self.analyze('x86-32', 'fcf26fc3')
        self.assertEqual([a for a in fs['accesses'] if a.get('space') == 'io'], [])
        self.assertTrue(any('unsupported' in w for w in fs['warnings']))

    def test_x86_string_io_preserves_comparison_flags(self):
        # cmp eax,7; cld; rep outsb; je +1; ret; ret.
        fs, text = self.analyze('x86-32', '83f807fcf36e7401c3c3')
        self.assertIn('taken when eax == 0x7', text)

    def test_x86_string_output_does_not_destroy_saved_stack_words(self):
        # push 7; cld; outsb; call next; ret. A read cannot overwrite the save.
        fs, _ = self.analyze('x86-32', '6a07fc6ee800000000c3')
        self.assertEqual(fs['calls'][0]['args'][0]['value'], '0x7')

    def test_x86_address_size_16_repeat_preserves_upper_counter_bits(self):
        # mov ecx,0xabcd0002; cld; address-size-16 rep outsb; mov eax,ecx; ret.
        fs, _ = self.analyze('x86-32', 'b90200cdabfc67f36e89c8c3')
        self.assertEqual(fs['exits'][0]['value'], '0xabcd0000')

    def test_x86_string_input_cannot_override_destination_segment(self):
        # A segment prefix does not replace INS's fixed ES destination.
        fs, _ = self.analyze('x86-32', 'fc646cc3')
        memory = next((a for a in fs['accesses'] if a['kind'] == 'store'), {})
        self.assertEqual(memory.get('segment'), 'es')

    def test_x86_string_direction_is_unknown_after_unsupported_effects(self):
        # cld; cpuid; outsb; mov eax,esi; ret.
        fs, _ = self.analyze('x86-32', 'fc0fa26e89f0c3')
        self.assertEqual(fs['exits'][0]['value'], '?')
        self.assertTrue(any('cpuid: unsupported' in w for w in fs['warnings']))

    def test_x86_string_index_wraps_at_32_bits(self):
        # mov esi,0xffffffff; cld; outsw; mov eax,esi; ret.
        fs, _ = self.analyze('x86-32', 'befffffffffc666f89f0c3')
        self.assertEqual(fs['exits'][0]['value'], '0x1')

    def test_x86_repeat_prefixed_direction_changes_remain_unsupported(self):
        for arch in ('x86-16', 'x86-32'):
            setup = 'be0020' if arch == 'x86-16' else 'be00200000'
            for repeat in ('f2', 'f3'):
                prefixes = (repeat, '66'+repeat, repeat+'66', '67'+repeat,
                            repeat+'67', '26'+repeat+'6667', '66'+repeat+'6764',
                            repeat+'66672e', '673666'+repeat,
                            '3e66'+repeat+'67', '65'+repeat+'6766')
                for opcode, name, prior in (('fc', 'cld', 'fd'), ('fd', 'std', 'fc')):
                    for prefix in prefixes:
                        with self.subTest(arch=arch, prefix=prefix, name=name):
                            # Establish the opposite DF first. Merely ignoring
                            # the invalid encoding must not preserve known DF.
                            code = setup + prior + prefix + opcode + '6e89f0c3'
                            site = 0x1000 + len(bytes.fromhex(setup+prior))
                            fs, _ = self.analyze(arch, code)
                            instruction = next(i for i in fs['instructions'] if i['addr'] == site)
                            self.assertEqual(instruction['bytes'], prefix+opcode)
                            self.assertIn(hex(site)+' '+name+': unsupported effects invalidated',
                                          fs['warnings'])
                            memory = next(a for a in fs['accesses'] if 'segment' in a)
                            self.assertIsNone(memory['stride'])
                            self.assertEqual(fs['exits'][0]['value'], '?')

    def test_x86_repeat_prefixed_direction_changes_discard_prior_flags_and_saves(self):
        for repeat in ('f2', 'f3'):
            for opcode in ('fc', 'fd'):
                with self.subTest(repeat=repeat, opcode=opcode):
                    # mov eax,7; cmp eax,8; invalid direction encoding; je;
                    # ret; ret. Generic unsupported effects lose comparison facts.
                    fs, _ = self.analyze('x86-32',
                        'b80700000083f808'+repeat+opcode+'7401c3c3')
                    branch = next(b for b in fs['blocks'] if 'taken_when' in b)
                    self.assertEqual(branch['taken_when'], 'Z == 1')
                    # push 7; invalid direction encoding; call next; ret.
                    fs, _ = self.analyze('x86-32', '6a07'+repeat+opcode+'e800000000c3')
                    self.assertEqual(fs['calls'][0]['args'][0]['value'], '?')

    def test_m68k_truncated_call_does_not_invent_a_target(self):
        # moveq #7,d0; incomplete jsr absolute-long (six bytes).
        call = '4eb9ffe735c4'
        for arch in ('m68k', 'coldfire'):
            for size in range(1, 6):
                with self.subTest(arch=arch, size=size):
                    fs, _ = self.analyze(arch, '7007' + call[:2 * size])
                    self.assertEqual([i['mn'] for i in fs['instructions']], ['moveq'])
                    self.assertEqual(fs['calls'], [])
                    self.assertEqual(fs['accesses'], [])
                    self.assertTrue(any('decoder stopped at 0x1002' in w
                                        for w in fs['warnings']))

    def test_m68k_truncated_move_does_not_invent_memory_operands(self):
        # moveq #7,d0; incomplete move.l #0x12345678,0x9abcdef0.l.
        move = '23fc123456789abcdef0'
        for arch in ('m68k', 'coldfire'):
            for size in range(2, 10):
                with self.subTest(arch=arch, size=size):
                    fs, _ = self.analyze(arch, '7007' + move[:2 * size])
                    self.assertEqual([i['mn'] for i in fs['instructions']], ['moveq'])
                    self.assertEqual(fs['accesses'], [])
                    self.assertEqual(fs['calls'], [])
                    self.assertEqual([(c['register'], c['value'])
                                      for c in fs['constants']], [('d0', '0x7')])

    def test_m68k_complete_long_operands_are_not_filtered_as_placeholders(self):
        for arch in ('m68k', 'coldfire'):
            with self.subTest(arch=arch):
                # 0xaaaaaaaa is also a legitimate fully encoded call target.
                fs, _ = self.analyze(arch, '4eb9aaaaaaaa4e75')
                self.assertEqual(fs['calls'][0]['target'], '0xaaaaaaaa')
                self.assertEqual([i['size'] for i in fs['instructions']], [6, 2])
                fs, _ = self.analyze(arch, '23fc123456789abcdef04e75')
                self.assertEqual([i['size'] for i in fs['instructions']], [10, 2])
                store = fs['accesses'][0]
                self.assertEqual((store['kind'], store['width'], store['absolute'],
                                  store['value']),
                                 ('store', 4, '0x9abcdef0', '0x12345678'))

    def test_arm_coprocessor_memory_direction_and_unknown_width(self):
        # stc p1,c0,[r0]; ldc p1,c0,[r0]; stcl p1,c0,[r0];
        # ldcl p1,c0,[r0]. Transfer length depends on the coprocessor.
        fs, text = self.analyze('arm', '000180ed000190ed0001c0ed0001d0ed')
        accesses = [a for a in fs['accesses'] if not a.get('implicit')]
        self.assertEqual([(a['kind'], a['width'], a.get('origin'),
                           a.get('origin_offset')) for a in accesses],
                         [(kind, 'unknown', 'r0', 0)
                          for kind in ('store', 'load', 'store', 'load')])
        self.assertIn('store wunknown stc', text)
        self.assertTrue(any('coprocessor transfer width is unknown' in warning
                            for warning in fs['warnings']))

    def test_arm_mrc_discards_previous_destination_value(self):
        # mov r3,#7; mrc/mrc2 p1,#0,r3,c0,c0,#3; mov r0,r3; bx lr.
        for transfer in ('703110ee', '703110fe'):
            with self.subTest(transfer=transfer):
                fs, _ = self.analyze('arm', '0730a0e3' + transfer +
                                     '0300a0e11eff2fe1')
                self.assertEqual(fs['exits'][0]['value'], '?')

    def test_symbol_size_override_records_explicit_extent(self):
        # Model a symbol-delimited x86 body: nop; ret; nop; ret.
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, 'blob')
            with open(p, 'wb') as f:
                f.write(bytes.fromhex('90c390c3'))
            image = hostfacts.FirmwareImage(p, 'x86-32', 0x1000)
            image.symbols = {'entry': [(0x1000, 2)]}
            for subject in ('entry', '0x1000'):
                with self.subTest(subject=subject):
                    self.assertEqual(image.find(subject, None)[2:],
                                     (2, 'next a.out symbol (inferred)'))
                    self.assertEqual(image.find(subject, 2)[2:],
                                     (2, 'next a.out symbol (inferred)'))
                    self.assertEqual(image.find(subject, 4)[2:], (4, 'given'))
                    self.assertEqual(image.find(subject, 1)[2:], (1, 'given'))

    def test_x86_indirect_far_transfers_read_offset_and_selector(self):
        # FF /3 and /5 read m16:16 or m16:32. The segment selector adds
        # two bytes even when Capstone reports only the offset width.
        for arch, address, far_modrm, near_modrm, default_width in (
                ('x86-16', '0020', ('1e', '2e'), ('16', '26'), 2),
                ('x86-32', '00200000', ('1d', '2d'), ('15', '25'), 4)):
            for prefix, offset_width in (('', default_width),
                                         ('66', 6 - default_width)):
                for modrm in far_modrm + near_modrm:
                    with self.subTest(arch=arch, prefix=prefix, modrm=modrm):
                        fs, _ = self.analyze(arch, prefix + 'ff' + modrm + address)
                        loads = [a for a in fs['accesses']
                                 if not a.get('implicit') and a['kind'] == 'load']
                        expected = offset_width + (2 if modrm in far_modrm else 0)
                        self.assertEqual([a['width'] for a in loads], [expected])

    def test_m68k_signed_displacement_and_store_width(self):
        # movea.l #0x10000000,a0; move.b -4(a0),d0; move.w #7,2(a0); rts
        fs, text = self.analyze('m68k', '207c100000001028fffc317c000700024e75')
        accesses = [a for a in fs['accesses'] if not a.get('implicit')]
        self.assertEqual([(a['kind'], a['width'], a['absolute']) for a in accesses],
                         [('load', 1, '0xffffffc'), ('store', 2, '0x10000002')])
        self.assertIn('=> abs 0xffffffc', text)

    def test_m68k_call_sees_pushed_stack_argument(self):
        # move.l #7,-(sp); jsr 0x2000; addq.l #4,sp; rts
        fs, _ = self.analyze('coldfire', '2f3c000000074eb900002000588f4e75')
        self.assertEqual(fs['calls'][0]['target'], '0x2000')
        self.assertEqual(fs['calls'][0]['args'][0]['value'], '0x7')

    def test_arm_branch_reaches_code_after_undecodable_word(self):
        # b 0x1008; unallocated word; mov r0,#7; str r0,[r1]; bx lr
        fs, text = self.analyze('arm', '000000eaffff00000700a0e3000081e51eff2fe1')
        stores = [a for a in fs['accesses'] if a['kind'] == 'store']
        self.assertEqual([(a['address'], a['origin'], a['value']) for a in stores],
                         [('0x100c', 'r1', '0x7')])
        self.assertEqual(fs['exits'][0]['address'], '0x1010')
        self.assertTrue(any('0x1004' in w for w in fs['warnings']))

    def test_arm_does_not_fall_through_undecodable_word(self):
        # mov r0,#7; unallocated word; str r0,[r1]; bx lr
        fs, _ = self.analyze('arm', '0700a0e3ffff0000000081e51eff2fe1')
        self.assertEqual([a for a in fs['accesses'] if a['kind'] == 'store'], [])
        self.assertEqual(fs['exits'], [])
        self.assertIn(0x1008, [i['addr'] for i in fs['instructions']])
        self.assertIn('0x1008', fs['unreached'])

    def test_arm_mov_pc_call_with_known_link_tracks_continuation(self):
        # mov r0,#7; mov lr,pc; mov pc,r4; str r0,[r5]; bx lr
        fs, _ = self.analyze('arm', '0700a0e30fe0a0e104f0a0e1000085e51eff2fe1')
        self.assertEqual(len(fs['calls']), 1)
        call = fs['calls'][0]
        self.assertEqual((call['address'], call['mnemonic'], call['target']),
                         ('0x1008', 'mov', None))
        self.assertEqual(call['args'][0]['value'], '0x7')
        store = next(a for a in fs['accesses'] if a['kind'] == 'store')
        self.assertEqual((store['address'], store['origin'], store['value']),
                         ('0x100c', 'r5', 'ret(unknown)'))
        self.assertEqual(fs['coverage']['unresolved_transfers'], [])

    def test_arm_mov_pc_call_resolves_target_register(self):
        # ldr ip,[pc,#16]; mov r0,#7; mov lr,pc; mov pc,ip; str r0,[r5]; bx lr; target
        fs, _ = self.analyze('arm', '10c09fe50700a0e30fe0a0e10cf0a0e1000085e51eff2fe100200000')
        self.assertEqual(len(fs['calls']), 1)
        self.assertEqual(fs['calls'][0]['target'], '0x2000')
        self.assertEqual(fs['calls'][0]['args'][0]['value'], '0x7')
        store = next(a for a in fs['accesses'] if a['kind'] == 'store')
        self.assertEqual(store['value'], 'ret(0x2000)')

    def test_arm_mov_pc_with_conflicting_link_drops_provisional_continuation(self):
        # cmp r0,#0; beq bypass; mov lr,pc; mov pc,r4; str r1,[r5]; bx lr
        # nop; bypass: nop; nop; b 0x100c
        fs, _ = self.analyze('arm', '000050e30400000a0fe0a0e104f0a0e1001085e51eff2fe1'
                            '0000a0e10000a0e10000a0e1f8ffffea')
        self.assertEqual(fs['calls'], [])
        self.assertEqual([a for a in fs['accesses'] if a['kind'] == 'store'], [])
        self.assertEqual(fs['exits'], [])
        self.assertIn('0x1010', fs['unreached'])

    def test_arm_removed_call_path_does_not_poison_live_join(self):
        # A provisional call path writes 9, but the only live path to the
        # final store writes 7 after bypassing the first link setup.
        code = ('000050e30500000a0fe0a0e104f0a0e10900a0e3060000ea0000a0e1'
                '0000a0e10000a0e1000051e3f7ffff0a0700a0e30000a0e1000085e51eff2fe1')
        fs, _ = self.analyze('arm', code)
        self.assertEqual(fs['calls'], [])
        stores = [a for a in fs['accesses'] if a['kind'] == 'store']
        self.assertEqual([(a['address'], a['value']) for a in stores], [('0x1034', '0x7')])

    def test_arm_removed_call_path_does_not_hide_later_call(self):
        code = ('000050e30500000a0fe0a0e104f0a0e10900a0e3060000ea0000a0e1'
                '0000a0e10000a0e1000051e3f7ffff0a0700a0e30fe0a0e106f0a0e1000085e51eff2fe1')
        fs, _ = self.analyze('arm', code)
        self.assertEqual([c['address'] for c in fs['calls']], ['0x1034'])
        self.assertEqual(fs['calls'][0]['args'][0]['value'], '0x7')
        stores = [a for a in fs['accesses'] if a['kind'] == 'store']
        self.assertEqual([(a['address'], a['value']) for a in stores],
                         [('0x1038', 'ret(unknown)')])

    def test_arm_mov_pc_without_matching_link_remains_jump(self):
        for code in ('04f0a0e1000085e51eff2fe1',
                     '01e0a0e304f0a0e1000085e51eff2fe1'):
            fs, _ = self.analyze('arm', code)
            self.assertEqual(fs['calls'], [])
            self.assertEqual([a for a in fs['accesses'] if a['kind'] == 'store'], [])
            self.assertEqual(len(fs['coverage']['unresolved_transfers']), 1)

    def test_arm_negative_literal_index_keeps_signed_stack_offset(self):
        # ldr r3,[pc,#8]; sub ip,sp,#12; strh r0,[ip,r3]; bx lr; -692
        fs, text = self.analyze('arm', '08309fe50cc04de2b3008ce11eff2fe14cfdffff')
        store = next(a for a in fs['accesses'] if a['kind'] == 'store')
        self.assertEqual((store['origin'], store['origin_offset'], store['width']),
                         ('sp', -704, 2))
        self.assertIn('=> sp -0x2c0', text)

    def test_arm_negative_literal_add_keeps_signed_pointer_offset(self):
        # ldr r3,[pc,#8]; add r0,sp,r3 (or r3,sp); str r1,[r0]; bx lr; -692
        for add in ('03008de0', '0d0083e0'):
            with self.subTest(add=add):
                fs, _ = self.analyze('arm', '08309fe5' + add + '001080e51eff2fe14cfdffff')
                store = next(a for a in fs['accesses'] if a['kind'] == 'store')
                self.assertEqual((store['origin'], store['origin_offset']), ('sp', -692))

    def test_arm_symbolic_offset_wraps_after_repeated_additions(self):
        # mov r0,sp; add r0,r0,#0x80000000 twice; str r1,[r0]; bx lr
        fs, _ = self.analyze('arm', '0d00a0e1020180e2020180e2001080e51eff2fe1')
        store = next(a for a in fs['accesses'] if a['kind'] == 'store')
        self.assertEqual((store['origin'], store['origin_offset']), ('sp', 0))

    def test_arm_displacement_wraps_with_symbolic_base(self):
        # add r0,sp,#0x80000000; str r1,[r0,#-4]; bx lr
        fs, _ = self.analyze('arm', '02018de2041000e51eff2fe1')
        store = next(a for a in fs['accesses'] if a['kind'] == 'store')
        self.assertEqual((store['origin'], store['origin_offset']), ('sp', 0x7ffffffc))

    def test_arm_wrapped_stack_alias_preserves_stored_value(self):
        # add r0,sp,#0x80000000; str r1,[r0,#-4]; sub r0,r0,#4; ldr r2,[r0]; bx lr
        fs, _ = self.analyze('arm', '02018de2041000e5040040e2002090e51eff2fe1')
        accesses = [a for a in fs['accesses'] if not a.get('implicit')]
        self.assertEqual([a['origin_offset'] for a in accesses], [0x7ffffffc, 0x7ffffffc])
        # The loaded value survives as the first argument candidate of a call.
        fs, _ = self.analyze('arm', '02018de2041000e5040040e2000090e5fa0300eb1eff2fe1')
        self.assertEqual(fs['calls'][0]['args'][0]['value'], 'r1')

    def test_arm_multiple_store_wraps_accesses_and_writeback(self):
        # add r0,sp,#0x80000000; stmdb r0!,{r1,r2}; str r1,[r0]; bx lr
        fs, _ = self.analyze('arm', '02018de2060020e9001080e51eff2fe1')
        stores = [a for a in fs['accesses'] if a['kind'] == 'store']
        self.assertEqual([a['origin_offset'] for a in stores],
                         [0x7ffffff8, 0x7ffffffc, 0x7ffffff8])
        # add r0,sp,#0x80000000; sub r0,r0,#4; stmia r0!,{r1,r2}; str r1,[r0]; bx lr
        fs, _ = self.analyze('arm', '02018de2040040e20600a0e8001080e51eff2fe1')
        stores = [a for a in fs['accesses'] if a['kind'] == 'store']
        self.assertEqual([a['origin_offset'] for a in stores],
                         [0x7ffffffc, -0x80000000, -0x7ffffffc])

    def test_thumb_push_wraps_symbolic_stack_address(self):
        # ldr r3,[pc,#4]; add sp,r3; push {r0}; bx lr; 0x80000000
        fs, _ = self.analyze('thumb', '014b9d4401b4704700000080')
        store = next(a for a in fs['accesses'] if a['kind'] == 'store')
        self.assertEqual((store['origin'], store['origin_offset']), ('sp', 0x7ffffffc))

    def test_arm_high_absolute_index_wraps_without_becoming_symbolic(self):
        # ldr r3,[pc,#8]; mov r2,#32; str r1,[r3,r2]; bx lr; 0xfffffffc
        fs, _ = self.analyze('arm', '08309fe52020a0e3021083e71eff2fe1fcffffff')
        store = next(a for a in fs['accesses'] if a['kind'] == 'store')
        self.assertEqual(store['absolute'], '0x1c')

    def test_arm_literal_base_load_and_aapcs_arguments(self):
        # ldr r4,[pc,#12]; mov r0,#7; strb r0,[r4,#2]; bl 0x2000; bx lr; literal
        fs, text = self.analyze('arm', '0c409fe50700a0e30200c4e5fb0300eb1eff2fe100000010')
        st = next(a for a in fs['accesses'] if a['kind'] == 'store')
        self.assertEqual((st['absolute'], st['width'], st['value']), ('0x10000002', 1, '0x7'))
        self.assertEqual(fs['calls'][0]['args'][0]['value'], '0x7')
        self.assertIn('returns (1)', text)

    def test_arm_branch_direction_and_conflicting_paths(self):
        # cmp r0,#0; beq 0x1010; mov r1,#1; b 0x1014; mov r1,#2; str r1,[r2]; bx lr
        fs, text = self.analyze('arm', '000050e30100000a0110a0e3000000ea0210a0e3001082e51eff2fe1')
        self.assertIn('taken when r0 == 0x0', text)
        self.assertIn('falls through when r0 != 0x0', text)
        store = next(a for a in fs['accesses'] if a['kind'] == 'store')
        self.assertNotEqual(store['value'], '0x1')
        self.assertNotEqual(store['value'], '0x2')

    def test_x86_frame_argument_base_and_stack_call(self):
        # push ebp; mov ebp,esp; mov eax,[ebp+8]; mov dl,[eax-4]; push 7; call 0x2000; leave; ret
        fs, text = self.analyze('x86-32', '5589e58b45088a50fc6a07e8f10f0000c9c3')
        load = next(a for a in fs['accesses'] if a['address'] == '0x1006')
        self.assertEqual(load['origin_offset'], -4)
        self.assertIn('sp', load['origin'])
        self.assertEqual(fs['calls'][0]['args'][0]['value'], '0x7')
        self.assertIn('cdecl32', text)

    def test_x86_partial_register_write_invalidates_full_register(self):
        # mov eax,0x10000000; mov al,cl; mov ebx,[eax]; ret
        fs, _ = self.analyze('x86-32', 'b80000001088c88b18c3')
        load = next(a for a in fs['accesses'] if a['kind'] == 'load' and not a.get('implicit'))
        self.assertNotIn('absolute', load)

    def test_x86_16_address_and_unsigned_branch(self):
        # mov bx,0x4000; mov al,[bx-2]; cmp al,3; jb +2; nop; nop; ret
        fs, text = self.analyze('x86-16', 'bb00408a47fe3c0372029090c3')
        self.assertEqual(fs['accesses'][0]['absolute'], '0x3ffe')
        self.assertEqual(fs['accesses'][0]['width'], 1)
        self.assertIn('(unsigned, 8-bit)', text)
        self.assertIn('taken when', text)
        self.assertIn('falls through when', text)

    def test_unmodeled_instruction_cannot_keep_old_value(self):
        # mov eax,0x1000; bswap eax; mov ecx,[eax]; ret
        fs, _ = self.analyze('x86-32', 'b8001000000fc88b08c3')
        load = next(a for a in fs['accesses'] if a['kind'] == 'load' and not a.get('implicit'))
        self.assertNotIn('absolute', load)

    def test_m68k_signed_link_frame(self):
        # link.w a6,#-16; move.l #7,(sp); jsr 0x2000; unlk a6; rts
        fs, _ = self.analyze('coldfire', '4e56fff02ebc000000074eb9000020004e5e4e75')
        store = next(a for a in fs['accesses'] if a['address'] == '0x1004')
        self.assertEqual(store['origin_offset'], -20)
        self.assertEqual(fs['calls'][0]['args'][0]['value'], '0x7')

    def test_m68k_movem_preserves_frame_and_call_arguments(self):
        # link a6,#-16; movem.l d2-d7/a2-a5,-(sp); move.l #7,-(sp); jsr 0x2000; rts
        fs, _ = self.analyze('coldfire', '4e56fff048e73f3c2f3c000000074eb9000020004e75')
        saves = [a for a in fs['accesses'] if a['address'] == '0x1004']
        self.assertEqual(len(saves), 10)
        self.assertTrue(all(a['kind'] == 'store' and a['width'] == 4 for a in saves))
        self.assertEqual(sorted(a['origin_offset'] for a in saves), list(range(-60,-20,4)))
        self.assertEqual(fs['calls'][0]['args'][0]['value'], '0x7')

    def test_m68k_movem_leaves_the_base_register_known(self):
        # movea.l #0x10000000,a0; movem.l d2-d3,(a0); move.l d0,4(a0);
        # movem.l (a0),d2-d3; move.l d0,(a0); rts
        fs, _ = self.analyze('coldfire', '207c10000000' '48d0000c' '21400004' '4cd0000c' '20800000' '4e75')
        stores = [a for a in fs['accesses'] if a['kind'] == 'store' and not a['implicit']]
        self.assertEqual([a.get('absolute') for a in stores][-2:], ['0x10000004', '0x10000000'])

    def test_m68k_tst_compares_value_with_zero(self):
        # moveq #1,d0; tst.l d0; beq +2; rts; rts
        fs, text = self.analyze('m68k', '70014a8067024e754e75')
        self.assertIn('taken when 0x1 == 0x0', text)
        self.assertNotIn('& 0x0', text)

    def test_x86_port_io_uses_dx_and_data_width(self):
        # mov edx,0x3f8; mov eax,7; out dx,al; in ax,dx; ret
        fs, text = self.analyze('x86-32', 'baf8030000b807000000ee66edc3')
        io = [a for a in fs['accesses'] if a.get('space') == 'io']
        self.assertEqual([(a['kind'],a['width'],a['absolute']) for a in io],
                         [('store',1,'0x3f8'),('load',2,'0x3f8')])
        self.assertEqual(io[0]['value'], '0x7')
        self.assertIn('space=io', text)

    def test_x86_x87_memory_stores_override_incorrect_decoder_read_flags(self):
        # fstp qword [esp]; fst dword [esp]; fistp dword [esp];
        # fstp tbyte [esp]; fnstcw word [esp]; fist dword [esp];
        # fisttp dword [esp]; fbstp tbyte [esp]; fnstsw word [esp]; ret
        fs, _ = self.analyze('x86-32', 'dd1c24d91424db1c24db3c24d93c24db1424db0c24df3424dd3c24c3')
        accesses = [a for a in fs['accesses'] if not a.get('implicit')]
        self.assertEqual([(a['kind'], a['width'], a['origin'], a['origin_offset'])
                          for a in accesses],
                         [('store', width, 'sp', 0) for width in (8, 4, 4, 10, 2, 4, 4, 10, 2)])
        self.assertTrue(all(a['value'] == '?' for a in accesses))

    def test_x86_x87_loads_remain_loads(self):
        # fld qword [esp]; fild dword [esp]; ret
        fs, _ = self.analyze('x86-32', 'dd0424db0424c3')
        accesses = [a for a in fs['accesses'] if not a.get('implicit')]
        self.assertEqual([(a['kind'], a['width']) for a in accesses],
                         [('load', 8), ('load', 4)])

    def test_x86_16_x87_store_keeps_effective_base(self):
        # fstp qword [bx]; ret
        fs, _ = self.analyze('x86-16', 'dd1fc3')
        store = next(a for a in fs['accesses'] if not a.get('implicit'))
        self.assertEqual((store['kind'], store['width'], store['origin'],
                          store['origin_offset'], store['value']),
                         ('store', 8, 'bx', 0, '?'))

    def test_x86_unknown_instruction_still_reports_memory_operand(self):
        # mov eax,0x3000; xchg [eax],ebx; ret
        fs, _ = self.analyze('x86-32', 'b8003000008718c3')
        accesses = [a for a in fs['accesses'] if a['address'] == '0x1005']
        self.assertEqual({a['kind'] for a in accesses}, {'load','store'})
        self.assertTrue(all(a['absolute']=='0x3000' for a in accesses))

    def test_arm_pop_return_reads_the_return_register(self):
        # mov r0,#7; push {r0,lr}; mov r0,#2; pop {r0,pc}
        fs, _ = self.analyze('arm', '0700a0e301402de90200a0e30180bde8')
        self.assertEqual(fs['exits'][0]['value'], '0x7')
        self.assertEqual(len([a for a in fs['accesses'] if a['address']=='0x100c']),2)

    def test_arm_shifted_move_does_not_copy_unshifted_register(self):
        # mov r1,#3; mov r0,r1,lsl #2; bx lr
        fs, _ = self.analyze('arm', '0310a0e30101a0e11eff2fe1')
        self.assertEqual(fs['exits'][0]['value'], '0xc')

    def test_arm_conditional_store_is_labeled_and_not_cached_as_unconditional(self):
        # cmp r0,#0; streq r1,[r2]; bx lr
        fs, _ = self.analyze('arm', '000050e3001082051eff2fe1')
        store = next(a for a in fs['accesses'] if a['kind']=='store')
        self.assertEqual(store['condition'],'r0 == 0x0')

    def test_arm_movt_does_not_replace_the_lower_half(self):
        fs, _ = self.analyze('arm','340201e3780645e3001090e51eff2fe1')
        load = next(a for a in fs['accesses'] if a['kind']=='load')
        self.assertEqual(load['absolute'],'0x56781234')

    def test_arm_double_store_preserves_sources_and_reports_access(self):
        fs, _ = self.analyze('arm','0700a0e30810a0e3f000c2e1003091e51eff2fe1')
        self.assertTrue(any(a['address']=='0x1008' and a['kind']=='store' and a['width']==8 for a in fs['accesses']))
        load = next(a for a in fs['accesses'] if a['address']=='0x100c')
        self.assertEqual(load['absolute'],'0x8')

    def test_arm_double_load_cannot_leave_the_second_destination_unchanged(self):
        fs, _ = self.analyze('arm','0710a0e3d000c2e1003091e51eff2fe1')
        load = next(a for a in fs['accesses'] if a['address']=='0x1008')
        self.assertNotIn('absolute',load)

    def test_arm_movs_invalidates_preceding_compare(self):
        _, text = self.analyze('arm','000050e30110b0e30000000a1eff2fe11eff2fe1')
        self.assertNotIn('taken when r0 == 0x0',text)

    def test_arm_cmn_is_not_a_subtraction_compare(self):
        _, text = self.analyze('arm','010070e30000000a1eff2fe11eff2fe1')
        self.assertNotIn('taken when r0 == 0x1',text)

    def test_arm_conditional_indirect_jump_retains_fallthrough(self):
        fs, _ = self.analyze('arm','000050e312ff2f110700a0e31eff2fe1')
        self.assertNotIn('0x1008',fs['unreached'])

    def test_arm_pc_load_does_not_fall_through(self):
        fs, _ = self.analyze('arm','00f091e50700a0e31eff2fe1')
        self.assertIn('0x1004',fs['unreached'])
        self.assertEqual(len(fs['accesses']),1)

    def test_arm_negative_postindex_decrements_base(self):
        fs, _ = self.analyze('arm','011ca0e3040001e4002091e51eff2fe1')
        load = next(a for a in fs['accesses'] if a['address']=='0x1008')
        self.assertEqual(load['absolute'],'0xfc')

    def test_arm_stack_byte_round_trip_truncates_store(self):
        fs, _ = self.analyze('arm','010ca0e30000cde50010dde5002091e51eff2fe1')
        load = next(a for a in fs['accesses'] if a['address']=='0x100c')
        self.assertEqual(load['absolute'],'0x0')

    def test_arm_symbolic_byte_stack_reload_truncates_argument(self):
        # strb r0,[sp]; ldrb r0,[sp]; bl 0x2000; bx lr
        fs, _ = self.analyze('arm', '0000cde50000dde5fc0300eb1eff2fe1')
        self.assertEqual(fs['calls'][0]['args'][0]['value'], '(r0 & 0xff)')
        store = next(a for a in fs['accesses'] if a['kind'] == 'store')
        self.assertEqual(store['value'], '(r0 & 0xff)')

    def test_arm_symbolic_halfword_stack_reload_truncates_argument(self):
        # strh r0,[sp]; ldrh r0,[sp]; bl 0x2000; bx lr
        fs, _ = self.analyze('arm', 'b000cde1b000dde1fc0300eb1eff2fe1')
        self.assertEqual(fs['calls'][0]['args'][0]['value'], '(r0 & 0xffff)')
        store = next(a for a in fs['accesses'] if a['kind'] == 'store')
        self.assertEqual(store['value'], '(r0 & 0xffff)')

    def test_arm_signed_byte_literal_extends(self):
        fs, _ = self.analyze('arm','d000dfe11eff2fe1ff000000')
        self.assertEqual(fs['exits'][0]['value'],'0xffffffff')

    def test_m68k_db_loop_keeps_target_and_invalidates_counter(self):
        fs, _ = self.analyze('m68k','700151c8fffc4e75')
        branch = next(b for b in fs['blocks'] if b['first']=='0x1002')
        self.assertEqual(branch['target'],'0x1000')
        self.assertEqual(fs['exits'][0]['value'],'?')

    def test_m68k_cmpa_word_is_signed_and_compared_as_long(self):
        _, text = self.analyze('m68k','207c0000ffffb0fcffff67024e754e75')
        self.assertIn('taken when 0xffff == 0xffffffff',text)

    def test_m68k_pea_then_push_keeps_the_stack_argument_order(self):
        fs, _ = self.analyze('m68k','4879000030002f3c000000074eb9000020004e75')
        self.assertEqual(fs['calls'][0]['args'][0]['value'],'0x7')
        self.assertEqual(fs['calls'][0]['args'][1]['value'],'0x3000')

    def test_x86_16_operand_and_address_overrides_keep_full_eax(self):
        # mov eax,0x12345678; mov ebx,[eax] with 32-bit address/operand prefixes; ret
        fs, _ = self.analyze('x86-16','66b87856341267668b18c3')
        load = next(a for a in fs['accesses'] if a['kind']=='load')
        self.assertEqual(load['absolute'],'0x12345678')
        self.assertEqual(fs['exits'][0]['value'],'0x5678')

    def test_x86_byte_value_survives_in_its_own_alias(self):
        # mov dl,[eax]; cmp dl,3; je +1; ret; ret
        fs, text = self.analyze('x86-32','8a1080fa037401c3c3')
        branch = next(b for b in fs['blocks'] if 'taken_when' in b)
        self.assertIn('[eax',branch['taken_when'])

    def test_mmsc_symbols_use_the_existing_aout_mapping(self):
        from sysco.test_mmsc_aout import build
        base=0x108000
        # call _helper; ret; _helper: mov eax,7; ret
        text=bytes.fromhex('e801000000c3b807000000c3')
        blob=build(text,b'ABCD',16,[('_start',5,base),('_helper',5,base+6),('_etext',5,base+len(text))])
        with tempfile.TemporaryDirectory() as d:
            path=os.path.join(d,'mmscfw.bin')
            with open(path,'wb') as f:f.write(blob)
            r=hostfacts.routine_for(path,'_start',arch='x86-32',load=base)
            fs=r.facts()
            self.assertEqual(fs['routine']['size'],6)
            self.assertEqual(fs['calls'][0]['callee'],'_helper')
            self.assertEqual(fs['calls'][0]['target'],'0x108006')
            self.assertEqual(r.img.read(base+len(text),4),b'ABCD')
            self.assertIsNone(r.img.read(base+len(text)+4,1))

    def test_flat_offset_excludes_the_container_header(self):
        with tempfile.TemporaryDirectory() as d:
            path=os.path.join(d,'image')
            with open(path,'wb') as f:f.write(b'header'+bytes.fromhex('70074e75'))
            r=hostfacts.routine_for(path,'0x1000',size=4,arch='m68k',load=0x1000,offset=6)
            self.assertEqual(r.facts()['exits'][0]['value'],'0x7')

    def test_explicit_incompatible_abi_is_rejected(self):
        with self.assertRaisesRegex(ValueError,'ABI'):
            self.analyze('arm','1eff2fe1',abi='cdecl32')

    def test_cmp_sign_extended_immediate_is_normalized_to_operand_width(self):
        fs,text=self.analyze('x86-32','83f8ff7401c3c3')
        branch=next(b for b in fs['blocks'] if 'taken_when' in b)
        self.assertIn('0xffffffff',branch['taken_when'])

    def test_m68k_memory_bit_test_is_a_byte_access(self):
        # btst #1,(a0); rts
        fs,_=self.analyze('m68k','081000014e75')
        self.assertEqual(fs['accesses'][0]['width'],1)
        self.assertEqual(fs['accesses'][0]['kind'],'load')

    def test_m68k_register_bit_test_uses_modulo32_and_preserves_base(self):
        # movea.l #0x2000,a0; move.l #0x2000,d6; btst #45,d6;
        # bne exit; clr.b (a0); exit: rts
        fs,text=self.analyze('m68k','207c000020002c3c000020000806002d660242104e75')
        store=next(a for a in fs['accesses'] if a['kind']=='store')
        self.assertEqual(store['absolute'],'0x2000')
        self.assertIn('taken when (0x2000 & 0x2000) != 0x0',text)
        self.assertIn('falls through when (0x2000 & 0x2000) == 0x0',text)

    def test_m68k_memory_bit_test_wraps_bit_and_advances_base_once(self):
        # movea.l #0x2000,a0; btst #9,(a0)+; bne exit;
        # move.b d0,(a0); exit: rts
        fs,text=self.analyze('m68k','207c0000200008180009660210804e75')
        accesses=[a for a in fs['accesses'] if not a.get('implicit')]
        self.assertEqual([(a['kind'],a['width'],a['absolute']) for a in accesses],
                         [('load',1,'0x2000'),('store',1,'0x2001')])
        self.assertIn('& 0x2) != 0x0',text)

    def test_m68k_unknown_bit_number_preserves_registers(self):
        # movea.l #0x2000,a0; moveq #7,d1; btst d0,(a0);
        # beq exit; move.b d1,(a0); exit: rts
        fs,text=self.analyze('m68k','207c0000200072070110670210814e75')
        self.assertEqual(next(a for a in fs['accesses'] if a['kind']=='load')['width'],1)
        store=next(a for a in fs['accesses'] if a['kind']=='store')
        self.assertEqual((store['absolute'],store['value']),('0x2000','0x7'))
        self.assertIn('taken when Z == 1',text)
        self.assertNotIn('taken when 0x7',text)

    def test_m68k_dynamic_memory_bit_test_uses_byte_width(self):
        # movea.l #0x2000,a0; moveq #63,d1; btst d1,EA;
        # bne exit; move.b d0,(a0); exit: rts
        # Capstone prints .l for these memory forms, but their access is a byte.
        for opcode,load_address,store_address in (
                ('0320','0x1fff','0x1fff'),  # -(a0)
                ('0318','0x2000','0x2001'),  # (a0)+
                ('0310','0x2000','0x2000')): # (a0)
            with self.subTest(opcode=opcode):
                fs,text=self.analyze('m68k','207c00002000723f'+opcode+'660210804e75')
                accesses=[a for a in fs['accesses'] if not a.get('implicit')]
                self.assertEqual([(a['kind'],a['width'],a['absolute']) for a in accesses],
                                 [('load',1,load_address),('store',1,store_address)])
                self.assertIn('& 0x80) != 0x0',text)

    def test_m68k_bit_test_does_not_supply_signed_comparison_flags(self):
        # moveq #1,d0; btst #0,d0; bge exit; rts; exit: rts
        fs,text=self.analyze('m68k','7001080000006c024e754e75')
        self.assertTrue(all(x['value']=='0x1' for x in fs['exits']))
        self.assertIn('ge flags condition (operands unknown)',text)

    def test_m68k_bit_test_preserves_saved_call_argument(self):
        # move.l #7,-(sp); btst #0,d1; jsr 0x2000; rts
        fs,_=self.analyze('m68k','2f3c00000007080100004eb9000020004e75')
        self.assertEqual(fs['calls'][0]['args'][0]['value'],'0x7')

    def test_m68k_bit_test_keeps_loop_invariant_pointer(self):
        # movea.l #0x2000,a5; moveq #0,d7;
        # loop: clr.b (a5); btst #5,(a5); addq.l #1,d7;
        # cmpi.l #3,d7; blt loop; rts
        fs,_=self.analyze('coldfire','2a7c000020007e0042150815000552870c87000000036df04e75')
        accesses=[a for a in fs['accesses'] if not a.get('implicit')]
        self.assertEqual([(a['kind'],a['absolute']) for a in accesses],
                         [('store','0x2000'),('load','0x2000')])

    def test_m68k_bit_test_predecrement_keeps_stack_byte_alignment(self):
        # btst #0,-(sp); move.l #7,-(sp); jsr 0x2000; rts
        fs,_=self.analyze('m68k','082700002f3c000000074eb9000020004e75')
        load=next(a for a in fs['accesses'] if a['kind']=='load')
        self.assertEqual((load['width'],load['origin'],load['origin_offset']),(1,'sp',-2))
        self.assertEqual(fs['calls'][0]['args'][0]['value'],'0x7')

    def test_m68k_move_byte_sets_flags_from_the_byte(self):
        _,text=self.analyze('m68k','203c00000100120067024e754e75')
        self.assertIn('taken when 0x0 == 0x0',text)

    def test_m68k_adda_word_sign_extends(self):
        fs,_=self.analyze('m68k','207c00001000d0fcffff22104e75')
        load=next(a for a in fs['accesses'] if a['kind']=='load')
        self.assertEqual(load['absolute'],'0xfff')

    def test_m68k_word_shift_does_not_shift_in_the_high_word(self):
        fs,_=self.analyze('m68k','203cffff0000e24822404e75')
        self.assertEqual(fs['exits'][0]['value'],'0xffff0000')

    def test_arm_register_postindex_subtracts(self):
        fs,_=self.analyze('arm','011ca0e30420a0e3020001e6003091e51eff2fe1')
        load=next(a for a in fs['accesses'] if a['address']=='0x100c')
        self.assertEqual(load['absolute'],'0xfc')

    def test_arm_multiple_load_return_reads_destinations(self):
        fs,_=self.analyze('arm','0700a0e30180b1e8')
        self.assertEqual(fs['exits'][0]['value'],'[r1]')
        self.assertEqual(len(fs['accesses']),2)

    def test_x86_loop_conditions_use_post_decrement_count_and_zero_flag(self):
        # mov cx/ecx,1; cmp ax/eax,7; loop-family +1; ret; ret.
        for arch, setup in (('x86-16', 'b90100'), ('x86-32', 'b901000000')):
            for opcode, taken, fall in (
                    ('e2', '0x0 != 0x0', '0x0 == 0x0'),
                    ('e1', '0x0 != 0x0 and (', '0x0 == 0x0 or ('),
                    ('e0', '0x0 != 0x0 and (', '0x0 == 0x0 or (')):
                with self.subTest(arch=arch, opcode=opcode):
                    fs, text = self.analyze(arch, setup+'83f807'+opcode+'01c3c3')
                    branch = next(b for b in fs['blocks'] if 'taken_when' in b)
                    self.assertTrue(branch['taken_when'].startswith(taken), branch)
                    self.assertTrue(branch['falls_through_when'].startswith(fall), branch)
                    if opcode != 'e2':
                        self.assertIn('== 0x7' if opcode == 'e1' else '!= 0x7', branch['taken_when'])
                        self.assertIn('!= 0x7' if opcode == 'e1' else '== 0x7', branch['falls_through_when'])
                    self.assertIn('taken when '+branch['taken_when'], text)
                    self.assertIn('falls through when '+branch['falls_through_when'], text)

    def test_x86_counter_branch_address_size_selects_wrap_width(self):
        # Deliberately nonzero upper half: CX=0, ECX=0x12340000.
        for arch, setup, cases in (
                ('x86-32', 'b900003412', (('', '0x1233ffff'), ('67', '0xffff'))),
                ('x86-16', '66b900003412', (('', '0xffff'), ('67', '0x1233ffff')))):
            for prefix, count in cases:
                with self.subTest(arch=arch, prefix=prefix):
                    fs, _ = self.analyze(arch, setup+prefix+'e201c3c3')
                    branch = next(b for b in fs['blocks'] if 'taken_when' in b)
                    self.assertEqual(branch['taken_when'], count+' != 0x0')
                    self.assertEqual(branch['falls_through_when'], count+' == 0x0')

    def test_x86_jcxz_checks_count_without_decrement_or_flag_test(self):
        for arch, setup, cases in (
                ('x86-32', 'b900003412', (('', '0x12340000'), ('67', '0x0'))),
                ('x86-16', '66b900003412', (('', '0x0'), ('67', '0x12340000')))):
            for prefix, count in cases:
                with self.subTest(arch=arch, prefix=prefix):
                    fs, _ = self.analyze(arch, setup+prefix+'e302909089c8c3')
                    branch = next(b for b in fs['blocks'] if 'taken_when' in b)
                    self.assertEqual(branch['taken_when'], count+' == 0x0')
                    self.assertEqual(branch['falls_through_when'], count+' != 0x0')
                    self.assertEqual(fs['exits'][0]['value'], '0x12340000' if arch == 'x86-32' else '0x0')

    def test_x86_counter_conditions_preserve_unknowns_and_flags(self):
        for arch, counter, bits in (('x86-16', 'cx', 16), ('x86-32', 'ecx', 32)):
            with self.subTest(arch=arch):
                fs, _ = self.analyze(arch, '0fa2e001c3c3')
                branch = next(b for b in fs['blocks'] if 'taken_when' in b)
                self.assertEqual(branch['taken_when'], '? ('+counter+' after decrement, '+str(bits)+'-bit wrap) != 0x0 and (Z == 0)')
                self.assertEqual(branch['falls_through_when'], '? ('+counter+' after decrement, '+str(bits)+'-bit wrap) == 0x0 or (not (Z == 0))')
                fs, _ = self.analyze(arch, '0fa2e301c3c3')
                branch = next(b for b in fs['blocks'] if 'taken_when' in b)
                self.assertEqual(branch['taken_when'], '? ('+counter+') == 0x0')
                # CMP flags must survive LOOP; its counter remains conservatively unknown.
                setup = 'b90100' if arch == 'x86-16' else 'b901000000'
                fs, _ = self.analyze(arch, setup+'83f807e2007401c3c3')
                branches = [b for b in fs['blocks'] if 'taken_when' in b]
                self.assertIn('== 0x7', branches[-1]['taken_when'])

    def test_x86_loop_invalidates_the_decremented_counter(self):
        fs,_=self.analyze('x86-32','b902000000e2008b01c3')
        load=next(a for a in fs['accesses'] if a['kind']=='load')
        self.assertNotEqual(load.get('absolute'),'0x2')

    def test_m68k_absolute_short_call_and_jump_sign_extend(self):
        fs,_=self.analyze('m68k','4eb8fffc4e75')
        self.assertEqual(fs['calls'][0]['target'],'0xfffffffc')
        fs,_=self.analyze('m68k','4ef8fffc4e75')
        self.assertEqual(fs['blocks'][0]['target'],'0xfffffffc')

    def test_m68k_pea_pushes_an_address_without_loading_its_contents(self):
        fs,_=self.analyze('m68k','4879000030004eb9000020004e75')
        self.assertEqual(fs['calls'][0]['args'][0]['value'],'0x3000')
        accesses=[a for a in fs['accesses'] if a['address']=='0x1000']
        self.assertEqual(len(accesses),1)
        self.assertEqual(accesses[0]['kind'],'store')
        self.assertEqual(accesses[0]['origin_offset'],-4)

    def test_x86_add_negative_immediate_keeps_a_signed_origin_offset(self):
        # mov eax,[esp+4]; add eax,-0x1003; mov ecx,[eax]; ret
        fs,_=self.analyze('x86-32','8b44240405fdefffff8b08c3')
        load=next(a for a in fs['accesses'] if a['address']=='0x1009')
        self.assertEqual(load['origin_offset'],-0x1003)

    def test_indirect_x86_jump_reports_pointer_read_and_incomplete_coverage(self):
        # mov eax,0x3000; jmp [eax]; mov eax,7; ret
        fs,text=self.analyze('x86-32','b800300000ff20b807000000c3')
        load=next(a for a in fs['accesses'] if a['address']=='0x1005')
        self.assertEqual(load['absolute'],'0x3000')
        self.assertEqual(load['kind'],'load')
        self.assertEqual(fs['coverage']['unresolved_transfers'],['0x1005'])
        self.assertIn('known edges only',text)

    def test_ppc32_decodes_big_endian_and_models_constants_loads_and_calls(self):
        # stwu r1,-16(r1); mflr r0; stw r0,20(r1); lis r3,0x1000; ori r3,r3,0x10;
        # lwz r4,8(r3); cmpwi r4,0; beq +16; li r5,5; bl +0xf00; lwz r0,20(r1);
        # mtlr r0; addi r1,r1,16; blr
        code = ('9421fff07c08' '02a690010014' '3c601000' '60630010' '80830008' '2c040000' '41820010'
                '38a00005' '48000f01' '80010014' '7c0803a6' '38210010' '4e800020')
        fs, text = self.analyze('ppc32', code)
        self.assertEqual((fs['routine']['arch'], fs['routine']['abi']), ('ppc32', 'ppc-sysv'))
        self.assertEqual(fs['warnings'], [])
        self.assertEqual([i['mn'] for i in fs['instructions']][:4], ['stwu', 'mflr', 'stw', 'lis'])
        load = next(a for a in fs['accesses'] if a['address'] == '0x1014')
        self.assertEqual((load['kind'], load['width'], load['absolute']), ('load', 4, '0x10000018'))
        call = fs['calls'][0]
        self.assertEqual((call['address'], call['mnemonic'], call['target']), ('0x1024', 'bl', '0x1f24'))
        self.assertEqual([a['value'] for a in call['args'][:3]], ['0x10000010', '[0x10000018]', '0x5'])
        self.assertEqual(call['args'][0]['location'], 'r3')
        self.assertIn('taken when [0x10000018] == 0x0', text)
        self.assertEqual([e['address'] for e in fs['exits']], ['0x1034'])
        self.assertEqual(fs['exits'][0]['register'], 'r3')

    def test_ppc32_branch_mnemonics(self):
        for mnemonic, expected in (('b', ('jump', None, None)), ('bl', ('call', None, None)),
                                   ('blr', ('return', 'lr', None)), ('bctrl', ('call', 'ctr', None)),
                                   ('ble', ('conditional', None, 'le')), ('bnel', ('conditional-call', None, 'ne')),
                                   ('beqlr', ('conditional-return', 'lr', 'eq')),
                                   ('bdnz', ('conditional', None, 'dnz')), ('bgtctr', ('conditional', 'ctr', 'gt'))):
            self.assertEqual(hostfacts.ppc_branch(mnemonic), expected, mnemonic)
        self.assertIsNone(hostfacts.ppc_branch('bcdadd'))
        self.assertIsNone(hostfacts.ppc_branch('lwz'))

    def test_ppc32_conditional_return_and_unmodelled_store_width(self):
        # cmpwi r3,0; beqlr; stb r3,3(r4); sth r3,4(r4); blr
        fs, _ = self.analyze('ppc32', '2c030000' '4d820020' '98640003' 'b0640004' '4e800020')
        self.assertEqual([e['address'] for e in fs['exits']], ['0x1004', '0x1010'])
        self.assertEqual([(a['kind'], a['width']) for a in fs['accesses']], [('store', 1), ('store', 2)])

    def test_ppc32_lmw_invalidates_only_its_destination_run(self):
        # lis r9,0xfa20; lis r30,0xfa20; lmw r28,0(r10); lwz r0,0(r9); lwz r1,0(r30); blr
        fs, _ = self.analyze('ppc32', '3d20fa20' '3fc0fa20' 'bb8a0000' '80090000' '803e0000' '4e800020')
        after_r9, after_r30 = fs['accesses'][-2:]
        self.assertEqual(after_r9['absolute'], '0xfa200000')
        self.assertNotIn('absolute', after_r30)

    def test_ppc32_stmw_keeps_the_base_register_known(self):
        # lis r9,0xfa20; stmw r29,0x10(r9); stw r0,0xfc(r9); stw r9,0x104(r9); blr
        fs, text = self.analyze('ppc32', '3d20fa20' 'bfa90010' '900900fc' '91290104' '4e800020')
        stores = [a for a in fs['accesses'] if a['kind'] == 'store']
        self.assertEqual([a.get('absolute') for a in stores], ['0xfa200010', '0xfa2000fc', '0xfa200104'])
        self.assertNotIn('to ?', text)
        self.assertEqual((stores[0]['width'], stores[0]['absolute']), (12, '0xfa200010'))

    def test_ppc32_unmodelled_alu_writes_only_its_destination(self):
        # lis r9,0xfa20; andi. r0,r0,0x3000; rlwinm r0,r0,20,0,29; stw r0,0xfc(r9); blr
        fs, _ = self.analyze('ppc32', '3d20fa20' '70003000' '5400a03a' '900900fc' '4e800020')
        self.assertEqual([a.get('absolute') for a in fs['accesses']], ['0xfa2000fc'])

    def test_ppc32_string_forms_write_only_their_destinations(self):
        # lis r9,0xfa20; stswi r5,r9,8; lswi r5,r9,8; stw r5,0xfc(r9); stw r0,0x100(r9); blr
        fs, _ = self.analyze('ppc32', '3d20fa20' '7ca945aa' '7ca944aa' '90a900fc' '90090100' '4e800020')
        stores = [a for a in fs['accesses'] if a['kind'] == 'store' and a['address'] in ('0x100c', '0x1010')]
        self.assertEqual([a.get('absolute') for a in stores], ['0xfa2000fc', '0xfa200100'])

    def test_ppc32_reservation_pair_is_an_access_at_ra_plus_rb(self):
        # lis r11,0x1000; li r0,0x2c; stwcx. r5,r11,r0; lwarx r6,r11,r0; stwcx. r5,0,r0;
        # stwcx. r5,r11,r3 (r3 unknown); blr
        fs, _ = self.analyze('ppc32', '3d601000' '3800002c' '7cab012d' '7ccb0028' '7ca0012d' '7cab192d' '4e800020')
        store, load, zero_base, unknown = fs['accesses']
        self.assertEqual((store['kind'], store['width'], store['absolute']), ('store', 4, '0x1000002c'))
        self.assertEqual((load['kind'], load['width'], load['absolute']), ('load', 4, '0x1000002c'))
        self.assertEqual((zero_base['kind'], zero_base['absolute']), ('store', '0x2c'))
        self.assertEqual((unknown['kind'], unknown['index_base']), ('store', '0x10000000'))
        self.assertNotIn('absolute', unknown)

    def test_ppc32_indexed_forms(self):
        # lis r11,0x1000; lwzx r0,r11,r3 (r3 unknown); li r4,0x10; stbx r0,r11,r4; lwzux r5,r11,r4; lwz r6,0(r11); blr
        fs, _ = self.analyze('ppc32', '3d601000' '7c0b182e' '38800010' '7c0b21ae' '7cab226e' '80cb0000' '4e800020')
        unknown, known, update, after = fs['accesses']
        self.assertEqual((unknown['kind'], unknown['width'], unknown['indexed'], unknown['index_base']),
                         ('load', 4, True, '0x10000000'))
        self.assertNotIn('absolute', unknown)
        self.assertEqual((known['kind'], known['width'], known['absolute']), ('store', 1, '0x10000010'))
        self.assertNotIn('indexed', known)
        self.assertEqual((update['kind'], update['absolute']), ('load', '0x10000010'))
        # the update form wrote the address back to r11
        self.assertEqual(after['absolute'], '0x10000010')

    def test_coldfire_unknown_index_is_marked_and_a_known_one_is_not(self):
        # movea.l #0x10000000,a0; move.l 0x10(a0,d1.l),d0; moveq #4,d1; move.l 0x10(a0,d1.l),d0; rts
        fs, _ = self.analyze('coldfire', '207c10000000' '20301810' '7204' '20301810' '4e75')
        unknown, known = [a for a in fs['accesses'] if not a['implicit']]
        self.assertEqual((unknown['indexed'], unknown['index_base']), (True, '0x10000010'))
        self.assertNotIn('absolute', unknown)
        self.assertEqual(known['absolute'], '0x10000014')
        self.assertNotIn('indexed', known)

    def test_coldfire_index_flag_does_not_leak_into_a_later_access(self):
        # movea.l #0x10000000,a0; lea 0x10(a0,d1.l),a1 (no access); move.b (a2),d0; rts
        fs, _ = self.analyze('coldfire', '207c10000000' '43f01810' '1012' '4e75')
        self.assertTrue(all('indexed' not in a for a in fs['accesses']))

    def test_ppc32_rejects_an_arm_abi(self):
        with self.assertRaises(ValueError):
            with tempfile.TemporaryDirectory() as d:
                p = os.path.join(d, 'blob')
                with open(p, 'wb') as f:
                    f.write(bytes(8))
                hostfacts.routine_for(p, '0x1000', size=4, arch='ppc32', load=0x1000, abi='arm-aapcs')

    def test_cli_requires_load_for_non_mips_flat_image(self):
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            hostfacts.main(['missing', '0x1000', '--arch', 'arm', '--flat', '--size', '4'])


if __name__ == '__main__':
    unittest.main()
