#!/usr/bin/env python3
"""Flat non-MIPS facts checked against hand-assembled instruction sequences."""
import contextlib
import io
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hostfacts


class FirmwareFacts(unittest.TestCase):
    def analyze(self, arch, code, **kwargs):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, 'blob')
            with open(p, 'wb') as f:
                f.write(bytes.fromhex(code))
            r = hostfacts.routine_for(p, '0x1000', size=len(bytes.fromhex(code)),
                                      flat=True, load=0x1000, arch=arch, **kwargs)
            fs = r.facts(False)
            return fs, hostfacts.render(r, fs)

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

    def test_cli_requires_load_for_non_mips_flat_image(self):
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            hostfacts.main(['missing', '0x1000', '--arch', 'arm', '--flat', '--size', '4'])


if __name__ == '__main__':
    unittest.main()
