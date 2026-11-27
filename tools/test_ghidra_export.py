#!/usr/bin/env python3
"""Tests of the language Ghidra's ELF import is given by ghidra-export.py, from stub ELF headers.

Run from the repository root: python3 tools/test_ghidra_export.py
"""
import contextlib
import importlib.util
import io
import json
import os
import pathlib
import struct
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('ghidra_export', os.path.join(HERE, 'ghidra-export.py'))
ge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ge)


def elf32(machine, order, flags=0, etype=1):
    """A bare ELF32 relocatable header: enough for the planner (no .mdebug read), not loadable."""
    ident = b'\x7fELF' + bytes([1, 1 if order == '<' else 2, 1]) + bytes(9)
    return ident + struct.pack(order + 'HHIIIIIHHHHHH', etype, machine, 1, 0, 0, 0, flags, 52, 0, 0, 40, 0, 0)


def pe(machine):
    """A DOS header pointing at a bare PE signature and COFF machine: enough for the planner."""
    return b'MZ' + bytes(0x3a) + struct.pack('<I', 0x40) + b'PE\0\0' + struct.pack('<H', machine)


class PlanLanguage(unittest.TestCase):
    def plan(self, blob):
        with tempfile.TemporaryDirectory() as d:
            obj = os.path.join(d, 'obj')
            job = os.path.join(d, 'job')
            os.mkdir(job)
            with open(obj, 'wb') as f:
                f.write(blob)
            ge.prepare(['--job', job, '--decompile-all', obj])
            with open(os.path.join(job, 'ghidra.sh')) as f:
                return f.read()

    def test_arm_le_elf_gets_arm_language_and_no_mips_gp_script(self):
        script = self.plan(elf32(ge.EM_ARM, '<'))
        self.assertIn('-processor ARM:LE:32:v4', script)
        self.assertNotIn('ReMipsGp', script)

    def test_ia64_elf_gets_ia64_language_and_its_gp_script(self):
        script = self.plan(elf32(ge.EM_IA_64, '<'))
        self.assertIn('-processor IA64:LE:64:default', script)
        self.assertIn('-preScript IA64Elf.java', script)
        self.assertNotIn('ReMipsGp', script)
        self.assertIn('-postScript IA64Signatures.java -postScript ReDecompileExport.java', script)

    def test_ia64_pe_gets_the_pe_loader_and_its_descriptor_script(self):
        script = self.plan(pe(ge.PE_MACHINE_IA64))
        self.assertIn('-processor IA64:LE:64:default', script)
        self.assertIn('-loader PeLoader -preScript IA64Pe.java', script)
        self.assertNotIn('IA64Elf', script)
        self.assertIn('-postScript IA64Signatures.java -postScript ReDecompileExport.java', script)

    def test_status_line_names_the_header_the_language_comes_from(self):
        for blob, header in ((pe(ge.PE_MACHINE_I386), 'PE'), (elf32(ge.EM_MIPS, '>'), 'ELF')):
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.plan(blob)
            self.assertIn('language from the %s header' % header, err.getvalue())
            self.assertNotIn('ELF header' if header == 'PE' else 'PE header', err.getvalue())

    def test_x86_64_pe_is_refused(self):
        with self.assertRaises(SystemExit):
            self.plan(pe(0x8664))

    def test_x86_pe_gets_the_pe_loader_and_its_symbol_scripts_in_order(self):
        with tempfile.TemporaryDirectory() as d:
            obj, job = os.path.join(d, 'a.dll'), os.path.join(d, 'job')
            for name in ('a.dbg', 'a.pdb'):
                open(os.path.join(d, name), 'wb').close()
            os.mkdir(job)
            with open(obj, 'wb') as f:
                f.write(pe(ge.PE_MACHINE_I386))
            ge.prepare(['--job', job, '--decompile-all', '--dbg', os.path.join(d, 'a.dbg'),
                        '--pdb', os.path.join(d, 'a.pdb'), obj])
            with open(os.path.join(job, 'ghidra.sh')) as f:
                script = f.read()
        self.assertIn('-loader PeLoader -preScript ReDbgImport.java', script)
        self.assertLess(script.index('ReDbgImport.java'), script.index('RePdbImport.java'))
        self.assertNotIn('IA64', script)
        self.assertNotIn('-processor', script)

    def test_returning_runs_after_analysis_and_before_the_export(self):
        with tempfile.TemporaryDirectory() as d:
            obj, job = os.path.join(d, 'a.dll'), os.path.join(d, 'job')
            os.mkdir(job)
            with open(obj, 'wb') as f:
                f.write(pe(ge.PE_MACHINE_I386))
            ge.prepare(['--job', job, '--decompile-all', '--returning', 'pulGetPacket,_foo@8',
                        '--returning', '@0x1000', obj])
            with open(os.path.join(job, 'ghidra.sh')) as f:
                script = f.read()
        self.assertIn('-postScript ReReturning.java pulGetPacket,_foo@8,@0x1000 -postScript ReDecompileExport.java',
                      script)

    def test_returning_needs_a_name(self):
        with tempfile.TemporaryDirectory() as d:
            obj = os.path.join(d, 'a.dll')
            with open(obj, 'wb') as f:
                f.write(pe(ge.PE_MACHINE_I386))
            with self.assertRaises(SystemExit):
                ge.prepare(['--job', d, '--decompile-all', '--returning', ',', obj])

    def prepare_pe(self, *args, touch=()):
        """Plan an x86 PE export with ARGS (@D is the temporary directory, holding the TOUCH files):
        the ghidra.sh text, the plan and the retype rules, with the directory shown as @D."""
        with tempfile.TemporaryDirectory() as d:
            for name in touch:
                open(os.path.join(d, name), 'w').close()
            obj, job = os.path.join(d, 'a.dll'), os.path.join(d, 'job')
            os.mkdir(job)
            with open(obj, 'wb') as f:
                f.write(pe(ge.PE_MACHINE_I386))
            ge.prepare(['--job', job, '--decompile-all'] + [a.replace('@D', d) for a in args] + [obj])
            files = {n: open(os.path.join(job, n)).read() for n in os.listdir(job) if os.path.isfile(os.path.join(job, n))}
        return (files['ghidra.sh'].replace(d, '@D'), json.loads(files['plan.json'].replace(d, '@D')),
                files.get('retype.tsv'))

    def test_callconv_and_param_type_write_rules_that_run_before_returning(self):
        script, plan, rules = self.prepare_pe('--callconv', 'fastcall:__gl*,_Foo@8', '--param-type', '__gl*:0:Ctx *',
                                              '--returning', 'bar')
        self.assertEqual(rules, 'callconv\tfastcall\t__gl*\ncallconv\tfastcall\t_Foo@8\nparam\t__gl*\t0\tCtx *\n')
        self.assertIn('-postScript ReFunctionTypes.java @D/job/retype.tsv -postScript ReReturning.java bar '
                      '-postScript ReDecompileExport.java', script)
        self.assertEqual(plan['retype_rules'], rules.splitlines())

    def test_callconv_file_and_the_rules_in_order(self):
        with tempfile.TemporaryDirectory() as d:
            rules = os.path.join(d, 'cc.txt')
            with open(rules, 'w') as f:
                f.write('# the ICD\nthiscall:A*\n\nstdcall:B\n')
            _, _, text = self.prepare_pe('--callconv', 'fastcall:C', '--callconv-file', rules)
        self.assertEqual(text, 'callconv\tfastcall\tC\ncallconv\tthiscall\tA*\ncallconv\tstdcall\tB\n')

    def test_bad_callconv_and_param_type_are_refused(self):
        for args in (['--callconv', 'fastcall'], ['--callconv', ':x'], ['--param-type', 'f:x:T'],
                     ['--param-type', 'f:1:'], ['--param-type', 'f']):
            with self.assertRaises(SystemExit, msg=args):
                self.prepare_pe(*args)

    def test_extra_scripts_run_in_order_around_the_built_in_ones(self):
        script, plan, _ = self.prepare_pe(
            '--dbg', '@D/a.dbg', '--returning', 'f', '--pre-script', '@D/pre1.java', '--post-script', '@D/post1.java',
            '--pre-script', '@D/pre2.java', touch=('a.dbg', 'pre1.java', 'pre2.java', 'post1.java'))
        self.assertIn('-scriptPath /opt/re-scripts;@D ', script.replace("'", ''))
        self.assertEqual(plan['pre_scripts'], ['@D/pre1.java', '@D/pre2.java'])
        self.assertEqual(plan['post_scripts'], ['@D/post1.java'])
        self.assertEqual(plan['returning'], ['f'])
        self.assertLess(script.index('-preScript ReDbgImport.java'), script.index('-preScript pre1.java'))
        self.assertLess(script.index('-preScript pre1.java'), script.index('-preScript pre2.java'))
        self.assertLess(script.index('-postScript ReReturning.java'), script.index('-postScript post1.java'))
        self.assertLess(script.index('-postScript post1.java'), script.index('-postScript ReDecompileExport.java'))

    def test_extra_script_must_exist_and_be_unique(self):
        with self.assertRaises(SystemExit):
            self.prepare_pe('--post-script', '@D/missing.java')
        with tempfile.TemporaryDirectory() as other:
            open(os.path.join(other, 'x.java'), 'w').close()
            with self.assertRaises(SystemExit):
                self.prepare_pe('--post-script', other + '/x.java', '--pre-script', other + '/x.java')

    def test_dbg_and_pdb_need_an_x86_pe(self):
        with tempfile.TemporaryDirectory() as d:
            obj, sym = os.path.join(d, 'obj'), os.path.join(d, 'a.dbg')
            open(sym, 'wb').close()
            for blob in (elf32(ge.EM_MIPS, '>'), pe(ge.PE_MACHINE_IA64)):
                with open(obj, 'wb') as f:
                    f.write(blob)
                for flag in ('--dbg', '--pdb'):
                    with self.assertRaises(SystemExit):
                        ge.prepare(['--job', d, '--decompile-all', flag, sym, obj])

    def test_sal_runtime_is_an_sn2_prom_option(self):
        with tempfile.TemporaryDirectory() as d:
            obj = os.path.join(d, 'prom.bin')
            with open(obj, 'wb') as f:
                f.write(bytes(4096))
            for n, (flags, want) in enumerate((([], '-preScript SN2PromImport.java -postScript'),
                                (['--sal-runtime'], '-preScript SN2PromImport.java sal-runtime -postScript'),
                                (['--gzip-elfs'], '-preScript SN2PromImport.java gzip-elfs -postScript'),
                                (['--sal-runtime', '--gzip-elfs'],
                                 '-preScript SN2PromImport.java sal-runtime gzip-elfs -postScript'))):
                job = os.path.join(d, 'job%d' % n)
                os.mkdir(job)
                ge.prepare(['--job', job, '--sn2-prom', '--decompile-all'] + flags + [obj])
                with open(os.path.join(job, 'ghidra.sh')) as f:
                    self.assertIn(want, f.read())
            with self.assertRaises(SystemExit):
                ge.prepare(['--job', d, '--sal-runtime', '--decompile-all', obj])
            with self.assertRaises(SystemExit):
                ge.prepare(['--job', d, '--gzip-elfs', '--decompile-all', obj])

    def test_gzip_kernel_is_inflated_and_planned_by_its_machine(self):
        import gzip
        script = self.plan(gzip.compress(elf32(ge.EM_IA_64, '<')))
        self.assertIn('-processor IA64:LE:64:default', script)
        self.assertIn('/inflated/obj ', script)

    def test_flat_image_heap_follows_its_size_and_an_option_overrides_it(self):
        with tempfile.TemporaryDirectory() as d:
            obj = os.path.join(d, 'prom.bin')
            for mib, option, want in ((6, [], 'GHIDRA_HEADLESS_MAXMEM=8G'), (12, [], 'GHIDRA_HEADLESS_MAXMEM=14G'),
                                      (30, [], 'GHIDRA_HEADLESS_MAXMEM=14G'),
                                      (12, ['--heap', '20G'], 'GHIDRA_HEADLESS_MAXMEM=20G')):
                with open(obj, 'wb') as f:
                    f.truncate(mib << 20)
                job = os.path.join(d, 'job%d%d' % (mib, len(option)))
                os.mkdir(job)
                ge.prepare(['--job', job, '--sn2-prom', '--decompile-all'] + option + [obj])
                with open(os.path.join(job, 'ghidra.sh')) as f:
                    self.assertIn('export ' + want, f.read())
            with self.assertRaises(SystemExit):
                ge.prepare(['--job', d, '--heap', 'big', '--sn2-prom', '--decompile-all', obj])

    def test_elf_keeps_the_default_heap_and_no_analysis_is_passed_on(self):
        script = self.plan(elf32(ge.EM_IA_64, '<'))
        self.assertNotIn('MAXMEM', script)
        self.assertNotIn('-noanalysis', script)
        with tempfile.TemporaryDirectory() as d:
            obj, job = os.path.join(d, 'obj'), os.path.join(d, 'job')
            os.mkdir(job)
            with open(obj, 'wb') as f:
                f.write(elf32(ge.EM_IA_64, '<'))
            ge.prepare(['--job', job, '--decompile-all', '--no-analysis', obj])
            with open(os.path.join(job, 'ghidra.sh')) as f:
                self.assertIn(' -noanalysis ', f.read())

    def test_decompile_limits_reach_the_request_and_the_scripts(self):
        with tempfile.TemporaryDirectory() as d:
            obj, job = os.path.join(d, 'obj'), os.path.join(d, 'job')
            os.mkdir(job)
            with open(obj, 'wb') as f:
                f.write(elf32(ge.EM_MIPS, '>'))
            ge.prepare(['--job', job, '--decompile-all', obj])
            default = json.load(open(os.path.join(job, 'export.json')))['budget']
            job2 = os.path.join(d, 'job2')
            os.mkdir(job2)
            ge.prepare(['--job', job2, '--decompile-all', '--decompile-max-instructions', '500',
                        '--decompile-max-payload', '7', '--decompile-max-jumptable', '9', obj])
            given = json.load(open(os.path.join(job2, 'export.json')))['budget']
            script = open(os.path.join(job2, 'ghidra.sh')).read()
            with self.assertRaises(SystemExit):
                ge.prepare(['--job', d, '--decompile-all', '--decompile-max-payload', '0', obj])
        self.assertEqual(default, {'max_instructions': 100000, 'max_payload_mb': 50, 'max_jumptable_entries': 1024,
                                   'other_options_reset': False})
        self.assertEqual(given, {'max_instructions': 500, 'max_payload_mb': 7, 'max_jumptable_entries': 9,
                                 'other_options_reset': True})
        self.assertIn('export RE_DECOMPILE_BUDGET=500,7,9', script)

    def test_finish_writes_the_budget_and_counts_ceiling_failures(self):
        with tempfile.TemporaryDirectory() as d:
            job = os.path.join(d, 'job')
            os.mkdir(job)
            budget = {'max_instructions': 5, 'max_payload_mb': 6, 'max_jumptable_entries': 7}
            json.dump({'budget': budget}, open(os.path.join(job, 'export.json'), 'w'))
            json.dump({'object': 'o', 'image_sha256': 'x', 'language': 'l', 'compiler_spec_requested': None,
                       'bsim': False, 'exporting': True, 'object_path': 'o'}, open(os.path.join(job, 'plan.json'), 'w'))
            open(os.path.join(job, 'rc'), 'w').write('0')
            json.dump({'notes': [], 'unmatched': []}, open(os.path.join(job, 'types.json'), 'w'))
            rows = [{'name': 'a', 'address': '0x1', 'complete': True, 'decompile_status': 'complete'},
                    {'name': 'b', 'address': '0x2', 'complete': False, 'decompile_status': 'failed',
                     'failure': {'reason': 'ceiling', 'message': 'timeout'}}]
            open(os.path.join(job, 'functions.jsonl'), 'w').write(''.join(json.dumps(r) + '\n' for r in rows))
            err = io.StringIO()
            with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                ge.finish(['--job', job])
            out = json.load(open(os.path.join(job, 'decompile.json')))
        self.assertEqual(out['budget'], budget)
        self.assertEqual([f['decompile_status'] for f in out['functions']], ['complete', 'failed'])
        self.assertIn('1 functions hit the decompile time ceiling', err.getvalue())

    def test_hand_function_names_are_checked(self):
        for name in ('a b', 'x;y', '', 'a\nb', "a'b", 'a/b'):
            with tempfile.TemporaryDirectory() as d:
                lst = os.path.join(d, 'hand.json')
                json.dump([{'entry': '0x10', 'end': '0x20', 'name': name}], open(lst, 'w'))
                with self.assertRaises(SystemExit, msg=repr(name)):
                    self.prepare_pe('--hand-functions', lst)

    def test_finish_fails_when_the_hand_script_did_not_report(self):
        for report, ok in ((2, True), (1, False), (0, False)):
            with tempfile.TemporaryDirectory() as d:
                job = os.path.join(d, 'job')
                os.mkdir(job)
                json.dump({'object': 'o', 'image_sha256': 'x', 'language': 'l', 'compiler_spec_requested': None,
                           'bsim': False, 'exporting': False, 'object_path': 'o', 'hand_functions': 3},
                          open(os.path.join(job, 'plan.json'), 'w'))
                open(os.path.join(job, 'rc'), 'w').write('0')
                open(os.path.join(job, 'headless.txt'), 'w').write(
                    'ReHandFunctions.java> ReHandFunctions: 3 functions, 0 restored, 0 dropped\n' * report)
                with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                    if ok:
                        ge.finish(['--job', job])
                    else:
                        with self.assertRaises(SystemExit):
                            ge.finish(['--job', job])

    def test_hand_functions_are_set_before_analysis_and_restored_after(self):
        with tempfile.TemporaryDirectory() as d:
            lst = os.path.join(d, 'hand.json')
            with open(lst, 'w') as f:
                json.dump([{'entry': '0x10', 'end': '0x20', 'name': 'a'}, {'entry': '0x20', 'end': '0x30', 'name': 'b'}], f)
            script, plan, _ = self.prepare_pe('--hand-functions', lst)
        self.assertLess(script.index('-preScript ReHandFunctions.java'), script.index('-postScript ReHandFunctions.java'))
        self.assertIn('hand-functions.json restore', script)
        self.assertEqual(plan['hand_functions'], 2)

    def test_hand_functions_list_is_checked(self):
        bad = ['{}', '[{"entry": "0x20", "end": "0x10", "name": "a"}]', '[{"entry": "0x10", "end": "0x20"}]',
               '[{"entry": "0x10", "end": "0x28", "name": "a"}, {"entry": "0x20", "end": "0x30", "name": "b"}]']
        for text in bad:
            with tempfile.TemporaryDirectory() as d:
                lst = os.path.join(d, 'hand.json')
                open(lst, 'w').write(text)
                with self.assertRaises(SystemExit, msg=text):
                    self.prepare_pe('--hand-functions', lst)

    def test_hand_functions_move_into_the_window_of_a_flat_image(self):
        with tempfile.TemporaryDirectory() as d:
            lst, obj, job = os.path.join(d, 'hand.json'), os.path.join(d, 'prom.bin'), os.path.join(d, 'job')
            os.mkdir(job)
            open(lst, 'w').write('[{"entry": "0x1fc00010", "end": "0x1fc00020", "name": "a"}]')
            open(obj, 'wb').write(bytes(64))
            ge.prepare(['--job', job, '--flat', '--load', '0x1fc00000', '--decompile-all', '--hand-functions', lst, obj])
            moved = json.load(open(os.path.join(job, 'hand-functions.json')))
        self.assertEqual(moved, [{'entry': '0xc00000001fc00010', 'end': '0xc00000001fc00020', 'name': 'a'}])

    def test_mips_elf_is_unchanged(self):
        script = self.plan(elf32(ge.EM_MIPS, '>'))
        self.assertNotIn('-processor', script)
        self.assertIn('ReMipsGp.java loader -', script)
        self.assertNotIn('IA64Signatures', script)

    def test_wide_mips32_elf_keeps_its_variant(self):
        script = self.plan(elf32(ge.EM_MIPS, '>', flags=0x20000000 | ge.EF_MIPS_ABI2))
        self.assertIn('-processor MIPS:BE:64:64-32addr -cspec n32', script)

    def test_other_machines_and_byte_orders_are_refused(self):
        for blob in (elf32(3, '<'), elf32(ge.EM_ARM, '>'), elf32(ge.EM_MIPS, '<'), elf32(ge.EM_IA_64, '>')):
            with self.assertRaises(SystemExit):
                self.plan(blob)


class Xref(unittest.TestCase):
    def test_xref_needs_no_decompile_option_and_names_the_install_path(self):
        with tempfile.TemporaryDirectory() as d:
            job, os_dir = os.path.join(d, 'job'), os.path.join(d, 'root', 'IP27')
            os.makedirs(job)
            os.makedirs(os_dir)
            old = os.getcwd()
            os.chdir(d)
            try:
                open('root/IP27/unix', 'wb').write(elf32(ge.EM_MIPS, '>'))
                ge.prepare(['--job', job, '--xref', 'generated/xref', 'root/IP27/unix'])
            finally:
                os.chdir(old)
            plan = json.load(open(os.path.join(job, 'plan.json')))
            script = open(os.path.join(job, 'ghidra.sh')).read()
        self.assertEqual(plan['xref'], 'generated/xref/IP27/unix')
        self.assertIn('-postScript ReXrefExport.java', script)
        self.assertNotIn('ReDecompileExport', script)

    def test_tables_are_sorted_in_the_published_address_space_with_escaped_text(self):
        window = 0xc000000000000000
        rows = {
            'xref-functions.jsonl': [
                {'entry': hex(window + 0x200), 'end': hex(window + 0x240), 'name': '', 'name_source': '', 'callers': [hex(window + 0x100)],
                 'callees': [], 'hardware': 'access'},
                {'entry': hex(window + 0x100), 'end': hex(window + 0x140), 'name': 'main', 'name_source': 'user',
                 'callers': [], 'callees': [hex(window + 0x200)], 'hardware': 'calls-access'}],
            'xref-sites.jsonl': [
                {'function': hex(window + 0x100), 'site': hex(window + 0x110), 'kind': 'call',
                 'target': hex(window + 0x200) + ' direct', 'grade': 'established'},
                {'function': hex(window + 0x200), 'site': hex(window + 0x210), 'kind': 'rmw', 'address': '0xbf000040',
                 'physical': '0x1f000040', 'width': 4, 'value': 'load@0x1', 'uses': ['or 0x1', 'eq 0x0'], 'grade': 'established'},
                {'function': hex(window + 0x100), 'site': hex(window + 0x120), 'kind': 'call', 'target': '? unresolved',
                 'grade': 'established'}],
            'xref-strings.jsonl': [
                {'string': hex(window + 0x300), 'text': 'a\tb\n\\' + 'x' * 300, 'function': hex(window + 0x100),
                 'site': hex(window + 0x114)}]}
        with tempfile.TemporaryDirectory() as d:
            job, out = pathlib.Path(d) / 'job', pathlib.Path(d) / 'out'
            job.mkdir()
            for name, items in rows.items():
                (job / name).write_text(''.join(json.dumps(r) + '\n' for r in items))
            with contextlib.redirect_stderr(io.StringIO()):
                ge.write_xref(job, out, window)
            got = {n: (out / n).read_text().splitlines() for n in ('functions.tsv', 'sites.tsv', 'strings.tsv')}
        self.assertEqual(got['functions.tsv'], ['entry\tend\tname\tname_source\tcallers\tcallees\thardware',
                         '0x100\t0x140\tmain\tuser\t\t0x200\tcalls-access', '0x200\t0x240\t\t\t0x100\t\taccess'])
        self.assertEqual(got['sites.tsv'][1:], ['0x100\t0x110\tcall\t\t\t\t\t\t0x200 direct\testablished',
                         '0x100\t0x120\tcall\t\t\t\t\t\t? unresolved\testablished',
                         '0x200\t0x210\trmw\t0xbf000040\t0x1f000040\t4\tload@0x1\tor 0x1;eq 0x0\t\testablished'])
        text = got['strings.tsv'][1].split('\t')
        self.assertEqual(text[0], '0x300')
        self.assertEqual(text[1], 'a\\tb\\n\\\\' + 'x' * (ge.XREF_TEXT_LIMIT - 5) + '...')
        self.assertEqual(text[2:], ['0x100', '0x114'])


if __name__ == '__main__':
    unittest.main()
