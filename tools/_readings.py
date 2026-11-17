"""Per-routine readings are filed by subject and binary: <subject>/readings/<binary>.md.

An entry is a list item "- `name` in `binary` ..." with its indented lines, or a heading
"### `name` in `binary` at 0x..." (or "### binary at 0x..." when the name is in the text) with the
text below it. Which subject directory a binary belongs to is
configuration: tools/config/readings-subjects.json holds ordered rules (a regular expression on the binary
path and the directory), and a default. `{1}` in a directory is the first group of the rule, lower-cased;
the default may use it for the platform prefix (IP27/... files under software/kernel/ip27).
"""
import json
import os
import re

BULLET = re.compile(r'^- `[^`]*` in `([^`]+)`')
HEADING = re.compile(r'^#{3,6} (?:`(?:[^`]*` in `)?([^`]+)`(?: at 0x[0-9a-fA-F]+)?|([^\s`]+/[^\s`]+) at 0x[0-9a-fA-F]+)')
ANY_HEADING = re.compile(r'^#{1,6}\s')
LINK_TARGET = re.compile(r'(\]\()([^)\s]*)((?:\s+"[^"]*")?\))')
REF_DEF = re.compile(r'^(\s*\[[^\]]+\]:\s*)(\S+)(.*)$')


def git(repo, *args, check=True):
    return subprocess.run(('git', '-C', repo) + args, check=check, capture_output=True, text=True).stdout


# ---------------------------------------------------------------- entries
def parse(text):
    """(entries, stray): entries is [(binary, [lines])], stray the non-blank lines outside any entry."""
    entries, stray, cur, kind = [], [], None, None
    for line in text.split('\n'):
        m = BULLET.match(line)
        h = None if m else HEADING.match(line)
        if m or h:
            cur = (m or h).group(1) or h.group(2), [line]
            kind = 'bullet' if m else 'heading'
            entries.append(cur)
            continue
        if cur is None:
            if line.strip():
                stray.append(line)
            continue
        if ANY_HEADING.match(line):
            cur = None
            stray.append(line)
        elif kind == 'bullet' and line.strip() and not line[0].isspace():
            cur = None
            stray.append(line)
        else:
            cur[1].append(line)
    out = []
    for binary, lines in entries:
        while lines and not lines[-1].strip():
            lines.pop()
        out.append((binary, lines))
    return out, stray


def normal(lines):
    """An entry with its link targets blanked, for comparing an entry before and after files move."""
    return LINK_TARGET.sub(r'\1L\3', '\n'.join(lines))


# ---------------------------------------------------------------- subjects
class Subjects:
    def __init__(self, repo):
        from _layout import Layout
        path = os.path.join(repo, Layout(repo).config('readings-subjects.json'))
        with open(path, encoding='utf-8') as f:
            cfg = json.load(f)
        self.default = cfg['default']
        self.rules = [(re.compile(r['match']), r['dir']) for r in cfg['rules']]

    def dir_for(self, binary):
        for rx, d in self.rules:
            m = rx.search(binary)
            if m:
                return re.sub(r'\{(\d)\}', lambda g: (m.group(int(g.group(1))) or '').lower(), d)
        m = re.match(r'^(IP\d+)/', binary)
        if m and '{1}' in self.default:
            return self.default.replace('{1}', m.group(1).lower())
        return self.default.replace('/{1}', '')


def reading_name(binary):
    """File name of a binary's readings: the path without the boot-directory noise, `/` and `(` flattened."""
    p = re.sub(r'usr/cpu/sysgen/IP\d+boot/', '', binary)
    p = p.replace('(', '-').replace(')', '').replace(':', '-').replace('/', '-')
    return re.sub(r'[^A-Za-z0-9._+-]', '_', p) + '.md'



def file_entries(repo, text, header='One entry per routine, filed here from the reading batches by binary.'):
    """Append every entry of text to the readings page of its binary, creating the page. Returns the
    repository-relative paths written."""
    subj = Subjects(repo)
    entries, _ = parse(text)
    by_page = {}
    for binary, lines in entries:
        rel = '%s/readings/%s' % (subj.dir_for(binary), reading_name(binary))
        by_page.setdefault(rel, (binary, []))[1].append(lines)
    for rel, (binary, items) in by_page.items():
        path = os.path.join(repo, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fresh = not os.path.exists(path)
        with open(path, 'a', encoding='utf-8') as f:
            if fresh:
                f.write('# Readings: `%s`\n\n%s\n' % (binary, header))
            for lines in items:
                f.write('\n' + '\n'.join(lines) + '\n')
    return sorted(by_page)
