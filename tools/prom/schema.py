"""Validate a document against sgi-prom.schema.json: the subset of JSON Schema the schema uses, over the stdlib."""
import json
import os
import re

SUPPORTED_VERSIONS = (1,)
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sgi-prom.schema.json'), encoding='utf-8') as _f:
    SCHEMA = json.load(_f)

_TYPES = {'object': dict, 'array': list, 'string': str, 'boolean': bool, 'null': type(None)}


class SchemaError(Exception):
    pass


def _is(value, name):
    if name == 'integer':
        return isinstance(value, int) and not isinstance(value, bool)
    return isinstance(value, _TYPES[name])


def _walk(schema, value, path, errors):
    if '$ref' in schema:
        schema = SCHEMA['$defs'][schema['$ref'].rsplit('/', 1)[1]]
    types = schema.get('type')
    if types is not None:
        types = types if isinstance(types, list) else [types]
        if not any(_is(value, t) for t in types):
            return errors.append('%s: expected %s, got %s' % (path, '/'.join(types), type(value).__name__))
    if 'const' in schema and (value != schema['const'] or type(value) is not type(schema['const'])):
        errors.append('%s: must be %r' % (path, schema['const']))
    if 'enum' in schema and value not in schema['enum']:
        errors.append('%s: %r is not one of %s' % (path, value, schema['enum']))
    if 'pattern' in schema and isinstance(value, str) and not re.search(schema['pattern'], value):
        errors.append('%s: %r does not match %s' % (path, value, schema['pattern']))
    if isinstance(value, dict):
        errors.extend('%s: missing %s' % (path, k) for k in schema.get('required', []) if k not in value)
        props = schema.get('properties', {})
        for k, v in value.items():
            if k in props:
                _walk(props[k], v, '%s.%s' % (path, k), errors)
            elif schema.get('additionalProperties') is False:
                errors.append('%s: unknown field %s' % (path, k))
    if isinstance(value, list) and 'items' in schema:
        for i, v in enumerate(value):
            _walk(schema['items'], v, '%s[%d]' % (path, i), errors)
    if 'oneOf' in schema:
        results = []
        for branch in schema['oneOf']:
            errs = []
            _walk(branch, value, path, errs)
            results.append(errs)
        if sum(1 for e in results if not e) != 1:
            # the branch whose kind the document names explains the failure; the others only say "wrong kind"
            kind = value.get('kind') if isinstance(value, dict) else None
            names = [b['$ref'].rsplit('/', 1)[1].replace('_file', '') for b in schema['oneOf']]
            errors.extend(e for n, errs in zip(names, results) if n == kind for e in errs)
            if kind not in names:
                errors.append('%s: kind must be one of %s' % (path, names))


def validate(doc):
    """Raise SchemaError listing every problem. A version this tool does not know is refused before anything else."""
    if not isinstance(doc, dict) or doc.get('schema') != 'sgi-prom':
        raise SchemaError('not an sgi-prom document (schema field is %r)' % (doc.get('schema') if isinstance(doc, dict) else None))
    if doc.get('version') not in SUPPORTED_VERSIONS or isinstance(doc.get('version'), bool):
        raise SchemaError('sgi-prom version %r is not supported (this tool reads %s)' % (doc.get('version'), list(SUPPORTED_VERSIONS)))
    errors = []
    _walk(SCHEMA, doc, '$', errors)
    if not errors and doc.get('kind') == 'prom':
        names = [s['name'] for s in doc['segments']]
        errors += ['$.segments: duplicate name %s' % n for n in sorted({n for n in names if names.count(n) > 1})]
        errors += ['$.segments[%d].parent: no segment named %s' % (i, s['parent'])
                   for i, s in enumerate(doc['segments']) if s['parent'] is not None and s['parent'] not in names]
    if errors:
        raise SchemaError('\n'.join(errors))
