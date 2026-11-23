"""The published PROM index (prom/index.json beside the images), cached so lookups work offline."""
import json
import os
import urllib.request

CACHE = os.path.join('.cache', 'prom', 'index.json')
URL = 'https://origami-dist.irix.fans/prom/index.json'
FIELDS = ('board', 'version', 'rev', 'part', 'kind', 'name', 'size', 'sha256')


def load(path=None, refresh=False, warn=lambda m: None, fetch=True):
    """sha256 -> row of the index at path, else of the cached copy (fetched once when absent unless fetch is false, or with refresh).
    Empty, with a warning, when there is neither a copy nor a network."""
    explicit = path is not None
    path = path or CACHE
    if not explicit and (refresh or (fetch and not os.path.isfile(path))):
        try:
            with urllib.request.urlopen(URL, timeout=20) as r:
                body = r.read()
            json.loads(body)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'wb') as f:
                f.write(body)
        except (OSError, ValueError) as e:
            warn('PROM index not fetched (%s)' % e)
    if not os.path.isfile(path) and not explicit:
        return {}
    with open(path, encoding='utf-8') as f:
        doc = json.load(f)
    return {p['sha256']: {k: p.get(k) for k in FIELDS} for p in doc.get('proms', []) if p.get('sha256')}

