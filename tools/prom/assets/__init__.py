"""Asset readers: bitmaps, fonts, palettes and sounds the PROM carries, written as open formats. Each family's reader
implements only formats a chips page establishes."""


class AssetError(Exception):
    """An asset could not be found, or what was found disagrees with what the drawing code uses."""


def extract(analysis, out):
    """Write the assets of an analysed image under out/assets and return their manifest entries (the schema's asset
    objects, each with its file relative to out, sha256 and source address)."""
    if 'ip32-flash' not in analysis.containers:
        raise AssetError('no asset reader for this image; only O2 (ip32-flash) images have one')
    from . import ip32
    segment = next((s for s in analysis.segments if s.name == 'firmware'), None)
    if segment is None:
        raise AssetError('the O2 flash has no firmware segment')
    return ip32.extract(segment, out)
