"""Asset readers: bitmaps, fonts, palettes and sounds the PROM carries, written as open formats. Each family's reader
implements only formats a chips page establishes."""


class AssetError(Exception):
    """An asset could not be found, or what was found disagrees with what the drawing code uses."""
