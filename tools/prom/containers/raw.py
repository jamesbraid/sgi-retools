"""Any bytes: one segment, the whole image. Always the last container tried."""
from ..model import Segment

NAME = 'raw'


def probe(data):
    return 'fallback'


def unpack(data):
    return [Segment('image', data, stored_length=len(data))], None
