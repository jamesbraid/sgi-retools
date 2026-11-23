from . import installer, io4_flat, io4_segmented, ip32_flash, promgen64, raw

# Probed in order; raw always matches, so it stays last.
CONTAINERS = [installer, ip32_flash, io4_flat, io4_segmented, promgen64, raw]
