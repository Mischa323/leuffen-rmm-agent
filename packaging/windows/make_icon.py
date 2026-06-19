"""Generate packaging/windows/leuffen.ico — the Leuffen RMM shield app icon.

Drawn programmatically (same look as the tray) so we don't need an external asset.
Run once to (re)produce the .ico; the file is committed to the repo.
"""
from PIL import Image, ImageDraw

ACCENT = (59, 130, 246, 255)
ACCENT_DK = (37, 99, 235, 255)

SIZE = 256
img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
d = ImageDraw.Draw(img)

# Vertical brand gradient inside the shield.
grad = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
gd = ImageDraw.Draw(grad)
for y in range(SIZE):
    t = y / SIZE
    r = int(ACCENT[0] * (1 - t) + ACCENT_DK[0] * t)
    g = int(ACCENT[1] * (1 - t) + ACCENT_DK[1] * t)
    b = int(ACCENT[2] * (1 - t) + ACCENT_DK[2] * t)
    gd.line([(0, y), (SIZE, y)], fill=(r, g, b, 255))

# Shield silhouette mask.
mask = Image.new("L", (SIZE, SIZE), 0)
md = ImageDraw.Draw(mask)
s = SIZE / 64.0
shield = [(13 * s, 11 * s), (51 * s, 11 * s), (51 * s, 34 * s),
          (32 * s, 56 * s), (13 * s, 34 * s)]
md.polygon(shield, fill=255)
img.paste(grad, (0, 0), mask)

# White check mark.
d.line([(22 * s, 31 * s), (29 * s, 39 * s), (43 * s, 22 * s)],
       fill=(255, 255, 255, 240), width=int(5 * s), joint="curve")

img.save("packaging/windows/leuffen.ico",
         sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
print("wrote packaging/windows/leuffen.ico")
