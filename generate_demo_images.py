from pathlib import Path
from PIL import Image, ImageDraw, ImageFilter

from core import PROFILES

OUT = Path(__file__).resolve().parent / "images"
OUT.mkdir(exist_ok=True)

CASES = {
    "negative": (175, 175, 175),
    "positive": (150, 70, 45),
    "inconclusive": (150, 135, 115),
}


def make_image(ref, test_color, subtitle):
    img = Image.new("RGB", (1000, 700), (225, 225, 225))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((30, 25, 400, 165), radius=10, fill=(245, 245, 245), outline=(30, 30, 30), width=3)
    for i, c in enumerate(ref):
        x1 = 50 + i * 110
        d.rectangle((x1, 50, x1 + 80, 135), fill=tuple(c), outline=(0, 0, 0), width=2)
    d.text((50, 140), "REFERENCE CARD", fill=(0, 0, 0))
    d.rounded_rectangle((350, 260, 650, 560), radius=20, fill=(255, 255, 255), outline=(20, 20, 20), width=5)
    d.rectangle((405, 315, 595, 505), fill=test_color, outline=(0, 0, 0), width=3)
    d.text((60, 620), subtitle, fill=(100, 0, 0))
    return img.filter(ImageFilter.GaussianBlur(radius=0.4))


count = 0
for profile in PROFILES.values():
    for label, color in CASES.items():
        name = f"{profile.kit_id}_{label}.jpg"
        image = make_image(profile.ref_rgb, color, f"SYNTHETIC DEMO — {profile.kit_id} — {label.upper()}")
        image.save(OUT / name, quality=95)
        count += 1

# Backward-compatible filenames for DEMO-001 used by the test suite and old demo instructions.
legacy = {
    "demo_negative.jpg": "DEMO-001_negative.jpg",
    "demo_positive.jpg": "DEMO-001_positive.jpg",
    "demo_inconclusive.jpg": "DEMO-001_inconclusive.jpg",
}
for old_name, new_name in legacy.items():
    (OUT / new_name).replace(OUT / old_name) if False else (OUT / old_name).write_bytes((OUT / new_name).read_bytes())

print(f"Generated {count + len(legacy)} demo image files in {OUT}")
