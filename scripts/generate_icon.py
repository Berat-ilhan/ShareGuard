from __future__ import annotations

import argparse
from pathlib import Path

from PIL import Image, ImageDraw


def generate_icon(destination: Path) -> None:
    size = 256
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    scale = size / 52

    def point(x: float, y: float) -> tuple[int, int]:
        return round(x * scale), round(y * scale)

    shield = [point(26, 2), point(48, 10), point(44, 34), point(26, 50), point(8, 34), point(4, 10)]
    draw.polygon(shield, fill="#3b82f6")
    draw.line([point(15, 26), point(22, 33), point(37, 17)], fill="white", width=round(4.5 * scale), joint="curve")

    destination.parent.mkdir(parents=True, exist_ok=True)
    image.save(
        destination,
        format="ICO",
        sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate the ShareGuard Windows icon.")
    parser.add_argument("output", type=Path)
    arguments = parser.parse_args()
    generate_icon(arguments.output)
    print(arguments.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
