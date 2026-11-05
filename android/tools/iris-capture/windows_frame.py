#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Turn one iris_capture RAW frame into what the Windows iris engine is fed.

Steps, each taken from the Windows Mobile image (FINDINGS sections 23 and 25):
  1. 8-bit grey from the raw value (top eight bits of RAW10). The exact Windows
     tone curve is not established; this is the simplest consistent model.
  2. Crop the leftmost 300 columns (camera\\tertiary\\cropWidthLeft).
  3. Split into two eye images with an overlap of min(300, size / 2), along the
     width for rotation 0/180 and along the height for 90/270; 180 and 270
     swap the two halves (irm2 split_frame).
Writes 8-bit PGMs and prints the statistics Windows' exposure control uses
(mean, median, p90/p95/p99) plus the engine's size checks.
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from raw_to_pgm import pixels  # noqa: E402


def stats(values):
    ordered = sorted(values)
    n = len(ordered)

    def pct(p):
        return ordered[min(n - 1, (p * n) // 100)]

    return {"mean": round(sum(ordered) / n, 1), "median": pct(50),
            "p90": pct(90), "p95": pct(95), "p99": pct(99)}


def write_pgm(path, width, height, rows):
    data = bytes(v for row in rows for v in row)
    path.write_bytes(b"P5\n%d %d\n255\n" % (width, height) + data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output_prefix", type=Path)
    parser.add_argument("--format", choices=("raw10", "raw16"), default="raw10")
    parser.add_argument("--width", type=int, required=True)
    parser.add_argument("--height", type=int, required=True)
    parser.add_argument("--stride", type=int, required=True)
    parser.add_argument("--crop-left", type=int, default=300)
    parser.add_argument("--crop-right", type=int, default=0)
    parser.add_argument("--rotation", type=int, default=0,
                        help="degrees passed to the engine; Windows' value for this phone is unknown")
    args = parser.parse_args()

    data = args.input.read_bytes()
    if len(data) < args.stride * (args.height - 1) + args.width:
        parser.exit(1, "Input is shorter than width/height/stride describe\n")
    shift = 2 if args.format == "raw10" else 8
    flat = [v >> shift for v in pixels(data, args.format, args.width, args.height, args.stride)]
    right = args.width - args.crop_right
    if not 0 <= args.crop_left < right <= args.width:
        parser.exit(1, "Crop leaves no image\n")
    rows = [flat[y * args.width + args.crop_left:y * args.width + right] for y in range(args.height)]
    width, height = right - args.crop_left, args.height

    quadrant = ((args.rotation % 360) + 45) // 90 & 3
    if quadrant & 1 == 0:
        overlap = min(300, width // 2)
        half = (width + overlap) // 2
        first = [row[:half] for row in rows]
        second = [row[width - half:] for row in rows]
        eye_size = (half, height)
    else:
        overlap = min(300, height // 2)
        half = (height + overlap) // 2
        first, second = rows[:half], rows[height - half:]
        eye_size = (width, half)
    eyes = (second, first) if quadrant & 2 else (first, second)

    prefix = args.output_prefix
    write_pgm(prefix.with_name(prefix.name + "-frame.pgm"), width, height, rows)
    for index, eye in enumerate(eyes):
        write_pgm(prefix.with_name(prefix.name + "-eye%d.pgm" % index), eye_size[0], eye_size[1], eye)

    print("engine frame %dx%d (needs >= 640x480: %s), rotation %d -> split along %s, overlap %d"
          % (width, height, "ok" if width >= 640 and height >= 480 else "TOO SMALL", args.rotation,
             "width" if quadrant & 1 == 0 else "height", overlap))
    print("frame stats", stats([v for row in rows for v in row]))
    for index, eye in enumerate(eyes):
        print("eye%d %dx%d stats" % (index, eye_size[0], eye_size[1]), stats([v for row in eye for v in row]))


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    main()
