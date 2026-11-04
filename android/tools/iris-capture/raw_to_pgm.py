#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Convert one iris_capture frame to an 8-bit PGM for viewing.

iris_capture prints width, height and stride for every frame. RAW10 is MIPI
packed (4 pixels in 5 bytes), RAW16 is little-endian 16-bit, yuv keeps only Y.
--stretch maps the frame's own min..max to 0..255, which helps with a dark,
unlit first image.
"""
import argparse
import sys
from pathlib import Path


def pixels(data, fmt, width, height, stride):
    for y in range(height):
        row = data[y * stride:]
        if fmt == "raw10":
            for x in range(width):
                group = row[(x // 4) * 5:(x // 4) * 5 + 5]
                yield (group[x % 4] << 2) | ((group[4] >> (2 * (x % 4))) & 3)
        elif fmt == "raw16":
            for x in range(width):
                yield row[2 * x] | (row[2 * x + 1] << 8)
        else:
            yield from row[:width]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--format", choices=("raw10", "raw16", "yuv"), required=True)
    parser.add_argument("--width", type=int, required=True)
    parser.add_argument("--height", type=int, required=True)
    parser.add_argument("--stride", type=int, required=True)
    parser.add_argument("--stretch", action="store_true")
    args = parser.parse_args()
    data = args.input.read_bytes()
    if len(data) < args.stride * (args.height - 1) + args.width:
        parser.exit(1, "Input is shorter than width/height/stride describe\n")
    values = list(pixels(data, args.format, args.width, args.height, args.stride))
    full = {"raw10": 1023, "raw16": 65535, "yuv": 255}[args.format]
    low, high = (min(values), max(values)) if args.stretch else (0, full)
    span = max(high - low, 1)
    out = bytes(min(255, max(0, (v - low) * 255 // span)) for v in values)
    args.output.write_bytes(b"P5\n%d %d\n255\n" % (args.width, args.height) + out)
    print("%s: min=%d max=%d mapped %d..%d" % (args.output, min(values), max(values), low, high))


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    main()
