#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Make the camera daemon probe libmmcamera_ir0861.so.

Same approach as tools/camera-a13/patch-sensor-list.py in
giannoccarol/android_device_msft_cityman: the daemon's sensor list is a
compiled string array in libmmcamera2_sensor_modules.so. On cityman it reads
imx179_liteon, imx179_sunny, imx214, imx230, s5k3m2xx, imx377, s5k3m2xm,
ov4688, vs6955. `ov4688` (an MTP board sensor, not on this phone) is replaced
by `ir0861`, which has the same length, so no offsets move.

The expected input is the already vs6955-patched file shipped in
giannoccarol/android_vendor_msft_cityman (lineage-23-cityman). Input and
output are proprietary and stay outside Git.
"""
import argparse
import hashlib
import sys
from pathlib import Path

INPUT_SHA256 = "2d14928f825d21dc3c0f1d7fd4ad3610cdfb56de34b0122eca213da1064bec1b"
OLD = b"\x00ov4688\x00"
NEW = b"\x00ir0861\x00"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    data = args.input.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != INPUT_SHA256:
        parser.exit(1, "Unexpected libmmcamera2_sensor_modules.so: %s\n" % digest)
    if data.count(OLD) != 1:
        parser.exit(1, "Expected exactly one %r entry, found %d\n" % (OLD, data.count(OLD)))
    if args.output.resolve() == args.input.resolve():
        parser.exit(1, "Refusing to overwrite the vendor input\n")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(data.replace(OLD, NEW, 1))
    print("patched %s -> %s" % (args.input, args.output))


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    main()
