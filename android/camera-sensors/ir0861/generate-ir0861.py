#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Generate the private iris (model 0x0861) register header for the plug-in.

Input is LumiaFaceID's private stream profile: 351 bytes as 702 hex digits
(optional trailing newline), the exact concatenation of the matched DCC's idle
block (87 records) and mode block (30 records), each record a big-endian
16-bit address followed by one data byte. The same file is what
tools/identify_cityman.sh pushes to /data/local/tmp/cityman-iris-stream-profile.hex.

The input is proprietary and stays outside Git; so does the generated header.
"""
import argparse
import hashlib
import sys
from pathlib import Path

PROGRAM_SHA256 = "75478697398abf8b21796d408844249af54e05ae7a399afffc33d51dd83e8eb5"
IDLE_RECORDS = 87
MODE_RECORDS = 30


def records(program):
    return [((program[i] << 8) | program[i + 1], program[i + 2], i)
            for i in range(0, len(program), 3)]


def emit(path, idle, mode):
    text = [
        "/* SPDX-License-Identifier: GPL-2.0-only */",
        "/* Private vendor register data: generated, do not commit. */",
        "/* Program SHA-256: " + PROGRAM_SHA256 + " */",
        "#ifndef IR0861_REGISTERS_GENERATED_H",
        "#define IR0861_REGISTERS_GENERATED_H",
        "",
    ]
    for name, entries in (("ir0861_idle", idle), ("ir0861_mode0", mode)):
        text.append("static struct msm_camera_i2c_reg_array %s[] = {" % name)
        text += ["    {0x%04x, 0x%02x, 0},  /* program byte %d */" % (a, v, o)
                 for a, v, o in entries]
        text += ["};", ""]
    text += ["#endif /* IR0861_REGISTERS_GENERATED_H */", ""]
    Path(path).write_text("\n".join(text))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", type=Path, help="cityman-iris-stream-profile.hex")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    text = args.profile.read_text().strip()
    try:
        program = bytes.fromhex(text)
    except ValueError:
        parser.exit(1, "Profile is not plain hex\n")
    if len(program) != (IDLE_RECORDS + MODE_RECORDS) * 3:
        parser.exit(1, "Expected %d bytes, got %d\n" % ((IDLE_RECORDS + MODE_RECORDS) * 3, len(program)))
    digest = hashlib.sha256(program).hexdigest()
    if digest != PROGRAM_SHA256:
        parser.exit(1, "Unexpected iris program: %s\n" % digest)
    entries = records(program)
    idle, mode = entries[:IDLE_RECORDS], entries[IDLE_RECORDS:]
    # Writes to these would change identity, reset or streaming behind the daemon.
    for address, _, offset in entries:
        if address in (0x0000, 0x0001, 0x0100, 0x0103):
            parser.exit(1, "Unexpected control register 0x%04x at byte %d\n" % (address, offset))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    emit(temporary, idle, mode)
    temporary.replace(args.output)


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    main()
