#!/bin/sh
# Fetch the original Lumia 950 XL camera drivers at a pinned commit, verify their
# SHA-256, and decompile each with REA + Ghidra 12.1.4.
#
# Usage: scripts/fetch_and_decompile.sh WORK_DIR
# Requires: curl, shasum or sha256sum, rea, GHIDRA_INSTALL_DIR, JAVA_HOME.
set -eu

[ $# -eq 1 ] || { echo "usage: $0 WORK_DIR" >&2; exit 2; }
command -v rea >/dev/null 2>&1 || { echo "rea not found (npm install -g rea-agents)" >&2; exit 2; }
[ -n "${GHIDRA_INSTALL_DIR:-}" ] || { echo "GHIDRA_INSTALL_DIR is not set" >&2; exit 2; }

if command -v sha256sum >/dev/null 2>&1; then sha() { sha256sum "$1" | cut -d' ' -f1; }
else sha() { shasum -a 256 "$1" | cut -d' ' -f1; }; fi

BASE=https://raw.githubusercontent.com/WOA-Project/Lumia-Drivers/b5af93f99ea800c28551727df55e57a07ba61a82/components/QC899X/Hardware/HARDWARE.CAMERA.MMO_8994/Drivers/Camera

mkdir -p "$1"
WORK=$(cd "$1" && pwd)

# name  path-under-Camera  sha256
while read -r name path hash; do
	out="$WORK/$name.bin"
	if [ ! -f "$out" ]; then
		curl -fsSL --retry 3 -o "$out.part" "$BASE/$path"
		mv "$out.part" "$out"
	fi
	got=$(sha "$out")
	if [ "$got" != "$hash" ]; then
		echo "$name: SHA-256 mismatch ($got), refusing to analyse" >&2
		exit 1
	fi
	echo "$name: hash ok"

	if [ -f "$WORK/pseudo-$name/decompile-index.json" ]; then
		echo "$name: already decompiled"
		continue
	fi
	rea decompile-all "$out" --output "$WORK/pseudo-$name" --provider ghidra \
		--format json > "$WORK/$name.log" 2>&1
	echo "$name: $(ls "$WORK/pseudo-$name/functions" | wc -l | tr -d ' ') functions"
done <<'EOF'
iris Sensors/Iris/arm/qccamsensor_tertiarySMIApp8994.sys 0ea99897a1623afd7f165aa2943f2f69687c31dc42a123d6d21c2339ca8e78e5
front Sensors/Front/arm/qccamfrontsensor_secondarySMIApp8994.sys febebc6290b30366c24e6a0a7b50c893dd3602bd11cdf2bc117098114696ce30
platform Platform/arm/qccamplatform8994.sys 6ae3eb8078998b3d4e75200c671b90c5e5f385168014c70465941bfad4e90aa2
flash3 Flash/Tertiary/arm/qccamflashtertiary8994.sys 58cf8c49d30756a5ddae896cf51aa1dd1ae2733217ee603aebacb44ce047c1c5
auth Authentication/arm/CameraAuthentication.dll 5e7be37803a0573727ea309a52d5f5e6569875485951ec56023f5d9175b5cd4e
isp ISP/arm/qccamisp8994.sys 0673448ca7b96c75fcb6ba7c4f50985e16e9f0a1b21b547fb37617f5ad60d78d
core Core/arm/qccamcore8994.sys d00cf6238c5885e45e89fb908c7dcf587fbab22a23eda1f650acb0d9e8cba415
EOF
