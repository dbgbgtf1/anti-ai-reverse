import argparse
from pathlib import Path
import re
import subprocess
import pefile


def rolling_xor(payload: bytes, seed: int, bit: int) -> bytes:
    padded = payload + (b"\0" if len(payload) % 2 else b"")
    encoded = bytearray()
    for offset in range(0, len(padded), bit):
        plain = int.from_bytes(padded[offset : offset + bit], "little")
        cipher = plain ^ seed
        encoded.extend(cipher.to_bytes(bit, "little"))
        if bit == 8:
            seed = (seed + cipher) & 0xFFFF_FFFF_FFFF_FFFF
        elif bit == 4:
            seed = (seed + cipher) & 0xFFFF_FFFF
    return bytes(encoded)


def render_header(name: str, payload: bytes, seed: int | None) -> str:
    guard = f"{name.upper()}_TEXT_H"
    rows = [
        "  " + ", ".join(f"0x{byte:02x}" for byte in payload[i : i + 12]) + ","
        for i in range(0, len(payload), 12)
    ]
    return (
        f"#ifndef {guard}\n"
        f"#define {guard}\n\n"
        "#include <stdint.h>\n\n"
        + f"static uint8_t {name}_text[] = {{\n"
        + "\n".join(rows)
        + f"\n}};\n\n#endif /* {guard} */\n"
    )


def main():
    parser = argparse.ArgumentParser(description="Build and extract a Windows payload")
    parser.add_argument("source_path", type=Path, help="C source file to compile")
    parser.add_argument(
        "--no-seed", action="store_true", help="omit the random 16-bit seed macro"
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    if args.source_path.is_absolute():
        candidates = [args.source_path]
    else:
        candidates = [Path.cwd() / args.source_path, root / args.source_path]
        if args.source_path.parent == Path("."):
            candidates.append(root / "src" / args.source_path)
    source_path = next((path.resolve() for path in candidates if path.is_file()), None)
    if source_path is None:
        parser.error(f"source file does not exist: {args.source_path}")

    source_name = source_path.stem
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", source_name):
        parser.error(f"source name is not a valid C identifier: {source_name}")

    exe_path = root / "build" / "payload.exe"
    payload_path = root / "build" / "payload.bin"
    header_path = root / "include" / f"{source_name}_text.h"

    exe_path.parent.mkdir(parents=True, exist_ok=True)

    subprocess.run(
        [
            "clang",
            "-Wl,/subsystem:console,/entry:main",
            "-Xlinker",
            "/merge:payload_data=code",
            "-Xlinker",
            "/section:code,ER",
            "-masm=intel",
            "-nostdlib",
            "-fno-builtin",
            "-fno-stack-protector",
            "-O0",
            "-g",
            str(source_path),
            "-o",
            str(exe_path),
        ],
        check=True,
    )

    if not exe_path.is_file():
        raise FileNotFoundError(f"can't find compile exe: {exe_path}")

    pe = pefile.PE(str(exe_path))
    try:
        sections = [
            section for section in pe.sections if section.Name.rstrip(b"\0") == b"code"
        ]
        sections.sort(key=lambda s: s.VirtualAddress)

        if not sections:
            raise ValueError("can't find code section")

        payload = b"".join(s.get_data(length=s.Misc_VirtualSize) for s in sections)
    finally:
        pe.close()
    payload_path.write_bytes(payload)
    header_path.parent.mkdir(parents=True, exist_ok=True)
    seed = None if args.no_seed else 0x6c28_7bd9_b398_a0ef
    header_payload = payload if seed is None else rolling_xor(payload, seed, 8)
    header_path.write_text(
        render_header(source_name, header_payload, seed), encoding="utf-8"
    )


if __name__ == "__main__":
    main()
