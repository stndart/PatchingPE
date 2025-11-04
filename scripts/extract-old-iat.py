import csv
import ida_bytes  # type: ignore
import ida_nalt  # type: ignore
import idaapi  # type: ignore
from pathlib import Path
from dotenv import load_dotenv
import os

load_dotenv(Path(__file__).parent.parent / ".env")

csv_base = Path(os.getenv("BASE_TO_DUMPS", "./"))

ibase = idaapi.get_imagebase()

if ida_nalt.get_input_file_path().endswith(".dll"):
    csv_path = csv_base / "patchingPE/neomon-dump/dumps/old-iat.csv"
    DEFAULT_START = hex(ibase + 0x16000)
    DEFAULT_END = hex(ibase + 0x16230)
elif ida_nalt.get_input_file_path().endswith(".exe"):
    csv_path = csv_base / "patchingPE/game-dump/dumps/old-iat.csv"
    DEFAULT_START = "0x1588000"
    DEFAULT_END = "0x1588E6C"
else:
    raise RuntimeError("Uknown file extension!")


def export_iat_to_csv(
    start_addr_str: str = DEFAULT_START, end_addr_str: str = DEFAULT_END
):
    """
    Extracts possible IAT entries between start and end address and saves to CSV.

    Args:
        start_addr_str (str): Start address (e.g. '0x14000000')
        end_addr_str (str): End address (e.g. '0x14001000')
    """
    start_addr = int(start_addr_str, 16)
    end_addr = int(end_addr_str, 16)

    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Address", "Destination"])

        ea = start_addr
        while ea < end_addr:
            # read 4 or 8 bytes depending on binary type
            ptr_size = 4
            value = ida_bytes.get_dword(ea)

            if value is None:
                ea += ptr_size
                continue

            writer.writerow([f"0x{ea:08X}", f"{value:08X}"])

            ea += ptr_size

    print(f"[+] IAT table exported to: {csv_path}")


export_iat_to_csv()
