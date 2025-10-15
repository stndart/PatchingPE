import csv
import ida_bytes

csv_path = r"C:\Users\Svyat\Desktop\RE\PatchingPE\old-iat.csv"

DEFAULT_START = "0x1588000"
DEFAULT_END = "0x1588E6C"


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
