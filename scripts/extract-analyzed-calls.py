import idautils  # type: ignore
import idc  # type: ignore
import csv

out_path = r"C:\Users\Svyat\Desktop\RE\PatchingPE\broken-analyzed-calls.csv"

f = open(out_path, "w", newline="")
writer = csv.writer(f)
writer.writerow(
    ["function", "Instruction", "Call address", "Destination", "Resolved name"]
)


def check_in_bounds(addr: int):
    if addr < 0x6D40000:
        return False  # main part
    if 0x6D40000 <= addr <= 0x6D41000:
        return True  # xinput
    if 0x10000000 <= addr <= 0x1000B000:
        return True  # physxloader
    if 0x5DD00000 <= addr <= 0x77000000:
        return True  # the rest
    return False


first_seg, second_seg = list(idautils.Segments())[:2]

count = 0
for func_ea in idautils.Functions(first_seg, second_seg):
    func_name = idc.get_func_name(func_ea)
    for head in idautils.FuncItems(func_ea):
        instr = idc.print_insn_mnem(head)
        if instr == "call" or instr == "jmp":
            target = idc.get_operand_value(head, 0)
            if not check_in_bounds(target):
                continue  # local function

            if idc.is_loaded(target):
                name = idc.get_name(target)
            else:
                name = ""

            writer.writerow([func_name, instr, hex(head), hex(target), name])
            count += 1

f.close()
print(f"Done. Processed {count} calls. Saved to {out_path}")
