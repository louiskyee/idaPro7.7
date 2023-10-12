import idc
import idautils
import idaapi
import ida_ida

idaapi.auto_wait()
# Get the start and end addresses
start = ida_ida.inf_get_min_ea()
end = ida_ida.inf_get_max_ea()

# print(f"start = {start}")
# print(f"end = {end}")

if start != idc.BADADDR and end != idc.BADADDR:
    curr_addr = start

    # Use 'with open' to open the file, ensuring automatic file closure
    instructions_output_path = idc.ARGV[1]
    with open(instructions_output_path, "w", encoding='utf-8') as output_file:
        while curr_addr <= end:
            # disasm = idc.GetDisasm(curr_addr) # Get disassembly line

            disasm = idc.print_insn_mnem(curr_addr)
            
            if disasm:
                # Write the instruction to the txt file
            	output_file.write(f"Address: {hex(curr_addr)}, Instruction: {disasm}\n")


            curr_addr = idc.next_head(curr_addr, end)

    print(f"Instructions saved to '{instructions_output_path}'")
else:
    print("Failed to get function start and end addresses.")
idc.qexit(0)
