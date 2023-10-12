# idaPro7.7
## install

### IDApython
* [idapython git](https://github.com/idapython/src)
* [IDAPython documentation](https://www.hex-rays.com/products/ida/support/idapython_docs/)
## useage
### command line mode
- 參數說明
    - https://hex-rays.com/products/ida/support/idadoc/417.shtml
- command line指令
    ```cmd=
    idat64.exe -c -A -SidaProScript.py <input-file-path>
    ```
    - `idat64.exe`: 32位元使用`idat.exe`，64位元使用`idat64.exe`
    - `-c`: disassemble a new file (delete the old database)
    - `-A`: 使用自動模式，所有問題都採用預設答案
    - `-S`: 載入檔案後運行idaProScript.py腳本，`-S`跟腳本名稱不用分開
        - 如果要傳參數的話用`"`引號括起來 `-S"idaProScript.py arg1 arg2"`，腳本中用`idc.ARGV[]`使用
- 取opcode腳本
    ```python=
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
        with open(instructions_output_path, "w") as output_file:
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
    ```
    - `idaapi.auto_wait()`
        - 蠻重要的，要等待分析結束再取資料，不然會是錯的
    - `idc.qexit(0)`
        - 正確的關閉ida pro，不然會卡住
    - 這篇文章寫得不錯，可以參考
        - [idapython使用笔记](https://wonderkun.cc/2020/12/11/idapython%E4%BD%BF%E7%94%A8%E7%AC%94%E8%AE%B0/)