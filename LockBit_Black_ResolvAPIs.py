import idaapi
import idautils
import ida_dbg
import ida_name
import ida_hexrays
import idc
import re
import time
import ida_kernwin


def rol(value, shift):
    bits = 32
    mask = (2**bits) - 1
    result = ((value << shift) | (value >> (bits - shift))) & mask
    return result

def ror(value, shift):
    bits = 32
    mask = (2**bits) - 1
    result = ((value >> shift) | (value << (bits - shift))) & mask
    return result

def xor(value, shift):
    return value ^ shift

def get_offname(addr_offset):
    size_off  = ida_bytes.get_item_size(addr_offset)

    if  size_off != 4:
        return False

    raw_addr   = idc.get_bytes(addr_offset, 4, False)
    shell_addr = int.from_bytes(raw_addr, byteorder='little')

    idc.create_insn(shell_addr)
    insn = idaapi.insn_t()
    size_ins = idaapi.decode_insn(insn, shell_addr)
    eax  = insn.Op2.value
    ip  = shell_addr
    asm_inst = {
    "ror":ror,
    "rol":rol,
    "xor":xor,}

    while True:
        '''
        Читаем ассемблерный инструкции до jmp, либо до тех пор, пока
        размер опкода инструкций не будет равен 0 или 1.'''
        idc.create_insn(ip)
        asm  = idc.GetDisasm(ip)
        print(asm)
        insn = idaapi.insn_t()
        size_ins = idaapi.decode_insn(insn, ip)

        for inst in asm_inst:
            if  inst in asm:
                eax  = asm_inst[inst](eax,  insn.Op2.value)

        if "jmp" in asm or size_ins in [0,1]:
            return eax

        ip += size_ins


def start_seg_ea(name_seg: str) -> int:
    for ea in idautils.Segments():
        if name_seg == idc.get_segm_name(ea):
            return ea
    return None

def is_name_used(name):
    '''
    Проверяет, используется ли имя функции
    ещё где-либо.'''
    ea = ida_name.get_name_ea(idc.BADADDR, name)
    return ea != idc.BADADDR


def C_code_set_comment(addr: int, comnt: str):
    '''
    Задает комментарий в псевдокоде на Си
    по определенному адресу.'''
    ea = addr
    cfunc = idaapi.decompile(ea)
    tl = idaapi.treeloc_t()
    tl.ea  = ea
    tl.itp = idaapi.ITP_SEMI
    cfunc.set_user_cmt(tl, comnt)
    cfunc.save_user_cmts()

def C_code_renvar(
    name_widget: str, 
    new_name: str, 
    old_name: str = None, 
    index: int = None):
    '''
    Переименовывает переменную, для определенного виджета,
    доступ к переменной либо по индексу 
    либо по известному имени.'''

    widget = ida_kernwin.find_widget(name_widget) 
    vu = ida_hexrays.get_widget_vdui(widget)

    if vu:
        vuars = vu.cfunc.lvars

        if not old_name and not index:
            return False

        if old_name:
            for var in vuars:
                if old_name == var.name:
                    vu.rename_lvar(var, new_name, 1)
                    return True

        if index:
            vu.rename_lvar(vu.cfunc.lvars[index], new_name, 1)
            return True
    else:
        return False

def refresh_pseudocode_view(ea):
    """Обновляет виджеты с псевдокодом на С."""
    names_cwidgt = ["Pseudocode-%c" % chr(ord("A") + i) for i in range(5)]
    for name in names_cwidgt:
        widget = ida_kernwin.find_widget(name)
        if widget:
            vu = ida_hexrays.get_widget_vdui(widget)
            # Check if the address is in the same function
            func_ea = vu.cfunc.entry_ea
            func = ida_funcs.get_func(func_ea)
            if ida_funcs.func_contains(func, ea):
                vu.refresh_view(True)

def set_renames_vars():
    '''
    Переименовывает имена переменных в
    псевдокоде на Си.'''
    names_cwidgt = ["Pseudocode-%c" % chr(ord("A") + i) for i in range(5)]

    ren_vars = {
    "result":"HeapAlloc",
    "v1":"wrong_HeapAlloc",
    "v2":"heapAlloc"}

    for wdgt in names_cwidgt:
        for old_name in ren_vars:
            C_code_renvar(
            name_widget = wdgt,
            new_name= ren_vars[old_name], 
            old_name= old_name)

def set_renames_func():
    '''
    Переименовывает имена функций.'''
    segm_text = start_seg_ea(".text")
    func_1 = 0x539c # ResolveAPIs
    func_2 = 0x4da0 # ParseAPIHashTable
    func_3 = 0x4aec # PEB_InOrderModuleList

    ren_func = {
    func_1: "ResolveAPIs",
    func_2: "ParseAPIHashTable",
    func_3: "PEB_InOrderModuleList",
    }

    for fea in ren_func:
        idc.set_name(
        segm_text+fea, 
        ren_func[fea])

    

def set_lot_comments():
    '''Задает комментарии для 
    дизассемблера и кода на Си.'''
    rvas_comments = {
    0x53a9: "0xf80f18e8 == hash(RtlCreateHeap) from ntdll.dll",
    0x53e8: "0x6e6047db == hash(HeapAlloc) from kernel32.dll",

    0x5403: 'ntdll.dll',    0x5414: 'kernel32.dll', 0x5425: 'advapi32.dll', 
    0x5436: 'userenv.dll',  0x5447: 'user32.dll',   0x5458: 'gdi32.dll', 
    0x5469: 'shell32.dll',  0x547A: 'ole32.dll',     
    0x549C: 'oleaut32.dll', 0x54AD: 'wtsapi32.dll', 0x54BE: 'RstrtMgr.dll', 
    
    0x54E0: 'activeds.dll', 0x54F1: 'wininet.dll', 
    0x5502: 'wsock32.dll',  0x5513: 'mpr.dll', 0x5524: 'winspool.drv', 
    0x5535: 'gpedit.dll',   0x553C: 'NtSetInformationThread',
    0x54CF: 'netapi32.dll 0x2CFF48C8', 
    0x548B: 'shlwapi.dll 0xD50F3890',}

    segm_text = start_seg_ea(".text")

    refr_area = (
    segm_text + 0x539c, # 0x539c refresh ResolvAPIs
    )

    for rva in rvas_comments:
        idc.set_cmt(segm_text + rva, rvas_comments[rva], 1) # Ассемблер.
        C_code_set_comment( # Код на Си.
        segm_text + rva, 
        rvas_comments[rva])

    for ref_ad in refr_area:
        refresh_pseudocode_view(ref_ad)
    
    


def main():
    set_renames_vars()
    set_renames_func()
    set_lot_comments()

    segm_data = start_seg_ea(".data")
    segm_text = start_seg_ea(".text")
    corr_eip  = segm_text + 0xa79d

    def go_cor_eip():
        """Отлаживает код до определенного адреса (corr_eip)"""
        idaapi.run_to(corr_eip)
        evt_code = idc.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
        idaapi.refresh_debugger_memory()

    # Режим отладки включен.
    if  idaapi.is_debugger_on():
        curr_eip  = idc.get_reg_value("EIP")
        # Если текущее значение EIP регистра
        # меньше ожидаемого, тогда отладить код
        # до этого значения (адреса).
        if curr_eip < corr_eip:
            go_cor_eip()

    '''
    Режим отладки отключен.'''
    if not idaapi.is_debugger_on():
        '''Отладчик не выбран.'''
        if  not idaapi.dbg_is_loaded():
            load_debugger("win32", 0)
        
        go_cor_eip()
           
        
    if segm_data:
        '''
        Первые четыре адреса указывают не не стаб 
        с шелл-кодом, а на виртуальные адреса функций
        из ntdll.dll и kernel32.dll:
        LdrLoadDll, LdrGetProcedureAddress,
        FindFirstFileW, FindNextFileW,
        FindClose'''
        raw_addr = segm_data + 0xa3f8
        for i in range(5):
            raw_virtaddr  = idc.get_bytes(raw_addr, 4, False)
            virtaddr  = int.from_bytes(raw_virtaddr, byteorder='little')
            func_name = ida_name.get_name(virtaddr)
            if is_name_used(func_name):
                if "raw_" not in func_name:
                    func_name = "raw_"+func_name
            idc.set_name(raw_addr, func_name, 0x02)
            raw_addr+=4

        '''
        Определим остальные имена функций, условной
        таблицы импорта малвари, start - адресс с которого
        начинаются стабы (шелл-коды), end - адрес последнего стаба.'''
        start = segm_data  + 0xa418 # начало чтения ассемблерных стабов
        end   = start + 0xa870  # адрес последнего стаба
        addr  = start  # адрес текущего стаба

        while True:
            try:
                ea = get_offname(addr)
                if ea:
                    name = ida_name.get_name(ea)
                    print(name)
                    idc.set_name(addr, name, 0x02)

                addr+=4

                if  addr >= end:
                    break

            except:
                continue

        ida_dbg.exit_process()
    

if __name__ == '__main__':
    main()
