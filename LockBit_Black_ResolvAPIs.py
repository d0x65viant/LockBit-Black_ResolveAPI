import idaapi
import idautils
import ida_name
import idc

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


def main():
    segm = [ea for ea in idautils.Segments() 
    if  idc.get_segm_name(ea) == ".data"]

    if segm:
        start = segm[0] + 0xa418 # начало чтения ассемблерных стабов
        end   = start   + 0x450  # адрес последнего стаба
        addr  = start   # адрес текущего стаба

    while True:
        try:
            ea   = get_offname(addr)
            if ea:
                name = ida_name.get_name(ea)
                print(name)
                set_name(addr, name, 0x02)

            addr+=4

            if  addr >= end:
                break

        except:
            continue
    

if __name__ == '__main__':
    main()
