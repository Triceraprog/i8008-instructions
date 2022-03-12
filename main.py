from collections import namedtuple
import itertools

old_conditions = ['FC', 'FZ', 'FS', 'FP', 'TC', 'TZ', 'TS', 'TP']
new_conditions = ['NC', 'NZ', 'P', 'PO', 'C', 'Z', 'M', 'PE']
registers = ['A', 'B', 'C', 'D', 'E', 'H', 'L', 'M']


def format_operand(operand):
    if isinstance(operand, int):
        return f'0x{operand:02x}'
    return operand.upper()


def format_instruction(mnemonic, *operands):
    space = '\t\t' if len(mnemonic) < 4 else '\t'
    return mnemonic + space + ','.join(format_operand(operand) for operand in operands if operand is not None)


def emit(files, old_name, new_name, code, parameter=None, size=None):
    files.old_asm.write(f"\t{old_name}\n")
    files.new_asm.write(f"\t{new_name}\n")
    files.binary.write(code.to_bytes(1, 'little'))

    if parameter is not None:
        files.binary.write(parameter.to_bytes(size, 'little'))


def emit_halt(files):
    emit(files, 'HLT', 'HLT', 0b00000001)


def emit_input_output(files):
    for input_port in range(0, 8):
        old_in = format_instruction('INP', input_port)
        new_in = format_instruction('IN', input_port)
        emit(files, old_in, new_in, 0b01000001 | (input_port << 1))

    for output_port in range(8, 32):
        out = format_instruction('OUT', output_port - 8)
        emit(files, out, out, 0b01000001 | (output_port << 1))


def emit_conditionals(files, initial_letter, base_code, address = None):
    for index, (old_condition, new_condition) in enumerate(zip(old_conditions, new_conditions)):
        old_condition = initial_letter + \
            format_instruction(old_condition, address)
        new_condition = initial_letter + \
            format_instruction(new_condition, address)
        emit(files, old_condition, new_condition,
             base_code | (index << 3), address, 2)


def emit_jump(files):
    address = 0x1234
    jmp = format_instruction('JMP', address)
    emit(files, jmp, jmp, 0b01000100, address, 2)

    emit_conditionals(files, 'J', 0b01000000, address)


def emit_call(files):
    address = 0x3cde
    old_call = format_instruction('CAL', address)
    new_call = format_instruction('CALL', address)
    emit(files, old_call, new_call, 0b01000110, address, 2)

    emit_conditionals(files, 'C', 0b01000010, address)

    for address in range(0, 8):
        rst = format_instruction('RST', address)
        emit(files, rst, rst, 0b00000101 | (address << 3))


def emit_return(files):
    ret = format_instruction('RET')
    emit(files, ret, ret, 0b00000111)

    emit_conditionals(files, 'R', 0b00000011)


def emit_load(files):
    for register_a, register_b in itertools.product(registers, registers):
        if register_a == 'M' and register_b == 'M':  # LMM is illegal
            continue
        old_syntax = 'L' + register_a + register_b
        new_syntax = format_instruction('MOV', register_a, register_b)
        emit(files, old_syntax, new_syntax, 0b11000000 | (
            registers.index(register_a) << 3) | registers.index(register_b))

    data = 0x42
    for register in registers:
        old_syntax = format_instruction('L' + register + 'I', data)
        new_syntax = format_instruction('MVI', register, data)
        emit(files, old_syntax, new_syntax, 0b00000110 |
             (registers.index(register) << 3), data, 1)


def emit_arithmetic_operator(files, old_mnemonic, new_mnemonic, old_direct, new_direct, base_code):
    data = 0x34
    for register in registers:
        old_syntax = format_instruction(old_mnemonic + register)
        new_syntax = format_instruction(new_mnemonic,  register)
        emit(files, old_syntax, new_syntax,
             base_code | registers.index(register))

    old_direct = format_instruction(old_direct, data)
    new_direct = format_instruction(new_direct, data)
    direct_code = (base_code & 0b00111111) | 0b00000100
    emit(files, old_direct, new_direct, direct_code, data, 1)


def emit_arithmetic(files):
    old_operators = ['AD', 'AC', 'SU', 'SB', 'ND', 'XR', 'OR', 'CP']
    new_operators = ['ADD', 'ADC', 'SUB', 'SBB', 'ANA', 'XRA', 'ORA', 'CMP']
    old_direct_operators = ['ADI', 'ACI', 'SUI',
                            'SBI', 'NDI', 'XRI', 'ORI', 'CPI']
    new_direct_operators = ['ADI', 'ACI', 'SUI',
                            'SBI', 'ANI', 'XRI', 'ORI', 'CPI']

    operators = enumerate(zip(old_operators, new_operators,
                              old_direct_operators, new_direct_operators))

    for index, (old_operator, new_operator, old_direct, new_direct) in operators:
        emit_arithmetic_operator(
            files, old_operator, new_operator, old_direct, new_direct, 0b10000000 | (index << 3))

    for register in registers[1:-1]:  # Neither M nor A can be used in INC/DEC
        old_inc = format_instruction('IN' + register)
        new_inc = format_instruction('INR', register)
        old_dec = format_instruction('DC' + register)
        new_dec = format_instruction('DCR', register)

        emit(files, old_inc, new_inc, 0b00000000 |
             (registers.index(register) << 3))
        emit(files, old_dec, new_dec, 0b00000001 |
             (registers.index(register) << 3))


def emit_rotate(files):
    emit(files, 'RLC', 'RLC', 0b00000010)
    emit(files, 'RRC', 'RRC', 0b00001010)
    emit(files, 'RAL', 'RAL', 0b00010010)
    emit(files, 'RAR', 'RAR', 0b00011010)


def pad_binary(f):
    binary_file_size = f.tell()

    PADDING_SIZE = 0x4000
    if (binary_file_size < PADDING_SIZE):
        padding_size = 0x4000 - binary_file_size
        f.write(bytes([0] * padding_size))


def main():
    files = namedtuple('Files', ['old_asm', 'new_asm', 'binary'])
    with open('old_syntax.asm', 'wt') as files.old_asm, \
            open('new_syntax.asm', 'wt') as files.new_asm, \
            open('binary.bin', 'wb') as files.binary:
        emit_halt(files)
        emit_input_output(files)
        emit_jump(files)
        emit_call(files)
        emit_return(files)
        emit_load(files)
        emit_arithmetic(files)
        emit_rotate(files)

        pad_binary(files.binary)


if __name__ == "__main__":
    main()
