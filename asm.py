import argparse

argparser = argparse.ArgumentParser()

argparser.add_argument("infile")
argparser.add_argument("-o", "--outfile")

args = argparser.parse_args()

BOOT_LENGTH = 0x9

data = {}
labels = {}
todo = []

def parse_number(number):
	if number[0] == "-":
		return -1 * parse_number(number[1:])
	if number[0] in "0123456789":
		if number[0] == "0" and len(number) > 2:
			if number[1] == "x":
				return int(number, 16)
			if number[1] == "b":
				return int(number, 2)
			if number[1] == "o":
				return int(number, 8)
			if number[1] == "d":
				return int(number, 10)
		return int(number)
	else:
		return None

def parse_reg(reg):
	if reg[0] == "%":
		return hex(int(reg[1:]))[-1]
	return {
		"zero": "0",
		"pc": "1",
		"data": "2",
		"code": "3",
		"sp": "4",
		"hp": "5",
		"ret": "6",
		"r0": "7",
		"r1": "8",
		"r2": "9",
		"r3": "a",
		"r4": "b",
		"r5": "c",
		"r6": "d",
		"r7": "e",
		"r8": "f",
	}[reg]

def parse_imm(imm):
	return format(parse_number(imm) & 0xff, "02x")[-2:][::-1]

def parse_imm_short(imm):
	return format(parse_number(imm) & 0xf, "01x")[-1]

def parse_intermediate(inter):
	if inter == "0" or inter == "m0":
		return "8"
	if inter == "1" or inter == "m1":
		return "9"
	if inter == "2" or inter == "f0":
		return "a"

def parse_offset(offset, line, ins):
	number = parse_number(offset)
	if number != None:
		return parse_imm(offset)
	label = labels.get(offset, None)
	if label != None:
		return parse_imm(str(label - line))
	else:
		todo.append({
			"action": "label",
			"label": offset,
			"line": line,
			"ins": ins
		})
		return "00"

def data_to_hex(data):
	if data[1] == "int":
		return format(parse_number(data[2]) & 0xffff, "04x")[-4:], 1

def decode(i, line):
	# Instructions
	if i[0] == "add":
		return [parse_reg(i[3]) + parse_reg(i[2]) + parse_reg(i[1]) + "0"]
	if i[0] == "sub":
		return [parse_reg(i[3]) + parse_reg(i[2]) + parse_reg(i[1]) + "1"]
	if i[0] == "sll":
		return [parse_reg(i[3]) + parse_reg(i[2]) + parse_reg(i[1]) + "2"]
	if i[0] == "srl":
		return [parse_reg(i[3]) + parse_reg(i[2]) + parse_reg(i[1]) + "3"]
	if i[0] == "and":
		return [parse_reg(i[3]) + parse_reg(i[2]) + parse_reg(i[1]) + "4"]
	if i[0] == "nand":
		return [parse_reg(i[3]) + parse_reg(i[2]) + parse_reg(i[1]) + "5"]
	if i[0] == "or":
		return [parse_reg(i[3]) + parse_reg(i[2]) + parse_reg(i[1]) + "6"]
	if i[0] == "xor":
		return [parse_reg(i[3]) + parse_reg(i[2]) + parse_reg(i[1]) + "7"]
	if i[0] == "lw":
		return [parse_imm_short(i[3]) + parse_reg(i[2]) + parse_reg(i[1]) + "8"]
	if i[0] == "sw":
		return [parse_imm_short(i[3]) + parse_reg(i[2]) + parse_reg(i[1]) + "9"]
	if i[0] == "addi":
		return [parse_imm(i[2]) + parse_reg(i[1]) + "a"]
	if i[0] == "lui":
		return [parse_imm(i[2]) + parse_reg(i[1]) + "b"]
	if i[0] == "mul":
		return [parse_reg(i[2]) + parse_reg(i[1]) + "0" + "c"]
	if i[0] == "div":
		return [parse_reg(i[2]) + parse_reg(i[1]) + "1" + "c"]
	if i[0] == "int":
		return [parse_imm_short(i[2]) + "0" + parse_imm_short(i[1]) + "d"]
	if i[0] == "jlt":
		return ["1" + parse_offset(i[1], line, "jump") + "e"]
	if i[0] == "jeq":
		return ["2" + parse_offset(i[1], line, "jump") + "e"]
	if i[0] == "jle":
		return ["3" + parse_offset(i[1], line, "jump") + "e"]
	if i[0] == "jgt":
		return ["4" + parse_offset(i[1], line, "jump") + "e"]
	if i[0] == "jne":
		return ["5" + parse_offset(i[1], line, "jump") + "e"]
	if i[0] == "jge":
		return ["6" + parse_offset(i[1], line, "jump") + "e"]
	if i[0] == "jmp":
		return ["7" + parse_offset(i[1], line, "jump") + "e"]
	if i[0] == "sint":
		return [parse_intermediate(i[2]) + "0" + parse_reg(i[1]) + "e"]
	
	# Pseudoinstructions
	if i[0] == "liau":
		num = parse_number(i[2])
		upper = num // 256
		if num & 192 == 192:
			upper += 1
		return decode(["lui", i[1], str(upper)], line) + decode(["addi", i[1], str(num % 256)], line)
	if i[0] == "li":
		num = parse_number(i[2])
		upper = num // 256
		if num & 192 == 192:
			upper += 1
		return (decode(["lui", i[1], str(upper)], line) if num > 255 else []) + decode(["addi", i[1], str(num % 256)], line)
	if i[0] == "ldv":
		addr = data.get(i[2])
		if addr != None:
			if addr < 8:
				return decode(["lw", i[1], "data", str(addr)], line)
			else:
				return decode(["li", i[1], str(addr)], line) + decode(["add", i[1], i[1], "data"], line) + decode(["lw", i[1], i[1], "0"], line)
		else:
			todo.append({
				"action": "data",
				"data": i[2],
				"line": line,
				"ins": "liau"
			})
			return decode(["liau", i[1], "0"], line) + decode(["add", i[1], i[1], "data"], line) + decode(["lw", i[1], i[1], "0"], line)

with open(args.infile, "r") as in_file:
	with open(args.outfile or (args.infile.rsplit(".", 1)[0] + ".out"), "wb") as out_file:
		hex_data = []
		data_position = 0
		hex_instructions = []
		line_number = 0
		section = ".comment"
		for line in in_file.readlines():
			ins = [a.strip() for a in line.strip().split()]
			if not ins:
				continue
			if ins[0] and ins[0][0] == ".":
				section = ins[0]
			elif ins[0] == "//":
				continue
			elif section == ".comment":
				continue
			elif section == ".data":
				hex_dat, width = data_to_hex(ins)
				data[ins[0]] = data_position
				hex_data.append(hex_dat)
				data_position += width
			elif section == ".code":
				if ins[0][-1] == ":":
					labels[ins[0][:-1]] = line_number
					continue
				hex_ins = decode(ins, line_number)
				hex_instructions.extend(hex_ins)
				line_number += len(hex_ins)
		hex_instructions.append("0000")
		line_number += 1
		for patch in todo:
			if patch["action"] == "label":
				current = hex_instructions[patch["line"]]
				if patch["ins"] == "jump":
					hex_instructions[patch["line"]] = current[0] + parse_imm(str(labels[patch["label"]] - patch["line"])) + current[3]
			if patch["action"] == "data":
				addr = data[patch["data"]]
				upper = addr // 256
				if addr & 192 == 192:
					upper += 1
				current = hex_instructions[patch["line"]]
				if patch["ins"] == "liau":
					hex_instructions[patch["line"]] = parse_imm(str(upper)) + current[2] + current[3]
					current2 = hex_instructions[patch["line"] + 1]
					hex_instructions[patch["line"] + 1] = parse_imm(str(addr % 256)) + current[2] + current[3]
		
		data_addr = BOOT_LENGTH
		code_addr = data_addr + data_position
		sp_addr = 0x7fff
		hp_addr = code_addr + line_number
		boot = [
			decode(["liau", "data", str(data_addr)], 0),
			decode(["liau", "code", str(code_addr)], 0),
			decode(["liau", "sp", str(sp_addr)], 0),
			decode(["liau", "hp", str(hp_addr)], 0),
			decode(["add", "pc", "zero", "code"], 0)
		]
		for line in boot:
			for l in line:
				out_file.write(bytes.fromhex(l))

		for dat in hex_data:
			out_file.write(bytes.fromhex(dat))
		for ins in hex_instructions:
			out_file.write(bytes.fromhex(ins))