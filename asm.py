import argparse
import shlex

argparser = argparse.ArgumentParser()

argparser.add_argument("infile")
argparser.add_argument("-o", "--outfile")

args = argparser.parse_args()

BOOT_LENGTH = 14

data = {}
labels = {}
todo = []
imported = []

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
		"bp": "6",
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
	if data[1] == "string":
		return "".join((format(ord(c) & 0xffff, "04x")[-4:] for c in data[2][1:-1])) + "0000", len(data[2]) - 1

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
	if i[0] == "li":
		num = parse_number(i[2])
		upper = num // 256
		if num & 192 == 192:
			upper += 1
		return decode(["lui", i[1], str(upper)], line) + decode(["addi", i[1], str(num % 256)], line)
	if i[0] == "lda":
		addr = data.get(i[2])
		if addr != None:
			return decode(["li", i[1], str(addr)], line) + decode(["add", i[1], i[1], "data"], line)
		else:
			todo.append({
				"action": "dataaddr",
				"data": i[2],
				"line": line,
				"ins": "li"
			})
			return decode(["li", i[1], "0"], line) + decode(["add", i[1], i[1], "data"], line)
	if i[0] == "ldv":
		return decode(["lda", i[1], i[2]], line) + decode(["lw", i[1], i[1], "0"], line)
	if i[0] == "lladdr":
		addr = labels.get(i[2])
		if addr != None:
			return decode(["li", i[1], str(addr)], line) + decode(["add", i[1], i[1], "code"], line)
		else:
			todo.append({
				"action": "label",
				"label": i[2],
				"line": line,
				"ins": "li"
			})
			return decode(["li", i[1], "0"], line) + decode(["add", i[1], i[1], "code"], line)
	if i[0] == "llbaddr":
		addr = labels.get(i[2])
		if addr != None:
			return decode(["li", i[1], str(addr - 1)], line) + decode(["add", i[1], i[1], "code"], line)
		else:
			todo.append({
				"action": "label",
				"label": i[2],
				"line": line,
				"ins": "li",
				"offset": -1
			})
			return decode(["li", i[1], "0"], line) + decode(["add", i[1], i[1], "code"], line)
	if i[0] == "j":
		return decode(["llbaddr", i[1], i[2]], line) + decode(["add", "pc", i[1], "zero"], line)
	if i[0] == "call":
		return decode(["sw", "bp", "sp", "1"], line) + decode(["add", "bp", "pc", "zero"], line) + decode(["addi", "bp", "6"], line) + decode(["sw", "bp", "sp", "0"], line) + decode(["j", i[1], i[2]], line)
	if i[0] == "ret":
		return decode(["lw", "bp", "sp", "1"], line) + decode(["lw", "pc", "sp", "0"], line)
	if i[0] == "push":
		reg_count = min(len(i) - 1, 8)
		out = decode(["addi", "sp", str(-1 * reg_count)], line)
		for j in range(reg_count):
			out += decode(["sw", i[j + 1], "sp", str(j)], line)
		return out
	if i[0] == "pop":
		reg_count = min(len(i) - 1, 8)
		out = []
		for j in range(reg_count):
			out += decode(["lw", i[j + 1], "sp", str(j)], line)
		return out + decode(["addi", "sp", str(reg_count)], line)

def assemble_file(path, counters):
	with open(path, "r") as in_file:
		section = ".comment"
		for line in in_file.readlines():
			ins = [a.strip() for a in shlex.split(line.split("//")[0].strip(), posix=False)]
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
				data[ins[0]] = counters["data_position"]
				counters["hex_data"].append(hex_dat)
				counters["data_position"] += width
			elif section == ".code":
				if ins[0][0] == "#":
					if ins[0] == "#import":
						if ins[1] not in imported:
							imported.append(ins[1])
							assemble_file(ins[1], counters)
						continue
				if ins[0][-1] == ":":
					labels[ins[0][:-1]] = counters["line_number"]
					continue
				hex_ins = decode(ins, counters["line_number"])
				counters["hex_instructions"].extend(hex_ins)
				counters["line_number"] += len(hex_ins)

with open(args.outfile or (args.infile.rsplit(".", 1)[0] + ".out"), "wb") as out_file:
	counters = {
		"hex_data": [],
		"data_position": 0,
		"hex_instructions": [],
		"line_number": 0
	}

	imported.append(args.infile)
	assemble_file(args.infile, counters)
	
	counters["hex_instructions"].append("0000")
	counters["line_number"] += 1
	for patch in todo:
		if patch["action"] == "label":
			addr = labels[patch["label"]]
			upper = addr // 256
			if addr & 192 == 192:
				upper += 1
			current = counters["hex_instructions"][patch["line"]]
			if patch["ins"] == "jump":
				counters["hex_instructions"][patch["line"]] = current[0] + parse_imm(str(labels[patch["label"]] - patch["line"])) + current[3]
			elif patch["ins"] == "li":
				counters["hex_instructions"][patch["line"]] = parse_imm(str(upper)) + current[2] + current[3]
				current2 = counters["hex_instructions"][patch["line"] + 1]
				counters["hex_instructions"][patch["line"] + 1] = parse_imm(str(addr % 256)) + current[2] + current[3]
		if patch["action"] == "dataaddr":
			addr = data[patch["data"]] + (patch.get("offset") or 0)
			upper = addr // 256
			if addr & 192 == 192:
				upper += 1
			current = counters["hex_instructions"][patch["line"]]
			if patch["ins"] == "li":
				counters["hex_instructions"][patch["line"]] = parse_imm(str(upper)) + current[2] + current[3]
				current2 = counters["hex_instructions"][patch["line"] + 1]
				counters["hex_instructions"][patch["line"] + 1] = parse_imm(str(addr % 256)) + current[2] + current[3]
	
	data_addr = BOOT_LENGTH
	code_addr = data_addr + counters["data_position"]
	sp_addr = 0xefff
	hp_addr = code_addr + counters["line_number"]
	bp_addr = sp_addr
	boot = [
		decode(["li", "data", str(data_addr)], 0),
		decode(["li", "code", str(code_addr)], 0),
		decode(["li", "sp", str(sp_addr)], 0),
		decode(["li", "hp", str(hp_addr)], 0),
		decode(["li", "bp", str(bp_addr)], 0),
		decode(["j", "r0", "entry"], 0)
	]
	for line in boot:
		for l in line:
			out_file.write(bytes.fromhex(l))

	for dat in counters["hex_data"]:
		out_file.write(bytes.fromhex(dat))
	for ins in counters["hex_instructions"]:
		out_file.write(bytes.fromhex(ins))