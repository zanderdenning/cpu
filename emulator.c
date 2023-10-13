#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define REG_ZERO 0
#define REG_PC 1
#define REG_M0 16
#define REG_M1 17
#define REG_F0 18

int16_t *memory;
int16_t *registers;

int16_t signed_nibble(int16_t n) {
	if (n < 8) {
		return n;
	}
	return n - 16;
}

void update_f0(int16_t value) {
	if (value == 0) {
		registers[REG_F0] = 0b010;
	}
	else if (value < 0) {
		registers[REG_F0] = 0b001;
	}
	else {
		registers[REG_F0] = 0b100;
	}
}

void execute(int16_t ins) {
	int16_t opcode = (ins & 0x0f00) >> 8;
	int16_t rd = (ins & 0xf000) >> 12;
	int16_t ra = (ins & 0x000f) >> 0;
	int16_t rb = (ins & 0x00f0) >> 4;
	int16_t imm = rb | (ra << 4);
	if (imm & 0b10000000) {
		imm |= 0xff00;
	}
	int16_t jimm = ra | (rd << 4);
	if (jimm & 0b10000000) {
		jimm |= 0xff00;
	}
	// printf("%x\n", opcode);
	switch (opcode) {
		case 0x0:
			registers[rd] = registers[ra] + registers[rb];
			update_f0(registers[rd]);
			break;
		case 0x1:
			registers[rd] = registers[ra] - registers[rb];
			update_f0(registers[rd]);
			break;
		case 0x2:
			registers[rd] = registers[ra] >> (registers[rb] & 0x000f);
			update_f0(registers[rd]);
			break;
		case 0x3:
			registers[rd] = registers[ra] << (registers[rb] & 0x000f);
			update_f0(registers[rd]);
			break;
		case 0x4:
			registers[rd] = registers[ra] & registers[rb];
			update_f0(registers[rd]);
			break;
		case 0x5:
			registers[rd] = registers[ra] | registers[rb];
			update_f0(registers[rd]);
			break;
		case 0x6:
			registers[rd] = registers[ra] ^ registers[rb];
			update_f0(registers[rd]);
			break;
		case 0x7:
			registers[rd] = ~(registers[ra] & registers[rb]);
			update_f0(registers[rd]);
			break;
		case 0x8:
			registers[rd] = memory[registers[ra] + signed_nibble(rb)];
			break;
		case 0x9:
			memory[registers[ra] + signed_nibble(rb)] = registers[rd];
			break;
		case 0xa:
			registers[rd] += imm;
			break;
		case 0xb:
			registers[rd] = imm << 8;
			break;
		case 0xc:
			printf("math not yet implemented");
			break;
		case 0xd:
			for (int i = 0; i < 19; i ++) {
				printf("%x: %x\n", i, registers[i]);
			}
			break;
		case 0xe:
			if (rb & 0b1000) {
				printf("sint not yet implemented");
			}
			else {
				if (rb == 0b110) {
					for (int i = 0; i < 19; i ++) {
						printf("%x: %x\n", i, registers[i]);
					}
					printf("%d\n", registers[REG_F0]);
				}
				if (registers[REG_F0] & rb & 0b111) {
					registers[REG_PC] += jimm - 1;
				}
			}
			break;
		case 0xf:
			printf("fpt not yet implemented");
			break;
	}
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		printf("Invalid argument count");
		return 1;
	}
	FILE *file = fopen(argv[1], "rb");
	if (!file) {
		printf("Could not read file");
		return 1;
	}

	memory = malloc(sizeof(int16_t) * 0xffff);
	registers = calloc(19, sizeof(int16_t));

	int read_index = 0;
	while (fread(memory + read_index, sizeof(int16_t), 1, file) != 0) {
		read_index ++;
	}
	while (1) {
		execute(memory[registers[REG_PC]]);
		registers[REG_PC] ++;
		registers[REG_ZERO] = 0;
	}

	return 0;
}