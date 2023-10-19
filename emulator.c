#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <curses.h>

#ifdef _WIN32
#define CLEAR "cls"
#else
#define CLEAR "clear"
#endif

#define REG_ZERO 0
#define REG_PC 1
#define REG_DATA 2
#define REG_CODE 3
#define REG_SP 4
#define REG_HP 5
#define REG_BP 6
#define REG_R0 7
#define REG_R1 8
#define REG_R2 9
#define REG_R3 10
#define REG_R4 11
#define REG_R5 12
#define REG_R6 13
#define REG_R7 14
#define REG_R8 15
#define REG_M0 16
#define REG_M1 17
#define REG_F0 18

#define REG_COUNT 19
#define COMMAND_SIZE 64

int16_t *memory;
int16_t *registers;

int mode = 0;
WINDOW *win_out;

char *reg_to_str(int16_t reg) {
	switch (reg) {
		case 0x0: return "zero";
		case 0x1: return "pc";
		case 0x2: return "data";
		case 0x3: return "code";
		case 0x4: return "sp";
		case 0x5: return "hp";
		case 0x6: return "bp";
		case 0x7: return "r0";
		case 0x8: return "r1";
		case 0x9: return "r2";
		case 0xa: return "r3";
		case 0xb: return "r4";
		case 0xc: return "r5";
		case 0xd: return "r6";
		case 0xe: return "r7";
		case 0xf: return "r8";
		default: return "???";
	}
}

int16_t str_to_reg(char *str) {
	for (int16_t i = 0; i < 16; i ++) {
		if (strcmp(reg_to_str(i), str) == 0) {
			return i;
		}
	}
	return -1;
}

char *math_op(int16_t op) {
	switch (op) {
		case 0x0: return "mul";
		case 0x1: return "div";
		default: return "???";
	}
}

char *intreg_to_str(int16_t intreg) {
	switch (intreg) {
		case 0x0: return "m0";
		case 0x1: return "m1";
		case 0x2: return "f0";
		default: return "???";
	}
}

char *jump_op(int16_t op) {
	switch (op) {
		case 0x1: return "jlt";
		case 0x2: return "jeq";
		case 0x3: return "jle";
		case 0x4: return "jgt";
		case 0x5: return "jne";
		case 0x6: return "jge";
		case 0x7: return "jmp";
		default: return "???";
	}
}

void disassemble_ins(char *buf, int n, int offset) {
	int16_t ins = (uint16_t) memory[((uint16_t) registers[REG_PC]) + offset];
	int16_t opcode = (ins & 0x000f) >> 0;
	int16_t rd = (ins & 0x00f0) >> 4;
	int16_t ra = (ins & 0x0f00) >> 8;
	int16_t rb = (ins & 0xf000) >> 12;
	int16_t imm = rb | (ra << 4);
	if (imm & 0b10000000) {
		imm |= 0xff00;
	}
	int16_t jimm = ra | (rd << 4);
	if (jimm & 0b10000000) {
		jimm |= 0xff00;
	}
	snprintf(buf, 15, " [%04x] {%04x} ", ((uint16_t) registers[REG_PC]) + offset, (uint16_t) ((rb << 12) | (ra << 8) | (rd << 4) | opcode));
	switch (opcode) {
		case 0x0:
			snprintf(buf, n, "%s add %s %s %s", buf, reg_to_str(rd), reg_to_str(ra), reg_to_str(rb));
			break;
		case 0x1:
			snprintf(buf, n, "%s sub %s %s %s", buf, reg_to_str(rd), reg_to_str(ra), reg_to_str(rb));
			break;
		case 0x2:
			snprintf(buf, n, "%s sll %s %s %s", buf, reg_to_str(rd), reg_to_str(ra), reg_to_str(rb));
			break;
		case 0x3:
			snprintf(buf, n, "%s srl %s %s %s", buf, reg_to_str(rd), reg_to_str(ra), reg_to_str(rb));
			break;
		case 0x4:
			snprintf(buf, n, "%s and %s %s %s", buf, reg_to_str(rd), reg_to_str(ra), reg_to_str(rb));
			break;
		case 0x5:
			snprintf(buf, n, "%s nand %s %s %s", buf, reg_to_str(rd), reg_to_str(ra), reg_to_str(rb));
			break;
		case 0x6:
			snprintf(buf, n, "%s nor %s %s %s", buf, reg_to_str(rd), reg_to_str(ra), reg_to_str(rb));
			break;
		case 0x7:
			snprintf(buf, n, "%s xor %s %s %s", buf, reg_to_str(rd), reg_to_str(ra), reg_to_str(rb));
			break;
		case 0x8:
			snprintf(buf, n, "%s lw %s %s %d", buf, reg_to_str(rd), reg_to_str(ra), rb);
			break;
		case 0x9:
			snprintf(buf, n, "%s sw %s %s %d", buf, reg_to_str(rd), reg_to_str(ra), rb);
			break;
		case 0xa:
			snprintf(buf, n, "%s addi %s %d", buf, reg_to_str(rd), (ra << 4) | rb);
			break;
		case 0xb:
			snprintf(buf, n, "%s lui %s %d", buf, reg_to_str(rd), (ra << 4) | rb);
			break;
		case 0xc:
			snprintf(buf, n, "%s %s %s %s", buf, math_op(rd), reg_to_str(ra), reg_to_str(rb));
			break;
		case 0xd:
			snprintf(buf, n, "%s int %x %d", buf, rd, rb);
			break;
		case 0xe:
			if (rb & 0b1000) {
				snprintf(buf, n, "%s sint %s %s", buf, reg_to_str(rd), intreg_to_str(rb));
			}
			else {
				snprintf(buf, n, "%s %s %d", buf, jump_op(rb), (rd << 4) | ra);
			}
			break;
		// case 0xf:
		// 	snprintf(buf, n, "%s xor %s %s %s", buf, reg_to_str(rd), reg_to_str(ra), reg_to_str(rb));
		// 	break;
	}
}

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

void reset_registers() {
	for (int i = 0; i < REG_COUNT; i ++) {
		registers[i] = 0;
	}
}

void print_debug(WINDOW *window, char *f, ...) {
	va_list args;
	int y, x;
	getyx(window, y, x);
	wmove(window, 9, 1);
	va_start(args, f);
	vwprintw(window, f, args);
	va_end(args);
}

int execute(int16_t ins) {
	int16_t opcode = (ins & 0x000f) >> 0;
	int16_t rd = (ins & 0x00f0) >> 4;
	int16_t ra = (ins & 0x0f00) >> 8;
	int16_t rb = (ins & 0xf000) >> 12;
	int16_t imm = rb | (ra << 4);
	if (imm & 0b10000000) {
		imm |= 0xff00;
	}
	int16_t jimm = ra | (rd << 4);
	if (jimm & 0b10000000) {
		jimm |= 0xff00;
	}
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
			registers[rd] = memory[(uint16_t) (registers[ra] + signed_nibble(rb))];
			break;
		case 0x9:
			memory[(uint16_t) (registers[ra] + signed_nibble(rb))] = registers[rd];
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
			switch (rd) {
				case 0x0:
					return 1;
					break;
				case 0x1:
					if (rb == 0x1) {
						for (uint16_t i = 0; 1; i ++) {
							char to_print = memory[i + (uint16_t) 0xf100] & 0xff;
							if (to_print == '\0') {
								break;
							}
							if (mode == 0) {
								printf("%c", to_print);
							}
							else if (mode == 1) {
								print_debug(win_out, "%c", to_print);
							}
						}
					}
					break;
			}
			break;
		case 0xe:
			if (rb & 0b1000) {
				printf("sint not yet implemented");
			}
			else {
				if (registers[REG_F0] & rb & 0b111) {
					registers[REG_PC] += jimm - 1;
				}
			}
			break;
		case 0xf:
			printf("fpt not yet implemented");
			break;
	}
	if (rd == REG_PC && !(opcode & 0b1000 && (opcode == 0b1001 || (opcode & 0b0100 && !(opcode == 0b1110 && rb & 0b1000))))) {
		return 2;
	}
	return 0;
}

void run() {
	mode = 0;

	while (1) {
		int res = execute((uint16_t) memory[(uint16_t) registers[REG_PC]]);
		if (res == 1) {
			exit(0);
		}
		if (res != 2) {
			registers[REG_PC] ++;
		}
		registers[REG_ZERO] = 0;
	}
}

void debug() {
	mode = 1;

	int maxh, maxw;
	initscr();
	getmaxyx(stdscr, maxh, maxw);
	WINDOW *win_input = newwin(3, COMMAND_SIZE + 9, 0, 0);
	WINDOW *win_src = newwin(maxh, maxw - COMMAND_SIZE - 9, 0, COMMAND_SIZE + 9);
	WINDOW *win_regs = newwin(maxh - 3, 20, 3, COMMAND_SIZE - 11);
	win_out = newwin(10, COMMAND_SIZE - 11, 3, 0);
	WINDOW *win_mem = newwin(maxh - 13, COMMAND_SIZE - 11, 13, 0);
	char *command = malloc(sizeof(char) * COMMAND_SIZE);
	char *src = malloc(sizeof(char) * maxw - COMMAND_SIZE - 10);
	uint16_t memory_pos = 0;
	char *last_command = malloc(sizeof(char) * COMMAND_SIZE);

	uint16_t *breakpoints = NULL;
	size_t breakpoints_length = 0;
	int highlight = -1;

	scrollok(win_out, 1);
	wsetscrreg(win_out, 1, 8);
	wclear(win_out);
	int running = 0;
	while (1) {
		uint16_t line = registers[REG_PC];
		int16_t print_offset = ((maxh - 2) / 2);
		if (print_offset > line) {
			print_offset = line;
		}
		wclear(win_input);
		box(win_input, 0, 0);
		wmove(win_input, 1, 1);
		wprintw(win_input, "[%04x] ", line);
		wrefresh(win_input);

		wclear(win_src);
		box(win_src, 0, 0);
		for (int i = 0; i < maxh - 2; i ++) {
			disassemble_ins(src, maxw - COMMAND_SIZE - 10, i - print_offset);
			wmove(win_src, i + 1, 1);
			wprintw(win_src, "%s", src);
		}
		for (size_t i = 0; i < breakpoints_length; i ++) {
			int l = breakpoints[i] + print_offset - line + 1;
			if (l >= 1 && l < maxh - 1) {
				wmove(win_src, l, 1);
				wprintw(win_src, "%c", '*');
			}
		}
		wmove(win_src, print_offset + 1, 1);
		wprintw(win_src, "%c", running ? '>' : '=');
		wrefresh(win_src);

		wclear(win_regs);
		box(win_regs, 0, 0);
		for (int i = 0; i < 16; i ++) {
			wmove(win_regs, i + 1, 1);
			wprintw(win_regs, "%4s: %04x (%d)", reg_to_str(i), (uint16_t) registers[i], registers[i]);
		}
		wrefresh(win_regs);

		box(win_out, 0, 0);
		wrefresh(win_out);
		wmove(win_out, 1, 1);

		wclear(win_mem);
		box(win_mem, 0, 0);
		for (int i = 0; i < maxh - 15; i ++) {
			wmove(win_mem, i + 1, 1);
			wprintw(win_mem, "[%04x] ", memory_pos + (uint16_t) (i * 8));
			for (int j = 0; j < 8; j ++) {
				if (highlight != -1 && memory_pos + (uint16_t) (i * 8 + j) == (uint16_t) registers[highlight]) {
					wattron(win_mem, A_REVERSE);
				}
				wprintw(win_mem, "%04x", (uint16_t) memory[memory_pos + (uint16_t) (i * 8 + j)]);
				wattroff(win_mem, A_REVERSE);
				wprintw(win_mem, " ");
			}
		}
		wrefresh(win_mem);

		wgetnstr(win_input, command, COMMAND_SIZE);

		char *cmd = strtok(command, " ");
		if (cmd == NULL) {
			if (last_command == NULL) {
				continue;
			}
			cmd = last_command;
		}
		else {
			strncpy(last_command, command, COMMAND_SIZE);
		}
		if (strcmp(cmd, "q") == 0) {
			system(CLEAR);
			return;
		}
		else if (strcmp(cmd, "s") == 0) {
			running = 1;
			int res = execute((uint16_t) memory[(uint16_t) registers[REG_PC]]);
			if (res == 1) {
				print_debug(win_out, "Execution complete.\n");
				running = 0;
				continue;
			}
			if (res != 2) {
				registers[REG_PC] ++;
			}
			registers[REG_ZERO] = 0;
		}
		else if (strcmp(cmd, "m") == 0) {
			cmd = strtok(NULL, " ");
			if (cmd == NULL) {
				print_debug(win_out, "Missing address.\n");
				continue;
			}
			memory_pos = strtoul(cmd, &cmd, 16);
		}
		else if (strcmp(cmd, "b") == 0) {
			cmd = strtok(NULL, " ");
			if (cmd == NULL) {
				print_debug(win_out, "Missing address.\n");
				continue;
			}
			uint16_t bp = strtoul(cmd, &cmd, 16);
			breakpoints_length ++;
			breakpoints = realloc(breakpoints, sizeof(uint16_t) * breakpoints_length);
			breakpoints[breakpoints_length - 1] = bp;
		}
		else if (strcmp(cmd, "r") == 0) {
			if (!running) {
				reset_registers();
			}
			running = 1;
			int done = 0;
			int started = 0;
			while (1) {
				if (started) {
					for (size_t i = 0; i < breakpoints_length; i ++) {
						if (registers[REG_PC] == breakpoints[i]) {
							done = 1;
							break;
						}
					}
					if (done) {
						break;
					}
				}
				started = 1;
				int res = execute((uint16_t) memory[(uint16_t) registers[REG_PC]]);
				if (res == 1) {
					print_debug(win_out, "Execution complete.\n");
					running = 0;
					done = 1;
				}
				if (res != 2) {
					registers[REG_PC] ++;
				}
				registers[REG_ZERO] = 0;
				if (done) {
					break;
				}
			}
		}
		else if (strcmp(cmd, "res") == 0) {
			reset_registers();
			running = 1;
		}
		else if (strcmp(cmd, "hl") == 0) {
			cmd = strtok(NULL, " ");
			if (cmd == NULL) {
				print_debug(win_out, "Missing register.\n");
				continue;
			}
			if (strcmp(cmd, "reset") == 0) {
				highlight = -1;
				continue;
			}
			int16_t new_hl = str_to_reg(cmd);
			if (new_hl == -1) {
				print_debug(win_out, "Invalid register.\n");
				continue;
			}
			highlight = new_hl;
		}
		registers[REG_ZERO] = 0;
	}
	free(command);
	free(last_command);
	free(src);
	free(breakpoints);
}

int main(int argc, char* argv[]) {
	if (argc != 3) {
		printf("Invalid argument count");
		return 1;
	}
	FILE *file = fopen(argv[2], "rb");
	if (!file) {
		printf("Could not read file");
		return 1;
	}

	memory = malloc(sizeof(int16_t) * 0xffff);
	if (memory == NULL) {
		printf("Could not malloc memory");
		return 1;
	}
	registers = calloc(REG_COUNT, sizeof(int16_t));
	if (registers == NULL) {
		printf("Could not malloc registers");
		return 1;
	}

	uint16_t read_index = 0;
	int16_t read_value;
	while (fread(&read_value, sizeof(int16_t), 1, file) != 0) {
		memory[read_index] = ((read_value & 0xff00) >> 8) | ((read_value & 0x00ff) << 8);
		read_index ++;
	}

	if (strcmp(argv[1], "-r") == 0) {
		run();
	}
	else if (strcmp(argv[1], "-d") == 0) {
		debug();
	}

	return 0;
}