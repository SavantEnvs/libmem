// Known-answer probe for the test oracle: calls libmem's pure-computation API with fixed inputs and prints
// the results. mayhem/test.sh compares this output to golden values, so a neutered or broken libmem fails it.
#include <libmem/libmem.h>
#include <stdio.h>
#include <string.h>

static void hex(const char *label, const lm_byte_t *b, size_t n)
{
	size_t i;
	printf("%s=", label);
	for (i = 0; i < n; ++i)
		printf("%02x", b[i]);
	printf("\n");
}

static lm_bool_t LM_CALL find_cb(lm_symbol_t *s, lm_void_t *arg)
{
	if (strcmp(s->name, "LM_AssembleEx") == 0) {
		*(lm_address_t *)arg = s->address;
		return LM_FALSE;
	}
	return LM_TRUE;
}

int main(int argc, char **argv)
{
	static const lm_byte_t x64[] = "\x55\x48\x89\xE5\x8B\x05\x39\x05\x00\x00\xFF\xD0\x48\x89\xEC\x5D\xC3";
	static const lm_byte_t arm[] = "\x01\x10\xA0\xE3\x1E\xFF\x2F\xE1";
	static const lm_byte_t hay[] = { 0x10, 0x20, 0xDE, 0xAD, 0xBE, 0xEF, 0x30, 0x40 };
	lm_byte_t *payload = NULL;
	lm_inst_t *insts = NULL;
	lm_size_t n, i;
	lm_char_t *dem;
	lm_module_t mod;
	lm_address_t found = LM_ADDRESS_BAD;

	n = LM_AssembleEx("mov eax, 1337", LM_ARCH_X64, 0, &payload);
	printf("asm_x64_size=%zu\n", n);
	if (n) { hex("asm_x64_bytes", payload, n); LM_FreePayload(payload); }

	payload = NULL;
	n = LM_AssembleEx("mov r1, #1 ; bx lr", LM_ARCH_ARMV7, 0, &payload);
	printf("asm_arm_size=%zu\n", n);
	if (n) { hex("asm_arm_bytes", payload, n); LM_FreePayload(payload); }

	n = LM_DisassembleEx((lm_address_t)x64, LM_ARCH_X64, sizeof(x64) - 1, 0, 0x1000, &insts);
	printf("disasm_x64_count=%zu\n", n);
	for (i = 0; i < n; ++i)
		printf("disasm_x64_%zu=%llx:%s %s\n", i, (unsigned long long)insts[i].address, insts[i].mnemonic, insts[i].op_str);
	if (n) LM_FreeInstructions(insts);

	insts = NULL;
	n = LM_DisassembleEx((lm_address_t)arm, LM_ARCH_ARMV7, sizeof(arm) - 1, 0, 0, &insts);
	printf("disasm_arm_count=%zu\n", n);
	for (i = 0; i < n; ++i)
		printf("disasm_arm_%zu=%s %s\n", i, insts[i].mnemonic, insts[i].op_str);
	if (n) LM_FreeInstructions(insts);

	dem = LM_DemangleSymbol("_ZN3foo3barEi", NULL, 0);
	printf("demangle=%s\n", dem ? dem : "(null)");
	if (dem) LM_FreeDemangledSymbol(dem);
	dem = LM_DemangleSymbol("_ZNSt6vectorIiSaIiEE9push_backERKi", NULL, 0);
	printf("demangle_stl=%s\n", dem ? dem : "(null)");
	if (dem) LM_FreeDemangledSymbol(dem);

	printf("sigscan_offset=%lld\n", (long long)((lm_address_t)LM_SigScan("DE AD ?? EF", (lm_address_t)hay, sizeof(hay)) - (lm_address_t)hay));
	printf("datascan_offset=%lld\n", (long long)((lm_address_t)LM_DataScan((lm_bytearray_t)"\xBE\xEF", 2, (lm_address_t)hay, sizeof(hay)) - (lm_address_t)hay));
	printf("patternscan_offset=%lld\n", (long long)((lm_address_t)LM_PatternScan((lm_bytearray_t)"\x20\x00\xAD", "x?x", (lm_address_t)hay, sizeof(hay)) - (lm_address_t)hay));

	/* ELF symbol reader: the address of LM_AssembleEx inside the shared library file given as argv[1] */
	if (argc > 1) {
		memset(&mod, 0, sizeof(mod));
		snprintf(mod.path, sizeof(mod.path), "%s", argv[1]);
		LM_EnumSymbols(&mod, find_cb, &found);
		printf("elf_sym_LM_AssembleEx=%llx\n", (unsigned long long)found);
	}
	return 0;
}
