// Disassemble fuzzer bytes for every architecture libmem supports (capstone via LM_DisassembleEx),
// then run the host-arch single-instruction helpers on the same bytes.
#include <libmem/libmem.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define PAD 128 /* LM_Disassemble/LM_CodeLength take a bare address: keep every read inside the allocation */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	lm_arch_t arch;
	lm_size_t max_count;
	lm_address_t runtime_address;
	lm_size_t codesize;
	uint8_t *code;
	lm_inst_t *insts = NULL;
	lm_inst_t inst;
	lm_size_t n, i, total = 0;

	if (size < 4)
		return -1;

	arch = (lm_arch_t)(data[0] % LM_ARCH_MAX);
	if (arch == LM_ARCH_GENERIC)
		return -1;
	max_count = data[1] % 32; /* 0 = disassemble everything */
	runtime_address = (lm_address_t)data[2] * 0x01010101u;
	data += 3;
	size -= 3;
	codesize = size;

	code = (uint8_t *)calloc(codesize + PAD, 1);
	if (!code)
		return 0;
	memcpy(code, data, codesize);

	n = LM_DisassembleEx((lm_address_t)code, arch, codesize, max_count, runtime_address, &insts);
	for (i = 0; i < n; ++i) {
		total += insts[i].size;
		total += strlen(insts[i].mnemonic) + strlen(insts[i].op_str);
	}
	if (n)
		LM_FreeInstructions(insts);

	if (LM_Disassemble((lm_address_t)code, &inst))
		total += inst.size + strlen(inst.mnemonic) + strlen(inst.op_str);
	total += LM_CodeLength((lm_address_t)code, data[0] % 16);

	free(code);
	return total == (lm_size_t)-1; /* never true; keeps the results live */
}
