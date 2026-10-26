// Assemble fuzzer text for every architecture (keystone via LM_AssembleEx), then disassemble the
// produced payload again (round trip) and run the host-arch LM_Assemble on the same text.
#include <libmem/libmem.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	lm_arch_t arch;
	lm_address_t runtime_address;
	char *code;
	lm_byte_t *payload = NULL;
	lm_inst_t *insts = NULL;
	lm_inst_t inst;
	lm_size_t n, count, total = 0;

	if (size < 3)
		return -1;

	arch = (lm_arch_t)(data[0] % LM_ARCH_MAX);
	if (arch == LM_ARCH_GENERIC)
		return -1;
	runtime_address = (lm_address_t)data[1] * 0x01010101u;
	data += 2;
	size -= 2;

	code = (char *)malloc(size + 1);
	if (!code)
		return 0;
	memcpy(code, data, size);
	code[size] = '\0';

	n = LM_AssembleEx(code, arch, runtime_address, &payload);
	if (n) {
		count = LM_DisassembleEx((lm_address_t)payload, arch, n, 0, runtime_address, &insts);
		if (count) {
			total += insts[0].size;
			LM_FreeInstructions(insts);
		}
		LM_FreePayload(payload);
	}

	if (LM_Assemble(code, &inst))
		total += inst.size + strlen(inst.mnemonic) + strlen(inst.op_str);

	free(code);
	return total == (lm_size_t)-1;
}
