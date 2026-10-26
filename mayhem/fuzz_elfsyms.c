// ELF symbol-table reader (LM_EnumSymbols / LM_EnumSymbolsDemangled). libmem only reads symbols from
// a file path, so each input is written to one scratch file under $TMPDIR (never an absolute image path).
#include <libmem/libmem.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char scratch_path[4096];
static int scratch_fd = -1;

static lm_bool_t LM_CALL count_symbol(lm_symbol_t *symbol, lm_void_t *arg)
{
	*(size_t *)arg += strlen(symbol->name) + (symbol->address != 0);
	return LM_TRUE;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	lm_module_t module;
	size_t total = 0;
	const char *tmp;

	if (size < 20 || memcmp(data, "\x7f" "ELF", 4) != 0)
		return -1;

	if (scratch_fd < 0) {
		tmp = getenv("TMPDIR");
		snprintf(scratch_path, sizeof(scratch_path), "%s/libmem-elf-XXXXXX", tmp && *tmp ? tmp : "/tmp");
		scratch_fd = mkstemp(scratch_path);
		if (scratch_fd < 0)
			return 0;
	}
	if (ftruncate(scratch_fd, 0) != 0 || pwrite(scratch_fd, data, size, 0) != (ssize_t)size)
		return 0;

	memset(&module, 0, sizeof(module));
	module.base = 0x10000;
	snprintf(module.path, sizeof(module.path), "%s", scratch_path);

	LM_EnumSymbols(&module, count_symbol, &total);
	LM_EnumSymbolsDemangled(&module, count_symbol, &total);
	return total == (size_t)-1;
}
