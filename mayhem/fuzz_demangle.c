// Itanium/LLVM symbol demangler through LM_DemangleSymbol, with an allocated or caller-sized buffer.
#include <libmem/libmem.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *symbol;
	char *out;
	size_t bufsize;
	char *buf;

	if (size < 2)
		return -1;

	bufsize = data[0]; /* 0 = let the library allocate */
	data += 1;
	size -= 1;

	symbol = (char *)malloc(size + 1);
	if (!symbol)
		return 0;
	memcpy(symbol, data, size);
	symbol[size] = '\0';

	if (bufsize == 0) {
		out = LM_DemangleSymbol(symbol, NULL, 0);
		if (out) {
			(void)strlen(out);
			LM_FreeDemangledSymbol(out);
		}
	} else {
		buf = (char *)malloc(bufsize);
		if (buf) {
			out = LM_DemangleSymbol(symbol, buf, bufsize);
			if (out)
				(void)strlen(out);
			free(buf);
		}
	}

	free(symbol);
	return 0;
}
