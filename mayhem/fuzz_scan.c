// libmem's memory-scan API over an in-process buffer: signature strings ("DE AD ?? EF"),
// raw byte patterns with an x/? mask, and plain data scans.
#include <libmem/libmem.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	unsigned mode;
	size_t hay_len, needle_len, i;
	uint8_t *hay, *needle;
	char *mask;
	lm_address_t match = LM_ADDRESS_BAD;

	if (size < 4)
		return -1;

	mode = data[0] % 3;
	hay_len = ((size - 2) * (size_t)data[1]) / 256;
	data += 2;
	size -= 2;
	needle_len = size - hay_len;
	if (hay_len == 0 || needle_len == 0)
		return -1;

	hay = (uint8_t *)malloc(hay_len);
	needle = (uint8_t *)malloc(needle_len + 1);
	if (!hay || !needle) {
		free(hay);
		free(needle);
		return 0;
	}
	memcpy(hay, data, hay_len);
	memcpy(needle, data + hay_len, needle_len);
	needle[needle_len] = '\0';

	if (mode == 0) {
		match = LM_SigScan((lm_string_t)needle, (lm_address_t)hay, hay_len);
	} else if (mode == 1) {
		match = LM_DataScan((lm_bytearray_t)needle, needle_len, (lm_address_t)hay, hay_len);
	} else {
		mask = (char *)malloc(needle_len + 1);
		if (mask) {
			for (i = 0; i < needle_len; ++i)
				mask[i] = (needle[i] & 1) ? 'x' : '?';
			mask[needle_len] = '\0';
			match = LM_PatternScan((lm_bytearray_t)needle, mask, (lm_address_t)hay, hay_len);
			free(mask);
		}
	}

	free(hay);
	free(needle);
	return match == (lm_address_t)1; /* never true; keeps the result live */
}
