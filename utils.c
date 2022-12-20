#include "utils.h"

// Not constant time
void packed_bit_array_set(uint8_t *bits, size_t i, bool b) {
  size_t byte_idx = i / 8;
  size_t in_byte_idx = i % 8;

  if (b) {
    b