#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

void fiat_pasta_fq_set_one(uint64_t out1[4]);
void fiat_pasta_fq_add(uint64_t out1[4], const uint64_t arg1[4], const uint64_t arg2[4]);
void f