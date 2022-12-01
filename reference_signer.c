
#include <stdio.h>
#include "pasta_fp.h"
#include "pasta_fq.h"
#include "crypto.h"
#include "base10.h"
#include "utils.h"

#include <sys/resource.h>
#include <inttypes.h>

#define MAINNET 0

#define DEFAULT_TOKEN_ID 1

int main(int argc, char* argv[]) {
  struct rlimit lim = {1, 1};
  if (setrlimit(RLIMIT_STACK, &lim) == -1) {
      printf("rlimit failed\n");
      return 1;