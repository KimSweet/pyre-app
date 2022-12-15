
#include <stdio.h>
#include <assert.h>
#include <sys/resource.h>
#include <inttypes.h>

#include "pasta_fp.h"
#include "pasta_fq.h"
#include "crypto.h"
#include "poseidon.h"
#include "base10.h"
#include "utils.h"
#include "sha256.h"
#include "curve_checks.h"

#ifdef OSX
  #define explicit_bzero bzero
#endif

#define ARRAY_LEN(x) (sizeof(x)/sizeof(x[0]))

#define DEFAULT_TOKEN_ID 1
static bool _verbose;
static bool _ledger_gen;

void privkey_to_hex(char *hex, const size_t len, const Scalar priv_key) {
  uint64_t priv_words[4];
  hex[0] = '\0';

  assert(len > 2*sizeof(priv_words));
  if (len < 2*sizeof(priv_words)) {
    return;
  }

  uint8_t *p = (uint8_t *)priv_words;
  fiat_pasta_fq_from_montgomery(priv_words, priv_key);
  // Mina privkey hex format is in big-endian
  for (size_t i = sizeof(priv_words); i > 0; i--) {
    sprintf(&hex[2*(sizeof(priv_words) - i)], "%02x", p[i - 1]);
  }
  hex[len] = '\0';
}

bool privkey_from_hex(Scalar priv_key, const char *priv_hex) {
  size_t priv_hex_len = strnlen(priv_hex, 64);
  if (priv_hex_len != 64) {
    return false;
  }
  uint8_t priv_bytes[32];
  // Mina privkey hex format is in big-endian
  for (size_t i = sizeof(priv_bytes); i > 0; i--) {
    sscanf(&priv_hex[2*(i - 1)], "%02hhx", &priv_bytes[sizeof(priv_bytes) - i]);
  }

  if (priv_bytes[3] & 0xc000000000000000) {
      return false;
  }

  fiat_pasta_fq_to_montgomery(priv_key, (uint64_t *)priv_bytes);

  char priv_key_hex[65];
  privkey_to_hex(priv_key_hex, sizeof(priv_key_hex), priv_key);

  // sanity check
  int result = memcmp(priv_key_hex, priv_hex, sizeof(priv_key_hex)) == 0;
  assert(result);
  return result;
}

bool privhex_to_address(char *address, const size_t len,
                        const char *account_number, const char *priv_hex) {
  Scalar priv_key;
  if (!privkey_from_hex(priv_key, priv_hex)) {
    return false;
  }

  Keypair kp;
  scalar_copy(kp.priv, priv_key);
  generate_pubkey(&kp.pub, priv_key);

  if (!generate_address(address, len, &kp.pub)) {
    return false;
  }

  if (_verbose) {
    printf("%s => %s\n", priv_hex, address);
  }
  else if (_ledger_gen) {
    printf("    # account %s\n", account_number);
    printf("    # private key %s\n", priv_hex);
    printf("    assert(test_get_address(%s) == \"%s\")\n\n",
           account_number, address);
  }

  return true;
}

void sig_to_hex(char *hex, const size_t len, const Signature sig) {
  hex[0] = '\0';

  assert(len == 2*sizeof(Signature) + 1);
  if (len < 2*sizeof(Signature) + 1) {
    return;
  }

  uint64_t words[4];
  fiat_pasta_fp_from_montgomery(words, sig.rx);
  for (size_t i = 4; i > 0; i--) {
    sprintf(&hex[16*(4 - i)], "%016" PRIx64, words[i - 1]);
  }
  fiat_pasta_fq_from_montgomery(words, sig.s);
  for (size_t i = 4; i > 0; i--) {
    sprintf(&hex[64 + 16*(4 - i)], "%016" PRIx64, words[i - 1]);
  }
}

bool sign_transaction(char *signature, const size_t len,
                      const char *account_number,
                      const char *sender_priv_hex,
                      const char *receiver_address,
                      Currency amount,
                      Currency fee,
                      Nonce nonce,
                      GlobalSlot valid_until,
                      const char *memo,
                      bool delegation,
                      uint8_t network_id) {
  Transaction txn;

  assert(len == 2*sizeof(Signature) + 1);
  if (len != 2*sizeof(Signature) + 1) {
    return false;
  }

  prepare_memo(txn.memo, memo);

  Scalar priv_key;
  if (!privkey_from_hex(priv_key, sender_priv_hex)) {
    return false;
  }

  Keypair kp;
  scalar_copy(kp.priv, priv_key);
  generate_pubkey(&kp.pub, priv_key);

  char source_str[MINA_ADDRESS_LEN];
  if (!generate_address(source_str, sizeof(source_str), &kp.pub)) {
    return false;
  }

  char *fee_payer_str = source_str;

  txn.fee = fee;
  txn.fee_token = DEFAULT_TOKEN_ID;
  read_public_key_compressed(&txn.fee_payer_pk, fee_payer_str);
  txn.nonce = nonce;
  txn.valid_until = valid_until;

  if (delegation) {
    txn.tag[0] = 0;
    txn.tag[1] = 0;
    txn.tag[2] = 1;
  }
  else {
    txn.tag[0] = 0;
    txn.tag[1] = 0;
    txn.tag[2] = 0;
  }

  read_public_key_compressed(&txn.source_pk, source_str);
  read_public_key_compressed(&txn.receiver_pk, receiver_address);
  txn.token_id = DEFAULT_TOKEN_ID;
  txn.amount = amount;
  txn.token_locked = false;

  Compressed pub_compressed;
  compress(&pub_compressed, &kp.pub);

  Signature sig;
  sign(&sig, &kp, &txn, network_id);

  if (!verify(&sig, &pub_compressed, &txn, network_id)) {
    return false;
  }

  sig_to_hex(signature, len, sig);

  if (_verbose) {
    fprintf(stderr, "%d %s\n", delegation, signature);
  }
  else if (_ledger_gen) {
    printf("    # account %s\n", account_number);
    printf("    # private key %s\n", sender_priv_hex);
    printf("    # sig=%s\n", signature);
    printf("    assert(test_sign_tx(mina.%s,\n"
           "                        %s,\n"
           "                        \"%s\",\n"
           "                        \"%s\",\n"
           "                        %" PRIu64 ",\n"
           "                        %" PRIu64 ",\n"
           "                        %u,\n"
           "                        %u,\n"
           "                        \"%s\",\n"
           "                        mina.%s) == \"%s\")\n\n",
           delegation ? "TX_TYPE_DELEGATION" : "TX_TYPE_PAYMENT",
           account_number,
           source_str,
           receiver_address,
           amount,
           fee,
           nonce,
           valid_until,
           memo,
           network_id == MAINNET_ID ? "MAINNET_ID" : "TESTNET_ID",
           signature);
  }

  return true;
}

bool check_get_address(const char *account_number,
                       const char *priv_hex, const char *address) {
  char target[MINA_ADDRESS_LEN];
  if (!privhex_to_address(target, sizeof(target), account_number, priv_hex)) {
    return false;
  }

  return strcmp(address, target) == 0;
}

bool check_sign_tx(const char *account_number,
                   const char *sender_priv_hex,
                   const char *receiver_address,
                   Currency amount,
                   Currency fee,
                   Nonce nonce,
                   GlobalSlot valid_until,
                   const char *memo,
                   bool delegation,
                   const char *signature,
                   uint8_t network_id) {
  char target[129];
  if (!sign_transaction(target, sizeof(target),
                        account_number,
                        sender_priv_hex,
                        receiver_address,
                        amount,
                        fee,
                        nonce,
                        valid_until,
                        memo,
                        delegation,
                        network_id)) {
    return false;
   }

   return strcmp(signature, target) == 0;
}

char *field_to_hex(char *hex, size_t len, const Field x) {
  assert(len == 65);
  hex[64] = '\0';
  Scalar y;
  fiat_pasta_fp_from_montgomery(y, x);
  uint8_t *p = (uint8_t *)y;
  for (size_t i = 0; i < sizeof(y); i++) {
    sprintf(&hex[2*i], "%02x", p[i]);
  }

  return hex;
}

char *scalar_to_hex(char *hex, size_t len, const Scalar x) {
  assert(len == 65);
  hex[64] = '\0';
  Scalar y;
  fiat_pasta_fq_from_montgomery(y, x);
  uint8_t *p = (uint8_t *)y;
  for (size_t i = 0; i < sizeof(y); i++) {
    sprintf(&hex[2*i], "%02x", p[i]);
  }

  return hex;
}

void print_scalar_as_cstruct(const Scalar x) {
  printf("        { ");
  for (size_t i = 0; i < sizeof(Scalar)/sizeof(x[0]); i++) {
    printf("0x%016" PRIx64 ", ", x[i]);
  }
  printf("},\n");
}

void print_affine_as_cstruct(const Affine *a) {
  printf("        {\n");
  printf("            { ");
  for (size_t i = 0; i < sizeof(Field)/sizeof(a->x[0]); i++) {
    printf("0x%016" PRIx64 ", ", a->x[i]);
  }
  printf(" },\n");
  printf("            { ");
  for (size_t i = 0; i < sizeof(Field)/sizeof(a->y[0]); i++) {
    printf("0x%016" PRIx64 ", ", a->y[i]);
  }
  printf(" },");
  printf("\n        },\n");
}

void print_scalar_as_ledger_cstruct(const Scalar x) {
  uint64_t tmp[4];
  uint8_t *p = (uint8_t *)tmp;

  fiat_pasta_fq_from_montgomery(tmp, x);
  printf("        {");
  for (size_t i = sizeof(Scalar); i > 0; i--) {
    if (i % 8 == 0) {
      printf("\n            ");
    }
    printf("0x%02x, ", p[i - 1]);
  }
  printf("\n        },\n");
}

void print_affine_as_ledger_cstruct(const Affine *a) {
  uint64_t tmp[4];
  uint8_t *p = (uint8_t *)tmp;

  fiat_pasta_fp_from_montgomery(tmp, a->x);
  printf("        {\n");
  printf("            {");
  for (size_t i = sizeof(Field); i > 0; i--) {
    if (i % 8 == 0) {
      printf("\n                ");
    }
    printf("0x%02x, ", p[i - 1]);
  }
  printf("\n            },\n");
  fiat_pasta_fp_from_montgomery(tmp, a->y);
  printf("            {");
  for (size_t i = sizeof(Field); i > 0; i--) {
    if (i % 8 == 0) {
      printf("\n                ");
    }
    printf("0x%02x, ", p[i - 1]);
  }