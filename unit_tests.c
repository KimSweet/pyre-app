
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
  printf("\n            },");
  printf("\n        },\n");
}

void generate_curve_checks(bool ledger_gen) {
  Scalar S[EPOCHS][3];
  Affine A[EPOCHS][3];

  printf("// curve_checks.h - elliptic curve unit tests\n");
  printf("//\n");
  printf("//    These constants were generated from the Mina c-reference-signer\n");
  printf("//    Do not edit this file\n");

  if (ledger_gen) {
    printf("//\n");
    printf("//    Details:  https://github.com/MinaProtocol/c-reference-signer/README.markdown\n");
    printf("//    Generate: ./unit_tests ledger_gen\n");
  }

  printf("\n");
  printf("#pragma once\n");
  printf("\n");
  printf("#include \"crypto.h\"\n");

  printf("\n");
  printf("#define EPOCHS %u\n", EPOCHS);
  printf("\n");

  // Generate test scalars
  printf("// Test scalars\n");
  printf("static const Scalar S[%u][2] = {\n", EPOCHS);

  Scalar s0; // Seed with zero scalar
  explicit_bzero(s0, sizeof(s0));
  for (size_t i = 0; i < EPOCHS; i++) {
    // Generate two more scalars
    Scalar s1, s2;
    sha256_hash(s0, sizeof(s0), s1, sizeof(s1));
    scalar_from_words(s1, s1);

    sha256_hash(s1, sizeof(s1), s2, sizeof(s2));
    scalar_from_words(s2, s2);

    memcpy(S[i][0], &s0, sizeof(S[i][0]));
    memcpy(S[i][1], &s1, sizeof(S[i][1]));
    memcpy(S[i][2], &s2, sizeof(S[i][2]));

    printf("    {\n");
    if (ledger_gen) {
      print_scalar_as_ledger_cstruct(S[i][0]);
      print_scalar_as_ledger_cstruct(S[i][1]);
      // Tests do not need S2
    }
    else {
      print_scalar_as_cstruct(S[i][0]);
      print_scalar_as_cstruct(S[i][1]);
      // Tests do not need S2
    }
    printf("    },\n");

    sha256_hash(s2, sizeof(s2), s0, sizeof(s0));
    scalar_from_words(s0, s0);
    // s0 is seed for next round!
  }
  printf("};\n");
  printf("\n");

  // Generate test curve points
  printf("// Test curve points\n");
  printf("static const Affine A[%u][3] = {\n", EPOCHS);

  for (size_t i = 0; i < EPOCHS; i++) {
    // Generate three curve points
    generate_pubkey(&A[i][0], S[i][0]);
    generate_pubkey(&A[i][1], S[i][1]);
    generate_pubkey(&A[i][2], S[i][2]);

    // Check on curve
    assert(affine_is_on_curve(&A[i][0]));
    assert(affine_is_on_curve(&A[i][1]));
    assert(affine_is_on_curve(&A[i][2]));

    printf("    {\n");
    if (ledger_gen) {
      print_affine_as_ledger_cstruct(&A[i][0]);
      print_affine_as_ledger_cstruct(&A[i][1]);
      print_affine_as_ledger_cstruct(&A[i][2]);
    }
    else {
      print_affine_as_cstruct(&A[i][0]);
      print_affine_as_cstruct(&A[i][1]);
      print_affine_as_cstruct(&A[i][2]);
    }
    printf("    },\n");
  }
  printf("};\n");
  printf("\n");

  // Generate target outputs
  printf("// Target outputs\n");
  printf("static const Affine T[%u][5] = {\n", EPOCHS);
  for (size_t i = 0; i < EPOCHS; i++) {
    Affine a3;
    Affine a4;
    union {
      // Fit in stackspace!
      Affine a5;
      Scalar s2;
    } u;

    // Test1: On curve after scaling
    assert(affine_is_on_curve(&A[i][0]));
    assert(affine_is_on_curve(&A[i][1]));
    assert(affine_is_on_curve(&A[i][2]));

    // Test2: Addition is commutative
    //     A0 + A1 == A1 + A0
    affine_add(&a3, &A[i][0], &A[i][1]); // a3 = A0 + A1
    affine_add(&a4, &A[i][1], &A[i][0]); // a4 = A1 + A0
    assert(affine_eq(&a3, &a4));
    assert(affine_is_on_curve(&a3));

    printf("    {\n");
    if (ledger_gen) {
      print_affine_as_ledger_cstruct(&a3);
    }
    else {
      print_affine_as_cstruct(&a3);
    }

    // Test3: Scaling commutes with adding scalars
    //     G*(S0 + S1) == G*S0 + G*S1
    scalar_add(u.s2, S[i][0], S[i][1]);
    generate_pubkey(&a3, u.s2);          // a3 = G*(S0 + S1)
    affine_add(&a4, &A[i][0], &A[i][1]); // a4 = G*S0 + G*S1
    assert(affine_eq(&a3, &a4));
    assert(affine_is_on_curve(&a3));

    if (ledger_gen) {
      print_affine_as_ledger_cstruct(&a3);
    }
    else {
      print_affine_as_cstruct(&a3);
    }

    // Test4: Scaling commutes with multiplying scalars
    //    G*(S0*S1) == S0*(G*S1)
    scalar_mul(u.s2, S[i][0], S[i][1]);
    generate_pubkey(&a3, u.s2);                // a3 = G*(S0*S1)
    affine_scalar_mul(&a4, S[i][0], &A[i][1]); // a4 = S0*(G*S1)
    assert(affine_eq(&a3, &a4));
    assert(affine_is_on_curve(&a3));

    if (ledger_gen) {
      print_affine_as_ledger_cstruct(&a3);
    }
    else {
      print_affine_as_cstruct(&a3);
    }

    // Test5: Scaling commutes with negation
    //    G*(-S0) == -(G*S0)
    scalar_negate(u.s2, S[i][0]);
    generate_pubkey(&a3, u.s2);   // a3 = G*(-S0)
    affine_negate(&a4, &A[i][0]); // a4 = -(G*S0)
    assert(affine_eq(&a3, &a4));
    assert(affine_is_on_curve(&a3));

    if (ledger_gen) {
      print_affine_as_ledger_cstruct(&a3);
    }
    else {
      print_affine_as_cstruct(&a3);
    }

    // Test6: Addition is associative
    //     (A0 + A1) + A2 == A0 + (A1 + A2)
    affine_add(&a3, &A[i][0], &A[i][1]);
    affine_add(&a4, &a3, &A[i][2]);      // a4 = (A0 + A1) + A2
    affine_add(&a3, &A[i][1], &A[i][2]);
    affine_add(&u.a5, &A[i][0], &a3);    // a5 = A0 + (A1 + A2)
    assert(affine_eq(&a4, &u.a5));
    assert(affine_is_on_curve(&a4));

    if (ledger_gen) {
      print_affine_as_ledger_cstruct(&a4);
    }
    else {
      print_affine_as_cstruct(&a4);
    }
    printf("    },\n");
  }
  printf("};\n\n");
  printf("bool curve_checks(void);\n\n");

  if (ledger_gen) {
     printf("\n");
     printf("** Copy the above constants and curve_checks.c into the ledger project\n");
     printf("\n");
  }
}

typedef struct poseidon_test {
  int   input_len;
  char *input[10];
  char *output;
} PoseidonTest;

#define ARRAY_SAFE(...) __VA_ARGS__
#define ASSERT_POSEIDON_EQ(type, input, len, out) { \
  char *inputs[len] = input; \
  Field fields[len]; \
  for (size_t i = 0; i < len; i++) { \
    assert(field_from_hex(fields[i], inputs[i])); \
  } \
  Scalar target; \
  assert(scalar_from_hex(target, out)); \
  PoseidonCtx ctx; \
  assert(poseidon_init(&ctx, type, NULLNET_ID)); \
  poseidon_update(&ctx, fields, ARRAY_LEN(fields)); \
  Scalar output; \
  poseidon_digest(output, &ctx); \
  if (memcmp(output, target, sizeof(output)) != 0) { \
    char buf[65]; \
    fprintf(stderr, " output: %s\n", scalar_to_hex(buf, ARRAY_LEN(buf), output)); \
    fprintf(stderr, " target: %s\n", scalar_to_hex(buf, ARRAY_LEN(buf), target)); \
    assert(memcmp(output, target, sizeof(output)) == 0); \
  } \
}

void test_scalars() {
    Scalar s;
    assert(scalar_from_hex(s, "d2f75185842484ba5a1a4e0ba5f3870ed48782cc4f89a8228f5eaf75e1833906"));
    assert(scalar_from_hex(s, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f"));
    assert(!scalar_from_hex(s, "0000000000000000000000000000000000000000000000000000000000000040"));
    assert(!scalar_from_hex(s, "01000000ed302d991bf94c09fc98462200000000000000000000000000000040"));
}

void test_fields() {
    Field f;
    assert(field_from_hex(f, "a4e2beebb09bd02ad42bbccc11051e8262b6ef50445d8382b253e91ab1557a0d"));
    assert(field_from_hex(f, "df698e389c6f1987ffe186d806f8163738f5bf22e8be02572cce99dc6a4ab030"));
    assert(field_from_hex(f, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f"));
    assert(!field_from_hex(f, "0000000000000000000000000000000000000000000000000000000000000040"));
    assert(!field_from_hex(f, "01000000ed302d991bf94c09fc98462200000000000000000000000000000040"));
}

void test_poseidon() {
    //
    // Legacy tests
    //

    ASSERT_POSEIDON_EQ(
      POSEIDON_LEGACY,
      ARRAY_SAFE({
      }),
      0,
      "1b3251b6912d82edc78bbb0a5c88f0c6fde1781bc3e654123fa6862a4c63e617"
    );

    ASSERT_POSEIDON_EQ(
      POSEIDON_LEGACY,
      ARRAY_SAFE({
        "df698e389c6f1987ffe186d806f8163738f5bf22e8be02572cce99dc6a4ab030"
      }),
      1,
      "f9b1b6c5f8c98017c6b35ac74bc689b6533d6dbbee1fd868831b637a43ea720c"
    );

    ASSERT_POSEIDON_EQ(
      POSEIDON_LEGACY,
      ARRAY_SAFE({
        "56b648a5a85619814900a6b40375676803fe16fb1ad2d1fb79115eb1b52ac026",
        "f26a8a03d9c9bbd9c6b2a1324d2a3f4d894bafe25a7e4ad1a498705f4026ff2f"
      }),
      2,
      "7a556e93bcfbd27b55867f533cd1df293a7def60dd929a086fdd4e70393b0918"
    );

    ASSERT_POSEIDON_EQ(
      POSEIDON_LEGACY,
      ARRAY_SAFE({
        "075c41fa23e4690694df5ded43624fd60ab7ee6ec6dd48f44dc71bc206cecb26",
        "a4e2beebb09bd02ad42bbccc11051e8262b6ef50445d8382b253e91ab1557a0d",
        "7dfc23a1242d9c0d6eb16e924cfba342bb2fccf36b8cbaf296851f2e6c469639"
      }),
      3,
      "f94b39a919aab06f43f4a4b5a3e965b719a4dbd2b9cd26d2bba4197b10286b35"
    );

    ASSERT_POSEIDON_EQ(
      POSEIDON_LEGACY,
      ARRAY_SAFE({
        "a1a659b14e80d47318c6fcdbbd388de4272d5c2815eb458cf4f196d52403b639",
        "5e33065d1801131b64d13038ff9693a7ef6283f24ec8c19438d112ff59d50f04",
        "38a8f4d0a9b6d0facdc4e825f6a2ba2b85401d5de119bf9f2bcb908235683e06",
        "3456d0313a30d7ccb23bd71ed6aa70ab234dad683d8187b677aef73f42f4f52e"
      }),
      4,
      "cc1ccfa964fd6ef9ff1994beb53cfce9ebe1212847ce30e4c64f0777875aec34"
    );