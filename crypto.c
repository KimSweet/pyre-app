// Mina schnorr signatures and eliptic curve arithmatic
//
//     * Produces a schnorr signature according to the specification here:
//       https://github.com/MinaProtocol/mina/blob/develop/docs/specs/signatures/description.md
//
//     * Signer reference here: https://github.com/MinaProtocol/signer-reference
//
//     * Curve arithmatic
//         - field_add, field_sub, field_mul, field_sq, field_inv, field_negate, field_pow, field_eq
//         - scalar_add, scalar_sub, scalar_mul, 