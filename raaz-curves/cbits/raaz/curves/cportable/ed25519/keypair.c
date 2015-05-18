#include "randombytes.h"
#include "ed25519.h"
#include "sha512.h"
#include "ge.h"

int ed25519_sign_keypair(unsigned char *pk,unsigned char *sk)
{
  unsigned char h[64];
  ge_p3 A;
  int i;

  ed25519_randombytes(sk,32);
  crypto_hash_sha512(h,sk,32);
  h[0] &= 248;
  h[31] &= 63;
  h[31] |= 64;

  ge_scalarmult_base(&A,h);
  ge_p3_tobytes(pk,&A);

  for (i = 0;i < 32;++i) sk[32 + i] = pk[i];
  return 0;
}

int ed25519_sign_keypair_given_random(unsigned char *pk,unsigned char *sk)
{
  unsigned char h[64];
  ge_p3 A;
  int i;

  crypto_hash_sha512(h,sk,32);
  h[0] &= 248;
  h[31] &= 63;
  h[31] |= 64;

  ge_scalarmult_base(&A,h);
  ge_p3_tobytes(pk,&A);

  for (i = 0;i < 32;++i) sk[32 + i] = pk[i];
  return 0;
}
