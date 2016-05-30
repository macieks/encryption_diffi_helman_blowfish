#include "EncryptionHelper.h"

#include <assert.h>

#include <openssl/rand.h>
#include <openssl/dh.h>
#include <openssl/blowfish.h>

struct EncryptionHelper
{
  bool m_isAlice;             // Indicates whether we're Alice; otherwise we're Bob

  DH* m_dh;                   // Diffi-Helman OpenSSL context; valid only during key exchange
  bool m_isExchangeDataSent;  // Indicates whether exchange data was successfully sent to Bob; valid for Alice only
  bool m_isExchangeDataRecved;// Indicates whether exchange data was successfully received from Alice; valid for Bob only

  BF_KEY m_blowfish;          // Blowfish key; valid once key exchange is finalized
};

void EncryptionHelper_StartupOpenSSL(int randSeed)
{
  CRYPTO_malloc_init();
  RAND_seed(&randSeed, sizeof(randSeed));
}

EncryptionHelper* EncryptionHelper_Create(bool isAlice)
{
  EncryptionHelper* helper = new EncryptionHelper();
  if (!helper)
    return NULL;
  helper->m_dh = NULL;
  helper->m_isAlice = isAlice;
  helper->m_isExchangeDataSent = false;
  helper->m_isExchangeDataRecved = false;
  return helper;
}

void EncryptionHelper_Destroy(EncryptionHelper* helper)
{
  if (helper->m_dh)
    DH_free(helper->m_dh);
  delete helper;
}

bool EncryptionHelper_IsAlice(EncryptionHelper* helper)
{
  return helper->m_isAlice;
}

bool EncryptionHelper_VerifyDiffiHelman(EncryptionHelper* helper)
{
  int flags;
  if (!DH_check(helper->m_dh, &flags))
    return false;
  return flags ? false : true;
}

bool EncryptionHelper_WriteNum(const BIGNUM* num, unsigned char* buffer, int bufferCapacity, int* bufferSize)
{
  if (*bufferSize + 1 >= bufferCapacity)
    return false;

  // Write number length followed by the number data

  unsigned char* numLengthPtr = buffer + *bufferSize;
  unsigned char* dataPtr = buffer + *bufferSize + 1;
  *numLengthPtr = (unsigned char) BN_bn2bin(num, dataPtr);

  *bufferSize += 1 + *numLengthPtr;
  assert(*bufferSize <= bufferCapacity);

  return true;
}

BIGNUM* EncryptionHelper_ReadNum(const unsigned char*& currPtr, const void* endPtr)
{
  // Read number length

  if ((unsigned char*) currPtr + 1 >= endPtr)
    return NULL;

  const unsigned char* numLengthPtr = currPtr;
  currPtr++;

  // Read data and create number

  if (currPtr + *numLengthPtr > endPtr)
    return NULL;

  BIGNUM* num = BN_bin2bn(currPtr, *numLengthPtr, NULL);
  if (!num)
    return NULL;
  currPtr += *numLengthPtr;

  return num;
}

bool EncryptionHelper_GetExchangeData(EncryptionHelper* helper, unsigned char* buffer, int bufferCapacity, int* bufferSize)
{
  assert((helper->m_isAlice && !helper->m_isExchangeDataSent) || (!helper->m_isAlice && helper->m_isExchangeDataRecved));

  *bufferSize = 0;

  if (helper->m_isAlice) // Bob initializes Diffi-Helman when exchange data gets received
  {
    // Initialize Diffi-Helman if not done before

    if (!helper->m_dh)
    {
      helper->m_dh = DH_new();
      if (!helper->m_dh)
        return false;
      helper->m_dh->flags &= ~DH_FLAG_NO_EXP_CONSTTIME;

      // Generate P and G

      if (!DH_generate_parameters_ex(helper->m_dh, 256, DH_GENERATOR_5, NULL))
      {
        DH_free(helper->m_dh);
        helper->m_dh = NULL;
        return false;
      }

      // Verify P and G

      if (!EncryptionHelper_VerifyDiffiHelman(helper))
      {
        DH_free(helper->m_dh);
        helper->m_dh = NULL;
        return false;
      }

      // Generate public and private keys

      if (!DH_generate_key(helper->m_dh))
      {
        DH_free(helper->m_dh);
        helper->m_dh = NULL;
        return false;
      }
    }

    // Write P and G numbers

    if (!EncryptionHelper_WriteNum(helper->m_dh->p, buffer, bufferCapacity, bufferSize) ||
      !EncryptionHelper_WriteNum(helper->m_dh->g, buffer, bufferCapacity, bufferSize))
      return false;
  }

  // Write public key

  return EncryptionHelper_WriteNum(helper->m_dh->pub_key, buffer, bufferCapacity, bufferSize);
}

void EncryptionHelper_MarkExchangeDataSent(EncryptionHelper* helper)
{
  assert(!helper->m_isExchangeDataSent);
  helper->m_isExchangeDataSent = true;

  if (!helper->m_isAlice)
  {
    assert(helper->m_dh);
    DH_free(helper->m_dh);
    helper->m_dh = NULL;
  }
}

bool EncryptionHelper_IsExchangeDataSent(EncryptionHelper* helper)
{
  return helper->m_isExchangeDataSent;
}

bool EncryptionHelper_ReceiveExchangeData(EncryptionHelper* helper, const unsigned char* buffer, int bufferSize)
{
  assert(!helper->m_isExchangeDataRecved);
  assert(!helper->m_isAlice || helper->m_isExchangeDataSent);

  const unsigned char* bufferEnd = buffer + bufferSize;

  // Read P and G if Bob (Alice already did it)

  if (!helper->m_isAlice)
  {
    assert(!helper->m_dh);

    helper->m_dh = DH_new();
    if (!helper->m_dh)
      return false;
    helper->m_dh->flags |= DH_FLAG_NO_EXP_CONSTTIME;

    // Read P and G

    helper->m_dh->p = EncryptionHelper_ReadNum(buffer, bufferEnd);
    if (!helper->m_dh->p)
    {
      DH_free(helper->m_dh);
      helper->m_dh = NULL;
      return false;
    }

    helper->m_dh->g = EncryptionHelper_ReadNum(buffer, bufferEnd);
    if (!helper->m_dh->g)
    {
      DH_free(helper->m_dh);
      helper->m_dh = NULL;
      return false;
    }

    // Verify P and G

    if (!EncryptionHelper_VerifyDiffiHelman(helper))
    {
      DH_free(helper->m_dh);
      helper->m_dh = NULL;
      return false;
    }

    // Generate public and private keys

    if (!DH_generate_key(helper->m_dh))
    {
      DH_free(helper->m_dh);
      helper->m_dh = NULL;
      return false;
    }
  }

  // Read public key

  BIGNUM* publicKey = EncryptionHelper_ReadNum(buffer, bufferEnd);
  if (!publicKey)
    return false;

  // Check end of buffer

  if (buffer != bufferEnd)
  {
    BN_free(publicKey);
    return false;
  }

  // Generate symmetric key to be used by Blowfish algorithm

  const int MAX_BLOWFISH_KEY_BITS = 1024;
  unsigned char symmetricKey[MAX_BLOWFISH_KEY_BITS / 8];

  const int symmetricKeyLength = DH_size(helper->m_dh);
  if (MAX_BLOWFISH_KEY_BITS < symmetricKeyLength)
  {
    BN_free(publicKey);
    return false;
  }

  const int computeResult = DH_compute_key(symmetricKey, publicKey, helper->m_dh);
  if (computeResult != symmetricKeyLength)
  {
    BN_free(publicKey);
    return false;
  }

  // Deinitialize Diffi-Helman if Alice

  if (helper->m_isAlice)
  {
    DH_free(helper->m_dh);
    helper->m_dh = NULL;
  }

  // Public key isn't needed anymore

  BN_free(publicKey);

  // Initialize Blowfish with symmetric key

  BF_set_key(&helper->m_blowfish, symmetricKeyLength, symmetricKey);

  helper->m_isExchangeDataRecved = true;
  return true;
}

bool EncryptionHelper_IsExchangeDataReceived(EncryptionHelper* helper)
{
  return helper->m_isExchangeDataRecved;
}

bool EncryptionHelper_CanReceiveData(EncryptionHelper* helper)
{
  return helper->m_isExchangeDataRecved; // Remote peer did all it was supposed to do
}

bool EncryptionHelper_CanSendData(EncryptionHelper* helper)
{
  return helper->m_isExchangeDataSent; // We did all we were supposed to do
}

bool EncryptionHelper_Encrypt(EncryptionHelper* helper, unsigned char* buffer, int bufferCapacity, int inputBufferSize, int* outputBufferSize)
{
  assert(EncryptionHelper_CanSendData(helper));

  // Must align data to 64 bits (8 bytes) for Blowfish algorithm

  const int remainderLength = inputBufferSize & 7;
  if (remainderLength) // We'll fit remainder length in the last 8 bits (there's at least 1 byte unused!)
  {
    *outputBufferSize = inputBufferSize - remainderLength + 8;
    assert(*outputBufferSize <= bufferCapacity);
    buffer[*outputBufferSize - 1] = remainderLength;
  }
  else // Must add extra 8 bytes
  {
    *outputBufferSize = inputBufferSize + 8;
    assert(*outputBufferSize <= bufferCapacity);
    buffer[*outputBufferSize - 1] = 0; // No remainder
  }

  // Encrypt the data

  for (int i = 0; i < *outputBufferSize; i += 8)
    BF_encrypt((BF_LONG*) (buffer + i), &helper->m_blowfish);

  return true;
}

bool EncryptionHelper_Decrypt(EncryptionHelper* helper, unsigned char* buffer, int inputBufferSize, int* outputBufferSize)
{
  assert(EncryptionHelper_CanReceiveData(helper));

  // Properly encrypted data is always 8-byte (64 bits) aligned

  if (inputBufferSize & 7)
    return false;

  // Decrypt the data

  for (int i = 0; i < inputBufferSize; i += 8)
    BF_decrypt((BF_LONG*) (buffer + i), &helper->m_blowfish);

  // Reconstruct original buffer length and fix up buffer

  const unsigned char remainderLength = buffer[inputBufferSize - 1];
  if (remainderLength)
  {
    if (remainderLength > 7)
      return false;
    *outputBufferSize = inputBufferSize - (8 - remainderLength);
  }
  else
    *outputBufferSize = inputBufferSize - 8;

  return true;
}

#if 0 // Unit test

#define check(op) { bool result = op; assert(result); }

void EncryptionHelper_UnitTest()
{
  int length;

  const int UNIT_TEST_BUFFER_SIZE = 256;
  unsigned char buffer[UNIT_TEST_BUFFER_SIZE];

  const int UNIT_TEST_MSG0_SIZE = UNIT_TEST_BUFFER_SIZE - 8; // Keep it 8-byte aligned
  const int UNIT_TEST_MSG1_SIZE = UNIT_TEST_BUFFER_SIZE - 9; // Make it non 8-byte aligned

  // Initialize OpenSSL

  EncryptionHelper_StartupOpenSSL();

  // Initialize Alice and Bob

  EncryptionHelper* alice = EncryptionHelper_Create(true);
  EncryptionHelper* bob = EncryptionHelper_Create(false);
  assert(alice && bob);
  check(EncryptionHelper_IsAlice(alice));
  check(!EncryptionHelper_IsAlice(bob));

  // Alice generates exchange data and sends it to Bob

  check(EncryptionHelper_GetExchangeData(alice, buffer, UNIT_TEST_BUFFER_SIZE, &length));
  // [ sending... ]
  EncryptionHelper_MarkExchangeDataSent(alice);
  check(EncryptionHelper_IsExchangeDataSent(alice));

  // Bob receives exchange data and sends another exchange data to Alice

  check(EncryptionHelper_ReceiveExchangeData(bob, buffer, length));
  check(EncryptionHelper_IsExchangeDataReceived(bob));
  check(EncryptionHelper_GetExchangeData(bob, buffer, UNIT_TEST_BUFFER_SIZE, &length));
  // [ sending... ]
  EncryptionHelper_MarkExchangeDataSent(bob);
  check(EncryptionHelper_IsExchangeDataSent(bob));

  // Alice receives exchange data from Bob

  check(EncryptionHelper_ReceiveExchangeData(alice, buffer, length));

  // Authentication done!
  
  // Communication begins...

  // Bob encrypts data for Alice; Alice decrypts the data

  for (int i = 0; i < UNIT_TEST_MSG0_SIZE; i++)
    buffer[i] = i;
  check(EncryptionHelper_Encrypt(bob, buffer, UNIT_TEST_BUFFER_SIZE, UNIT_TEST_MSG0_SIZE, &length));
  check(EncryptionHelper_Decrypt(alice, buffer, length, &length));
  for (int i = 0; i < length; i++)
    check(buffer[i] == i);

  // Alice encrypts data for Bob; Bob decrypts the data

  for (int i = 0; i < UNIT_TEST_MSG1_SIZE; i++)
    buffer[i] = i;
  check(EncryptionHelper_Encrypt(alice, buffer, UNIT_TEST_BUFFER_SIZE, UNIT_TEST_MSG1_SIZE, &length));
  check(EncryptionHelper_Decrypt(bob, buffer, length, &length));
  for (int i = 0; i < length; i++)
    check(buffer[i] == i);

  // Shut down Alice and Bob

  EncryptionHelper_Destroy(alice);
  EncryptionHelper_Destroy(bob);
}

#endif