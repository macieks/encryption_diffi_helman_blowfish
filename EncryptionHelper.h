/**
 *  @struct EncryptionHelper
 *  @brief Encryption helper to be used for communication between 2 peers (Alice and Bob).
 *    Internally uses Diffi-Helman to first establish shared key which is then used by Blowfish
 *    algorithm for regular data encryption/decryption. Uses OpenSSL for both algorithms.
 */
struct EncryptionHelper;

//! Helper function that does default OpenSSL startup
void EncryptionHelper_StartupOpenSSL(int randSeed = 0x12345678);

//! Creates encryption helper (either for Alice or Bob); it is up to user to decide who is Alice and who is Bob
EncryptionHelper* EncryptionHelper_Create(bool isAlice);
//! Destroys encryption helper
void EncryptionHelper_Destroy(EncryptionHelper* helper);
//! Gets whether helper is used for Alice; otherwise it's used for Bob
bool EncryptionHelper_IsAlice(EncryptionHelper* helper);

//! Gets exchange data to be sent (first Alice to Bob, then, once received, Bob to Alice)
bool EncryptionHelper_GetExchangeData(EncryptionHelper* helper, unsigned char* buffer, int bufferCapacity, int* bufferSize);
//! Marks exchange data as successfully sent; this is so we can internally deinitialize Diffi-Helman for Bob
void EncryptionHelper_MarkExchangeDataSent(EncryptionHelper* helper);
//! Gets whether exchange data was successfully sent
bool EncryptionHelper_IsExchangeDataSent(EncryptionHelper* helper);

//! To be invoked when exchange data is received
bool EncryptionHelper_ReceiveExchangeData(EncryptionHelper* helper, const unsigned char* buffer, int bufferSize);
//! Gets whether exchange data has been successfully received
bool EncryptionHelper_IsExchangeDataReceived(EncryptionHelper* helper);

//! Gets whether regular data can now be received
bool EncryptionHelper_CanReceiveData(EncryptionHelper* helper);
//! Gets whether regular data can now be sent
bool EncryptionHelper_CanSendData(EncryptionHelper* helper);
//! Encrypts data in place
bool EncryptionHelper_Encrypt(EncryptionHelper* helper, unsigned char* buffer, int bufferCapacity, int inputBufferSize, int* outputBufferSize);
//! Decrypts data in place
bool EncryptionHelper_Decrypt(EncryptionHelper* helper, unsigned char* buffer, int inputBufferSize, int* outputBufferSize);