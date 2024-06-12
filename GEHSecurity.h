#ifndef GEHSECURITY_H
#define GEHSECURITY_H

#include "gehub_message.pb.h"

#define GE_SECURITY_KEY_SIZE 32
#define GE_SECURITY_BLOCK_SIZE 16
#define GE_SECURITY_MAX_RSA_DATA_LENGTH 512

class GEHSecurity {
private:
    uint8_t sharedKey[GE_SECURITY_KEY_SIZE];

    // Encrypt by RSA
    uint32_t encode(const uint8_t *data, uint32_t size, uint8_t *outBuffer);
    GEHSecurity();

public:
    static GEHSecurity* Instance;

    // Public key used for RSA encryption
    bool setup(const char *publicKey);

    // Return the shared key ecrypted by RSA with the public key
    // and size of it
    uint32_t getSharedKey(uint8_t *outKey);
    
    // Calculate size of string encrypted by AES
    uint32_t calcEncryptedSize(uint32_t length);
    uint32_t encryptRSA(const uint8_t *data, uint32_t size, uint8_t *output);
    uint32_t encrypt(uint8_t *data, uint32_t length, uint8_t *outIV, uint8_t *output);
    uint32_t decrypt(uint8_t *iv, uint8_t *data, uint32_t length, uint8_t *output);
};

#endif
