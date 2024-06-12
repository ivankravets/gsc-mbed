#include <GEHSecurity.h>
#include <BigNumber.h>
#include <Crypto.h>
#include <NBase64.h>
#include <pb.h>
#include <pb_common.h>
#include <pb_decode.h>
#include <gehub_message.pb.h>

GEHSecurity *GEHSecurity::Instance = new GEHSecurity();

namespace gelib {
    struct PublicKey {
        BigNumber E;
        BigNumber N;
    };
    PublicKey publicKey;
}

GEHSecurity::GEHSecurity() {
    BigNumber::begin();
}

bool GEHSecurity::setup(const char *publicKey) {
    // Generate shared key
    RNG::fill(this->sharedKey, GE_SECURITY_KEY_SIZE);

    // Setup public key
    std::string decoded = base64_decode(std::string(publicKey));
    gschub_PublicKey key = gschub_PublicKey_init_default;
    pb_istream_t istream = pb_istream_from_buffer((uint8_t *)decoded.c_str(), decoded.length());
    if (pb_decode(&istream, gschub_PublicKey_fields, &key) == false) {
        return false;
    }
    gelib::publicKey.E = BigNumber(key.E);
    gelib::publicKey.N = BigNumber(key.N);
    return true;
}

uint32_t GEHSecurity::getSharedKey(uint8_t *outKey) {
    return this->encryptRSA(this->sharedKey, GE_SECURITY_KEY_SIZE, outKey);
}

uint32_t GEHSecurity::calcEncryptedSize(uint32_t length) {
    length += 4;
    uint32_t bufferSize = (length / GE_SECURITY_BLOCK_SIZE) * GE_SECURITY_BLOCK_SIZE;
    bufferSize = (bufferSize < length) ? bufferSize + GE_SECURITY_BLOCK_SIZE : bufferSize;
    return bufferSize;
}

uint32_t GEHSecurity::encryptRSA(const uint8_t *data, uint32_t size, uint8_t *output) {
    if (size == 0 || size > GE_SECURITY_MAX_RSA_DATA_LENGTH) {
        return 0;
    }

    // Encode message
    uint8_t encodedData[128]; // length of mask (1 byte) + mask (32 bytes)
    uint32_t encodedSize  = this->encode(data, size, encodedData);

    // Encrypt message
    const char delim = ',';
    char *buffer = BigNumber(encodedData[0]).powMod(gelib::publicKey.E, gelib::publicKey.N).toString();
    memcpy(output, buffer, strlen(buffer));
    uint32_t bufferSize = strlen(buffer);
    free(buffer);
    for (uint32_t iByte = 1; iByte < encodedSize; ++iByte) {
        buffer = BigNumber(encodedData[iByte]).powMod(gelib::publicKey.E, gelib::publicKey.N).toString();
        memcpy(output + bufferSize, &delim, 1);
        memcpy(output + bufferSize + 1, buffer, strlen(buffer));
        bufferSize += strlen(buffer) + 1;
        free(buffer);
    }
    return bufferSize;
}

uint32_t GEHSecurity::encrypt(uint8_t *data, uint32_t length, uint8_t *outIV, uint8_t *output) {
    uint32_t bufferSize = this->calcEncryptedSize(length);
    memcpy(output + 4, data, length);
    memcpy(output, &length, 4);
    RNG::fill(outIV, GE_SECURITY_BLOCK_SIZE);
    AES aesEncryptor(this->sharedKey, outIV, AES::AES_MODE_256, AES::CIPHER_ENCRYPT);
    aesEncryptor.process(output, output, bufferSize);
    return bufferSize;
}

uint32_t GEHSecurity::decrypt(uint8_t *iv, uint8_t *data, uint32_t length, uint8_t *output) {
    AES aesDecryptor(this->sharedKey, iv, AES::AES_MODE_256, AES::CIPHER_DECRYPT);
    aesDecryptor.process(data, output, length);
    uint32_t bufferSize;
    memcpy(&bufferSize, output, 4);
    memcpy(output, output + 4, bufferSize);
    return bufferSize;
}

uint32_t GEHSecurity::encode(const uint8_t *data, uint32_t size, uint8_t *outBuffer) {
    uint8_t mask[32];
    uint8_t sizeMask = min((int)size, 32);
    
    // Random mask
    RNG::fill(mask, sizeMask);
    
    // Setup output
    uint8_t *pEncoded = outBuffer + sizeMask + 1; // the first byte will be the size of mask
    memcpy(outBuffer, &sizeMask, 1);
    memcpy(outBuffer + 1, mask, sizeMask);
    for (uint32_t iByte = 0; iByte < size; ++iByte) {
        pEncoded[iByte] = data[iByte] ^ mask[iByte % sizeMask];
    }
    return size + sizeMask + 1;
}
