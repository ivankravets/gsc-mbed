#include <GEHBuilder.h>
#include <GEHSecurity.h>
#include <pb.h>
#include <pb_encode.h>
#include <pb_decode.h>

uint16_t GEHBuilder::getMsgID(const GEHMessage &msg) {
    uint16_t msgID;
    memcpy(&msgID, msg.content, 2);
    return msgID;
}

uint8_t *GEHBuilder::getContent(const GEHMessage &msg) {
    return msg.content + 2;
}

GEHMessage GEHBuilder::buildRegistrationMessage(const gschub_Client &client) {
    // Encode client's information
    pb_ostream_t stream = pb_ostream_from_buffer(this->buffer, gschub_Client_size);
    if (!pb_encode(&stream, gschub_Client_fields, &client)) {
        return GEHMessage_init_default;
    }

    // Build body
    gschub_SharedKey sharedKey = gschub_SharedKey_init_default;
    sharedKey.key.size = GEHSecurity::Instance->getSharedKey(sharedKey.key.bytes);
    sharedKey.cipher.IV.size = GE_SECURITY_BLOCK_SIZE;
    sharedKey.cipher.data.size = GEHSecurity::Instance->encrypt(
        buffer,
        stream.bytes_written,
        sharedKey.cipher.IV.bytes,
        sharedKey.cipher.data.bytes
    );
    stream = pb_ostream_from_buffer(this->buffer, gschub_SharedKey_size);
    if (!pb_encode(&stream, gschub_SharedKey_fields, &sharedKey)) {
        return GEHMessage_init_default;
    }
    return GEHMessage{stream.bytes_written, this->buffer};
}

GEHMessage GEHBuilder::buildActivationMessage(const gschub_ClientTicket &clientTicket) {
    // Build content
    pb_ostream_t stream = pb_ostream_from_buffer(this->buffer, gschub_ClientTicket_size);
    if (!pb_encode(&stream, gschub_ClientTicket_fields, &clientTicket)) {
        return GEHMessage_init_default;
    }

    // Build cipher ticket
    gschub_CipherTicket cipherTicket = gschub_CipherTicket_init_default;
    cipherTicket.cipher.IV.size = GE_SECURITY_BLOCK_SIZE;
    cipherTicket.cipher.data.size = GEHSecurity::Instance->encrypt(
        this->buffer,
        stream.bytes_written,
        cipherTicket.cipher.IV.bytes,
        cipherTicket.cipher.data.bytes
    );

    cipherTicket.ID.size = GEHSecurity::Instance->encryptRSA(
        (uint8_t *)clientTicket.connID,
        strlen(clientTicket.connID),
        cipherTicket.ID.bytes
    );

    stream = pb_ostream_from_buffer(this->buffer, gschub_CipherTicket_size);
    if (!pb_encode(&stream, gschub_CipherTicket_fields, &cipherTicket)) {
        return GEHMessage_init_default;
    }

    // Build message
    return this->formatMessage(-1, this->buffer, stream.bytes_written);
}

GEHMessage GEHBuilder::buildRenameMessage(uint16_t msgID, const char* aliasName, const char *connID, const char *connToken) {
    // Build content
    gschub_Client client = gschub_Client_init_default;
    strcpy(client.aliasName, aliasName);
    strcpy(client.ID, connID);
    strcpy(client.token, connToken);
    pb_ostream_t stream = pb_ostream_from_buffer(this->buffer, gschub_Client_size);
    if (!pb_encode(&stream, gschub_Client_fields, &client)) {
        return GEHMessage_init_default;
    }

    return this->buildMessage(
        msgID,
        gschub_Letter_Type_Rename,
        "",
        this->buffer,
        stream.bytes_written,
        true
    );
}

GEHMessage GEHBuilder::buildMessage(uint16_t msgID, gschub_Letter_Type type, const char *receiver, uint8_t *content, uint32_t length, bool isEncrypted) {
    // Build letter
    this->letter.type = type;
    this->letter.data.size = length;
    strcpy(this->letter.receiver, receiver);
    memcpy(this->letter.data.bytes, content, length);
    pb_ostream_t stream = pb_ostream_from_buffer(this->buffer, gschub_Cipher_size);
    if (!pb_encode(&stream, gschub_Letter_fields, &this->letter)) {
        return GEHMessage_init_default;
    }

    // Build cipher
    this->cipher = gschub_Cipher_init_default;
    if (isEncrypted) {
        this->cipher.IV.size = GE_SECURITY_BLOCK_SIZE;
        this->cipher.data.size = GEHSecurity::Instance->encrypt(
            this->buffer,
            stream.bytes_written,
            this->cipher.IV.bytes,
            this->cipher.data.bytes
        );
    } else {
        this->cipher.IV.size = 0;
        this->cipher.data.size = stream.bytes_written;
        memcpy(this->cipher.data.bytes, this->buffer, stream.bytes_written);
    }
    stream = pb_ostream_from_buffer(this->buffer, gschub_Cipher_size);
    if (!pb_encode(&stream, gschub_Cipher_fields, &this->cipher)) {
        return GEHMessage_init_default;
    }

    // Build message
    return this->formatMessage(msgID, this->buffer, stream.bytes_written);
}

gschub_Ticket GEHBuilder::parseTicket(const uint8_t *data, uint32_t length) {
    pb_istream_t istream = pb_istream_from_buffer(data, length);
    if (!pb_decode(&istream, gschub_Cipher_fields, &this->cipher)) {
        this->ticket.address[0] = '\0';
        return this->ticket;
    }

    uint32_t size = GEHSecurity::Instance->decrypt(
        this->cipher.IV.bytes,
        this->cipher.data.bytes,
        this->cipher.data.size,
        this->buffer
    );

    // Build ticket
    istream = pb_istream_from_buffer(this->buffer, size);
    pb_decode(&istream, gschub_Ticket_fields, &this->ticket);
    memcpy(this->secretKey, this->ticket.secretKey, 36);
    return this->ticket;
}

GEHMessage GEHBuilder::parseReceivedMessage(WiFiClient &socket, uint32_t length) {
    // Limit size of received message
    uint32_t nRead = 0;
    if (length > MAX_MESSAGE_SIZE) {
        uint32_t remainBytes = length;
        while (remainBytes > MAX_MESSAGE_SIZE) {
            remainBytes -= MAX_MESSAGE_SIZE;
            nRead = socket.readBytes(this->buffer, MAX_MESSAGE_SIZE);
            if (nRead != MAX_MESSAGE_SIZE) {
                socket.stop();
                return GEHMessage_init_default;
            }
        }
        nRead = socket.readBytes(this->buffer, remainBytes);
        if (nRead != length) {
            socket.stop();
        }
        return GEHMessage_init_default;
    }

    // Read message
    nRead = socket.readBytes(this->buffer, length);
    if (nRead != length) {
        socket.stop();
        return GEHMessage_init_default;
    }
    
    // Parse cipher
    pb_istream_t stream = pb_istream_from_buffer(this->buffer, length);
    if (!pb_decode(&stream, gschub_Cipher_fields, &this->cipher)) {
        return GEHMessage_init_default;
    }

    uint32_t size = cipher.data.size;
    if (cipher.IV.size > 0) {
        size = GEHSecurity::Instance->decrypt(
            this->cipher.IV.bytes,
            this->cipher.data.bytes,
            this->cipher.data.size,
            this->buffer
        );
    } else {
        memcpy(this->buffer, this->cipher.data.bytes, size);
    }

    // Parse message
    pb_istream_t istream = pb_istream_from_buffer(this->buffer, size);
    if (!pb_decode(&istream, gschub_Reply_fields, &this->reply)) {
        return GEHMessage{
            0,
            nullptr
        };
    }

    // Validate message
    if (!this->validateMessage(
        this->reply.data.bytes,
        this->reply.data.size,
        this->reply.HMAC.bytes
    )) {
        return GEHMessage_init_default;
    }

    uint8_t *data = new uint8_t[this->reply.data.size];
    memcpy(data, this->reply.data.bytes, this->reply.data.size);
    return GEHMessage{
        reply.data.size,
        data
    };
}

GEHMessage GEHBuilder::formatMessage(uint16_t msgID, const uint8_t *content, uint32_t length) {
    uint8_t *data = new uint8_t[length + 6]; // 2 bytes for message's ID + 4 bytes for value of length
    if (data == nullptr) {
        return GEHMessage_init_default;
    }
    memcpy(data, &msgID, 2);
    memcpy(data + 2, &length, 4);
    memcpy(data + 6, content, length);
    return GEHMessage{length + 4, data};
}

bool GEHBuilder::validateMessage(const uint8_t *content, uint32_t length, const uint8_t *expectedHMAC) {
    byte hmacResult[32];
    mbedtls_md_context_t ctx;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
    mbedtls_md_hmac_starts(&ctx, this->secretKey, 36);
    mbedtls_md_hmac_update(&ctx, content, length);
    mbedtls_md_hmac_finish(&ctx, hmacResult);
    mbedtls_md_free(&ctx);
    for(int idx = 0; idx < sizeof(hmacResult); idx++){
        if (hmacResult[idx] != expectedHMAC[idx]) {
            return false;
        }
    }
    return true;
}
