#include "GEHClient.h"
#include "GEHErrorDefine.h"
#include <GEHSecurity.h>
#include <mbedtls/md.h>
#include <WiFi.h>
#include <pb_common.h>
#include <pb.h>
#include <pb_encode.h>
#include <pb_decode.h>
#include <SPIFFS.h>
#include <NBase64.h>
#include <base64.h>


#define CHARACTER_END_STRING '\0'
#define MAX_LENGTH_READ_BUFFER 1600
#define MAX_LENGTH_WRITE_BUFFER 1600
#define MAX_NUMBER_MESSAGE 1024

#define VERSION "2.2.0"
#define FILE_CONFIG "/gsc-services.json"
#define URL_REGISTER "/conn/register"
#define URL_SECURITY "/public-key"


namespace gelib {
    namespace message {
        namespace {
            SemaphoreHandle_t xTableMutex;
            bool tableMessageID[MAX_NUMBER_MESSAGE];
        }

        void init() {
            if (xTableMutex != NULL) {
                return;
            }
            xTableMutex = xSemaphoreCreateMutex();
            xSemaphoreGive(xTableMutex);
        }

        uint16_t registerNext() {
            uint16_t msgID = MAX_NUMBER_MESSAGE;
            if (xSemaphoreTake(xTableMutex, (TickType_t) 100) != pdTRUE) { // Waiting 1500ms
                return msgID;
            }

            for (uint16_t idx = 0; idx < MAX_NUMBER_MESSAGE; ++idx) {
                if (tableMessageID[idx] == false) {
                    msgID = idx;
                    break;
                }
            }

            if (msgID < MAX_NUMBER_MESSAGE) {
                tableMessageID[msgID] = true;
            }
            xSemaphoreGive(xTableMutex);
            return msgID;
        }

        void unregister(uint16_t msgID) {
            if (xSemaphoreTake(xTableMutex, (TickType_t) 100) != pdTRUE) { // Waiting 1500ms
                return;
            }
            tableMessageID[msgID] = false;
            xSemaphoreGive(xTableMutex);
        }

        bool isRegistered(uint16_t msgID) {
            bool isRegistered = false;
            if (xSemaphoreTake(xTableMutex, (TickType_t) 100) != pdTRUE) { // Waiting 1500ms
                return isRegistered;
            }
            isRegistered = tableMessageID[msgID];
            xSemaphoreGive(xTableMutex);
            return isRegistered;
        }
    }

    uint8_t *buildRequest(const uint8_t *content, size_t length) {
        uint8_t *msg = new uint8_t[length + 4]; // 4 bytes for value of length
        memcpy(msg + 4, content, length);
        for (int idx = 0; idx < 4; ++idx) {
            msg[idx] = (uint8_t)length;
            length >>= 8;
        }
        return msg;
    }
}

GEHClient *GEHClient::Shared = new GEHClient();

GEHClient* const GEHClient::Instance() {
    return GEHClient::Shared;
}

GEHClient::GEHClient() {
    gelib::message::init();

    this->listener = NULL;
    this->isOpened = false;
    this->lastErrorID = GEH_ERROR_NONE;
    this->recvQueue = new GEHQueue(MAX_NUMBER_MESSAGE);
    this->writeQueue = new GEHQueue(MAX_NUMBER_MESSAGE);
}

GEHClient::~GEHClient() {
    delete this->recvQueue;
    delete this->writeQueue;
    if (this->listener != NULL) {
        delete this->listener;
    }
}

void GEHClient::nextMessage() {
    vTaskDelay(1);
    if (this->listener == NULL || this->recvQueue->isEmpty()) {
        return;
    }
    gelib::GEHMessage msg = this->recvQueue->pop();
    this->listener->onMessage(msg.content, msg.length);
    delete []msg.content;
}

uint8_t GEHClient::getLastError() {
    return this->lastErrorID;
}

void GEHClient::setListener(GEHListener *listener) {
    this->listener = listener;
}

bool GEHClient::open(const char *aliasName) {
    if (this->isOpened) {
        return true;
    }

    if (this->setupConfig() == false) {
        return false;
    }
    this->isOpened = true;

    strcpy(this->client.aliasName, aliasName);
    xTaskCreatePinnedToCore(
        GEHClient::loopAction,
        "GEHClient::loopAction",
        100 * 1024, // 5 Kb
        GEHClient::Shared,
        1,
        &this->loopActionTask,
        0
    );
    return true;
}

bool GEHClient::renameConnection(const char *aliasName) {
    if (this->isOpened == false) {
        return false;
    }

    // Build message
    uint8_t *buffer = new uint8_t[gschub_Cipher_size];
    gschub_Client client = gschub_Client_init_default;
    strcpy(client.aliasName, aliasName);
    strcpy(client.ID, clientTicket.connID);
    strcpy(client.token, clientTicket.token);
    pb_ostream_t stream = pb_ostream_from_buffer(buffer, gschub_Client_size);
    if (!pb_encode(&stream, gschub_Client_fields, &client)) {
        delete []buffer;
        return false;
    }

    // Build cipher
    gschub_Cipher cipher = gschub_Cipher_init_default;
    cipher.IV.size = GE_SECURITY_BLOCK_SIZE;
    cipher.data.size = GEHSecurity::Instance->encrypt(
        buffer,
        stream.bytes_written,
        cipher.IV.bytes,
        cipher.data.bytes
    );
    stream = pb_ostream_from_buffer(buffer, gschub_Cipher_size);
    if (!pb_encode(&stream, gschub_Cipher_fields, &cipher)) {
        delete []buffer;
        return false;
    }
    // Send message
    size_t len = stream.bytes_written;
    uint8_t *data = gelib::buildRequest((uint8_t *)buffer, len);
    const size_t numSendBytes = this->socket.write(data, len + 4);
    delete []buffer;
    delete []data;
    if (numSendBytes != (len + 4)) {
        return false;
    }
    strcpy(this->client.aliasName, aliasName);
    return true;
}

uint16_t GEHClient::writeMessage(const char *receiver, uint8_t *content, size_t length, bool isEncrypted) {
    if (WiFi.status() != WL_CONNECTED) {
        this->lastErrorID = GEH_ERROR_DISCONNECTED;
        return 0;
    }

    if (this->writeQueue->isFull()) {
        this->lastErrorID = GEH_ERROR_NOT_ENOUGH_QUEUE;
        return 0;
    }

    uint16_t msgID = gelib::message::registerNext();
    if (msgID == MAX_NUMBER_MESSAGE) {
        this->lastErrorID = GEH_ERROR_NOT_ENOUGH_QUEUE;
        return 0;
    }

    // Build message
    uint8_t *buffer = new uint8_t[gschub_Cipher_size];
    gschub_Letter letter = gschub_Letter_init_default;
    letter.type = gschub_Letter_Type_Single;
    letter.data.size = length;
    strcpy(letter.receiver, receiver);
    memcpy(letter.data.bytes, content, length);
    pb_ostream_t stream = pb_ostream_from_buffer(buffer, gschub_Letter_size);
    if (!pb_encode(&stream, gschub_Letter_fields, &letter)) {
        return false;
    }

    // Build cipher
    gschub_Cipher cipher = gschub_Cipher_init_default;
    if (isEncrypted) {
        cipher.IV.size = GE_SECURITY_BLOCK_SIZE;
        cipher.data.size = GEHSecurity::Instance->encrypt(
            buffer,
            stream.bytes_written,
            cipher.IV.bytes,
            cipher.data.bytes
        );
    } else {
        cipher.IV.size = 0;
        cipher.data.size = stream.bytes_written;
        memcpy(cipher.data.bytes, buffer, stream.bytes_written);
    }
    stream = pb_ostream_from_buffer(buffer, gschub_Cipher_size);
    if (!pb_encode(&stream, gschub_Cipher_fields, &cipher)) {
        delete []buffer;
        return false;
    }

    // Prepare message
    length = stream.bytes_written;
    uint8_t *req = new uint8_t[length + 2];
    memcpy(req + 2, buffer, length);
    memcpy(req, &msgID, 2);
    delete []buffer;

    // Push message to queue
    bool result = this->writeQueue->push(gelib::GEHMessage{
        length,
        req
    });
    if (result) {
        this->lastErrorID = GEH_ERROR_NONE;
        return msgID;
    }
    delete []req;

    gelib::message::unregister(msgID);
    this->lastErrorID = GEH_ERROR_NOT_ENOUGH_QUEUE;
    return 0;
}

uint16_t GEHClient::writeMessage(const char *receiver, uint8_t *content, size_t length, uint16_t msgID, bool isEncrypted) {
    if (msgID >= 0 && gelib::message::isRegistered(msgID)) {
        return msgID;
    }
    return this->writeMessage(receiver, content, length, isEncrypted);
}

/////////////////////
// PRIVATE METHODS //
/////////////////////

void GEHClient::loopAction(void *param) {
    GEHClient *instance = (GEHClient *)param;
    while(1) {
        vTaskDelay(1);
        if (WiFi.status() != WL_CONNECTED) {
            continue;
        }

        if (instance->socket.connected() == false || instance->ping() == false) {
            instance->socket.stop();
            if (instance->connect() == false) {
                instance->socket.stop();
                continue;
            }
        }

        instance->writeNextMessage();

        if (!instance->socket.available()) {
            continue;
        }
        gelib::GEHMessage msg = instance->readNextMessage();
        if (msg.length > 0 && instance->recvQueue->push(msg) == false) {
            delete []msg.content;
        }
    }
    vTaskDelete(&instance->loopActionTask);
}

bool GEHClient::connect() {
    char body[512];

    if (this->setupSecurity() == false) {
        return false;
    }

    if (this->registerConnection(body) == false) {
        return false;
    }

    StaticJsonDocument<512> doc;
    auto err = deserializeJson(doc, body);
    if (err || doc.containsKey("data") == false || doc["returncode"].as<int>() < 1) {
        return false;
    }

    // Parse response
    std::string data = base64_decode(std::string(doc["data"].as<char *>()));
    gschub_Cipher cipher = gschub_Cipher_init_default;
    pb_istream_t istream = pb_istream_from_buffer((uint8_t *)data.c_str(), data.length());
    if (!pb_decode(&istream, gschub_Cipher_fields, &cipher)) {
        return false;
    }

    uint8_t buffer[gschub_Cipher_size];
    uint32_t bufferSize = GEHSecurity::Instance->decrypt(
        cipher.IV.bytes,
        cipher.data.bytes,
        cipher.data.size,
        buffer
    );

    // Build ticket
    gschub_Ticket ticket = gschub_Ticket_init_default;
    istream = pb_istream_from_buffer(buffer, bufferSize);
    pb_decode(&istream, gschub_Ticket_fields, &ticket);
    if (this->connectSocket(ticket.address) == false) {
        return false;
    }
    memcpy(this->secretKey, ticket.secretKey, 36);
    return this->activateSocket(ticket);
}

bool GEHClient::setupSecurity() {
    HTTPClient http;

    if (http.begin(this->baseURL + URL_SECURITY) == false) {
        return false;
    }

    if (http.GET() <= 0) {
        http.end();
        return false;
    }

    char body[1024];
    http.getString().toCharArray(body, 1024);
    http.end();

    StaticJsonDocument<1024> doc;
    auto err = deserializeJson(doc, body);
    if (err || doc.containsKey("data") == false || doc["returncode"] < 1) {
        return false;
    }
    return GEHSecurity::Instance->setup(doc["data"].as<char *>());
}

bool GEHClient::registerConnection(char *output) {
    uint8_t buffer[gschub_Client_size];

    // Encode client's information
    pb_ostream_t stream = pb_ostream_from_buffer(buffer, gschub_Client_size);
    if (!pb_encode(&stream, gschub_Client_fields, &this->client)) {
        return false;
    }

    // Build body
    uint8_t body[gschub_SharedKey_size];
    gschub_SharedKey sharedKey = gschub_SharedKey_init_default;
    sharedKey.key.size = GEHSecurity::Instance->getSharedKey(sharedKey.key.bytes);
    sharedKey.cipher.IV.size = GE_SECURITY_BLOCK_SIZE;
    sharedKey.cipher.data.size = GEHSecurity::Instance->encrypt(
        buffer,
        stream.bytes_written,
        sharedKey.cipher.IV.bytes,
        sharedKey.cipher.data.bytes
    );
    stream = pb_ostream_from_buffer(body, gschub_SharedKey_size);
    if (!pb_encode(&stream, gschub_SharedKey_fields, &sharedKey)) {
        return false;
    }

    // Send request
    body[stream.bytes_written] = '\0';
    HTTPClient http;
    http.begin(this->baseURL + URL_REGISTER);
    http.addHeader("Version", VERSION);
    http.addHeader("Content-Type", "application/json");
    if (http.POST(base64::encode(String((char *)body)).c_str()) <= 0) {
        http.end();
        return false;
    }

    String content = http.getString();
    content.toCharArray((char *)output, 512);
    http.end();
    return true;
}

bool GEHClient::connectSocket(const char *host) {
    try {
        char *socketIP = strtok((char *)host, ":");
        int socketPort = atoi(strtok (NULL, ":"));
        return this->socket.connect(socketIP, socketPort) == 1;
    }
    catch(const std::exception& e) {
        return false;
    }
}

bool GEHClient::activateSocket(const gschub_Ticket &ticket) {
    // Build message
    uint8_t clientTicketBuffer[gschub_ClientTicket_size];
    pb_ostream_t stream = pb_ostream_from_buffer(clientTicketBuffer, gschub_ClientTicket_size);
    if (!pb_encode(&stream, gschub_ClientTicket_fields, &ticket.clientTicket)) {
        return false;
    }

    gschub_CipherTicket cipherTicket = gschub_CipherTicket_init_default;
    cipherTicket.cipher.IV.size = GE_SECURITY_BLOCK_SIZE;
    cipherTicket.cipher.data.size = GEHSecurity::Instance->encrypt(
        clientTicketBuffer,
        stream.bytes_written,
        cipherTicket.cipher.IV.bytes,
        cipherTicket.cipher.data.bytes
    );

    cipherTicket.ID.size = GEHSecurity::Instance->encryptRSA(
        (uint8_t *)ticket.clientTicket.connID,
        strlen(ticket.clientTicket.connID),
        cipherTicket.ID.bytes
    );

    uint8_t cipherTicketBuffer[gschub_CipherTicket_size];
    stream = pb_ostream_from_buffer(cipherTicketBuffer, gschub_CipherTicket_size);
    if (!pb_encode(&stream, gschub_CipherTicket_fields, &cipherTicket)) {
        return false;
    }

    // Activate socket
    size_t len = stream.bytes_written;
    uint8_t *data = gelib::buildRequest((uint8_t *)cipherTicketBuffer, len);
    const size_t numSendBytes = this->socket.write(data, len + 4);
    delete []data;
    if (numSendBytes != (len + 4)) {
        return false;
    }

    strcpy(this->clientTicket.connID, ticket.clientTicket.connID);
    strcpy(this->clientTicket.token, ticket.clientTicket.token);
    return true;
}

bool GEHClient::ping() {
    static volatile uint64_t lastTimePing = 0;
    uint64_t currentTime = millis();
    if (lastTimePing + 1000 > currentTime) { // Only ping every 1 seconds
        return true;
    }

    // Build message
    uint8_t buffer[gschub_Cipher_size];
    gschub_Letter letter = gschub_Letter_init_default;
    letter.type = gschub_Letter_Type_Ping;
    letter.data.size = 4;
    memcpy(letter.data.bytes, (uint8_t*)"Ping", 4);
    pb_ostream_t stream = pb_ostream_from_buffer(buffer, gschub_Cipher_size);
    if (!pb_encode(&stream, gschub_Letter_fields, &letter)) {
        return false;
    }

    // Build cipher
    gschub_Cipher cipher = gschub_Cipher_init_default;
    cipher.IV.size = GE_SECURITY_BLOCK_SIZE;
    cipher.data.size = GEHSecurity::Instance->encrypt(
        buffer,
        stream.bytes_written,
        cipher.IV.bytes,
        cipher.data.bytes
    );
    stream = pb_ostream_from_buffer(buffer, gschub_Cipher_size);
    if (!pb_encode(&stream, gschub_Cipher_fields, &cipher)) {
        return false;
    }

    // Ping
    size_t len = stream.bytes_written;
    uint8_t *data = gelib::buildRequest((uint8_t *)buffer, len);
    const size_t numSendBytes = this->socket.write(data, len + 4);
    delete []data;
    if (numSendBytes != (len + 4)) {
        lastTimePing = currentTime + 1000;
        return false;
    }
    lastTimePing = currentTime;
    return true;
}

void GEHClient::writeNextMessage() {
    static size_t pendingLength = -1;
    static uint8_t *pendingData = NULL;
    static uint16_t msgID = 0;

    // Get next message
    if (pendingData == NULL) {
        if (this->writeQueue->isEmpty()) {
            return;
        }
        gelib::GEHMessage msg = this->writeQueue->pop();
        pendingData = gelib::buildRequest(msg.content + 2, msg.length);
        memcpy(&msgID, msg.content, 2);
        pendingLength = msg.length + 4;
        delete []msg.content;
    }

    // Send message
    const size_t numSendBytes = this->socket.write(pendingData, pendingLength);
    if (numSendBytes != pendingLength) {
        return;
    }
    delete []pendingData;
    pendingLength = -1;
    pendingData = NULL;
    gelib::message::unregister(msgID);
}

gelib::GEHMessage GEHClient::readNextMessage() {
    uint8_t header[4];
    size_t length;
    this->socket.readBytes(header, 4);
    memcpy(&length, header, 4);

    uint8_t *body = new uint8_t[length];
    this->socket.readBytes(body, length);
    gelib::GEHMessage msg = this->parseReceivedMessage(body, length);
    delete []body;
    return msg;
}

gelib::GEHMessage GEHClient::parseReceivedMessage(const uint8_t *content, size_t length) {
    // Parse cipher
    gschub_Cipher cipher = gschub_Cipher_init_default;
    pb_istream_t stream = pb_istream_from_buffer(content, length);
    if (!pb_decode(&stream, gschub_Cipher_fields, &cipher)) {
        return gelib::GEHMessage{
            0,
            NULL
        };
    }

    uint32_t bufferSize = cipher.data.size;
    uint8_t buffer[gschub_Reply_size];
    if (cipher.IV.size > 0) {
        bufferSize = GEHSecurity::Instance->decrypt(
            cipher.IV.bytes,
            cipher.data.bytes,
            cipher.data.size,
            buffer
        );
    } else {
        memcpy(buffer, cipher.data.bytes, cipher.data.size);
    }

    // Parse message
    gschub_Reply reply = gschub_Reply_init_default;
    pb_istream_t istream = pb_istream_from_buffer(buffer, bufferSize);
    if (!pb_decode(&istream, gschub_Reply_fields, &reply)) {
        return gelib::GEHMessage{
            0,
            NULL
        };
    }

    // Validate message
    if (!this->validateMessage(
        reply.data.bytes,
        reply.data.size,
        reply.HMAC.bytes
    )) {
        return gelib::GEHMessage{
            0,
            NULL
        };
    }

    uint8_t *data = new uint8_t[reply.data.size];
    memcpy(data, reply.data.bytes, reply.data.size);
    return gelib::GEHMessage{
        reply.data.size,
        data
    };
}

bool GEHClient::validateMessage(const uint8_t *content, size_t length, const uint8_t *expectedHMAC) {
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

bool GEHClient::setupConfig() {
    String strConfig = this->readConfig();
    if (strConfig.length() == 0) {
        return false;
    }

    StaticJsonDocument<1024> config;
    deserializeJson(config, strConfig);
    this->baseURL = String(config["host"].as<char *>());
    strcpy(this->client.ID, config["id"].as<char *>());
    strcpy(this->client.token, config["token"].as<char *>());
    return true;
}

String GEHClient::readConfig() {
    if (SPIFFS.begin() == false) {
        return "";
    }

    File file = SPIFFS.open(FILE_CONFIG, FILE_READ);
    if(!file){
        return "";
    }
    auto content = file.readStringUntil('}');
    content += '}';
    file.close();
    return content;
}
