#include <GEHClient.h>
#include <GEHRegistration.h>
#include <GEHErrorDefine.h>
#include <GEHSecurity.h>
#include <GEHDefine.h>
#include <WiFi.h>
#include <SPIFFS.h>
#include <NBase64.h>
#include <base64.h>
#include <ArduinoJson.h>


#define PING_TIME 1000 // // Only ping every 1 second

#define VERSION "2.2.0"
#define FILE_CONFIG "/gsc-services.json"
#define URL_REGISTER "/conn/register"
#define URL_SECURITY "/public-key"


GEHClient *GEHClient::Shared = new GEHClient();

GEHClient* const GEHClient::Instance() {
    return GEHClient::Shared;
}

GEHClient::GEHClient() {
    this->listener = nullptr;
    this->isOpened = false;
    this->lastErrorID = GEH_ERROR_NONE;
    this->recvQueue = new GEHQueue(MAX_NUMBER_MESSAGE);
    this->writeQueue = new GEHQueue(MAX_NUMBER_MESSAGE);
}

GEHClient::~GEHClient() {
    delete this->recvQueue;
    delete this->writeQueue;
    if (this->listener != nullptr) {
        delete this->listener;
    }
}

void GEHClient::nextMessage() {
    vTaskDelay(100);
    if (this->listener == nullptr || this->recvQueue->isEmpty()) {
        return;
    }
    GEHMessage msg = this->recvQueue->pop();
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
        32 * 1024, // 32 Kb
        GEHClient::Shared,
        1,
        &this->loopActionTask,
        0
    );
    return true;
}

bool GEHClient::renameConnection(const char *aliasName) {
    if (this->isOnline() == false) {
        this->lastErrorID = GEH_ERROR_DISCONNECTED;
        return false;
    }

    // Get message's id
    uint16_t msgID = GEHRegistration::Instance->registerNextMessage();
    if (msgID == INVALID_MESSAGE_ID) {
        this->lastErrorID = GEH_ERROR_NOT_ENOUGH_QUEUE;
        return false;
    }

    // Build message
    GEHMessage msg = this->messageBuilder.buildRenameMessage(
        msgID,
        aliasName,
        clientTicket.connID,
        clientTicket.token
    );
    if (msg.content == nullptr) {
        this->lastErrorID = GEH_ERROR_NOT_ENOUGH_MEMORY;
        GEHRegistration::Instance->unregisterMessage(msgID);
        return false;
    }

    // Send message
    const size_t numSendBytes = this->socket.write(
        this->messageBuilder.getContent(msg),
        msg.length
    );
    delete []msg.content;
    GEHRegistration::Instance->unregisterMessage(msgID);

    if (numSendBytes != msg.length) {
        this->lastErrorID = GEH_ERROR_NOT_ENOUGH_MEMORY;
        return false;
    }

    this->lastErrorID = GEH_ERROR_NONE;
    strcpy(this->client.aliasName, aliasName);
    return true;
}

uint16_t GEHClient::writeMessage(const char *receiver, uint8_t *content, size_t length, bool isEncrypted) {
    if (this->isOnline() == false) {
        this->lastErrorID = GEH_ERROR_DISCONNECTED;
        return INVALID_MESSAGE_ID;
    }

    if (this->writeQueue->isFull()) {
        this->lastErrorID = GEH_ERROR_NOT_ENOUGH_QUEUE;
        return INVALID_MESSAGE_ID;
    }

    // Get message's id
    uint16_t msgID = GEHRegistration::Instance->registerNextMessage();
    if (msgID == INVALID_MESSAGE_ID) {
        this->lastErrorID = GEH_ERROR_NOT_ENOUGH_QUEUE;
        return INVALID_MESSAGE_ID;
    }

    GEHMessage msg = this->messageBuilder.buildMessage(
        msgID,
        gschub_Letter_Type_Single,
        receiver,
        content,
        length,
        isEncrypted
    );
    if (msg.content == nullptr) {
        this->lastErrorID = GEH_ERROR_NOT_ENOUGH_MEMORY;
        GEHRegistration::Instance->unregisterMessage(msgID);
        return INVALID_MESSAGE_ID;
    }

    // Push message to queue
    bool result = this->writeQueue->push(msg);
    if (result) {
        this->lastErrorID = GEH_ERROR_NONE;
        return msgID;
    }
    delete []msg.content;
    this->lastErrorID = GEH_ERROR_NOT_ENOUGH_QUEUE;
    GEHRegistration::Instance->unregisterMessage(msgID);
    return INVALID_MESSAGE_ID;
}

uint16_t GEHClient::writeMessage(const char *receiver, uint8_t *content, size_t length, uint16_t msgID, bool isEncrypted) {
    if (msgID >= 0 && GEHRegistration::Instance->isMessageRegistered(msgID)) {
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
        vTaskDelay(100);
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
        GEHMessage msg = instance->readNextMessage();
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

    // Connect and activate
    StaticJsonDocument<512> doc;
    auto err = deserializeJson(doc, body);
    if (err || doc.containsKey("data") == false || doc["returncode"].as<int>() < 1) {
        DEBUG_LOG("Register connection failed");
        DEBUG_LOG(doc["data"].as<char *>());
        return false;
    }
    std::string data = base64_decode(std::string(doc["data"].as<char *>()));
    gschub_Ticket ticket = this->messageBuilder.parseTicket((uint8_t *)data.c_str(), data.length());
    if (strlen(ticket.address) == 0 || this->connectSocket(ticket.address) == false) {
        return false;
    }
    return this->activateSocket(ticket.clientTicket);
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
    GEHMessage msg = this->messageBuilder.buildRegistrationMessage(this->client);
    if (msg.length == 0) {
        return false;
    }

    // Send request
    HTTPClient http;
    http.begin(this->baseURL + URL_REGISTER);
    http.addHeader("Version", VERSION);
    http.addHeader("Content-Type", "application/json");
    if (http.POST(base64::encode(msg.content, msg.length)) <= 0) {
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
        int socketPort = atoi(strtok (nullptr, ":"));
        return this->socket.connect(socketIP, socketPort) == 1;
    }
    catch(const std::exception& e) {
        return false;
    }
}

bool GEHClient::activateSocket(const gschub_ClientTicket &clientTicket) {
    if (this->isOnline() == false) {
        return false;
    }

    // Build message
    GEHMessage msg = this->messageBuilder.buildActivationMessage(clientTicket);

    // Activate socket
    const size_t numSendBytes = this->socket.write(
        this->messageBuilder.getContent(msg),
        msg.length
    );
    delete []msg.content;
    if (numSendBytes != msg.length) {
        return false;
    }
    strcpy(this->clientTicket.connID, clientTicket.connID);
    strcpy(this->clientTicket.token, clientTicket.token);
    return true;
}

bool GEHClient::ping() {
    if (this->isOnline() == false) {
        return false;
    }

    static volatile uint64_t lastTimePing = 0;
    uint64_t currentTime = millis();
    if (lastTimePing + PING_TIME > currentTime) {
        return true;
    }

    // Get message's id
    uint16_t msgID = GEHRegistration::Instance->registerNextMessage();
    if (msgID == INVALID_MESSAGE_ID) {
        return false;
    }

    // Build message
    const char *content = "Ping";
    GEHMessage msg = this->messageBuilder.buildMessage(
        msgID,
        gschub_Letter_Type_Ping,
        "",
        (uint8_t *)content,
        4,
        true
    );
    if (msg.content == nullptr) {
        GEHRegistration::Instance->unregisterMessage(msgID);
        return false;
    }

    // Ping
    const size_t numSendBytes = this->socket.write(
        this->messageBuilder.getContent(msg),
        msg.length
    );
    GEHRegistration::Instance->unregisterMessage(msgID);
    delete []msg.content;
    if (numSendBytes != msg.length) {
        lastTimePing = currentTime + PING_TIME;
        return false;
    }
    lastTimePing = currentTime;
    return true;
}

bool GEHClient::isOnline() {
    return this->isOpened && WiFi.status() == WL_CONNECTED;
}

void GEHClient::writeNextMessage() {
    static GEHMessage msg {0, nullptr};

    // Get next message
    if (msg.content == nullptr) {
        if (this->writeQueue->isEmpty()) {
            return;
        }
        msg = this->writeQueue->pop();
    }

    // Send message
    const size_t numSendBytes = this->socket.write(
        this->messageBuilder.getContent(msg),
        msg.length
    );
    if (numSendBytes != msg.length) {
        return;
    }

    // Clean
    GEHRegistration::Instance->unregisterMessage(this->messageBuilder.getMsgID(msg));
    delete []msg.content;
    msg.content = nullptr;
}

GEHMessage GEHClient::readNextMessage() {
    uint8_t header[4];
    size_t length;
    this->socket.readBytes(header, 4);
    memcpy(&length, header, 4);
    return this->messageBuilder.parseReceivedMessage(this->socket, length);
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
