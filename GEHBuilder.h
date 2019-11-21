#ifndef GEHBUILDER_H
#define GEHBUILDER_H

#include <GEHMessage.h>
#include <gehub_message.pb.h>
#include <WiFi.h>
#include <HTTPClient.h>

#define MAX_MESSAGE_SIZE 16384 // 16kb
#define BUFFER_SIZE 32768 // 32kb

class GEHBuilder {
private:
    gschub_Reply reply;
    gschub_Ticket ticket;
    gschub_Letter letter;
    gschub_Cipher cipher;
    uint8_t secretKey[36];
    uint8_t buffer[BUFFER_SIZE];

    GEHMessage formatMessage(uint16_t msgID, const uint8_t *content, uint32_t length);
    bool validateMessage(const uint8_t *content, uint32_t length, const uint8_t *expectedHMAC);

public:
    uint16_t getMsgID(const GEHMessage &msg);
    uint8_t *getContent(const GEHMessage &msg);
    GEHMessage buildRegistrationMessage(const gschub_Client &client);
    GEHMessage buildActivationMessage(const gschub_ClientTicket &clientTicket);
    GEHMessage buildRenameMessage(uint16_t msgID, const char* aliasName, const char *connID, const char *connToken);
    GEHMessage buildMessage(uint16_t msgID, gschub_Letter_Type type, const char *receiver, uint8_t *content, uint32_t length, bool isEncrypted);
    gschub_Ticket parseTicket(const uint8_t *data, uint32_t length);
    GEHMessage parseReceivedMessage(WiFiClient &socket, uint32_t length);
};

#endif
