#ifndef GEHCLIENT_H_
#define GEHCLIENT_H_

#include "GEHImport.h"
#include "GEHQueue.h"
#include "GEHListener.h"
#include <gehub_message.pb.h>

#define configTOTAL_HEAP_SIZE  ( 180 * 1024 )

class GEHClient {
private:
    static GEHClient *Shared;
    static void loopAction(void *param); // task loop

    TaskHandle_t loopActionTask;
    WiFiClient socket;

    bool isOpened;
    uint8_t lastErrorID;
    String baseURL;

    GEHQueue *recvQueue;
    GEHQueue *writeQueue;
    GEHListener *listener;
    gschub_Client client;
    gschub_ClientTicket clientTicket;
    uint8_t secretKey[36];

    GEHClient();
    bool connect();
    bool setupSecurity();
    bool registerConnection(char *buffer);
    bool activateSocket(const gschub_Ticket &ticket);
    bool connectSocket(const char *host);

    bool ping();
    void writeNextMessage();
    gelib::GEHMessage readNextMessage();
    gelib::GEHMessage parseReceivedMessage(const uint8_t *content, size_t length);
    bool validateMessage(const uint8_t *content, size_t length, const uint8_t *expectedHMAC);
    bool setupConfig();
    String readConfig();
public:
    static GEHClient* const Instance();
    ~GEHClient();

    uint8_t getLastError();
    void setListener(GEHListener *listener);
    bool open(const char *aliasName);
    bool renameConnection(const char *aliasName);
    uint16_t writeMessage(const char *receiver, uint8_t *content, size_t length, bool isEncrypted);
    uint16_t writeMessage(const char *receiver, uint8_t *content, size_t length, uint16_t msgID, bool isEncrypted);

    // Invoke this method in main loop
    void nextMessage();
};

#endif // GEHCLIENT_H_
