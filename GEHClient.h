#ifndef GEHCLIENT_H_
#define GEHCLIENT_H_

#include <GEHQueue.h>
#include <GEHListener.h>
#include <GEHBuilder.h>

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
    GEHBuilder messageBuilder;

    GEHClient();
    bool connect();
    bool setupSecurity();
    bool registerConnection(char *buffer);
    bool activateSocket(const gschub_ClientTicket &ticket);
    bool connectSocket(const char *host);

    bool ping();
    bool isOnline();
    void writeNextMessage();
    GEHMessage readNextMessage();
    bool isConfigReady();
    bool setupConfig();
    String readConfig();
public:
    static GEHClient* const Instance();
    ~GEHClient();

    void setup(const char *baseURL, const char *id, const char *token);
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
