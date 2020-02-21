#ifndef _SEND_CLIENT
#define _SEND_CLIENT

#include "SendSocket.h"

class SendClient : SendSocket
{
private:
    
public:
    SendClient( const std::string s_addr_,
                const short port_);
    ~SendClient();

    virtual void CreateSocket() override;
    virtual void InitSocket() override;
    virtual void Connect() override;
    virtual void Authentification() override;

};

#endif