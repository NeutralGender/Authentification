#ifndef _RECEIVE_CLIENT
#define _RECEIVE_CLIENT

#include "ReceiveSocket.h"

class ReceiveClient : public ReceiveSocket
{
private:
    //int socketfd;
public:
    ReceiveClient( const std::string s_addr_, 
                   const short port_);
    ~ReceiveClient();

    virtual void CreateSocket() override;
    virtual void InitSocket() override;
    virtual void BindSocket() override;
    virtual void ListenSocket() override;
    virtual void SelectSocket() override;

};

#endif