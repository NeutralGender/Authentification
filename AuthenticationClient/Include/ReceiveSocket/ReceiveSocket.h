#ifndef _RECEIVESOCKET
#define _RECEIVESOCKET

#include <iostream>
#include <exception>
#include <string.h>
#include <vector>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

class ReceiveSocket
{
protected:
    int socketfd;
    int clientfd;
    const short port;
    const std::string s_addr;
    struct sockaddr_in sockaddr;
    std::vector<int> clients;       // vector for client`s socketd
public:
    ReceiveSocket( const std::string s_addr_, 
                   const short port );
    ~ReceiveSocket();

    virtual void CreateSocket() = 0;
    virtual void InitSocket() = 0;
    virtual void BindSocket() = 0;
    virtual void ListenSocket() = 0;
    virtual void SelectSocket() = 0;

    friend class SendSocket;

};


#endif