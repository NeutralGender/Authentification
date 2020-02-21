#include "../../Include/ReceiveSocket/ReceiveClient.h"

ReceiveClient::ReceiveClient(const std::string s_addr_, 
                             const short port_)
                            : ReceiveSocket( s_addr_, port_ )
{

}

ReceiveClient::~ReceiveClient()
{
    close(socketfd);
}

void ReceiveClient::CreateSocket()
{
    try
    {
        // CREATE TCP SOCKET FOR CONNECTION
        socketfd = socket( AF_INET, SOCK_STREAM, 0 );
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << " : " << errno << '\n';
    }

}

void ReceiveClient::InitSocket()
{
    try
    {
        bzero(&sockaddr, sizeof(sockaddr));
        sockaddr.sin_family = AF_INET;
        sockaddr.sin_port = htons(port);
        sockaddr.sin_addr.s_addr = inet_addr( s_addr.c_str() );

    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << " : " << errno << '\n';
    }
    
}

void ReceiveClient::BindSocket()
{
    try
    {
        int check = 0;
        if ( (check = bind( socketfd, (struct sockaddr*)&sockaddr, sizeof(sockaddr) ) < 0) )
            throw std::runtime_error(" BindSocket() Error \n ");
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << " : " << errno << '\n';
    }
    
}

void ReceiveClient::ListenSocket()
{
    try
    {
        int check = 0;
        if ( (listen( socketfd, 10 )) < 0 )
            throw std::runtime_error(" ListenSocket() Error \n ");
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << " : " << errno << '\n';
    }
    
}

void ReceiveClient::SelectSocket()
{
    try
    {
        char buf[50] = "I am Server";
        while(1)
        {
            clientfd - accept( socketfd, NULL, NULL );
            write( clientfd, buf, sizeof(buf) );

            close(clientfd);

        }
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << " : " << errno << '\n';
    }
    
}