#include "../../Include/SendSocket/SendClient.h"

#include "../../Include/CryptoAssymetric/CryptoAssymetric.h"
#include "../../Include/CryptoAssymetric/RSA.h"

#include "../../Include/CryptoHash/HashAbstract.h"

#include "../../Include/CryptoSymmetric/CryptoSymmetric.h"
#include "../../Include/CryptoSymmetric/AesModeCBC.h"


SendClient::SendClient( const std::string s_addr_,
                        const short port_ )
                      : SendSocket(s_addr_, port_)
{
}

SendClient::~SendClient()
{
}

void SendClient::CreateSocket()
{
    try
    {
        socketfd = socket( AF_INET, SOCK_STREAM, 0 );
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }
    
}

void SendClient::InitSocket()
{
    try
    {
        bzero( &sockaddr, sizeof(sockaddr) );
        sockaddr.sin_family = AF_INET;
        sockaddr.sin_port = htons(port);
        sockaddr.sin_addr.s_addr = inet_addr( s_addr.c_str() );
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }
    
}

void SendClient::Connect()
{
    try
    {
        int check = 0;
        if( ( check = connect( socketfd, 
                               (struct sockaddr*)&sockaddr, 
                               sizeof(sockaddr) 
                             ) 
            ) < 0
          )
          throw std::runtime_error(" Connect() Error \n");
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }
    
}

void SendClient::Authentification()
{
    RSA Bob(2048);
    Bob.LoadPublicKeyFromFile("/root/Documents/VSCode/Authentication/server_pubkey.dat");
    
    RSA Alice(3072);
    Alice.Key_generation();

    std::string Alice_login; // Alice_login ciphertext is encoded in Hex
    Bob.Encrypt("Alice", Alice_login);

    /*
    std::cout << "Alice Login: " ;
    std::cout << Alice_login.data() << std::endl;
    std::cout << "->" << Alice_login.size() << std::endl;
    */
    int n = 0;

    n = write(socketfd, Alice_login.data(), Alice_login.size() );
        std::cout << n << std::endl;

    std::string Alice_public_key; // Key is encoded in Base64
    Alice.SavingPublicKeyToString(Alice_public_key);

    std::cout << "Alice_public_key: ";
    std::cout << Alice_public_key << std::endl;

    sleep(1);

    n = write( socketfd, Alice_public_key.data(), Alice_public_key.size() );
        std::cout << "Alice_public_key send: " << n << std::endl;

    sleep(1);

    //std::vector<byte> recv_message;
    std::string recv_message;
    std::vector<byte> AES_KEY;
    recv_message.resize(768);
    n = read ( socketfd, &recv_message[0], 768 );

    std::cout << "Recv_message AES_KEY: " << recv_message.data() << std::endl;

    std::cout << "Key: ";
    std::cout << Bob.Verify( Alice.Decrypt(recv_message) ).data();
    std::cout << std::endl;
    //Alice.Encrypt(Bob.Verify(recv_message), AES_KEY );

    std::cout << "AES_KEY: " << AES_KEY.size() << std::endl;

}