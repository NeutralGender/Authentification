#include "../../Include/ReceiveSocket/ReceiveSocket.h"

ReceiveSocket::ReceiveSocket( const std::string s_addr_, 
                              const short port_ )
                            : port( port_ ),
                              s_addr( s_addr_ )
{
}

ReceiveSocket::~ReceiveSocket()
{
}