#include "../../Include/CryptoAssymetric/RSA.h"

RSA::RSA( const size_t& keysize ) : CryptoAssymetric(keysize)
{
}

RSA::~RSA()
{
}

void RSA::Key_generation()
{
    try
    {
        std::cout << "KeySize: " << keysize << std::endl;
        params.GenerateRandomWithKeySize(rng, keysize);
    }
    catch(const CryptoPP::Exception& e)
    {
        std::cerr << e.what() << '\n';
    }

    try
    {
        // Init private key by pseudorandom: n, e, d;
        private_key.Initialize(
                                params.GetModulus(),
                                params.GetPublicExponent(),
                                params.GetPrivateExponent()
                             );

        std::cout << "BitCount: " << private_key.GetModulus().BitCount() << std::endl;
    }
    catch(const CryptoPP::Exception& e)
    {
        std::cerr << e.what() << '\n';
    }

    try
    {
        // Init public key by pseudorandom: n, e;
        public_key.Initialize(
                                params.GetModulus(),
                                params.GetPublicExponent()
                             );

                             std::cout << "Modulus: " << public_key.GetModulus() << std::endl;
    }
    catch(const CryptoPP::Exception& e)
    {
        std::cerr << e.what() << '\n';
    }
    
}

void RSA::LoadPublicKeyFromFile( const std::string& pubkey_filename )
{
    /*
    CryptoPP::ByteQueue queue;
    CryptoPP::FileSource file( pubkey_filename.c_str(), true );

    file.TransferTo( queue );
    queue.MessageEnd();

    public_key.Load(queue);
    */

   try
   {
        CryptoPP::ByteQueue queue;
        CryptoPP::FileSource file( pubkey_filename.c_str(), true );

        file.TransferTo( queue );
        queue.MessageEnd();

        public_key.Load(queue);
        std::cout << "PublLoadFromServer:" << public_key.GetModulus() << std::endl;

       //CryptoPP::FileSink in(pubkey_filename.c_str(), true);
       //public_key.BERDecode(in);
   }
   catch(const std::exception& e)
   {
       std::cerr << e.what() << '\n';
   }
   

}

void RSA::LoadPrivateKeyFromFile( const std::string& private_filename )
{
    /*
    CryptoPP::ByteQueue queue;
    CryptoPP::FileSource file( private_filename.c_str(), true );

    file.TransferTo( queue );
    queue.MessageEnd();

    private_key.Load(queue);
    */
   try
   {
        CryptoPP::ByteQueue queue;
        CryptoPP::FileSource file( private_filename.c_str(), true );

        file.TransferTo( queue );
        queue.MessageEnd();

        private_key.Load(queue);

       //CryptoPP::FileSink in(private_filename.c_str(), true);
       //private_key.BERDecode(in);
   }
   catch(const std::exception& e)
   {
       std::cerr << e.what() << '\n';
   }
}

void RSA::SavingPublicKeyToFile(const std::string& pubkey_string)
{
    try
    {
        /*
        CryptoPP::ByteQueue queue;

        public_key.Save(queue);

        CryptoPP::FileSink file(pubkey_string.c_str());

        queue.CopyTo(file);
        file.MessageEnd();
        */

       CryptoPP::FileSink out( pubkey_string.c_str() );
       public_key.DEREncode(out);

    }
    catch(const CryptoPP::Exception& e)
    {
        std::cerr << e.what() << '\n';
    }

}

void RSA::SavingPrivateKeyToFile(const std::string& private_string)
{
    try
    {
        /*
        CryptoPP::ByteQueue queue;

        private_key.Save(queue);

        CryptoPP::FileSink file(private_string.c_str());

        queue.CopyTo(file);
        file.MessageEnd();
        */
       CryptoPP::FileSink out( private_string.c_str() );
       private_key.DEREncode(out);

    }
    catch(const CryptoPP::Exception& e)
    {
        std::cerr << e.what() << '\n';
    }

}

void RSA::LoadPublicKeyFromString( const std::string& public_key_string )
{
    try
    {
        //public_key.Load( CryptoPP::StringSource( public_key_string, true ).Ref() );

        CryptoPP::StringSource ss(public_key_string, true, new CryptoPP::Base64Decoder);
        //CryptoPP::RSA::PublicKey npk;
        public_key.BERDecode(ss);

        std::cout << "NEW: " << public_key.GetModulus() << std::endl;

    }
    catch(const CryptoPP::Exception& e)
    {
        std::cerr << e.what() << '\n';
    }
    
}

void RSA::LoadPrivateKeyFromString( const std::string& private_key_string )
{
    try
    {
        //private_key.Load( CryptoPP::StringSource( private_key_string, true ).Ref() );
        CryptoPP::StringSource stringSource(private_key_string, true);
        private_key.BERDecode(stringSource);
    }
    catch(const CryptoPP::Exception& e)
    {
        std::cerr << e.what() << '\n';
    }

}

void RSA::SavingPublicKeyToString( std::string& public_key_string )
{
    try
    {
        /*
            std::cout << "Start:" << public_key.GetModulus() << std::endl;
            CryptoPP::StringSink ss(public_key_string);
            public_key.Save(ss);
            public_key.DEREncode(ss);
        */

        CryptoPP::Base64Encoder pkencode(new CryptoPP::StringSink(public_key_string));
        public_key.DEREncode(pkencode);
        pkencode.MessageEnd(); // needs to write up to the end

        std::cout << "SavingPublicKeyToString:" << public_key.GetModulus() << std::endl;

        //std::cout << "SavingPublicKeyToString: " << public_key_string << std::endl;

        
            //CryptoPP::StringSource ss(public_key_string, true, new CryptoPP::Base64Decoder);
            //CryptoPP::RSA::PublicKey npk;
            //npk.BERDecode(ss);

            //std::cout << "OLD: " << public_key.GetModulus() << std::endl;
            //std::cout << "NEW: " << npk.GetModulus() << std::endl;
        

    }
    catch(const CryptoPP::Exception& e)
    {
        std::cerr << e.what() << '\n';
    }
    
}

void RSA::SavingPrivateKeyToString( std::string& private_key_string )
{
    try
    {

        CryptoPP::Base64Encoder priv_encode(new CryptoPP::StringSink(private_key_string));
        private_key.DEREncode(priv_encode);
        priv_encode.MessageEnd(); // needs to write up to the end

        //private_key.Save( CryptoPP::StringSink(private_key_string).Ref() );
        //CryptoPP::StringSource stringSource(private_key_string, true);
        //private_key.DEREncode(stringSource);
        //private_key.DEREncode(stringSource);
    }
    catch(const CryptoPP::Exception& e)
    {
        std::cerr << e.what() << '\n';
    }

}

void RSA::Encrypt( const std::string& plaintext, std::string& ciphertext )
{
    try
    {

        CryptoPP::RSAES_OAEP_SHA_Encryptor e( public_key );
        CryptoPP::StringSource ss1( plaintext,
                                    true,
                                    new CryptoPP::PK_EncryptorFilter
                                        ( 
                                            rng, // random generator
                                            e, // open exponent
                                            new CryptoPP::HexEncoder
                                                (
                                                    new CryptoPP::StringSink(ciphertext)
                                                )
                                        )
                                  );
        std::cout << "BitCount: " << private_key.GetModulus().BitCount() << std::endl;

        std::cout << "Ciphertext: " << std::endl;
        std::cout << ciphertext << std::endl;
    }
    catch(const CryptoPP::Exception& e)
    {
        std::cerr << e.what() << '\n';
    }

}

void RSA::Encrypt( const std::vector<byte>& plaintext, std::string& ciphertext )
{
    try
    {
        CryptoPP::RSAES_OAEP_SHA_Encryptor e( public_key );
        CryptoPP::StringSource ss1( plaintext.data(),
                                    true,
                                    new CryptoPP::PK_EncryptorFilter
                                        ( 
                                            rng, // random generator
                                            e, // open exponent
                                            new CryptoPP::HexEncoder
                                                (
                                                    new CryptoPP::StringSink(ciphertext)
                                                )
                                        )
                                  );
        std::cout << "BitCount: " << private_key.GetModulus().BitCount() << std::endl;
    }
    catch(const CryptoPP::Exception& e)
    {
        std::cerr << e.what() << '\n';
    }

}

void RSA::Encrypt( const std::vector<byte>& plaintext, std::vector<byte>& ciphertext )
{
    try
    {
        
        CryptoPP::RSAES_OAEP_SHA_Encryptor e( public_key );
        CryptoPP::StringSource ss1( plaintext.data(),
                                    true,
                                    new CryptoPP::PK_EncryptorFilter
                                        ( 
                                            rng, // random generator
                                            e, // open exponent
                                            new CryptoPP::HexEncoder
                                                (
                                                    new CryptoPP::ArraySink(ciphertext.data(),
                                                                            plaintext.size())
                                                )
                                        )
                                  );

        /*
        // RSA Encryption CryptoSystem c = m^e ( mod n )
        CryptoPP::Integer m(
                                (const byte*)plaintext.data(),
                                plaintext.size()
                           );
        std::cout << "M: " << std::hex << m << std::endl;

        CryptoPP::Integer c(public_key.ApplyFunction(m));
        stream << std::hex << c;

        std::copy(stream.str().begin(), 
                  stream.str().end(), 
                  std::back_inserter(ciphertext)
                 );

        std::cout << "CipherText: " << std::hex << ciphertext.data() << std::endl;
        */
    }
    catch(const CryptoPP::Exception& e)
    {
        std::cerr << "Encrypt! " << e.what() << '\n';
    }

}

std::string RSA::Encrypt(const std::string& plaintext)
{
     try
    { 
        std::string ciphertext;

        CryptoPP::RSAES_OAEP_SHA_Encryptor e( public_key );
        CryptoPP::StringSource ss1
                                 (  plaintext.data(),
                                    true,
                                    new CryptoPP::PK_EncryptorFilter
                                    ( 
                                        rng, // random generator
                                        e, // open exponent
                                        new CryptoPP::HexEncoder
                                            (
                                                new CryptoPP::StringSink(ciphertext)
                                            )
                                    )
                                );
        return ( ciphertext );
        /*
        std::string ciphertext;

        // RSA Encryption CryptoSystem c = m^e ( mod n )
        CryptoPP::Integer m(
                                (const byte*)plaintext.data(),
                                plaintext.size()
                           );
        std::cout << "M: " << std::hex << m << std::endl;

        CryptoPP::Integer c(public_key.ApplyFunction(m));

        ciphertext.resize( c.MinEncodedSize() );

        c.Encode( (byte*)ciphertext.data(), 
                  ciphertext.size(),
                  CryptoPP::Integer::UNSIGNED 
                );

        stream << std::hex << c;

        ciphertext = stream.str();

        std::cout << std::hex << ciphertext << std::endl;

        return ( ciphertext );
        */
    }
    catch(const CryptoPP::Exception& e)
    {
        std::cerr << e.what() << '\n';
        return ("");
    }
}

void RSA::Decrypt( const std::string& ciphertext, std::string& plaintext )
{
    // RSA Decryption CryptoSystem m = loge(c) ( mod n )
    // d*e = 1 mod( (p-1)(q-1) ) => d = e^(-1) mod( (p-1)(q-1) ); (e,fi(n)) = 1;

    try
    {

        CryptoPP::RSAES_OAEP_SHA_Decryptor d( private_key );

        CryptoPP::StringSource ss2(
                                     ciphertext,
                                     true,
                                     new CryptoPP::PK_DecryptorFilter
                                                    (
                                                        rng,
                                                        d,
                                                        new CryptoPP::StringSink(plaintext)
                                                    )
                                  );

        std::cout << "Plaintext: " << std::endl;
        std::cout << plaintext << std::endl;

    }
    catch(const CryptoPP::Exception& e)
    {
        std::cerr << e.what() << '\n';
    }
}

void RSA::Decrypt( const std::vector<byte>& ciphertext, std::vector<byte>& plaintext )
{
    // RSA Decryption CryptoSystem m = loge(c) ( mod n )
    // d*e = 1 mod( (p-1)(q-1) ) => d = e^(-1) mod( (p-1)(q-1) ); (e,fi(n)) = 1;

    try
    {
        CryptoPP::RSAES_OAEP_SHA_Decryptor d( private_key );
        CryptoPP::StringSource ss2( ciphertext.data(),
                                    ciphertext.size(),
                                    true,
                                    new CryptoPP::HexDecoder
                                        (
                                            new CryptoPP::PK_DecryptorFilter
                                            ( 
                                                rng, // random generator
                                                d, // closed exponent
                                                new CryptoPP::ArraySink(plaintext.data(),
                                                                        ciphertext.size())
                                                )
                                        )
                                  );
    }
    catch(const CryptoPP::Exception& e)
    {
        std::cerr << e.what() << '\n';
    }
    
}

std::string RSA::Decrypt( const std::string& ciphertext )
{
    try
    {
        std::string plaintext;

        CryptoPP::RSAES_OAEP_SHA_Decryptor d( private_key );

        CryptoPP::StringSource ss2( ciphertext,
                                    true,
                                    new CryptoPP::HexDecoder
                                        (
                                            new CryptoPP::PK_DecryptorFilter
                                                ( 
                                                    rng, // random generator
                                                    d, // closed exponent
                                                    new CryptoPP::StringSink(plaintext)
                                                )
                                        )
                                  );
        std::cout << "Decrypt: " << plaintext << std::endl;

        return ( plaintext );
    }
    catch(const CryptoPP::Exception& e)
    {
        std::cerr << e.what() << '\n';
        return ("Wrong CryptoMaterials\n");
    }
}

//void RSA::Sign( const std::string& message, std::vector< byte >& signature )
void RSA::Sign( const std::vector<byte>& message, std::vector< byte >& signature )
{
    CryptoPP::RSASSA_PKCS1v15_SHA_Signer signer( private_key );

    size_t length = signer.MaxSignatureLength();
    signature.resize(length);

    try
    {
        length = signer.SignMessage( rng, 
                                 (const byte*)message.data(),
                                 //message.length(),
                                 message.size(), 
                                 signature.data() );

        signature.resize(length);
    }
    catch(const CryptoPP::Exception& e)
    {
        std::cerr << e.what() << '\n';
    }

}

std::string RSA::Sign ( const std::string& message )
{
    CryptoPP::RSASSA_PKCS1v15_SHA_Signer signer( private_key );

    std::string signature;
    size_t length = signer.MaxSignatureLength();
    signature.resize(length);

    try
    {
        length = signer.SignMessage( rng, 
                                 ( const byte* )message.data(),
                                 //message.length(),
                                 message.size(), 
                                 ( byte* )signature.data() );

        signature.resize(length);

        return ( signature );
    }
    catch(const CryptoPP::Exception& e)
    {
        std::cerr << e.what() << '\n';
        return ("Wrong CryptoMaterials\n");
    }
}


void RSA::Sign( const std::string& message, std::string& signature )
{
    CryptoPP::RSASSA_PKCS1v15_SHA_Signer signer( private_key );

    size_t length = signer.MaxSignatureLength();
    signature.resize(length);

    try
    {
        length = signer.SignMessage( rng, 
                                 ( const byte* )message.c_str(),
                                 message.length(), 
                                 ( byte* )signature.data() );

        signature.resize(length);
    }
    catch(const CryptoPP::Exception& e)
    {
        std::cerr << e.what() << '\n';
    }

}

std::vector<byte> RSA::Sign ( const std::vector<byte>& message )
{
    CryptoPP::RSASSA_PKCS1v15_SHA_Signer signer( private_key );

    std::vector<byte> signature;
    size_t length = signer.MaxSignatureLength();
    signature.resize(length);

    try
    {
        length = signer.SignMessage( rng, 
                                 ( const byte* )message.data(),
                                 //message.length(),
                                 message.size(), 
                                 ( byte* )signature.data() );

        signature.resize(length);

        return ( signature );
    }
    catch(const CryptoPP::Exception& e)
    {
        std::cerr << e.what() << '\n';
        return ( signature );
    }
}


//bool RSA::Verify( const std::string& message, std::vector< byte >& signature)

std::vector< byte > RSA::Verify( const std::vector< byte >& signature)//, 
                  //const std::vector< byte >& signature )
{
    try
    {
        //CryptoPP::RSASSA_PKCS1v15_SHA_Verifier verifier(public_key);
        CryptoPP::RSASS<CryptoPP::PSSR, CryptoPP::SHA256>::Verifier verifier( public_key );

        //std::cout << "Signature: " << signature.size() << ":" << signature.data() << std::endl;

        std::vector< byte > result;
        result.resize(signature.size());

        CryptoPP::DecodingResult r = verifier.RecoverMessage
                                                    (
                                                        result.data(),
                                                        NULL,
                                                        0,
                                                        (const byte*)signature.data(),
                                                        signature.size()
                                                    );


        /*
        bool result =  verifier.VerifyMessage( (const byte*)message.data(),
                                                message.size(),
                                                signature.data(),
                                                signature.size() );
        */

       /*
        CryptoPP::StringSource ss2
                    (
                        signature.data(),
                        true,
                        new CryptoPP::SignatureVerificationFilter
                                            (
                                                verifier,
                                                new CryptoPP::ArraySink(result.data(),
                                                                         signature.size())
                                            )
                        
                    );
        */
        std::cout << "Result: " << result.size() << ":" << result.data() << std::endl;
        std::cout << "isValidCoding: " << r.isValidCoding << r.messageLength << std::endl;
        return ( result );

    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        //return 0;
    }

}

std::string RSA::Verify( const std::string& signature)//, 
                  //const std::vector< byte >& signature )
{
    try
    {
        //CryptoPP::RSASSA_PKCS1v15_SHA_Verifier verifier(public_key);
        CryptoPP::RSASS<CryptoPP::PSSR, CryptoPP::SHA256>::Verifier verifier( public_key );

        //std::cout << "Signature: " << signature.size() << ":" << signature.data() << std::endl;

        std::string result;
        result.resize(signature.size());

        CryptoPP::DecodingResult r = verifier.RecoverMessage
                                                    (
                                                        (byte*)result.data(),
                                                        NULL,
                                                        0,
                                                        (const byte*)signature.data(),
                                                        signature.size()
                                                    );


        /*
        bool result =  verifier.VerifyMessage( (const byte*)message.data(),
                                                message.size(),
                                                signature.data(),
                                                signature.size() );
        */

       /*
        CryptoPP::StringSource ss2
                    (
                        signature.data(),
                        true,
                        new CryptoPP::SignatureVerificationFilter
                                            (
                                                verifier,
                                                new CryptoPP::ArraySink(result.data(),
                                                                         signature.size())
                                            )
                        
                    );
        */
        std::cout << "Result: " << result.size() << ":" << result.data() << std::endl;
        std::cout << "isValidCoding: " << r.isValidCoding << ":" << r.messageLength << std::endl;
        return ( result );

    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        //return 0;
    }

}



bool RSA::Verify( const std::string& message, 
                  const std::string& signature )
{
    try
    {
        CryptoPP::RSASSA_PKCS1v15_SHA_Verifier verifier(public_key);

        bool result =  verifier.VerifyMessage( ( const byte* ) message.data(),
                                                message.size(),
                                                ( const byte* ) signature.data(),
                                                signature.size() );

        return ( result );

    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';

        return 0;
    }

    
}
