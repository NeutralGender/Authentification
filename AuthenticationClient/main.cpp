#include <iostream>

#include "Include/CryptoSymmetric/AesModeCBC.h"
#include "Include/CryptoAssymetric/RSA.h"
#include "Include/CryptoHash/HashSHA3_256.h"

#include "Include/SendSocket/SendClient.h"

#include "crypto++/aes.h"

int main()
{
    /*
    {
        std::string plaintext = "CBC Mode Test";
        std::string encoded = "";
        std::vector<byte> key;
        std::vector<byte> iv;

    
        AesModeCBC aes_cbc(AES::DEFAULT_KEYLENGTH, AES::BLOCKSIZE);
    
        aes_cbc.SetKeyIVLength(key,iv);
        aes_cbc.GenerateKey(key);
        aes_cbc.SetIV(iv);
        aes_cbc.Encrypt(key, iv, plaintext, encoded);
        aes_cbc.Decrypt(key, iv, encoded, plaintext);

        std::cout << "Plaintext:" << plaintext << std::endl;
    }
    */

    /*
    {
        std::string plaintext = "Login";
        std::string encoded = "";
        std::string saving = "saving.txt";
        std::string stest = "";
        std::string sstest = "";
        std::string signature;

        RSA rsa(2048);
        rsa.Key_generation();
        rsa.Encrypt(plaintext, encoded);
        rsa.Decrypt(encoded, plaintext);

        rsa.Sign(plaintext, signature);
        std::cout << "Verify Result: " << rsa.Verify(plaintext, signature) << std::endl;

        //rsa.SavingPublicKeyToFile(saving);
        //rsa.LoadPublicKeyFromFile(saving);

        //rsa.SavingPublicKeyToString(stest);
        //rsa.LoadPublicKeyFromString(stest);
    }
    */
    
    SendClient sc("127.0.0.1", 8000);
    sc.CreateSocket();
    sc.InitSocket();
    sc.Connect();
    sc.Authentification();

    /*
    {
        std::string message = "Yoda said, Do or do not. There is no try.";
        std::string digest = "";

        HashSHA3 sha3;
        sha3.AddDataToSHA3object(message);
        sha3.SetDigestStringSHAsize(digest);
        sha3.CalculateDigest(digest);
        
        std::cout << "Verify Result: " << sha3.Verify(message, digest) << std::endl;
    }
    */
    

    return 0;
}