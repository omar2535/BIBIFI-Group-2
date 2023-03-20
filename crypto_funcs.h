#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <iostream>

#define RSA_KEY_LEN 4096
#define PLAINTEXT_MAX_LEN RSA_KEY_LEN / 8 - 42

std::string priv_key_loc = "filesystem/metadata/private_keys/";
std::string pub_key_loc = "filesystem/metadata/public_keys/";

void create_keys(std::string username)
{
    RSA *rsa = RSA_generate_key(RSA_KEY_LEN, RSA_F4, NULL, NULL);
    if (!rsa) {
        std::cerr << "Failed to generate RSA key" << std::endl;
        exit(1);
    }

    // To write private key to PEM file
    BIO *pri = BIO_new_file((priv_key_loc + username + "_priv").c_str(), "w");
    if (!pri) {
        std::cerr << "Failed to open private key file" << std::endl;
        RSA_free(rsa);
        exit(1);
    }
    PEM_write_bio_RSAPrivateKey(pri, rsa, NULL, NULL, 0, NULL, NULL);
    BIO_free(pri);

    // To write public key to PEM file
    BIO *pub = BIO_new_file((pub_key_loc + username + "_pub").c_str(), "w");
    if (!pub) {
        std::cerr << "Failed to open public key file" << std::endl;
        RSA_free(rsa);
        exit(1);
    }
    PEM_write_bio_RSAPublicKey(pub, rsa);
    
    BIO_free(pub);
    RSA_free(rsa);
}

std::string encrypt(std::string plaintext, std::string username)
{
    // Throw exceptions when the encryption is failed.
    // Get public key 
    BIO *pub = BIO_new_file((pub_key_loc + username + "_pub").c_str(), "r");
    
    if (!pub) {
        BIO_free(pub);
        throw std::runtime_error("Failed to open public key file.");
    }
    RSA *pb_rsa = PEM_read_bio_RSAPublicKey(pub, NULL, NULL, NULL);
    if (!pb_rsa) {
        throw std::runtime_error("The public key is not valid.");
    }
    BIO_free(pub);

    // Check plaintext
    if (plaintext.length() == 0 || plaintext.length() > PLAINTEXT_MAX_LEN) {
        throw std::invalid_argument("The plaintext is invalid.");
    }

    // Encrypt
    unsigned char* plaintext_char = reinterpret_cast<unsigned char*>(&plaintext[0]);
    unsigned char* ciphertext_char = new unsigned char[RSA_KEY_LEN / 8];
    if ( -1 == RSA_public_encrypt(plaintext.length(), plaintext_char, ciphertext_char, pb_rsa, RSA_PKCS1_OAEP_PADDING)) {
        throw std::runtime_error("Encryption failed.");
    } else {
        return std::string (reinterpret_cast<char*>(ciphertext_char), RSA_size(pb_rsa));
    }
}

std::string decrypt(std::string ciphertext, std::string keypath)
{
    // Throw exceptions when the decryption is failed.
    if (ciphertext.length() == 0) {
        throw std::invalid_argument("The ciphertext is empty.");
    }
    // Get privat key
    // BIO *pri = BIO_new_file((priv_key_loc + keypath).c_str(), "r");
    BIO *pri = BIO_new_file(keypath.c_str(), "r");
    if (!pri) {
        BIO_free(pri);
        throw std::runtime_error("Failed to open private key file.");
    }
    RSA *pri_rsa = PEM_read_bio_RSAPrivateKey(pri, NULL, NULL, NULL);
    if (!pri_rsa) {
        throw std::runtime_error("The private key is not valid.");
    }
    BIO_free(pri);
    
    // Decrypt
    unsigned char* ciphertext_char = reinterpret_cast<unsigned char*>(&ciphertext[0]);
    unsigned char* plaintext_char  = new unsigned char[PLAINTEXT_MAX_LEN];
    int plaintext_length = RSA_private_decrypt(RSA_size(pri_rsa), ciphertext_char, plaintext_char, pri_rsa, RSA_PKCS1_OAEP_PADDING);
    if (-1 == plaintext_length) {
        throw std::runtime_error("Decryption failed.");
    } else {
        // Return
        return std::string (reinterpret_cast<char*>(plaintext_char), plaintext_length);
    }
}

std::string decryptByMetadataPrivateKey(std::string ciphertext, std::string username)
{
    // Throw exceptions when the decryption is failed.
    if (ciphertext.length() == 0) {
        throw std::invalid_argument("The ciphertext is empty.");
    }
    // Get privat key
    BIO *pri = BIO_new_file((priv_key_loc + username + "_priv").c_str(), "r");
    // BIO *pri = BIO_new_file(keypath.c_str(), "r");
    if (!pri) {
        BIO_free(pri);
        throw std::runtime_error("Failed to open private key file.");
    }
    RSA *pri_rsa = PEM_read_bio_RSAPrivateKey(pri, NULL, NULL, NULL);
    if (!pri_rsa) {
        throw std::runtime_error("The private key is not valid.");
    }
    BIO_free(pri);
    
    // Decrypt
    unsigned char* ciphertext_char = reinterpret_cast<unsigned char*>(&ciphertext[0]);
    unsigned char* plaintext_char  = new unsigned char[2048];
    int plaintext_length = RSA_private_decrypt(RSA_size(pri_rsa), ciphertext_char, plaintext_char, pri_rsa, RSA_PKCS1_OAEP_PADDING);
    if (-1 == plaintext_length) {
        throw std::runtime_error("Decryption failed.");
    } else {
        // Return
        return std::string (reinterpret_cast<char*>(plaintext_char), plaintext_length);
    }
}

/*
Encrypt plaintext and convert it to base64
*/
std::string encrypt_b64(std::string plaintext, std::string username)
{
    // encrypt and base64 encode
    std::string ciphertext = encrypt(plaintext, username);
    const auto b64_code_pre_len = 4 * ((ciphertext.length() + 2) / 3);
    unsigned char* ciphertext_char = reinterpret_cast<unsigned char*>(&ciphertext[0]);
    unsigned char* b64_code_char = reinterpret_cast<unsigned char *>(calloc(b64_code_pre_len+1, 1));
    const auto b64_code_len = EVP_EncodeBlock(b64_code_char, ciphertext_char, ciphertext.length());
    if (b64_code_pre_len != b64_code_len) {
        std::cerr << "Whoops, encode predicted " << b64_code_pre_len << " but we got " << b64_code_len << "\n"; 
        throw std::runtime_error("Base64 Encode failed.");
    }
    std::string b64_code_str(reinterpret_cast<char*>(b64_code_char), b64_code_len);
    std::replace(b64_code_str.begin(), b64_code_str.end(), '/', '_'); // replace all '/' with '_', avoid confusion in path string
    return b64_code_str;
}

