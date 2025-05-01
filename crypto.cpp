#include <iostream>
#include <fstream>
#include <vector>
#include <chrono>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>

// Размер блока для Кузнечика (16 байт)
const size_t BLOCK_SIZE = 16;
// Размер ключа для Кузнечика (32 байта)
const size_t KEY_SIZE = 32;

void handle_openssl_error() {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

EVP_PKEY* generate_ecdh_key() {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (!pctx) handle_openssl_error();
    
    if (EVP_PKEY_keygen_init(pctx) <= 0) handle_openssl_error();
    
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string("group", (char*)"secp256k1", 0);
    params[1] = OSSL_PARAM_construct_end();
    
    if (EVP_PKEY_CTX_set_params(pctx, params) <= 0) handle_openssl_error();
    
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_generate(pctx, &pkey) <= 0) handle_openssl_error();
    
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

std::vector<unsigned char> derive_shared_secret(EVP_PKEY* priv_key, EVP_PKEY* peer_pub_key) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv_key, nullptr);
    if (!ctx) handle_openssl_error();
    
    if (EVP_PKEY_derive_init(ctx) <= 0) handle_openssl_error();
    if (EVP_PKEY_derive_set_peer(ctx, peer_pub_key) <= 0) handle_openssl_error();
    
    size_t secret_len = 0;
    if (EVP_PKEY_derive(ctx, nullptr, &secret_len) <= 0) handle_openssl_error();
    
    std::vector<unsigned char> secret(secret_len);
    if (EVP_PKEY_derive(ctx, secret.data(), &secret_len) <= 0) handle_openssl_error();
    
    EVP_PKEY_CTX_free(ctx);
    return secret;
}

std::vector<unsigned char> generate_iv() {
    std::vector<unsigned char> iv(BLOCK_SIZE);
    if (RAND_bytes(iv.data(), iv.size()) <= 0) {
        handle_openssl_error();
    }
    return iv;
}

std::vector<unsigned char> encrypt_kuznyechik_ctr(const std::vector<unsigned char>& plaintext,
                                               const std::vector<unsigned char>& key,
                                               std::vector<unsigned char>& iv,
                                               size_t& block_count) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handle_openssl_error();
    
    // Устанавливаем алгоритм Кузнечик (GOST R 34.12-2015) в режиме CTR
    EVP_CIPHER* cipher = EVP_CIPHER_fetch(nullptr, "kuznyechik-ctr", nullptr);
    if (!cipher) {
        EVP_CIPHER_CTX_free(ctx);
        handle_openssl_error();
    }
    
    if (EVP_EncryptInit_ex2(ctx, cipher, key.data(), iv.data(), nullptr) <= 0) {
        EVP_CIPHER_free(cipher);
        EVP_CIPHER_CTX_free(ctx);
        handle_openssl_error();
    }
    
    int ciphertext_len = plaintext.size() + EVP_CIPHER_get_block_size(cipher);
    std::vector<unsigned char> ciphertext(ciphertext_len);
    
    int len;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) <= 0) {
        EVP_CIPHER_free(cipher);
        EVP_CIPHER_CTX_free(ctx);
        handle_openssl_error();
    }
    ciphertext_len = len;
    
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) <= 0) {
        EVP_CIPHER_free(cipher);
        EVP_CIPHER_CTX_free(ctx);
        handle_openssl_error();
    }
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);
    
    block_count = (plaintext.size() + BLOCK_SIZE - 1) / BLOCK_SIZE;
    
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return ciphertext;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <input_file>\n";
        return EXIT_FAILURE;
    }
    
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_ADD_ALL_CIPHERS, nullptr);
    
    try {
        auto start = std::chrono::high_resolution_clock::now();
        
        std::cout << "Generating ECDH keys (secp256k1)...\n";
        EVP_PKEY* alice_key = generate_ecdh_key();
        EVP_PKEY* bob_key = generate_ecdh_key();
        
        std::cout << "Deriving shared secret...\n";
        std::vector<unsigned char> alice_secret = derive_shared_secret(alice_key, bob_key);
        std::vector<unsigned char> bob_secret = derive_shared_secret(bob_key, alice_key);
        
        if (alice_secret != bob_secret) {
            std::cerr << "Error: Shared secrets don't match!\n";
            return EXIT_FAILURE;
        }
        
        // Проверка и подготовка ключа
        if (alice_secret.size() < KEY_SIZE) {
            // Хешируем секрет, если он слишком короткий
            EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
            EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
            EVP_DigestUpdate(mdctx, alice_secret.data(), alice_secret.size());
            alice_secret.resize(KEY_SIZE);
            EVP_DigestFinal_ex(mdctx, alice_secret.data(), nullptr);
            EVP_MD_CTX_free(mdctx);
        } else if (alice_secret.size() > KEY_SIZE) {
            // Обрезаем, если слишком длинный
            alice_secret.resize(KEY_SIZE);
        }
        
        std::cout << "Reading input file...\n";
        std::ifstream file(argv[1], std::ios::binary);
        if (!file) {
            std::cerr << "Error opening file: " << argv[1] << "\n";
            return EXIT_FAILURE;
        }
        
        file.seekg(0, std::ios::end);
        size_t file_size = file.tellg();
        file.seekg(0, std::ios::beg);
        
        std::vector<unsigned char> file_data(file_size);
        file.read(reinterpret_cast<char*>(file_data.data()), file_size);
        file.close();
        
        std::vector<unsigned char> iv = generate_iv();
        
        std::cout << "Encrypting with Kuznyechik (GOST R 34.12-2015) in CTR mode...\n";
        size_t block_count = 0;
        auto encrypt_start = std::chrono::high_resolution_clock::now();
        std::vector<unsigned char> ciphertext = encrypt_kuznyechik_ctr(file_data, alice_secret, iv, block_count);
        auto encrypt_end = std::chrono::high_resolution_clock::now();
        
        auto end = std::chrono::high_resolution_clock::now();
        auto total_duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        auto encrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(encrypt_end - encrypt_start).count();
        
        std::cout << "\nResults:\n";
        std::cout << "========================================\n";
        std::cout << "File size:          " << file_size << " bytes\n";
        std::cout << "Blocks processed:   " << block_count << "\n";
        std::cout << "Total time:         " << total_duration << " ms\n";
        std::cout << "Encryption time:    " << encrypt_duration << " ms\n";
        std::cout << "Encryption speed:   " 
                  << (file_size / (encrypt_duration / 1000.0) / 1024 / 1024) 
                  << " MB/s\n";
        std::cout << "========================================\n";
        
        std::ofstream out_file("encrypted.bin", std::ios::binary);
        out_file.write(reinterpret_cast<char*>(iv.data()), iv.size());
        out_file.write(reinterpret_cast<char*>(ciphertext.data()), ciphertext.size());
        out_file.close();
        
        std::cout << "Encrypted data (with IV) saved to 'encrypted.bin'\n";
        
        EVP_PKEY_free(alice_key);
        EVP_PKEY_free(bob_key);
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}