#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#define HANDLE_ERROR(msg) do { perror(msg); exit(EXIT_FAILURE); } while(0)

// PKCS7 填充（AES块大小16字节）
int pkcs7_pad(unsigned char *data, int data_len, int block_size, unsigned char **padded_data) 
{
    int pad_len = block_size - (data_len % block_size);
    *padded_data = (unsigned char *)malloc(data_len + pad_len);
    if (!*padded_data) return -1;

    memcpy(*padded_data, data, data_len);
    // 填充值为填充的长度（PKCS7标准）
    memset(*padded_data + data_len, pad_len, pad_len);
    return data_len + pad_len;
}

// PKCS7 去填充
int pkcs7_unpad(unsigned char *padded_data, int padded_len, unsigned char **unpadded_data) 
{
    if (padded_len % 16 != 0) return -1; // 不是16的倍数，无效数据

    int pad_len = padded_data[padded_len - 1];
    if (pad_len < 1 || pad_len > 16) return -1; // 填充值非法

    // 验证填充值
    for (int i = 0; i < pad_len; i++) {
        if (padded_data[padded_len - 1 - i] != pad_len) {
            return -1;
        }
    }

    *unpadded_data = (unsigned char *)malloc(padded_len - pad_len);
    if (!*unpadded_data) return -1;

    memcpy(*unpadded_data, padded_data, padded_len - pad_len);
    return padded_len - pad_len;
}

/**
 * AES-CBC 加密
 * @param plaintext 明文
 * @param plaintext_len 明文长度
 * @param key 密钥（16/24/32字节对应128/192/256位）
 * @param iv 初始化向量（必须16字节）
 * @param ciphertext 输出密文（需外部释放）
 * @return 密文长度，失败返回-1
 */
int aes_cbc_encrypt(const unsigned char *plaintext, int plaintext_len,
                    const unsigned char *key, const unsigned char *iv,
                    unsigned char **ciphertext) 
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) HANDLE_ERROR("EVP_CIPHER_CTX_new failed");

    int len, ciphertext_len;
    unsigned char *padded_plaintext = NULL;
    int padded_len = pkcs7_pad((unsigned char *)plaintext, plaintext_len, 16, &padded_plaintext);
    if (padded_len < 0) {
        EVP_CIPHER_CTX_free(ctx);
        HANDLE_ERROR("pkcs7_pad failed");
    }

    // 根据密钥长度选择AES模式
    const EVP_CIPHER *cipher = NULL;
    int key_len = strlen((char *)key);
    if (key_len == 16) cipher = EVP_aes_128_cbc();
    else if (key_len == 24) cipher = EVP_aes_192_cbc();
    else if (key_len == 32) cipher = EVP_aes_256_cbc();
    else {
        EVP_CIPHER_CTX_free(ctx);
        free(padded_plaintext);
        HANDLE_ERROR("key length must be 16/24/32 bytes");
    }

    // 初始化加密上下文
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(padded_plaintext);
        HANDLE_ERROR("EVP_EncryptInit_ex failed");
    }

    // 分配密文内存（填充后长度=明文填充长度）
    *ciphertext = (unsigned char *)malloc(padded_len);
    if (!*ciphertext) {
        EVP_CIPHER_CTX_free(ctx);
        free(padded_plaintext);
        HANDLE_ERROR("malloc ciphertext failed");
    }

    // 执行加密
    if (EVP_EncryptUpdate(ctx, *ciphertext, &len, padded_plaintext, padded_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(padded_plaintext);
        free(*ciphertext);
        HANDLE_ERROR("EVP_EncryptUpdate failed");
    }
    ciphertext_len = len;

    // 完成加密（处理最后一块）
    if (EVP_EncryptFinal_ex(ctx, *ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(padded_plaintext);
        free(*ciphertext);
        HANDLE_ERROR("EVP_EncryptFinal_ex failed");
    }
    ciphertext_len += len;

    // 释放资源
    EVP_CIPHER_CTX_free(ctx);
    free(padded_plaintext);

    return ciphertext_len;
}

/**
 * AES-CBC 解密
 * @param ciphertext 密文
 * @param ciphertext_len 密文长度
 * @param key 密钥（16/24/32字节）
 * @param iv 初始化向量（16字节）
 * @param plaintext 输出明文（需外部释放）
 * @return 明文长度，失败返回-1
 */
int aes_cbc_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                    const unsigned char *key, const unsigned char *iv,
                    unsigned char **plaintext) 
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) HANDLE_ERROR("EVP_CIPHER_CTX_new failed");

    int len, plaintext_len;
    unsigned char *decrypted_data = (unsigned char *)malloc(ciphertext_len);
    if (!decrypted_data) {
        EVP_CIPHER_CTX_free(ctx);
        HANDLE_ERROR("malloc decrypted_data failed");
    }

    // 选择AES模式
    const EVP_CIPHER *cipher = NULL;
    int key_len = strlen((char *)key);
    if (key_len == 16) cipher = EVP_aes_128_cbc();
    else if (key_len == 24) cipher = EVP_aes_192_cbc();
    else if (key_len == 32) cipher = EVP_aes_256_cbc();
    else {
        EVP_CIPHER_CTX_free(ctx);
        free(decrypted_data);
        HANDLE_ERROR("key length must be 16/24/32 bytes");
    }

    // 初始化解密上下文
    if (EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(decrypted_data);
        HANDLE_ERROR("EVP_DecryptInit_ex failed");
    }

    // 执行解密
    if (EVP_DecryptUpdate(ctx, decrypted_data, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(decrypted_data);
        HANDLE_ERROR("EVP_DecryptUpdate failed");
    }
    plaintext_len = len;

    // 完成解密
    if (EVP_DecryptFinal_ex(ctx, decrypted_data + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(decrypted_data);
        HANDLE_ERROR("EVP_DecryptFinal_ex failed");
    }
    plaintext_len += len;

    // 去填充
    int unpadded_len = pkcs7_unpad(decrypted_data, plaintext_len, plaintext);
    if (unpadded_len < 0) {
        EVP_CIPHER_CTX_free(ctx);
        free(decrypted_data);
        HANDLE_ERROR("pkcs7_unpad failed");
    }

    // 释放资源
    EVP_CIPHER_CTX_free(ctx);
    free(decrypted_data);

    return unpadded_len;
}

// 辅助函数：打印十六进制数据
void print_hex(const char *label, const unsigned char *data, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    // 1. 测试参数（注意：密钥长度必须是16/24/32字节，IV必须16字节）
    const unsigned char *plaintext = (unsigned char *)"Hello Ubuntu AES C Programming!!";
    const unsigned char *key = (unsigned char *)"1234567890123456"; // 16字节=128位密钥
    const unsigned char *iv = (unsigned char *)"abcdefghijklmnop";  // 16字节IV

    // 2. 加密
    unsigned char *ciphertext = NULL;
    int ciphertext_len = aes_cbc_encrypt(plaintext, strlen((char *)plaintext), key, iv, &ciphertext);
    if (ciphertext_len < 0) exit(EXIT_FAILURE);

    // 3. 打印结果
    printf("a:%s\n", plaintext);
    print_hex("AES-CBC 密文", ciphertext, ciphertext_len);

    // 4. 解密
    unsigned char *decrypted_text = NULL;
    int decrypted_len = aes_cbc_decrypt(ciphertext, ciphertext_len, key, iv, &decrypted_text);
    if (decrypted_len < 0) exit(EXIT_FAILURE);

    printf("b:%s\n", decrypted_text);

    // 5. 验证解密结果
  int alen = strlen(plaintext) ; 
  int blen = strlen(decrypted_text); 

  printf("plaintext:\n");
  for(int i=0;i<alen;i++)
  {
	  printf("%02x ",plaintext[i]) ;
  }
  printf("\n");

printf("decrypted text:\n");
  for(int i=0;i<blen;i++)
  {
	  printf("%02x ",decrypted_text[i]) ;
  }
  printf("\n");

  printf("alen is %d and blen is %d\n",alen,blen);


    if (strcmp((char *)plaintext, (char *)decrypted_text) == 0) {
        printf(" 加密解密验证成功！\n");
    } else {
        printf(" 加密解密验证失败！\n");
    }

    // 6. 释放内存
    free(ciphertext);
    free(decrypted_text);

    return 0;
}

