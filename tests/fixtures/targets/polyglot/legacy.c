#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/rsa.h>

void demo(void) {
    const EVP_MD *m = EVP_md5();
    const EVP_MD *s = EVP_sha1();
    const EVP_CIPHER *d = EVP_des_ede3_cbc();
    const EVP_CIPHER *a = EVP_aes_128_cbc();
    RSA *r = RSA_new();
    (void)m; (void)s; (void)d; (void)a; (void)r;
}
