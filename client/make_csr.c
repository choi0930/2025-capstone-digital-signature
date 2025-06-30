#include <stdio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

EVP_PKEY *get_key(){
    FILE *fp = fopen("./client_key/ec_priv_key.pem", "r");
    
    if(!fp){
        perror("비밀키 파일 열기 실패");
        return 0;
    }

    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if(!pkey){
        fprintf(stderr, "비밀키 로딩 실패");
        return 0;
    }

    return pkey;
}

X509_REQ *generate_csr(){
    EVP_PKEY *pkey = get_key();

    X509_REQ *req = X509_REQ_new();

    X509_NAME *name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"KR", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (unsigned char *)"Seoul", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)"ClientOrg", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"client.local", -1, -1, 0);

    X509_REQ_set_subject_name(req, name);

    X509_REQ_set_pubkey(req, pkey);

    X509_REQ_sign(req, pkey, EVP_sha256());
    EVP_PKEY_free(pkey);
    return req;

}

int main(){
    //test
    X509_REQ *req = generate_csr();

    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509_REQ(bio, req);

    char *csr_pem;
    long csr_len = BIO_get_mem_data(bio, &csr_pem);

    fwrite(csr_pem, 1, csr_len, stdout);

    BIO_free(bio);
    X509_REQ_free(req);
    

    return 0;
}