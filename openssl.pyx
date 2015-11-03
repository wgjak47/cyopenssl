

cdef extern from "openssl/evp.h":
    ctypedef struct EVP_CIPHER_CTX:
        pass

    ctypedef struct EVP_CIPHER:
        pass

    ctypedef struct ENGINE:
        pass

    EVP_CIPHER_CTX* EVP_CIPHER_CTX_new()
    void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX*)

    int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
        ENGINE *impl, unsigned char *key, unsigned char *iv)

    int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
        ENGINE *impl, unsigned char *key, unsigned char *iv)

    int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
         int *outl, unsigned char *inp, int inl)

    int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
         int *outl, unsigned char *inp, int inl)

    int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)

    int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)

    int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)

    const EVP_CIPHER* EVP_aes_128_gcm()
    const EVP_CIPHER* EVP_aes_192_gcm()
    const EVP_CIPHER* EVP_aes_256_gcm()

    # #define constants
    int EVP_CTRL_GCM_SET_IVLEN
    int EVP_CTRL_GCM_GET_TAG
    int EVP_CTRL_GCM_SET_TAG


from cpython.mem cimport PyMem_Malloc, PyMem_Free


def aes_gcm_encrypt(bytes plaintext, bytes key, bytes iv, bytes authdata=None, int tagsize=16):
    cdef:
        EVP_CIPHER_CTX *ctx = NULL
        unsigned char *outbuf = NULL
        int outlen
        int tmplen
        char tagbuf[16]
    try:
        ctx = EVP_CIPHER_CTX_new()
        outbuf = <unsigned char*>PyMem_Malloc(len(plaintext))
        if outbuf == NULL:
            raise MemoryError()
        EVP_EncryptInit_ex(ctx, get_aes_gcm_cipher(len(key)), NULL, NULL, NULL)
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, len(iv), NULL)
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)
        if authdata is not None:
            EVP_EncryptUpdate(ctx, None, &outlen, authdata, len(authdata))
        EVP_EncryptUpdate(ctx, outbuf, &outlen, plaintext, len(plaintext))
        EVP_EncryptFinal_ex(ctx, outbuf + outlen, &tmplen)
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tagsize, tagbuf)
        return bytes(outbuf[:outlen]), bytes(tagbuf[:tagsize])
    finally:
        if ctx:
            EVP_CIPHER_CTX_free(ctx)
        if outbuf:
            PyMem_Free(outbuf)


def aes_gcm_decrypt(bytes ciphertext, bytes key, bytes iv, bytes tag, bytes authdata=None):
    cdef:
        EVP_CIPHER_CTX *ctx = NULL
        unsigned char *outbuf = NULL
        int outlen
        int tmplen
        int authenticated
    try:
        ctx = EVP_CIPHER_CTX_new()
        outbuf = <unsigned char*>PyMem_Malloc(len(ciphertext))
        if outbuf == NULL:
            raise MemoryError()
        EVP_DecryptInit_ex(ctx, get_aes_gcm_cipher(len(key)), NULL, NULL, NULL)  # set CIPHER
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, len(iv), NULL)  # set IV-len
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, len(tag), <char*>tag)  # set TAG
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)  # set IV
        if authdata:
            EVP_DecryptUpdate(ctx, NULL, &outlen, authdata, len(authdata))
        EVP_DecryptUpdate(ctx, outbuf, &outlen, ciphertext, len(ciphertext))
        authenticated = EVP_DecryptFinal_ex(ctx, outbuf + outlen, &tmplen)
        if not authenticated:
            raise ValueError("message authentication failed (tag does not match)"
                " decrypt {0} bytes of data".format(int(outlen)))
        return bytes(outbuf[:outlen])
    finally:
        if ctx:
            EVP_CIPHER_CTX_free(ctx)
        if outbuf:
            PyMem_Free(outbuf)


cdef const EVP_CIPHER* get_aes_gcm_cipher(int keylen):
    if keylen == 128 / 8:
        return EVP_aes_128_gcm()
    elif keylen == 192 / 8:
        return EVP_aes_192_gcm()
    elif keylen == 256 / 8:
        return EVP_aes_256_gcm()


def test():
    import timeit
    dur = timeit.timeit(lambda: aes_gcm_encrypt('abc', 'a' * 16, 'a' * 12), number=1000)
    print dur * 1000, "us per aes gcm encrypt"

    plaintext = "hello world!"
    ciphertext, tag = aes_gcm_encrypt(plaintext, 'a' * 16, 'a' * 12)
    assert plaintext == aes_gcm_decrypt(ciphertext, 'a' * 16, 'a' * 12, tag)

    dur2 = timeit.timeit(lambda: aes_gcm_decrypt(ciphertext, 'a' * 16, 'a' * 12, tag), number=1000)
    print dur2 * 1000, "us per aes gcm decrypt"
