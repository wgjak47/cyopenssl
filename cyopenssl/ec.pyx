from libc.stdlib cimport malloc, free


cdef extern from "openssl/crypto.h":
    void OPENSSL_free(void *addr)


cdef extern from "openssl/bn.h" nogil:
    ctypedef struct BIGNUM:
        pass

    ctypedef struct BN_CTX:
        pass

    BN_CTX *BN_CTX_new()
    void BN_CTX_free(BN_CTX *ctx)

    char *BN_bn2hex(const BIGNUM *a)
    int BN_hex2bn(BIGNUM **a, const char *str)

    int BN_bn2bin(const BIGNUM *a, unsigned char *to)
    BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret)

    int BN_num_bytes(const BIGNUM *a)

    void BN_zero(BIGNUM *a)


cdef extern from "openssl/ec.h" nogil:
    ctypedef struct EC_KEY:
        pass

    ctypedef struct EC_POINT:
        pass

    ctypedef struct EC_GROUP:
        pass

    ctypedef enum point_conversion_form_t:
        POINT_CONVERSION_COMPRESSED = 2
        POINT_CONVERSION_UNCOMPRESSED = 4
        POINT_CONVERSION_HYBRID = 6

    ctypedef struct EC_builtin_curve:
        int nid
        const char *comment

    size_t EC_get_builtin_curves(EC_builtin_curve *r, size_t nitems)

    # pre-defined NIST curves
    int NID_sect163r2, NID_sect233r1, NID_sect283r1, NID_sect409r1, NID_sect571r1
    int NID_sect163k1, NID_sect233k1, NID_sect283k1, NID_sect409k1, NID_sect571k1
    int NID_X9_62_prime192v1, NID_secp224r1, NID_X9_62_prime256v1, NID_secp384r1
    int NID_secp521r1

    EC_KEY *EC_KEY_new()

    void EC_KEY_free(EC_KEY *key)

    int EC_KEY_set_group(EC_KEY *key, const EC_GROUP *group)
    int EC_KEY_set_private_key(EC_KEY *key, const BIGNUM *prv)
    int EC_KEY_set_public_key(EC_KEY *key, const EC_POINT *pub)

    const EC_GROUP *EC_KEY_get0_group(const EC_KEY *key)
    const EC_POINT *EC_KEY_get0_public_key(const EC_KEY *key)


    EC_POINT *EC_POINT_new(const EC_GROUP *group)

    int EC_POINT_oct2point(const EC_GROUP *group, EC_POINT *p,
                        const unsigned char *buf, size_t len, BN_CTX *ctx)

    size_t EC_POINT_point2oct(const EC_GROUP *group, const EC_POINT *p,
                           point_conversion_form_t form,
                           unsigned char *buf, size_t len, BN_CTX *ctx)

    int EC_POINT_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *n, 
        const EC_POINT *q, const BIGNUM *m, BN_CTX *ctx)

    EC_GROUP *EC_GROUP_new_by_curve_name(int nid)
    const EC_POINT *EC_GROUP_get0_generator(const EC_GROUP *group)


cdef extern from "openssl/ecdsa.h" nogil:
    ctypedef struct ECDSA_SIG:
        BIGNUM *r
        BIGNUM *s

    ECDSA_SIG *ECDSA_do_sign(const unsigned char *dgst, int dgst_len,
                          EC_KEY *eckey)

    int ECDSA_do_verify(const unsigned char *dgst, int dgst_len,
                     const ECDSA_SIG *sig, EC_KEY* eckey)

    ECDSA_SIG *ECDSA_SIG_new()
    void ECDSA_SIG_free(ECDSA_SIG *sig)

    void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps)

    int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s)


from  cyopenssl.evp_h cimport *


cdef extern from "openssl/err.h":
    unsigned long ERR_get_error()
    unsigned long ERR_peek_error()
    char *ERR_error_string(unsigned long e, char *buf)
    const char *ERR_lib_error_string(unsigned long e)
    const char *ERR_func_error_string(unsigned long e)
    const char *ERR_reason_error_string(unsigned long e)


cdef BN_CTX *GLOBAL_BN_CTX = BN_CTX_new()
if GLOBAL_BN_CTX is NULL:
    raise MemoryError()  # could not allocate BN_CTX


cdef class EllipticCurve:
    cdef int nid
    cdef char *name
    cdef char *description
    cdef EC_GROUP *ec_group

    def __cinit__(self, nid, name, description):
        self.nid = nid
        self.name = name
        self.description = description
        self.ec_group = EC_GROUP_new_by_curve_name(nid)
        if self.ec_group is NULL:
            raise ValueError("nid {0} is not a known elliptic curve".format(nid))

    def get_description(self):
        return self.description

    def __repr__(self):
        return "<EllipticCurve {0}>".format(self.name)


cdef EVP_PKEY *ec2evp_pkey(EC_POINT *pub_point, BIGNUM *priv_n, EC_GROUP *group) except NULL:
    '''
    Wraps an EC_POINT into an EVP_PKEY structure with that point
    as the public key; the EVP_PKEY assumes ownership of the EC_POINT
    (optionally can also set private key)
    '''
    cdef:
        EC_KEY *ec_key
        EVP_PKEY *evp_pkey

    ec_key = EC_KEY_new()
    if ec_key is NULL:
        raise MemoryError()  # could not allocate EC_KEY
    if pub_point is NULL:
        raise ValueError("pub_point may not be NULL")
    if EC_KEY_set_group(ec_key, group) == 0:
        raise ValueError('EC_KEY_set_group() failed: ' + _pop_and_format_error_list())
    if EC_KEY_set_public_key(ec_key, pub_point) == 0:
        raise ValueError('EC_KEY_set_public_key() failed: ' + _pop_and_format_error_list())
    if priv_n is not NULL:
        if EC_KEY_set_private_key(ec_key, priv_n) == 0:
            raise ValueError("EC_KEY_set_private_key() error")
    evp_pkey = EVP_PKEY_new()
    if evp_pkey is NULL:
        EC_KEY_free(ec_key)
        raise MemoryError()  # could not allocate EVP_PKEY
    EVP_PKEY_assign_EC_KEY(evp_pkey, ec_key)
    return evp_pkey


cdef class PublicKey:
    cdef EVP_PKEY *key

    def __cinit__(self, bytes sec_point, EllipticCurve curve):
        'creates an openssl EC public key from sec serialized point'
        cdef EC_POINT *pub_point

        pub_point = EC_POINT_new(curve.ec_group)
        if pub_point is NULL:
            raise MemoryError()  # could not allocate EC_POINT
        if EC_POINT_oct2point(
                curve.ec_group, pub_point, sec_point, len(sec_point), GLOBAL_BN_CTX) != 1:
            raise ValueError("unable to parse EC_POINT")  # TODO: parse openssl error
        self.key = ec2evp_pkey(pub_point, NULL, curve.ec_group)

    def verify(self, bytes digest, ECDSA_Signature sig):
        cdef int result
        cdef EC_KEY *ec_key

        ec_key = EVP_PKEY_get1_EC_KEY(self.key)
        result = ECDSA_do_verify(digest, len(digest), sig.sig, ec_key)
        EC_KEY_free(ec_key)
        if result == 1:
            return True
        elif result == 0:
            return False
        elif result == -1:  # TODO: ERR_get_error() for better info
            raise ValueError('could not check signature')
        raise ValueError('unexpected result from ECDSA_do_verify: {0}'.format(result))

    def __dealloc__(self):
        if self.key is not NULL:
            EVP_PKEY_free(self.key)


cdef class KeyPair:
    cdef EVP_PKEY *keypair

    def encode_pubkey(self):
        '''
        encode the public key into SEC format, so it can be shared.
        '''
        cdef:
            EC_GROUP *ec_group
            EC_KEY *ec_key
            EC_POINT *ec_point
            size_t size

        ec_key = EVP_PKEY_get1_EC_KEY(self.keypair)
        ec_point = EC_KEY_get0_public_key(ec_key)
        ec_group = EC_KEY_get0_group(ec_key)
        size = EC_POINT_point2oct(ec_group, ec_point,
            POINT_CONVERSION_COMPRESSED, NULL, 0, GLOBAL_BN_CTX)
        buf = bytearray(size)
        EC_POINT_point2oct(ec_group, ec_point, POINT_CONVERSION_COMPRESSED,
            buf, size, GLOBAL_BN_CTX)
        EC_KEY_free(ec_key)
        return buf

    def sign(self, digest):
        cdef:
            EC_KEY *ec_key
            ECDSA_SIG *sig

        ec_key = EVP_PKEY_get1_EC_KEY(self.keypair)
        sig = ECDSA_do_sign(digest, len(digest), ec_key)
        if sig is NULL:
            raise ValueError('could not complete signature')
        EC_KEY_free(ec_key)
        pysig = ECDSA_Signature()
        pysig.sig = sig
        return pysig

    def __dealloc__(self):
        if self.keypair is not NULL:
            EVP_PKEY_free(self.keypair)


def int2keypair(n, EllipticCurve curve):
    raise NotImplemented()
    cdef:
        BIGNUM *priv_n
        EC_POINT *pub_point
        EVP_PKEY *keypair

    priv_n = NULL
    pub_point = NULL

    buf = "{0:X}".format(n)
    assert BN_hex2bn(&priv_n, buf) == len(buf)

    pubpoint = EC_POINT_new(curve.ec_group)
    if pubpoint is NULL:
        raise MemoryError()  # could not allocate EC_POINT

    assert EC_POINT_mul(curve.ec_group, pub_point, priv_n, NULL, NULL, NULL) == 1
    keypair = ec2evp_pkey(pub_point, priv_n, curve.ec_group)
    ret = KeyPair()
    ret.keypair = keypair
    return ret


def sec_point_and_int2keypair(bytes sec_point, n, EllipticCurve curve):
    cdef:
        BIGNUM *priv_n
        EC_KEY *ec_key
        EVP_PKEY *keypair

    priv_n = NULL
    pub_point = NULL

    buf = "{0:X}".format(n)
    assert BN_hex2bn(&priv_n, buf) == len(buf)

    pubpoint = EC_POINT_new(curve.ec_group)
    if pubpoint is NULL:
        raise MemoryError()  # could not allocate EC_POINT

    # these 5 lines are an elaborate work-around; not sure why
    # EC_POINT_oct2point call below segfaults
    pubkey = PublicKey(sec_point, curve)
    keypair = pubkey.key
    pubkey.key = NULL
    ec_key = EVP_PKEY_get1_EC_KEY(keypair)
    EC_KEY_set_private_key(ec_key, priv_n)
    EC_KEY_free(ec_key)

    #if EC_POINT_oct2point(
    #        curve.ec_group, pub_point, sec_point, len(sec_point), GLOBAL_BN_CTX) != 1:
    #    raise ValueError("unable to parse EC_POINT")  # TODO: parse openssl error
    #keypair = ec2evp_pkey(pub_point, priv_n, curve.ec_group)

    ret = KeyPair()
    ret.keypair = keypair
    return ret


cdef bytes _pop_and_format_error_list():
    cdef:
        int err
        list err_list

    err_list = []
    err = ERR_get_error()
    while err:
        err_list.append((
            <bytes>ERR_lib_error_string(err),
            <bytes>ERR_func_error_string(err),
            <bytes>ERR_reason_error_string(err)))
        err = ERR_get_error()
    return b"-".join([b":".join(e) for e in err_list])


def ecdh(PublicKey pubkey, KeyPair keypair):
    cdef:
        EVP_PKEY_CTX *ctx = NULL
        size_t secret_len

    ctx = EVP_PKEY_CTX_new(keypair.keypair, NULL)
    if ctx is NULL:
        raise MemoryError()  # could not allocate EVP_PKEY_CTX struct
    try:
        assert EVP_PKEY_derive_init(ctx) == 1
        assert EVP_PKEY_derive_set_peer(ctx, pubkey.key) == 1
        assert EVP_PKEY_derive(ctx, NULL, &secret_len) == 1
        secret = bytearray(secret_len)
        assert EVP_PKEY_derive(ctx, secret, &secret_len) == 1
    except:
        raise Exception(_pop_and_format_error_list())
    finally:
        EVP_PKEY_CTX_free(ctx)
    return secret


def gen_keypair(EllipticCurve curve):
    '''
    generate a new random EC keypair on the given curve
    '''
    cdef:
        EVP_PKEY_CTX *pctx = NULL
        EVP_PKEY_CTX *kctx = NULL
        EVP_PKEY *params = NULL
        EVP_PKEY *pkey = NULL

    try:
        pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)
        assert pctx != NULL
        assert EVP_PKEY_paramgen_init(pctx) == 1
        assert EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, curve.nid) == 1
        assert EVP_PKEY_paramgen(pctx, &params) != 0
        kctx = EVP_PKEY_CTX_new(params, NULL)
        assert kctx != NULL
        assert EVP_PKEY_keygen_init(kctx) == 1
        assert EVP_PKEY_keygen(kctx, &pkey) == 1
        assert pkey != NULL
    finally:
        if kctx:
            EVP_PKEY_CTX_free(kctx)
        if params:
            EVP_PKEY_free(params)
        if pctx:
            EVP_PKEY_CTX_free(pctx)

    ret = KeyPair()
    ret.keypair = pkey
    return ret


cdef class ECDSA_Signature:
    cdef ECDSA_SIG *sig

    def get_r_s_hex(self):
        '''
        Get the R and S values as a pair of hex formatted strings.
        (May be converted to ints with int(r, 16), int(s, 16))
        '''
        cdef:
            char *hex_r
            char *hex_s

        tmp = NULL
        assert self.sig is not NULL
        #ECDSA_SIG_get0(self.sig, &bn_r, &bn_s)
        # switch to ECDSA_SIG_get0 when support for old version not needed
        hex_r, hex_s = BN_bn2hex(self.sig.r), BN_bn2hex(self.sig.s)
        r, s = hex_r, hex_s
        OPENSSL_free(hex_r)
        OPENSSL_free(hex_s)
        return r, s

    def get_r_s_buf(self):
        '''
        Get the R and S values as a binary buffer.
        (First half of string R, second half of string S)
        '''
        assert self.sig is not NULL
        py_r = bytearray(BN_num_bytes(self.sig.r))
        py_s = bytearray(BN_num_bytes(self.sig.s))
        BN_bn2bin(self.sig.r, py_r)
        BN_bn2bin(self.sig.s, py_s)
        return py_r, py_s

    def __dealloc__(self):
        if self.sig is not NULL:
            ECDSA_SIG_free(self.sig)


def buf2ECDSA_Signature(bytes r, bytes s):
    'converts a binary buffers containing r and s into ECDSA_Signature'
    cdef ECDSA_SIG *sig

    sig = ECDSA_SIG_new()
    if sig is NULL:
        raise MemoryError()  # could not allocate ECDSA_SIG struct
    sig.r = BN_bin2bn(r, len(r), NULL)
    sig.s = BN_bin2bn(s, len(s), NULL)

    pysig = ECDSA_Signature()
    pysig.sig = sig
    return pysig


def r_s2ECDSA_Signature(r, s):
    'converts an r and s integer into an ECDSA signature'
    cdef:
        BIGNUM *bn_r
        BIGNUM *bn_s
        ECDSA_SIG *sig

    bn_r = NULL
    bn_s = NULL
    sig = ECDSA_SIG_new()
    if sig is NULL:
        raise MemoryError()  # could not allocate ECDSA_SIG struct
    buf = "{0:X}".format(r)
    BN_hex2bn(&sig.r, buf)
    #BN_hex2bn(&bn_r, buf)
    buf = "{0:X}".format(s)
    BN_hex2bn(&sig.s, buf)
    #BN_hex2bn(&bn_s, buf)
    #ECDSA_SIG_set0(sig, bn_r, bn_s)
    # switch to ECDSA_SIG_set0 when old support not needed

    pysig = ECDSA_Signature()
    pysig.sig = sig
    return pysig


CURVES = {}


cdef init_builtin_curves():
    cdef size_t nitems
    cdef EC_builtin_curve *curves

    nitems = EC_get_builtin_curves(NULL, 0)
    curves = <EC_builtin_curve*>malloc(nitems * sizeof(EC_builtin_curve))
    assert curves is not NULL

    nid2desc = {}
    EC_get_builtin_curves(curves, nitems)

    for i in range(nitems):
        nid2desc[curves[i].nid] = curves[i].comment

    free(curves)

    curves_by_name = {
        "B-163": NID_sect163r2,
        "B-233": NID_sect233r1,
        "B-283": NID_sect283r1,
        "B-409": NID_sect409r1,
        "B-571": NID_sect571r1,
        "K-163": NID_sect163k1,
        "K-233": NID_sect233k1,
        "K-283": NID_sect283k1,
        "K-409": NID_sect409k1,
        "K-571": NID_sect571k1,
        "P-192": NID_X9_62_prime192v1,
        "P-224": NID_secp224r1,
        "P-256": NID_X9_62_prime256v1,
        "P-384": NID_secp384r1,
        "P-521": NID_secp521r1}

    for name, nid in curves_by_name.items():
        CURVES[name] = EllipticCurve(nid, name, nid2desc[nid])


init_builtin_curves()

def print_errs():
    print "errors so far...", _pop_and_format_error_list()
