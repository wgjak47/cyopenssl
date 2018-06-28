from libc cimport string
from libc.stdio cimport printf


from cyopenssl.evp_h cimport *


cdef extern from "openssl/pkcs7.h" nogil:
    ctypedef struct PKCS7:
        pass

    PKCS7 *PKCS7_sign(
        X509 *signcert, EVP_PKEY *pkey, stack_st_X509 *certs, BIO *data, int flags)

    int PKCS7_verify(
        PKCS7 *p7, stack_st_X509 *certs, X509_STORE *store, BIO *indata, BIO *out, int flags)

    PKCS7 *PKCS7_encrypt(
        stack_st_X509 *certs, BIO *in_, const EVP_CIPHER *cipher, int flags)

    int PKCS7_decrypt(
        PKCS7 *p7, EVP_PKEY *pkey, X509 *cert, BIO *data, int flags)

    void PKCS7_free(PKCS7 *p7)

    int PKCS7_BINARY


cdef extern from "openssl/x509.h" nogil:
    ctypedef struct X509:
        int references

    ctypedef struct X509_STORE:
        int references

    ctypedef struct X509_NAME:
        pass

    X509 *d2i_X509(X509 **px, const unsigned char **inp, int len)
    int i2d_X509(X509 *x, unsigned char **out)
    X509 *X509_new()
    X509_NAME *X509_get_subject_name(X509 *self)
    X509_NAME *X509_get_issuer_name(X509 *self)
    EVP_PKEY *X509_get_pubkey(X509 *self)
    void X509_free(X509 *a)

    int X509_NAME_cmp(X509_NAME*, X509_NAME*)

    X509_STORE *X509_STORE_new()
    void X509_STORE_free(X509_STORE *x509_store)
    int X509_STORE_add_cert(X509_STORE *x509_store, X509 *cert)

    struct stack_st_X509_NAME:
        pass

    struct stack_st_X509:
        pass

    stack_st_X509 *sk_X509_new_null()
    void sk_X509_free(stack_st_X509*)
    void sk_X509_push(stack_st_X509*, X509*)


cdef extern from "openssl/x509_vfy.h" nogil:
    ctypedef struct X509_STORE_CTX:
        pass

    int X509_verify(X509 *cert, EVP_PKEY *pub)  # 1 means EVP_PKEY was signed by X509 cert


cdef extern from "openssl/pem.h" nogil:
    ctypedef int pem_password_cb(char *buf, int size, int rwflag, void *userdata)
    EVP_PKEY *PEM_read_bio_PrivateKey(
        BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u)

    PKCS7 *PEM_read_bio_PKCS7(BIO *bp, PKCS7 **x, pem_password_cb *cb, void *u)

    int PEM_write_bio_PKCS7(BIO *bp, PKCS7 *x)


cdef extern from "openssl/bio.h" nogil:
    ctypedef struct BIO:
        pass

    ctypedef struct BIO_METHOD:
        pass

    BIO *BIO_new_mem_buf(void *buf, int len)
    BIO *BIO_new(BIO_METHOD *method)
    int BIO_read(BIO *b, void *buf, int len)
    int BIO_write(BIO *b, const void *buf, int len)
    long BIO_set_nbio(BIO *b, long n)
    int BIO_pending(BIO *b)
    BIO_METHOD *BIO_s_mem()
    long BIO_set_nbio(BIO *b, long n)
    int BIO_test_flags(BIO *b, int flags)
    int BIO_free(BIO *a)

    int BIO_FLAGS_READ, BIO_FLAGS_WRITE, BIO_FLAGS_IO_SPECIAL, BIO_FLAGS_SHOULD_RETRY


cdef extern from "openssl/ssl.h" nogil:
    int SSL_library_init()
    void SSL_load_error_strings()

    ctypedef struct SSL:
        pass

    ctypedef struct SSL_CTX:
        pass

    ctypedef struct SSL_SESSION:
        int references

    ctypedef struct SSL_CIPHER:
        pass

    ctypedef struct SSL_METHOD:
        pass

    SSL *SSL_new(SSL_CTX *ctx)
    void SSL_free(SSL *ssl)
    int SSL_get_error(const SSL *ssl, int ret)
    int SSL_write(SSL *ssl, const void *buf, int num)
    int SSL_read(SSL *ssl, void *buf, int num)
    int SSL_do_handshake(SSL *ssl)
    int SSL_shutdown(SSL *ssl)
    int SSL_get_shutdown(const SSL *ssl)
    int SSL_pending(const SSL *ssl)
    int SSL_set_fd(SSL *ssl, int fd)
    int SSL_set_session(SSL *ssl, SSL_SESSION *session)
    SSL_SESSION *SSL_get_session(SSL *ssl)
    void SSL_set_connect_state(SSL *ssl)
    void SSL_set_accept_state(SSL *ssl)
    BIO *SSL_get_rbio(SSL *ssl)
    BIO *SSL_get_wbio(SSL *ssl)
    void SSL_set_bio(SSL *ssl, BIO *rbio, BIO *wbio)
    long SSL_get_verify_result(const SSL *ssl)
    X509 *SSL_get_peer_certificate(const SSL *ssl)
    SSL_CIPHER *SSL_get_current_cipher(const SSL *ssl)
    stack_st_X509_NAME *SSL_load_client_CA_file(char *file)
    int SSL_set_cipher_list(SSL *ssl, char *str)
    long SSL_ctrl(SSL *ssl, int cmd, long larg, char *parg)
    const char *SSL_state_string(const SSL *ssl)
    const char *SSL_state_string_long(const SSL *ssl)
    long SSL_set_mode(SSL *ssl, long mode)
    long SSL_get_mode(SSL *ssl)
    long SSL_session_reused(SSL *ssl)

    void SSL_set_info_callback(SSL *ssl, void (*callback)(SSL*, int, int))

    const char *SSL_alert_type_string(int value)
    const char *SSL_alert_type_string_long(int value)

    const char *SSL_alert_desc_string(int value)
    const char *SSL_alert_desc_string_long(int value)

    SSL_CTX *SSL_CTX_new(const SSL_METHOD *method)
    void SSL_CTX_free(SSL_CTX *ctx)
    int SSL_CTX_set_session_id_context(SSL_CTX *ctx,
        const unsigned char *sid_ctx, unsigned int sid_ctx_len)
    int SSL_CTX_use_certificate(SSL_CTX *ctx, X509 *x)
    int SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file)
    void SSL_CTX_set_verify(SSL_CTX *ctx, int mode,
        int (*verify_callback)(int, X509_STORE_CTX *))
    void SSL_CTX_set_cert_store(SSL_CTX *ctx, X509_STORE *store)
    X509_STORE *SSL_CTX_get_cert_store(const SSL_CTX *ctx)
    int SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey)
    int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, char *file, int type)
    ctypedef int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata)
    stack_st_X509_NAME *SSL_CTX_get_client_CA_list(const SSL_CTX *ctx)
    void SSL_CTX_set_client_CA_list(SSL_CTX *ctx, stack_st_X509_NAME *list)
    int SSL_CTX_add_client_CA(SSL_CTX *ctx, X509 *x)
    int SSL_CTX_set_cipher_list(SSL_CTX *ctx, char *str)
    int SSL_CTX_add_session(SSL_CTX *ctx, SSL_SESSION *c)
    int SSL_CTX_load_verify_locations(SSL_CTX *ctx, char *CAfile, char *CApath)
    long SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long larg, char *parg)
    long SSL_CTX_set_session_cache_mode(SSL_CTX *ctx, long mode)
    long SSL_CTX_get_session_cache_mode(SSL_CTX *ctx)
    long SSL_CTX_set_options(SSL_CTX *ctx, long options)
    long SSL_CTX_get_options(SSL_CTX *ctx)
    long SSL_CTX_add_extra_chain_cert(SSL_CTX *ctx, X509 *x509)
    int SSL_CTX_check_private_key(const SSL_CTX *ctx)

    void SSL_CTX_set_default_passwd_cb(SSL_CTX *ctx, pem_password_cb *cb)
    void SSL_CTX_set_default_passwd_cb_userdata(SSL_CTX *ctx, void *u)

    const char *SSL_CIPHER_get_name(SSL_CIPHER *cipher)
    char *SSL_CIPHER_get_version(SSL_CIPHER *cipher)
    char *SSL_CIPHER_description(SSL_CIPHER *cipher, char *buf, int len)
    int SSL_CIPHER_get_bits(SSL_CIPHER *cipher, int *alg_bits)

    const SSL_METHOD *TLSv1_method()
    const SSL_METHOD *TLSv1_1_method()
    const SSL_METHOD *SSLv23_method()

    SSL_SESSION *d2i_SSL_SESSION(SSL_SESSION **a, const unsigned char **pp, long length)
    int i2d_SSL_SESSION(SSL_SESSION *in_, unsigned char **pp)
    void SSL_SESSION_free(SSL_SESSION* sess)

    # set_verify parameters
    int SSL_VERIFY_NONE, SSL_VERIFY_PEER, SSL_VERIFY_FAIL_IF_NO_PEER_CERT
    int SSL_VERIFY_CLIENT_ONCE

    # SSL error codes
    int SSL_ERROR_NONE, SSL_ERROR_SSL, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE
    int SSL_ERROR_ZERO_RETURN, SSL_ERROR_SYSCALL, SSL_ERROR_WANT_CONNECT
    int SSL_ERROR_WANT_X509_LOOKUP, SSL_ERROR_WANT_ACCEPT

    int SSL_FILETYPE_PEM, SSL_FILETYPE_ASN1

    # session cache options
    long SSL_SESS_CACHE_OFF, SSL_SESS_CACHE_CLIENT, SSL_SESS_CACHE_SERVER
    long SSL_SESS_CACHE_BOTH, SSL_SESS_CACHE_NO_AUTO_CLEAR, SSL_SESS_CACHE_NO_INTERNAL_LOOKUP
    long SSL_SESS_CACHE_NO_INTERNAL_STORE, SSL_SESS_CACHE_NO_INTERNAL

    # SSL mode flags
    long SSL_MODE_ENABLE_PARTIAL_WRITE, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER
    long SSL_MODE_AUTO_RETRY, SSL_MODE_RELEASE_BUFFERS
    long SSL_MODE_RELEASE_BUFFERS, SSL_MODE_SEND_FALLBACK_SCSV

    # SSL callback flags
    int SSL_CB_LOOP, SSL_CB_EXIT, SSL_CB_READ, SSL_CB_WRITE, SSL_CB_ALERT

    # SSL states
    int SSL_ST_MASK, SSL_ST_CONNECT, SSL_ST_ACCEPT

    # SSL shutdown states
    int SSL_SENT_SHUTDOWN, SSL_RECEIVED_SHUTDOWN

    # version flags
    long SSL_OP_NO_SSLv2, SSL_OP_NO_SSLv3
    long SSL_OP_NO_TICKET



cdef extern from "openssl/err.h":
    unsigned long ERR_get_error()
    unsigned long ERR_peek_error()
    char *ERR_error_string(unsigned long e, char *buf)
    const char *ERR_lib_error_string(unsigned long e)
    const char *ERR_func_error_string(unsigned long e)
    const char *ERR_reason_error_string(unsigned long e)


from cpython.mem cimport PyMem_Malloc, PyMem_Free
from cpython cimport bool, PyErr_SetExcFromWindowsErr, PyErr_SetFromErrno, PyErr_Clear


cdef struct PasswordInfo:
    int nbytes
    char *bytes


cdef class Context:
    '''
    Wrapper around an OpenSSL SSL_CTX structure.
    '''
    cdef:
        SSL_CTX *ctx
        bytes password
        PasswordInfo password_info

    def __cinit__(self, method, bool verify=True, bytes certfile=None, bytes keyfile=None,
                  bytes ca_certs=None, bytes passphrase=None):
        self.ctx = NULL
        if method == "TLSv1.1":
            self.ctx = SSL_CTX_new(TLSv1_1_method())
        elif method == "TLS":
            self.ctx = SSL_CTX_new(SSLv23_method())
        else:
            raise ValueError("supported versions are 'TLSv1.1' and 'TLS' (1.0, 1.1, 1.2)")
        if self.ctx == NULL:
            raise ValueError("SSL context creation failed")
        if method == "TLS":
            SSL_CTX_set_options(self.ctx,
                SSL_CTX_get_options(self.ctx) | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3)
        if not verify:
            SSL_CTX_set_verify(self.ctx, SSL_VERIFY_NONE, NULL)
        SSL_CTX_set_options(self.ctx, SSL_CTX_get_options(self.ctx) | SSL_OP_NO_TICKET)

    def set_session_id(self, bytes id_str):
        if not SSL_CTX_set_session_id_context(self.ctx, id_str, len(id_str)):
            raise ValueError("set_session_id() string too long: " + str(len(id_str)))

    def set_session_cache_mode(self, mode):
        SSL_CTX_set_session_cache_mode(self.ctx, mode)

    def set_options(self, options):
        SSL_CTX_set_options(self.ctx, options)

    def add_session(self, Session session not None):
        SSL_CTX_add_session(self.ctx, session.sess)
        session.sess.references += 1

    def set_verify(self, int flags):
        '''
        flags parameter should be generated by bitwise-oring together of
        SSL_VERIFY_* values.
        verify_func should accept two parameters: an integer, and an X509 object
        pointer.
        See https://www.openssl.org/docs/ssl/SSL_CTX_set_verify.html
        '''
        SSL_CTX_set_verify(self.ctx, flags, NULL)
        # need to figure out how to create a "dynamic" C callback here
        # ... this is a bit tricky, there is no passed parameter

    def use_certificate_chain_file(self, bytes certfile):
        '''
        Load and use the certificate file at location certfile
        '''
        if not SSL_CTX_use_certificate_chain_file(self.ctx, certfile):
            raise ValueError("error using certificate file " +
                repr(certfile) + "\n" + _pop_and_format_error_list())

    def load_client_CA_list(self, certfile_or_certs):
        '''
        Load the certificate file at location certfile into client CA list,
        or the list of Certificates
        '''
        cdef stack_st_X509_NAME *ca_list_p = NULL

        if isinstance(certfile_or_certs, basestring):
            ca_list_p = SSL_load_client_CA_file(certfile_or_certs)
            if ca_list_p == NULL:
                raise ValueError("error loading certificate file " + 
                    repr(certfile_or_certs) + "\n" + _pop_and_format_error_list())
            SSL_CTX_set_client_CA_list(self.ctx, ca_list_p)
        else:
            for cert in certfile_or_certs:
                if not SSL_CTX_add_client_CA(self.ctx, (<Certificate?>cert).cert):
                    raise ValueError("error loading certificate " +
                        repr(cert) + "\n" + _pop_and_format_error_list())

    def use_certificate(self, Certificate cert not None):
        if not SSL_CTX_use_certificate(self.ctx, cert.cert):
            raise _ssleay_err2value_err() or ValueError("SSL_CTX_use_certificate() error")
        cert.cert.references += 1

    def set_cert_store(self, CertStore cert_store not None):
        '''
        Note: this operation destroys the CertStore; ownership of the underlying
        structure passes to the Context
        '''
        SSL_CTX_set_cert_store(self.ctx, cert_store.cert_store)
        cert_store.cert_store = NULL

    def add_extra_chain_cert(self, Certificate cert not None):
        '''
        Note: this operation destroys the Certificate; ownership of the underlying
        structure passes to the Context
        '''
        if not SSL_CTX_add_extra_chain_cert(self.ctx, cert.cert):
            raise _ssleay_err2value_err() or ValueError("SSL_CTX_add_extra_chain_cert() failed")
        cert.cert.references += 1

    def get_cert_store(self):
        cdef X509_STORE *store = SSL_CTX_get_cert_store(self.ctx)
        if store == NULL:
            return None
        # a bit wasteful since we alloc and de-alloc an empty X509_STORE
        pystore = CertStore()
        X509_STORE_free(pystore.cert_store)
        pystore.cert_store = store
        store.references += 1
        return pystore

    def use_privatekey(self, PrivateKey private_key not None):
        if not SSL_CTX_use_PrivateKey(self.ctx, private_key.private_key):
            raise _ssleay_err2value_err() or ValueError("SSL_CTX_use_PrivateKey() failed")

    def use_privatekey_file(self, bytes keyfile not None, int filetype=SSL_FILETYPE_PEM):
        if not SSL_CTX_use_PrivateKey_file(self.ctx, keyfile, filetype):
            raise ValueError("error using private key from " + repr(keyfile) +
                _pop_and_format_error_list())

    def set_password(self, bytes password not None):
        self.password = password
        self.password_info.nbytes = len(password)
        self.password_info.bytes = <char*>password
        SSL_CTX_set_default_passwd_cb_userdata(self.ctx, &self.password_info)
        SSL_CTX_set_default_passwd_cb(self.ctx, passwd_cb_passthru)

    def check_privatekey(self):
        if not SSL_CTX_check_private_key(self.ctx):
            raise ValueError("private key and public cert do not match")

    def load_verify_locations(self, bytes pemfile not None):
        if not SSL_CTX_load_verify_locations(self.ctx, pemfile, NULL):
            raise ValueError("error using load_verify_locations(" + repr(pemfile) + ")"
                + _pop_and_format_error_list())

    def set_cipher_list(self, bytes cipher_list not None):
        if not SSL_CTX_set_cipher_list(self.ctx, cipher_list):
            raise ValueError("no usable ciphers in " + repr(cipher_list))

    def __dealloc__(self):
        if self.ctx:
            SSL_CTX_free(self.ctx)


cdef int passwd_cb_passthru(char *buf, int size, int rwflag, void *userdata) nogil:
    cdef PasswordInfo *password_info
    password_info = <PasswordInfo*>userdata
    string.strncpy(buf, password_info.bytes, password_info.nbytes)
    return password_info.nbytes


cdef class Session:
    '''
    A Session may be serialized for long term storage, or
    transfer to another process.  Or, it may be explicitly passed
    to the constructor of a Socket for manual management of
    session cache.
    '''
    cdef:
        SSL_SESSION* sess

    def dumps(self):
        '''
        Serialize the Session into a bytearray and return.
        '''
        cdef int size
        cdef unsigned char *bufptr
        size = i2d_SSL_SESSION(self.sess, NULL)
        buf = bytearray(size)
        bufptr = buf
        i2d_SSL_SESSION(self.sess, &bufptr)
        return buf

    def __dealloc__(self):
        if self.sess:
            SSL_SESSION_free(self.sess)


cdef class ParsedSession(Session):
    def __cinit__(self, data):
        self.sess = NULL
        cdef const unsigned char* data_ptr
        data_ptr = data
        self.sess = d2i_SSL_SESSION(NULL, &data_ptr, len(data))
        if self.sess == NULL:
            raise ValueError("d2i_SSL_SESSION error")


cdef BorrowedSession(SSL_SESSION *sess):
    '''
    Factory function for a session borrowed from an
    existing one.
    '''
    session = Session()
    session.sess = sess
    session.sess.references += 1


cdef class PrivateKey:
    cdef:
        EVP_PKEY *private_key

    def __cinit__(self, data, passphrase=None):
        self.private_key = NULL
        cdef const unsigned char *data_ptr = data
        cdef BIO *data_bio = NULL
        if passphrase is None:
            self.private_key = d2i_AutoPrivateKey(NULL, &data_ptr, len(data))
        else:
            data_bio = BIO_new_mem_buf(data_ptr, len(data))
            self.private_key = PEM_read_bio_PrivateKey(
                data_bio, NULL, NULL, <const unsigned char*>passphrase)
            BIO_free(data_bio)
        if self.private_key == NULL:
            raise _ssleay_err2value_err() or ValueError("PrivateKey init error")

    def __dealloc__(self):
        if self.private_key:
            pass # EVP_PKEY_free(self.private_key)


cdef class Certificate:
    cdef:
        X509 *cert 

    def __cinit__(self, bytes data not None):
        cdef const unsigned char* data_ptr = data
        self.cert = NULL
        self.cert = d2i_X509(NULL, &data_ptr, len(data))
        if not self.cert:
            code = ERR_get_error()
            if code:
                raise ValueError(ERR_error_string(code, NULL))

    def is_signed_by(self, Certificate other):
        cdef:
            EVP_PKEY *pub
            int result
        if X509_NAME_cmp(X509_get_issuer_name(self.cert), X509_get_subject_name(other.cert)):
            return False
        pub = X509_get_pubkey(self.cert)
        result = X509_verify(other.cert, pub)
        EVP_PKEY_free(pub)
        return result == 1

    def __dealloc__(self):
        if self.cert:
            pass # X509_free(self.cert)


cdef class CertStore:
    cdef:
        X509_STORE *cert_store

    def __cinit__(self):
        self.cert_store = X509_STORE_new()

    def add_cert(self, Certificate cert not None):
        if not X509_STORE_add_cert(self.cert_store, cert.cert):
            raise _ssleay_err2value_err() or ValueError("error adding cert to cert store")

    def __dealloc__(self):
        if self.cert_store:
            X509_STORE_free(self.cert_store)


cdef class CertStack:
    'append-only for now'
    cdef:
        stack_st_X509 *cert_stack

    def __cinit__(self, certs):
        self.cert_stack = sk_X509_new_null()
        for cert in certs:
            self.append(cert)

    def append(self, Certificate cert not None):
        sk_X509_push(self.cert_stack, cert.cert)

    def __dealloc__(self):
        if self.cert_stack:
            pass # sk_X509_free(self.cert_stack)


cdef object _ssleay_err2value_err():
    cdef int code
    code = ERR_get_error()
    if code:
        return ValueError(<bytes>ERR_error_string(code, NULL))


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


import socket
import time


cdef enum SSL_OP:
    DO_SSL_WRITE
    DO_SSL_READ
    DO_SSL_HANDSHAKE
    DO_SSL_SHUTDOWN


cdef class Socket:
    cdef:
        SSL *ssl
        bint server_side, do_handshake_on_connect, suppress_ragged_eofs
        object sock
        int fileno
        double timeout
        BIO *rbio
        BIO *wbio
        bytearray buf

    def __cinit__(self, sock, Context context not None, bool server_side=False,
            bool do_handshake_on_connect=True, bool suppress_ragged_eofs=True,
            Session session=None, bytes cipherlist=b'', bool debug_print=False):

        self.ssl = SSL_new(context.ctx)
        if self.ssl == NULL:
            raise Exception("SSL_new error")
        if debug_print:
            self.enable_debug_print()
        self.server_side = server_side
        self.do_handshake_on_connect = do_handshake_on_connect
        self.suppress_ragged_eofs = suppress_ragged_eofs
        self.fileno = sock.fileno()
        # TODO: should these be read/write?
        self.rbio = BIO_new(BIO_s_mem())  # MemBIO()
        self.wbio = BIO_new(BIO_s_mem())  # MemBIO()
        self.buf = bytearray(32 * 1024)
        SSL_set_bio(self.ssl, rbio=self.rbio, wbio=self.wbio)
        self.sock = sock
        if cipherlist:
            if not SSL_set_cipher_list(self.ssl, cipherlist):
                raise ValueError("no ciphers matched " + repr(cipherlist))
        '''
        if not SSL_set_fd(self.ssl, self.fileno):
            raise socket.error("SSL_set_fd failed " + _pop_and_format_error_list())
        '''
        if self.server_side:
            SSL_set_accept_state(self.ssl)
        else:
            SSL_set_connect_state(self.ssl)
            if session is not None:
                if session.sess == NULL:
                    raise ValueError("passed SSL Session with null session structure")
                SSL_set_session(self.ssl, session.sess)
        '''
        timeout = sock.gettimeout()
        if timeout is None:
            timeout = socket.getdefaulttimeout()
            if timeout is None:
                timeout = -1
        self.set_timeout(timeout)
        '''
        if self.do_handshake_on_connect:
            try:
                self.sock.getpeername()
            except:
                pass
            else:
                self.do_handshake()

    def send(self, object data not None, int flags=0):
        cdef char *_data
        dt = type(data)
        if dt is bytes:
            _data = <char*>(<bytes>data)
        elif dt is bytearray:
            _data = <char*>(<bytearray>data)
        else:
            raise TypeError("parameter data must be bytes or bytearray, not " + repr(dt)) 
        if flags:
            raise ValueError("flags not supported for SSL socket")
        return self._do_ssl(DO_SSL_WRITE, data, len(data))

    sendall = send

    def recv(self, int size, int flags=0):
        cdef char *buf
        cdef int read
        if flags:
            raise ValueError("flags not supported for SSL socket")
        buf = <char *>PyMem_Malloc(size)
        read = self._do_ssl(DO_SSL_READ, buf, size)
        response = <bytes>buf[:read]
        PyMem_Free(buf)
        return response

    def recv_into(self, bytearray dst not None, int size=0, int flags=0):
        if size == 0:
            size = len(dst)
        if flags:
            raise ValueError("flags not supported for SSL socket")
        return self._do_ssl(DO_SSL_READ, <char*>dst, size)

    def do_handshake(self, double timeout=-1):
        cdef int result = self._do_ssl(DO_SSL_HANDSHAKE, NULL, 0)
        if result <= 0:
            # sometimes when handshake fails, SSL_get_error still returns 0
            raise SSLError('SSL handshake failed: {0}'.format(result))
        return result

    def shutdown(self, int how=socket.SHUT_RDWR):
        '''
        Accepts a how parameter for compatibility with normal sockets,
        however a half-open SSL socket is not safe (at any time, either
        side may request a key renegotiation which requires both side
        to be able to send data; so a SSL Socket recv() may require
        packets to be sent as well)
        '''
        cdef int i = 0
        try:
            while not self._do_ssl(DO_SSL_SHUTDOWN, NULL, 0) and i < 10:
                i += 1
        except:
            pass
        # OpenSSL docs claim that SSL shutdown may need to be called twice.
        # other practical implementations seem to call it in a loop
        # TODO: NGINX does some fancy stuff here.... investigate that

    def settimeout(self, float timeout):
        self.timeout = timeout
        self.sock.settimeout(timeout)

    cdef int _do_ssl(self, SSL_OP op, char* data, int size) except *:
        cdef:
            int ret = 0, err = 0, shutdown = 0
            long verify_result
            int io_size = 0
            double timeout = self.timeout
            double start = 0
            SSL *ssl

        start = time.time()
        ssl = self.ssl

        while 1:
            shutdown = SSL_get_shutdown(ssl)
            if shutdown and op != DO_SSL_SHUTDOWN:
                if shutdown & SSL_RECEIVED_SHUTDOWN:
                    raise SSLError("received shutdown")
                elif shutdown & SSL_SENT_SHUTDOWN:
                    raise SSLError("sent shutdown")
                else:
                    raise SSLError("unknown shutdown state " + str(shutdown))
            # flush_errors()
            with nogil:
                if op == DO_SSL_WRITE:
                    ret = SSL_write(ssl, data, size)
                elif op == DO_SSL_READ:
                    ret = SSL_read(ssl, data, size)
                elif op == DO_SSL_HANDSHAKE:
                    ret = SSL_do_handshake(ssl)
                elif op == DO_SSL_SHUTDOWN:
                    ret = SSL_shutdown(ssl)
            if ret > 0:
                if op == DO_SSL_READ:
                    return ret
                elif op == DO_SSL_WRITE:
                    self._flush(start)
                    return ret
            err = SSL_get_error(self.ssl, ret)
            if BIO_pending(self.wbio):
                self._flush(start)
            if err == SSL_ERROR_NONE:
                return ret
            elif err == SSL_ERROR_SSL:
                verify_result = SSL_get_verify_result(ssl)
                if verify_result:
                    raise SSLError("SSL_ERROR_SSL, peer cert verify error: " + str(verify_result))
                raise SSLError("SSL_ERROR_SSL")
            elif err == SSL_ERROR_WANT_READ:
                # xfer data from socket to BIO
                self._update_timeout(start)
                io_size = self.sock.recv_into(self.buf)
                if io_size == 0:
                    return 0
                BIO_write(self.rbio, <char *>self.buf,  io_size)
                # raise SSLWantRead()
            elif err == SSL_ERROR_WANT_WRITE:
                # xfer data from BIO to socket
                self._flush(start)
                # raise SSLWantWrite()
            elif err == SSL_ERROR_WANT_X509_LOOKUP:
                raise SSLError("SSL_ERROR_WANT_X509_LOOKUP")
            elif err == SSL_ERROR_SYSCALL:
                if not self._handle_syscall_error(ret, err):
                    return 0
            elif err == SSL_ERROR_ZERO_RETURN:
                return 0
            elif err == SSL_ERROR_WANT_CONNECT:
                raise SSLError("SSL_ERROR_WANT_CONNECT")
            elif err == SSL_ERROR_WANT_ACCEPT:
                raise SSLError("SSL_ERROR_WANT_ACCEPT")
            else:
                raise SSLError("unknown")

    def __dealloc__(self):
        if self.ssl:
            SSL_free(self.ssl)

    cdef _flush(self, double start):
        'flush write bio to socket'
        cdef int io_size
        io_size = BIO_read(self.wbio, <char *>self.buf, 32 * 1024)
        self._update_timeout(start)
        self.sock.sendall(self.buf[:io_size])

    cdef int _update_timeout(self, double since) except -1:
        cdef double left
        if self.timeout:
            left = self.timeout - (time.time() - since)
            if left <= 0:
                raise socket.timeout('timed out')
            self.sock.settimeout(left)
        return 0

    cdef int _handle_syscall_error(self, int ret, int err) except *:
        cdef:
            int rflags, wflags

        if ERR_peek_error():
            raise SSLError(_pop_and_format_error_list())

        rflags = BIO_test_flags(SSL_get_rbio(self.ssl), 0xFF)
        wflags = BIO_test_flags(SSL_get_wbio(self.ssl), 0xFF)
        if self._check_flags(rflags):
            return 1
        if self._check_flags(wflags):
            return 1
        if ret == 0:
            errmsg = _pop_and_format_error_list()
            if errmsg:
                raise SSLError(errmsg)
            if self.suppress_ragged_eofs:
                return 0
            else:
                raise SSLError("EOF in violation of protocol")
        elif ret == -1:
            IF UNAME_SYSNAME == "Windows":
                PyErr_SetExcFromWindowsErr(SSLError, 0)
            ELSE:
                PyErr_SetFromErrno(SSLError)

    cdef int _check_flags(self, flags) except *:
        if flags & BIO_FLAGS_SHOULD_RETRY:
            if flags & BIO_FLAGS_READ:
                pass
            elif flags & BIO_FLAGS_WRITE:
                pass
            else:
                raise SSLError("BIO_SHOULD_RETRY but neither read nor write set")
            return 1
        return 0

    def get_session(self):
        '''
        Returns the Session (SSL_SESSION wrapper) currently used by this
        Socket.
        '''
        return BorrowedSession(SSL_get_session(self.ssl))


    def state_string(self):
        return <bytes>SSL_state_string(self.ssl)

    def state_string_long(self):
        return <bytes>SSL_state_string_long(self.ssl)

    def ssl_mode_dict(self):
        return ssl_mode2dict(SSL_get_mode(self.ssl))

    def set_auto_retry(self, bool auto_retry not None):
        cdef long flags = SSL_get_mode(self.ssl)
        if auto_retry:
            flags = flags | SSL_MODE_AUTO_RETRY
        else:
            flags = flags & (~ SSL_MODE_AUTO_RETRY)
        SSL_set_mode(self.ssl, flags)

    def enable_debug_print(self):
        SSL_set_info_callback(self.ssl, print_ssl_state_callback)

    def disable_debug_print(self):
        SSL_set_info_callback(self.ssl, NULL)

    def session_reused(self):
        'returns True if the last handshake reused a cached session'
        return SSL_session_reused(self.ssl) != 0

    def verify_result(self):
        'returns True if peer cert was verified'
        if SSL_get_verify_result(self.ssl) == 0:
            return True
        return False


'''
cdef void flush_errors():
    #TODO: better way to clear out previous errors
    IF UNAME_SYSNAME == "Windows":
        PyErr_SetExcFromWindowsErr(SSLError, 0)
    ELSE:
        PyErr_SetFromErrno(SSLError)
    PyErr_Clear()
'''


def ssl_mode2dict(int flags):
    flag_dict = {}
    flag_dict['ENABLE_PARTIAL_WRITE'] = bool(SSL_MODE_ENABLE_PARTIAL_WRITE & flags)
    flag_dict['ACCEPT_MOVING_WRITE_BUFFER'] = bool(SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER & flags)
    flag_dict['AUTO_RETRY'] = bool(SSL_MODE_AUTO_RETRY & flags)
    flag_dict['RELEASE_BUFFERS'] = bool(SSL_MODE_RELEASE_BUFFERS & flags)
    flag_dict['SEND_FALLBACK_SCSV'] = bool(SSL_MODE_SEND_FALLBACK_SCSV & flags)
    return flag_dict


cdef void print_ssl_state_callback(const SSL *ssl, int where, int ret) nogil:
    cdef:
        int w, flags
        const char *s
        BIO *bio

    w = where & ~SSL_ST_MASK
    if w & SSL_ST_CONNECT:
        s = "SSL_connect"
    elif w & SSL_ST_ACCEPT:
        s = "SSL_accept"
    else:
        s = "undefined"

    if where & SSL_CB_LOOP:
        printf("%s:%s\n", s, SSL_state_string_long(ssl))
    elif where & SSL_CB_ALERT:
        if where & SSL_CB_READ:
            bio = SSL_get_rbio(ssl)
        else:
            s = "write"
            bio = SSL_get_wbio(ssl)
        flags = BIO_test_flags(bio, 0xFF)
        if flags & BIO_FLAGS_SHOULD_RETRY:
            printf("(Retry)")
        if flags & BIO_FLAGS_READ:
            printf("(Read)")
        printf("SSL3 alert %s:%s:%s\n", s, 
            SSL_alert_type_string_long(ret), SSL_alert_desc_string_long(ret))
    elif where & SSL_CB_EXIT:
        if ret == 0:
            printf("%s:failed in %s\n", s, SSL_state_string_long(ssl))
        elif ret < 0:
            printf("%s:error in %s\n", s, SSL_state_string_long(ssl))
            s = "read"


class SSLError(socket.error):
    pass


class SSLWantRead(SSLError):
    pass


class SSLWantWrite(SSLError):
    pass


cdef class MemBIO:
    cdef BIO *bio

    def __cinit__(self):
        self.bio = BIO_new(BIO_s_mem())

    def __dealloc__(self):
        if self.bio:
            BIO_free(self.bio)


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
            EVP_EncryptUpdate(ctx, NULL, &outlen, authdata, len(authdata))
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


cdef const EVP_CIPHER* get_aes_gcm_cipher(int keylen) except? NULL:
    if keylen == 128 / 8:
        return EVP_aes_128_gcm()
    elif keylen == 192 / 8:
        return EVP_aes_192_gcm()
    elif keylen == 256 / 8:
        return EVP_aes_256_gcm()
    raise ValueError("keylen must be 128, 192, or 256 bits")


def pkcs7_sign(Certificate signcert not None, PrivateKey key not None, bytes data not None, CertStack certs=None):
    cdef:
        PKCS7* p7 = NULL
        stack_st_X509* cert_stack = NULL
        const unsigned char *data_ptr = data
        EVP_PKEY *pkey
        X509* _signcert
    if certs:
        cert_stack = certs.cert_stack
    pkey = key.private_key
    _signcert = signcert.cert
    data_bio = BIO_new_mem_buf(data_ptr, len(data))
    with nogil:
        p7 = PKCS7_sign(_signcert, pkey, cert_stack, data_bio, PKCS7_BINARY)
        BIO_free(data_bio)
    if not p7:
        raise ValueError(_pop_and_format_error_list())
    return wrap_p7(p7)


def pkcs7_verify(
    PKCS7_digest p7 not None, CertStore trustedcerts not None, CertStack signcerts=None):
    'verify a PKCS7 digest; returns either True or False'
    cdef:
        stack_st_X509 *_signcerts = NULL
    if signcerts:
        _signcerts = signcerts.cert_stack
    if 1 == PKCS7_verify(p7.p7, _signcerts, trustedcerts.cert_store, NULL, NULL, 0):
        return True
    return False  # TODO: better error checking / exceptions?


def pkcs7_encrypt(CertStack keychain not None, bytes data not None):
    'PKCS7 encrypt data with the passed certificates'
    cdef:
        PKCS7* p7 = NULL
        BIO *bio = NULL
        const unsigned char *data_ptr = data
    try:
        bio = BIO_new_mem_buf(data_ptr, len(data))
        p7 = PKCS7_encrypt(keychain.cert_stack, bio, EVP_des_ede3_cbc(), PKCS7_BINARY)
        if not p7:
            raise ValueError(_pop_and_format_error_list())
        return wrap_p7(p7)
    finally:
        if bio:
            BIO_free(bio)


def pkcs7_decrypt(PKCS7_digest p7 not None, PrivateKey priv not None, Certificate pub not None):
    'decrypts the passed PKCS7 structure and returns the plaintext payload'
    cdef:
        BIO *bio = NULL
    bio = BIO_new(BIO_s_mem())
    try:
        if 1 == PKCS7_decrypt(p7.p7, priv.private_key, pub.cert, bio, PKCS7_BINARY):
            size = BIO_pending(bio)
            out = bytearray(size)
            BIO_read(bio, <char*>out, size)
            return out
        raise ValueError(_pop_and_format_error_list())
    finally:
        if bio:
            BIO_free(bio)


cdef wrap_p7(PKCS7 *p7):
    'wrap a bare PKCS7* into a Python extension type'
    digest = PKCS7_digest()
    digest.p7 = p7
    return digest


# TODO: should the "real" OpenSSL PKCS7 struct correspond 1:1 with these digests?
cdef class PKCS7_digest:
    '''
    represents a PKCS7 digest, which may be serialized to various forms
    should not be instantiated directly
    '''
    cdef PKCS7 *p7

    # TODO: how can I ensure these are only made through wrap_p7
    # in order to guarantee self.p7 is not NULL?

    def pem_digest(self):
        cdef:
            BIO *bio = NULL
            int size = 0
        try:
            bio = BIO_new(BIO_s_mem())
            PEM_write_bio_PKCS7(bio, self.p7)
            size = BIO_pending(bio)
            out = bytearray(size)
            BIO_read(bio, <char*>out, size)
            return out
        finally:
            if bio:
                BIO_free(bio)

    @classmethod
    def parse_pem(cls, bytes data not None):
        cdef:
            BIO *bio = NULL
            PKCS7 *p7 = NULL
        try:
            bio = BIO_new_mem_buf(<char *>data, len(data))
            p7 = PEM_read_bio_PKCS7(bio, NULL, NULL, NULL)
            if not p7:
                raise ValueError(_pop_and_format_error_list())
            return wrap_p7(p7)
        finally:
            if bio:
                BIO_free(bio)

    def __dealloc__(self):
        if self.p7:
            PKCS7_free(self.p7)


cdef _library_init():
    SSL_load_error_strings()
    SSL_library_init()
    OpenSSL_add_all_algorithms()


_library_init()
