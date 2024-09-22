/*
 * Copyright (c) 2015-2024 Free Software Foundation, Inc.
 *
 * This file is part of libwget.
 *
 * Libwget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Libwget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libwget.  If not, see <https://www.gnu.org/licenses/>.
 *
 *
 * SSL/TLS routines, with OpenSSL as the backend engine
 *
 * Author: Ander Juaristi
 */

#include <config.h>

#include <dirent.h>
#include <limits.h> // INT_MAX
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/ocsp.h>
#include <openssl/crypto.h>
#include <openssl/ossl_typ.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>

#ifdef _WIN32
#  include <w32sock.h>
#else
#  define FD_TO_SOCKET(x) (x)
#  define SOCKET_TO_FD(x) (x)
#endif

#ifdef LIBRESSL_VERSION_NUMBER
  #ifndef TLS_MAX_VERSION
    #ifndef TLS1_3_VERSION
      #define TLS1_3_VERSION TLS1_2_VERSION
      #define TLS_MAX_VERSION TLS1_2_VERSION
    #else
      #define TLS_MAX_VERSION TLS1_3_VERSION
    #endif
  #endif
#endif

#include <wget.h>
#include "private.h"
#include "net.h"

static wget_tls_stats_callback
	*tls_stats_callback;
static void
	*tls_stats_ctx;

static wget_ocsp_stats_callback
	*ocsp_stats_callback;
static void
	*ocsp_stats_ctx;

static struct config
{
	const char
		*secure_protocol,
		*ca_directory,
		*ca_file,
		*cert_file,
		*key_file,
		*crl_file,
		*ocsp_server,
		*alpn;
	wget_ocsp_db
		*ocsp_cert_cache,
		*ocsp_host_cache;
	wget_tls_session_db
		*tls_session_cache;
	wget_hpkp_db
		*hpkp_cache;
	char
		ca_type,
		cert_type,
		key_type;
	bool
		check_certificate :1,
		check_hostname :1,
		print_info :1,
		ocsp :1,
		ocsp_date :1,
		ocsp_stapling :1,
		ocsp_nonce :1;
} config = {
	.check_certificate = 1,
	.check_hostname = 1,
#ifdef WITH_OCSP
	.ocsp = 0,
	.ocsp_stapling = 1,
#endif
	.ca_type = WGET_SSL_X509_FMT_PEM,
	.cert_type = WGET_SSL_X509_FMT_PEM,
	.key_type = WGET_SSL_X509_FMT_PEM,
	.secure_protocol = "AUTO",
	.ca_directory = "system",
	.ca_file = "system",
#ifdef WITH_LIBNGHTTP2
	.alpn = "h2,http/1.1"
#endif
	};

static int init;
static wget_thread_mutex mutex;

static SSL_CTX *_ctx;
static int ssl_userdata_idx;

/*
 * Constructor & destructor
 */
static void tls_exit(void)
{
	if (mutex) {
		wget_thread_mutex_destroy(&mutex);
#if !defined LIBRESSL_VERSION_NUMBER
		// LibreSSL 3.8.1 doesn't know this function (latest version as of 30.09.2023).
		CRYPTO_free_ex_index(CRYPTO_EX_INDEX_APP, ssl_userdata_idx);
#endif
	}
}

INITIALIZER(tls_init)
{
	if (!mutex) {
		wget_thread_mutex_init(&mutex);

		// Initialize paths while in a thread-safe environment (mostly for _WIN32).
		wget_ssl_default_cert_dir();
		wget_ssl_default_ca_bundle_path();

		ssl_userdata_idx = CRYPTO_get_ex_new_index(
			CRYPTO_EX_INDEX_APP,
			0, NULL,  /* argl, argp */
			NULL,     /* new_func, dup_func, free_func */
			NULL,     /* dup_func */
			NULL      /* free_func */
		);

		atexit(tls_exit);
	}
}

/*
 * SSL/TLS configuration functions
 */

/**
 * \param[in] key An identifier for the config parameter (starting with `WGET_SSL_`) to set
 * \param[in] value The value for the config parameter (a NULL-terminated string)
 *
 * Set a configuration parameter, as a string.
 *
 * The following parameters accept a string as their value (\p key can have any of those values):
 *
 *  - WGET_SSL_SECURE_PROTOCOL: A string describing which SSL/TLS version should be used. It can have either
 *  an arbitrary value, or one of the following fixed values (case does not matter):
 *      - "SSL": SSLv3 will be used. Warning: this protocol is insecure and should be avoided.
 *      - "TLSv1": TLS 1.0 will be used.
 *      - "TLSv1_1": TLS 1.1 will be used.
 *      - "TLSv1_2": TLS 1.2 will be used.
 *      - "TLSv1_3": TLS 1.3 will be used.
 *      - "AUTO": Let the TLS library decide.
 *      - "PFS": Let the TLS library decide, but make sure only forward-secret ciphers are used.
 *
 *  An arbitrary string can also be supplied (an string that's different from any of the previous ones). If that's the case
 *  the string will be directly taken as the priority string and sent to the library. Priority strings provide the greatest flexibility,
 *  but have a library-specific syntax. A GnuTLS priority string will not work if your libwget has been compiled with OpenSSL, for instance.
 *  - WGET_SSL_CA_DIRECTORY: A path to the directory where the root certificates will be taken from
 *  for server cert validation. Every file of that directory is expected to contain an X.509 certificate,
 *  encoded in PEM format. If the string "system" is specified, the system's default directory will be used.
 *  The default value is "system". Certificates get loaded in wget_ssl_init().
 *  - WGET_SSL_CA_FILE: A path to a file containing a single root certificate. This will be used to validate
 *  the server's certificate chain. This option can be used together with `WGET_SSL_CA_DIRECTORY`. The certificate
 *  can be in either PEM or DER format. The format is specified in the `WGET_SSL_CA_TYPE` option (see
 *  wget_ssl_set_config_int()).
 *  - WGET_SSL_CERT_FILE: Set the client certificate. It will be used for client authentication if the server requests it.
 *  It can be in either PEM or DER format. The format is specified in the `WGET_SSL_CERT_TYPE` option (see
 *  wget_ssl_set_config_int()). The `WGET_SSL_KEY_FILE` option specifies the private key corresponding to the cert's
 *  public key. If `WGET_SSL_KEY_FILE` is not set, then the private key is expected to be in the same file as the certificate.
 *  - WGET_SSL_KEY_FILE: Set the private key corresponding to the client certificate specified in `WGET_SSL_CERT_FILE`.
 *  It can be in either PEM or DER format. The format is specified in the `WGET_SSL_KEY_TYPE` option (see
 *  wget_ssl_set_config_int()). IF `WGET_SSL_CERT_FILE` is not set, then the certificate is expected to be in the same file
 *  as the private key.
 *  - WGET_SSL_CRL_FILE: Sets a CRL (Certificate Revocation List) file which will be used to verify client and server certificates.
 *  A CRL file is a black list that contains the serial numbers of the certificates that should not be treated as valid. Whenever
 *  a client or a server presents a certificate in the TLS handshake whose serial number is contained in the CRL, the handshake
 *  will be immediately aborted. The CRL file must be in PEM format.
 *  - WGET_SSL_OCSP_SERVER: Set the URL of the OCSP server that will be used to validate certificates.
 *  OCSP is a protocol by which a server is queried to tell whether a given certificate is valid or not. It's an approach contrary
 *  to that used by CRLs. While CRLs are black lists, OCSP takes a white list approach where a certificate can be checked for validity.
 *  Whenever a client or server presents a certificate in a TLS handshake, the provided URL will be queried (using OCSP) to check whether
 *  that certificate is valid or not. If the server responds the certificate is not valid, the handshake will be immediately aborted.
 *  - WGET_SSL_ALPN: Sets the ALPN string to be sent to the remote host. ALPN is a TLS extension
 *  ([RFC 7301](https://tools.ietf.org/html/rfc7301))
 *  that allows both the server and the client to signal which application-layer protocols they support (HTTP/2, QUIC, etc.).
 *  That information can then be used for the server to ultimately decide which protocol will be used on top of TLS.
 *
 *  An invalid value for \p key will not harm the operation of TLS, but will cause
 *  a complain message to be printed to the error log stream.
 */
void wget_ssl_set_config_string(int key, const char *value)
{
	switch (key) {
	case WGET_SSL_SECURE_PROTOCOL:
		config.secure_protocol = value;
		break;
	case WGET_SSL_CA_DIRECTORY:
		config.ca_directory = value;
		break;
	case WGET_SSL_CA_FILE:
		config.ca_file = value;
		break;
	case WGET_SSL_CERT_FILE:
		config.cert_file = value;
		break;
	case WGET_SSL_KEY_FILE:
		config.key_file = value;
		break;
	case WGET_SSL_CRL_FILE:
		config.crl_file = value;
		break;
	case WGET_SSL_OCSP_SERVER:
		config.ocsp_server = value;
		break;
	case WGET_SSL_ALPN:
		config.alpn = value;
		break;
	default:
		error_printf(_("Unknown configuration key %d (maybe this config value should be of another type?)\n"), key);
	}
}

/**
 * \param[in] key An identifier for the config parameter (starting with `WGET_SSL_`) to set
 * \param[in] value The value for the config parameter (a pointer)
 *
 * Set a configuration parameter, as a libwget object.
 *
 * The following parameters expect an already initialized libwget object as their value.
 *
 * - WGET_SSL_OCSP_CACHE: This option takes a pointer to a \ref wget_ocsp_db
 *  structure as an argument. Such a pointer is returned when initializing the OCSP cache with wget_ocsp_db_init().
 *  The cache is used to store OCSP responses locally and avoid querying the OCSP server repeatedly for the same certificate.
 *  - WGET_SSL_SESSION_CACHE: This option takes a pointer to a \ref wget_tls_session_db structure.
 *  Such a pointer is returned when initializing the TLS session cache with wget_tls_session_db_init().
 *  This option thus sets the handle to the TLS session cache that will be used to store TLS sessions.
 *  The TLS session cache is used to support TLS session resumption. It stores the TLS session parameters derived from a previous TLS handshake
 *  (most importantly the session identifier and the master secret) so that there's no need to run the handshake again
 *  the next time we connect to the same host. This is useful as the handshake is an expensive process.
 *  - WGET_SSL_HPKP_CACHE: Set the HPKP cache to be used to verify known HPKP pinned hosts. This option takes a pointer
 *  to a \ref wget_hpkp_db structure. Such a pointer is returned when initializing the HPKP cache
 *  with wget_hpkp_db_init(). HPKP is a HTTP-level protocol that allows the server to "pin" its present and future X.509
 *  certificate fingerprints, to support rapid certificate change in the event that the higher level root CA
 *  gets compromised ([RFC 7469](https://tools.ietf.org/html/rfc7469)).
 */
void wget_ssl_set_config_object(int key, void *value)
{
	switch (key) {
	case WGET_SSL_OCSP_CACHE:
		config.ocsp_cert_cache = (wget_ocsp_db *) value;
		break;
	case WGET_SSL_SESSION_CACHE:
		config.tls_session_cache = (wget_tls_session_db *) value;
		break;
	case WGET_SSL_HPKP_CACHE:
		config.hpkp_cache = (wget_hpkp_db *) value;
		break;
	default:
		error_printf(_("Unknown configuration key %d (maybe this config value should be of another type?)\n"), key);
	}
}

/**
 * \param[in] key An identifier for the config parameter (starting with `WGET_SSL_`)
 * \param[in] value The value for the config parameter
 *
 * Set a configuration parameter, as an integer.
 *
 * These are the parameters that can be set (\p key can have any of these values):
 *
 *  - WGET_SSL_CHECK_CERTIFICATE: whether certificates should be verified (1) or not (0)
 *  - WGET_SSL_REPORT_INVALID_CERT: currently ignored on the OpenSSL backend
 *  - WGET_SSL_CHECK_HOSTNAME: whether or not to check if the certificate's subject field
 *  matches the peer's hostname. This check is done according to the rules in [RFC 6125](https://tools.ietf.org/html/rfc6125)
 *  and typically involves checking whether the hostname and the common name (CN) field of the subject match.
 *  - WGET_SSL_PRINT_INFO: whether or not information should be printed about the established SSL/TLS handshake (negotiated
 *  ciphersuites, certificates, etc.). The default is no (0).
 *
 * The following three options all can take either `WGET_SSL_X509_FMT_PEM` (to specify the PEM format) or `WGET_SSL_X509_FMT_DER`
 * (for the DER format). The default in for all of them is `WGET_SSL_X509_FMT_PEM`.
 *
 *  - WGET_SSL_CA_TYPE: Specifies what's the format of the root CA certificate(s) supplied with either `WGET_SSL_CA_DIRECTORY`
 *  or `WGET_SSL_CA_FILE`.
 *  - WGET_SSL_CERT_TYPE: Specifies what's the format of the certificate file supplied with `WGET_SSL_CERT_FILE`. **The certificate
 *  and the private key supplied must both be of the same format.**
 *  - WGET_SSL_KEY_TYPE: Specifies what's the format of the private key file supplied with `WGET_SSL_KEY_FILE`. **The private key
 *  and the certificate supplied must both be of the same format.**
 *
 * The following two options control OCSP queries. These don't affect the CRL set with `WGET_SSL_CRL_FILE`, if any.
 * If both CRLs and OCSP are enabled, both will be used.
 *
 *  - WGET_SSL_OCSP: whether or not OCSP should be used. The default is yes (1).
 *  - WGET_SSL_OCSP_STAPLING: whether or not OCSP stapling should be used. The default is yes (1).
 *  - WGET_SSL_OCSP_NONCE: whether or not an OCSP nonce should be sent in the request. The default is yes (1).
 *  If a nonce was sent in the request, the OCSP verification will fail if the response nonce doesn't match.
 *  However if the response does not include a nonce extension, verification will be allowed to continue.
 *  The OCSP nonce extension is not a critical one.
 *  - WGET_SSL_OCSP_DATE: Reject the OCSP response if it's older than 3 days.
 */
void wget_ssl_set_config_int(int key, int value)
{
	switch (key) {
	case WGET_SSL_CHECK_CERTIFICATE:
		config.check_certificate = value;
		break;
	case WGET_SSL_REPORT_INVALID_CERT:
		// The OpenSSL backend doesn't report any certificate errors if certificate verification is disabled
		break;
	case WGET_SSL_CHECK_HOSTNAME:
		config.check_hostname = value;
		break;
	case WGET_SSL_PRINT_INFO:
		config.print_info = value;
		break;
	case WGET_SSL_CA_TYPE:
		config.ca_type = (char) value;
		break;
	case WGET_SSL_CERT_TYPE:
		config.cert_type = (char) value;
		break;
	case WGET_SSL_KEY_TYPE:
		config.key_type = (char) value;
		break;
	case WGET_SSL_OCSP:
		config.ocsp = value;
		break;
	case WGET_SSL_OCSP_STAPLING:
		config.ocsp_stapling = value;
		break;
	case WGET_SSL_OCSP_NONCE:
		config.ocsp_nonce = value;
		break;
	case WGET_SSL_OCSP_DATE:
		config.ocsp_date = value;
		break;
	default:
		error_printf(_("Unknown configuration key %d (maybe this config value should be of another type?)\n"), key);
	}
}

/*
 * SSL/TLS core public API
 */
static int openssl_load_crl(X509_STORE *store, const char *crl_file)
{
	X509_LOOKUP *lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());

	if (!X509_load_crl_file(lookup, crl_file, X509_FILETYPE_PEM))
		return WGET_E_UNKNOWN;
	if (!X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL | X509_V_FLAG_USE_DELTAS))
		return WGET_E_UNKNOWN;

	return 0;
}

#define SET_MIN_VERSION(ctx, ver) \
	if (!SSL_CTX_set_min_proto_version(ctx, ver)) \
		return WGET_E_UNKNOWN

static int openssl_set_priorities(SSL_CTX *ctx, const char *prio)
{
	/*
	 * Default ciphers. This is what will be used
	 * if 'auto' is specified as the priority (currently the default).
	 */
	const char *openssl_ciphers = "HIGH:!aNULL:!RC4:!MD5:!SRP:!PSK";

	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
	SSL_CTX_set_max_proto_version(ctx, TLS_MAX_VERSION);

	if (!wget_strcasecmp_ascii(prio, "SSL")) {
		SET_MIN_VERSION(ctx, SSL3_VERSION);
	} else if (!wget_strcasecmp_ascii(prio, "TLSv1")) {
		SET_MIN_VERSION(ctx, TLS1_VERSION);
	} else if (!wget_strcasecmp_ascii(prio, "TLSv1_1")) {
		SET_MIN_VERSION(ctx, TLS1_1_VERSION);
	/*
	 * Skipping "TLSv1_2".
	 * Checking for "TLSv1_2" is totally redundant - we already set it as the minimum supported version by default
	 */
	} else if (!wget_strcasecmp_ascii(prio, "TLSv1_3")) {
		/* OpenSSL supports TLS 1.3 starting at 1.1.1-beta9 (0x10101009) */
#if OPENSSL_VERSION_NUMBER >= 0x10101009
		SET_MIN_VERSION(ctx, TLS1_3_VERSION);
#else
		info_printf(_("OpenSSL: TLS 1.3 is not supported by your OpenSSL version. Will use TLS 1.2 instead.\n"));
#endif
	} else if (!wget_strcasecmp_ascii(prio, "PFS")) {
		/* Forward-secrecy - Disable RSA key exchange! */
		openssl_ciphers = "HIGH:!aNULL:!RC4:!MD5:!SRP:!PSK:!kRSA";
	} else if (prio && wget_strcasecmp_ascii(prio, "AUTO") && wget_strcasecmp_ascii(prio, "TLSv1_2")) {
		openssl_ciphers = prio;
	}

	if (!SSL_CTX_set_cipher_list(ctx, openssl_ciphers)) {
		error_printf(_("OpenSSL: Invalid priority string '%s'\n"), prio);
		return WGET_E_INVALID;
	}

	return 0;
}

static int openssl_load_trust_file(SSL_CTX *ctx, const char *dir, const char *file)
{
	char sbuf[256];
	wget_buffer buf;
	int rc;

	wget_buffer_init(&buf, sbuf, sizeof(sbuf));

	wget_buffer_printf(&buf, "%s/%s", dir, file);
	rc = (SSL_CTX_load_verify_locations(ctx, buf.data, NULL) ? 0 : -1);

	wget_buffer_deinit(&buf);

	return rc;
}

static int openssl_load_trust_files_from_directory(SSL_CTX *ctx, const char *dirname)
{
	DIR *dir;
	struct dirent *dp;
	int loaded = 0;

	if ((dir = opendir(dirname))) {
		while ((dp = readdir(dir))) {
			if (*dp->d_name == '.')
				continue;

			if (wget_match_tail_nocase(dp->d_name, ".pem")
				&& openssl_load_trust_file(ctx, dirname, dp->d_name) == 0)
			{
				loaded++;
			}
		}

		closedir(dir);
	}

	return loaded;
}

static int openssl_load_trust_files(SSL_CTX *ctx, const char *dir)
{
	int retval;

	if (!strcmp(dir, "system")) {
		/*
		 * Load system-provided certificates.
		 * Either "/etc/ssl/certs" or OpenSSL's default (if provided).
		 */
		if (SSL_CTX_set_default_verify_paths(ctx)) {
			retval = 0;
			goto end;
		}

		dir = wget_ssl_default_cert_dir();
		info_printf(_("OpenSSL: Could not load certificates from default paths. Falling back to '%s'."), dir);
	}

	retval = openssl_load_trust_files_from_directory(ctx, dir);
	if (retval == 0)
		error_printf(_("OpenSSL: No certificates could be loaded from directory '%s'\n"), dir);
	else if (retval > 0)
		debug_printf("OpenSSL: Loaded %d certificates\n", retval);
	else
		error_printf(_("OpenSSL: Could not open directory '%s'. No certificates were loaded.\n"), dir);

end:
	return retval;
}

static int verify_hpkp(const char *hostname, X509 *subject_cert, wget_hpkp_stats_result *hpkp_stats)
{
	int retval, spki_len;
	unsigned char *spki = NULL;

	/* Get certificate's public key in DER format */
	spki_len = i2d_PUBKEY(X509_get0_pubkey(subject_cert), &spki);
	if (spki_len <= 0)
		return -1;

	/* Lookup database */
	retval = wget_hpkp_db_check_pubkey(config.hpkp_cache,
		hostname,
		spki, spki_len);

	switch (retval) {
	case 1:
		debug_printf("Matching HPKP pinning found for host '%s'\n", hostname);
		*hpkp_stats = WGET_STATS_HPKP_MATCH;
		retval = 0;
		break;
	case 0:
		debug_printf("No HPKP pinning found for host '%s'\n", hostname);
		*hpkp_stats = WGET_STATS_HPKP_NO;
		retval = 1;
		break;
	case -2:
		debug_printf("Public key for host '%s' does not match\n", hostname);
		*hpkp_stats = WGET_STATS_HPKP_NOMATCH;
		retval = -1;
		break;
	default:
		debug_printf("Could not check HPKP pinning for host '%s' (%d)\n", hostname, retval);
		*hpkp_stats = WGET_STATS_HPKP_ERROR;
		retval = 0;
	}

	OPENSSL_free(spki);
	return retval;
}

static int check_cert_chain_for_hpkp(STACK_OF(X509) *certs, const char *hostname, wget_hpkp_stats_result *hpkp_stats)
{
	int retval, pin_ok = 0;
	X509 *cert;
	unsigned cert_list_size = sk_X509_num(certs);

	for (unsigned i = 0; i < cert_list_size; i++) {
		cert = sk_X509_value(certs, i);

		if ((retval = verify_hpkp(hostname, cert, hpkp_stats)) >= 0)
			pin_ok = 1;
		if (retval == 1)
			break;
	}

	return pin_ok;
}

struct verification_flags {
	X509_STORE
		*certstore;
	wget_vector
		*ocsp_stapled_cache;
};

struct ocsp_stapled_response {
	int status;
	OCSP_CERTID *certid;
};

static int check_ocsp_response(OCSP_RESPONSE *,
		STACK_OF(X509) *,
		X509_STORE *,
		bool,
		void (*ocsp_singleresp_callback_func)(const OCSP_SINGLERESP *, int, void *arg), void *func_arg);

static char *compute_cert_fingerprint(X509 *cert);

static int _ocsp_stapled_response_compare_func(const void *elem1, const void *elem2)
{
	const OCSP_CERTID *certid = elem1;
	const struct ocsp_stapled_response *stored = elem2;
	return OCSP_id_cmp(certid, stored->certid);
}

static void _ocsp_stapled_response_destroy_func(void *elem)
{
	struct ocsp_stapled_response *resp = elem;
	OCSP_CERTID_free((OCSP_CERTID *) resp->certid);
	xfree(elem);
}

static wget_vector *ocsp_create_stapled_response_vector(void)
{
	wget_vector *vec = wget_vector_create(5, _ocsp_stapled_response_compare_func);
	if (!vec)
		return NULL;

	wget_vector_set_resize_factor(vec, 1);
	wget_vector_set_destructor(vec, _ocsp_stapled_response_destroy_func);
	return vec;
}

static void ocsp_destroy_stapled_response_vector(wget_vector **vec)
{
	wget_vector_free(vec);
}

static void ocsp_stapled_responses_add_single(const OCSP_SINGLERESP *singleresp, int status, void *arg)
{
	wget_vector *vec = arg;
	struct ocsp_stapled_response *resp = wget_malloc(sizeof(struct ocsp_stapled_response));
	OCSP_CERTID *certid = OCSP_CERTID_dup(OCSP_SINGLERESP_get0_id(singleresp));

	if (resp && certid) {
		resp->status = status;
		resp->certid = certid;
		wget_vector_insert(vec, (const void *) resp, 0);
	} else {
		if (certid)
			OCSP_CERTID_free(certid);
		xfree(resp);
	}
}

static const struct ocsp_stapled_response *ocsp_stapled_response_get(const X509 *cert, const X509 *issuer,
								     const wget_vector *vec)
{
	OCSP_CERTID *certid = OCSP_cert_to_id(NULL, cert, issuer);
	int pos = wget_vector_find(vec, (const void *) certid);

	OCSP_CERTID_free(certid);

	return wget_vector_get(vec, pos);
}

static int ocsp_lookup_in_cache(X509 *cert, X509 *issuer,
				const wget_vector *ocsp_stapled_cache, const wget_ocsp_db *ocsp_cert_cache,
				int *revoked, const char **cache_origin)
{
	const struct ocsp_stapled_response *ocsp_stapled_resp;

	/* Check if there's already a stapled OCSP response in our cache */
	ocsp_stapled_resp = ocsp_stapled_response_get(cert, issuer, ocsp_stapled_cache);
	if (ocsp_stapled_resp &&
			(ocsp_stapled_resp->status == V_OCSP_CERTSTATUS_GOOD || ocsp_stapled_resp->status == V_OCSP_CERTSTATUS_REVOKED)) {
		*revoked = (ocsp_stapled_resp->status == V_OCSP_CERTSTATUS_REVOKED);
		*cache_origin = "stapled";
		return 1;
	}

	if (ocsp_cert_cache) {
		/* Compute cert fingerprint */
		char *fingerprint = compute_cert_fingerprint(cert);
		if (!fingerprint)
			return -1; /* Treat this as an error */

		/* Check if there's already an OCSP response stored in cache */
		if (wget_ocsp_fingerprint_in_cache(ocsp_cert_cache, fingerprint, revoked)) {
			/* Found cert's fingerprint in cache */
			xfree(fingerprint);
			*cache_origin = "cached";
			return 1;
		}

		xfree(fingerprint);
	}

	return 0;
}

static int ocsp_resp_cb(SSL *s, void *arg)
{
	int result;
	long ocsp_resp_len;
	const unsigned char *ocsp_resp_raw = NULL;
	OCSP_RESPONSE *ocspresp;
	STACK_OF(X509) *certstack;
	struct verification_flags *ocsp_verif = NULL;

	(void) arg;  // Unused

	ocsp_verif = SSL_get_ex_data(s, ssl_userdata_idx);
	if (!ocsp_verif) {
		error_printf(_("Could not get user data to verify stapled OCSP.\n"));
		return 0;
	}

	ocsp_resp_len = SSL_get_tlsext_status_ocsp_resp(s, &ocsp_resp_raw);
	if (ocsp_resp_len == -1) {
		debug_printf("No stapled OCSP response was received. Continuing.\n");
		return 1;
	}

	ocspresp = d2i_OCSP_RESPONSE(NULL, &ocsp_resp_raw, ocsp_resp_len);
	if (!ocspresp) {
		error_printf(_("Got a stapled OCSP response, but could not parse it. Aborting.\n"));
		return 0;
	}

	certstack = SSL_get_peer_cert_chain(s);
	if (!certstack) {
		error_printf(_("Could not get server's cert stack\n"));
		return 0;
	}

	result = check_ocsp_response(ocspresp,
		certstack,
		ocsp_verif->certstore,
		0,
		ocsp_stapled_responses_add_single, ocsp_verif->ocsp_stapled_cache);

	if (result == -1) {
		OCSP_RESPONSE_free(ocspresp);
		error_printf(_("Could not verify stapled OCSP response. Aborting.\n"));
		return 0;
	}

	OCSP_RESPONSE_free(ocspresp);
	debug_printf("*** Stapled OCSP response verified. Length: %ld. Status: OK\n", ocsp_resp_len);

	return 1;
}

static OCSP_REQUEST *send_ocsp_request(const char *uri,
		OCSP_CERTID *certid,
		wget_http_response **response)
{
	OCSP_REQUEST *ocspreq;
	wget_http_response *resp;
	unsigned char *ocspreq_bytes = NULL;
	size_t ocspreq_bytes_len;

	ocspreq = OCSP_REQUEST_new();
	if (!ocspreq)
		goto end;

	if (!OCSP_request_add0_id(ocspreq, certid)) {
		OCSP_REQUEST_free(ocspreq);
		ocspreq = NULL;
		goto end;
	}

	if (config.ocsp_nonce && !OCSP_request_add1_nonce(ocspreq, NULL, 0)) {
		OCSP_REQUEST_free(ocspreq);
		ocspreq = NULL;
		goto end;
	}

	ocspreq_bytes_len = i2d_OCSP_REQUEST(ocspreq, &ocspreq_bytes);
	if (!ocspreq_bytes || !ocspreq_bytes_len) {
		OCSP_REQUEST_free(ocspreq);
		ocspreq = NULL;
		goto end;
	}

	resp = wget_http_get(
		WGET_HTTP_URL, uri,
		WGET_HTTP_SCHEME, "POST",
		WGET_HTTP_HEADER_ADD, "Accept-Encoding", "identity",
		WGET_HTTP_HEADER_ADD, "Accept", "*/*",
		WGET_HTTP_HEADER_ADD, "Content-Type", "application/ocsp-request",
		WGET_HTTP_MAX_REDIRECTIONS, 5,
		WGET_HTTP_BODY, ocspreq_bytes, ocspreq_bytes_len,
		WGET_HTTP_DEBUG_SKIP_BODY,
		0);

	OPENSSL_free(ocspreq_bytes);

	if (resp) {
		*response = resp;
	} else {
		OCSP_REQUEST_free(ocspreq);
		ocspreq = NULL;
	}

end:
	return ocspreq;
}

static const char *get_printable_ocsp_reason_desc(int reason)
{
	switch (reason) {
	case OCSP_REVOKED_STATUS_NOSTATUS:
		return "not given";
	case OCSP_REVOKED_STATUS_UNSPECIFIED:
		return "unspecified";
	case OCSP_REVOKED_STATUS_KEYCOMPROMISE:
		return "key compromise";
	case OCSP_REVOKED_STATUS_CACOMPROMISE:
		return "CA compromise";
	case OCSP_REVOKED_STATUS_AFFILIATIONCHANGED:
		return "affiliation changed";
	case OCSP_REVOKED_STATUS_SUPERSEDED:
		return "superseded";
	case OCSP_REVOKED_STATUS_CESSATIONOFOPERATION:
		return "cessation of operation";
	case OCSP_REVOKED_STATUS_CERTIFICATEHOLD:
		return "certificate hold";
	case OCSP_REVOKED_STATUS_REMOVEFROMCRL:
		return "remove from CRL";
	default:
		return "unknown reason";
	}
}

static void print_ocsp_response_status(int status)
{
	char msg[64];
	const char *status_string;

	switch (status) {
	case OCSP_RESPONSE_STATUS_SUCCESSFUL:
		status_string = "successful";
		break;
	case OCSP_RESPONSE_STATUS_MALFORMEDREQUEST:
		status_string = "malformed request";
		break;
	case OCSP_RESPONSE_STATUS_INTERNALERROR:
		status_string = "internal error";
		break;
	case OCSP_RESPONSE_STATUS_TRYLATER:
		status_string = "try later";
		break;
	case OCSP_RESPONSE_STATUS_SIGREQUIRED:
		status_string = "signature required";
		break;
	case OCSP_RESPONSE_STATUS_UNAUTHORIZED:
		status_string = "unauthorized";
		break;
	default:
		wget_snprintf(msg, sizeof(msg), "unknown status code %d", status);
		status_string = msg;
		break;
	}

	debug_printf("*** OCSP response status: %s\n", status_string);
}

static void print_ocsp_cert_status(int status, int reason)
{
	char msg[64];
	const char *reason_string;

	switch (status) {
	case V_OCSP_CERTSTATUS_GOOD:
		reason_string = "good";
		break;
	case V_OCSP_CERTSTATUS_UNKNOWN:
		reason_string = "unknown";
		break;
	case V_OCSP_CERTSTATUS_REVOKED:
		wget_snprintf(msg, sizeof(msg), "revoked (%s)", get_printable_ocsp_reason_desc(reason));
		reason_string = msg;
		break;
	default:
		reason_string = "invalid status code";
		break;
	}

	debug_printf("*** OCSP cert status: %s\n", reason_string);
}

static void print_openssl_time(const char *prefix, const ASN1_GENERALIZEDTIME *t)
{
	int nread;
	char buf[128];
	BIO *mem = BIO_new(BIO_s_mem());

	ASN1_GENERALIZEDTIME_print(mem, t);

	nread = BIO_read(mem, buf, sizeof(buf)-1);
	if (nread > 0) {
		buf[nread] = '\0';
		debug_printf("%s%s\n", prefix, buf);
	} else {
		error_printf(_("ERROR: print_openssl_time: BIO_read failed\n"));
	}

	BIO_free_all(mem);
}

static int check_ocsp_response_times(const ASN1_GENERALIZEDTIME *thisupd,
				     const ASN1_GENERALIZEDTIME *nextupd)
{
	int day, sec, retval = -1;
	ASN1_TIME *now;

	now = ASN1_TIME_adj(NULL, time(NULL), 0, 0);
	if (!now) {
		error_printf(_("Could not get current time!\n"));
		return -1;
	}

	print_openssl_time("*** OCSP issued time: ", thisupd);

	if (!nextupd) {
		debug_printf("OCSP nextUpd not set. Checking thisUpd is not too old.\n");
		if (!ASN1_TIME_diff(&day, &sec, now, thisupd)) {
			error_printf(_("Could not compute time difference for thisUpd. Aborting.\n"));
			goto end;
		}
		if (day < -3) {
			error_printf(_("*** OCSP response thisUpd is too old. Aborting.\n"));
			goto end;
		}

		retval = 0;
		goto end;
	}

	print_openssl_time("*** OCSP update time: ", nextupd);

	if (!ASN1_TIME_diff(&day, &sec, now, nextupd)) {
		error_printf(_("Could not compute time difference for nextUpd. Aborting.\n"));
		goto end;
	}

	if (day < 0 || (day == 0 && sec < 0)) {
		error_printf(_("*** OCSP next update is in the past!\n"));
		goto end;
	}

	retval = 0;

end:
	ASN1_STRING_free(now);
	return retval;
}

static int check_ocsp_response(OCSP_RESPONSE *ocspresp,
		STACK_OF(X509) *certstack,
		X509_STORE *certstore,
		bool check_time,
		void (*ocsp_singleresp_callback_func)(const OCSP_SINGLERESP *, int, void *arg), void *func_arg)
{
	int
		retval = -1,
		status, reason;
	OCSP_BASICRESP *ocspbs = NULL;
	OCSP_SINGLERESP *single;
	ASN1_GENERALIZEDTIME *revtime = NULL,
			*thisupd = NULL,
			*nextupd = NULL;

	status = OCSP_response_status(ocspresp);
	print_ocsp_response_status(status);

	if (status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
		error_printf(_("Unsuccessful OCSP response\n"));
		goto end;
	}

	if (!(ocspbs = OCSP_response_get1_basic(ocspresp)))
		goto end;

	if (!OCSP_basic_verify(ocspbs, certstack, certstore, 0)) {
		error_printf(_("Could not verify OCSP certificate chain\n"));
		goto end;
	}

	single = OCSP_resp_get0(ocspbs, 0);
	if (!single) {
		error_printf(_("Could not parse OCSP single response\n"));
		goto end;
	}

	// thisupd and nextupd are internal pointers and MUST NOT be freed
	status = OCSP_single_get0_status(single, &reason, &revtime, &thisupd, &nextupd);
	if (status == -1) {
		error_printf(_("Could not obtain OCSP response status\n"));
		goto end;
	}

	print_ocsp_cert_status(status, reason);

	if (status == V_OCSP_CERTSTATUS_REVOKED) {
		print_openssl_time("*** Certificate revoked by OCSP at: ", revtime);
		retval = 1; // Failure
		goto end;
	}

	/* Check time is within an acceptable range */
	if (check_time) {
		if (!thisupd) {
			error_printf(_("Could not get 'thisUpd' from OCSP response. Cannot check time.\n"));
			goto end;
		}

		if (check_ocsp_response_times(thisupd, nextupd) < 0) {
			retval = 1; // Failure
			goto end;
		}
	}

	/*
	 * Add response to cache
	 * Other than these two, the cert could also be V_OCSP_CERTSTATUS_UNKNOWN. We're not adding these ones to the cache.
	 */
	if (ocsp_singleresp_callback_func && (status == V_OCSP_CERTSTATUS_GOOD || status == V_OCSP_CERTSTATUS_REVOKED))
		ocsp_singleresp_callback_func(single, status, func_arg);

	retval = 0; // Success!

end:
	if (ocspbs)
		OCSP_BASICRESP_free(ocspbs);
	return retval;
}

static int verify_ocsp(const char *ocsp_uri,
		X509 *subject_cert, X509 *issuer_cert,
		STACK_OF(X509) *certs, X509_STORE *certstore,
		bool check_time, bool check_nonce)
{
	int retval;
	wget_http_response *resp;
	const unsigned char *body;
	OCSP_CERTID *certid;
	OCSP_REQUEST *ocspreq;
	OCSP_RESPONSE *ocspresp;
	OCSP_BASICRESP *ocspbs = NULL;

	/* Generate CertID and OCSP request */
	certid = OCSP_cert_to_id(EVP_sha1(), subject_cert, issuer_cert);

	/* Send OCSP request to server, via HTTP */
	if (!(ocspreq = send_ocsp_request(ocsp_uri, certid, &resp)) || !resp || !resp->body)
		return -1;

	/* Check server's OCSP response */
	body = (const unsigned char *) resp->body->data;
	ocspresp = d2i_OCSP_RESPONSE(NULL, &body, resp->body->length);
	if (!ocspresp) {
		wget_http_free_response(&resp);
		OCSP_REQUEST_free(ocspreq);
		return -1;
	}

	if ((retval = check_ocsp_response(ocspresp, certs, certstore, check_time, NULL, NULL)) != 0)
		goto end;

	/* If we sent a nonce, verify the server's response contains the nonce */
	if (check_nonce) {
		if (!(ocspbs = OCSP_response_get1_basic(ocspresp))) {
			error_printf(_("Could not obtain OCSP_BASICRESPONSE\n"));
			retval = -1;
			goto end;
		}

		if (!OCSP_check_nonce(ocspreq, ocspbs)) {
			error_printf(_("OCSP nonce does not match\n"));
			retval = 1; // Failure
			goto end;
		}

		OCSP_BASICRESP_free(ocspbs);
		ocspbs = NULL;
	}

	retval = 0; // Success

end:
	if (ocspbs)
		OCSP_BASICRESP_free(ocspbs);
	wget_http_free_response(&resp);
	OCSP_RESPONSE_free(ocspresp);
	OCSP_REQUEST_free(ocspreq);
	return retval;
}

static char *read_ocsp_uri_from_certificate(X509 *cert)
{
	STACK_OF(OPENSSL_STRING) *str_stack = X509_get1_ocsp(cert);

	if (str_stack && sk_OPENSSL_STRING_num(str_stack) > 0) {
		char *uri = wget_strdup(sk_OPENSSL_STRING_value(str_stack, 0));
		X509_email_free(str_stack); // utterly misnamed, it simply frees a stack of strings.
		return uri;
	}

	return NULL;
}

static char *compute_cert_fingerprint(X509 *cert)
{
	/*
	 * OpenSSL does not provide a function that calculates the cert fingerprint directly
	 * (like GnuTLS' gnutls_x509_crt_get_fingerprint()), but we can code it away. Fingerprint
	 * is basically a SHA-256 hash of the DER-encoded certificate.
	 */
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	char *hexstring = NULL;
	unsigned char
		*der_output = NULL,
		*digest_output = NULL;
	int
		der_length,
		digest_length,
		hexstring_length;

	if ((der_length = i2d_X509(cert, &der_output)) < 0)
		goto bail;

	/* Compute SHA-256 digest of the DER-encoded certificate */
	digest_length = EVP_MD_size(EVP_sha256());
	digest_output = wget_malloc(digest_length);
	if (!digest_output)
		goto bail;

	if (!EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
		goto bail;
	if (!EVP_DigestUpdate(mdctx, der_output, der_length))
		goto bail;
	if (!EVP_DigestFinal_ex(mdctx, digest_output, NULL))
		goto bail;

	OPENSSL_free(der_output);
	der_output = NULL;

	EVP_MD_CTX_free(mdctx);
	mdctx = NULL;

	/* Convert SHA-256 digest to hex string */
	hexstring_length = (digest_length * 2) + 1;
	hexstring = wget_malloc(hexstring_length);
	if (!hexstring)
		goto bail;

	wget_memtohex(digest_output, digest_length, hexstring, hexstring_length);
	xfree(digest_output);
	return hexstring;

bail:
	xfree(hexstring);
	xfree(digest_output);
	if (der_output)
		OPENSSL_free(der_output);
	if (mdctx)
		EVP_MD_CTX_free(mdctx);
	return NULL;
}

static X509 *find_issuer_cert(const STACK_OF(X509) *certs, X509 *subject, unsigned starting_idx)
{
	X509 *candidate;
	unsigned cert_chain_size = sk_X509_num(certs), next = starting_idx;

	for (unsigned i = 0; i < cert_chain_size - 1; i++) {
		next = (next == cert_chain_size - 1) ? 0 : next + 1;
		candidate = sk_X509_value(certs, next);
		if (candidate && X509_check_issued(candidate, subject) == X509_V_OK)
			return candidate;
	}

	return NULL;
}

static int check_cert_chain_for_ocsp(STACK_OF(X509) *certs, X509_STORE *store, const char *hostname,
				     wget_vector *ocsp_stapled_cache)
{
	wget_ocsp_stats_data stats;
	int num_ok = 0, num_revoked = 0, num_ignored = 0, revoked, ocsp_ok, retval;
	const char
		*ocsp_uri = NULL,
		*fingerprint,
		*cache_origin;
	X509 *cert, *issuer_cert;
	unsigned cert_list_size = sk_X509_num(certs);

	for (unsigned i = 0; i < cert_list_size; i++) {
		cert = sk_X509_value(certs, i);
		issuer_cert = find_issuer_cert(certs, cert, i);

		if (!issuer_cert)
			break;

		/*
		 * Check if there's already a valid (stapled or cached) OCSP response in our cache
		 * for this cert
		 */
		retval = ocsp_lookup_in_cache(cert, issuer_cert, ocsp_stapled_cache, config.ocsp_cert_cache,
					      &revoked, &cache_origin);
		if (retval == 1) {
			if (revoked) {
				debug_printf("Certificate %u has been revoked (%s response)\n", i, cache_origin);
				num_revoked++;
			} else {
				debug_printf("Certificate %u is valid (%s response)\n", i, cache_origin);
				num_ok++;
			}

			continue;
		}

		if (retval == -1) {
			error_printf(_("Could not compute certificate fingerprint for cert %u\n"), i);
			return 0;  // treat this as an error
		}

		/*
		 * We don't have an OCSP response for this certificate.
		 * So now it's time to ask the OCSP server.
		 */

		if (!config.ocsp_server) {
			ocsp_uri = read_ocsp_uri_from_certificate(cert);
			if (!ocsp_uri) {
				debug_printf("OCSP URI not given and not found in certificate. Skipping OCSP check for cert %u.\n",
						i);
				num_ignored++;
				continue;
			}
		}

		debug_printf("Contacting OCSP server. URI: %s\n",
				config.ocsp_server ? config.ocsp_server : ocsp_uri);

		ocsp_ok = verify_ocsp(config.ocsp_server ? config.ocsp_server : ocsp_uri,
				cert, issuer_cert, certs, store,
				config.ocsp_date, config.ocsp_nonce);
		if (ocsp_ok == 0)
			num_ok++;
		else if (ocsp_ok == 1)
			num_revoked++;
		else
			num_ignored++;

		/* Add the certificate to the OCSP cache */
		fingerprint = compute_cert_fingerprint(cert);
		if (!fingerprint) {
			error_printf(_("Could not compute certificate fingerprint for cert %u\n"), i);
			return 0;
		}

		if (ocsp_ok == 0 || ocsp_ok == 1) {
			wget_ocsp_db_add_fingerprint(config.ocsp_cert_cache,
				fingerprint,
				time(NULL) + 3600, /* Cache entry valid for 1 hour */
				(ocsp_ok == 0));   /* valid? */
		}

		xfree(fingerprint);
		xfree(ocsp_uri);
	}

	if (ocsp_stats_callback) {
		stats.hostname = hostname;
		stats.nvalid = num_ok;
		stats.nrevoked = num_revoked;
		stats.nignored = num_ignored;
		stats.stapling = 0;
		ocsp_stats_callback(&stats, ocsp_stats_ctx);
	}

	return (num_revoked == 0);
}

static int openssl_init(SSL_CTX *ctx)
{
	int retval = 0;
	X509_STORE *store;

	if (!config.check_certificate) {
		SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
		info_printf(_("Certificate check disabled. Peer's certificate will NOT be checked.\n"));
		goto end;
	}

	store = SSL_CTX_get_cert_store(ctx);
	if (!store) {
		error_printf(_("OpenSSL: Could not obtain cert store\n"));
		retval = WGET_E_UNKNOWN;
		goto end;
	}

	if (config.ca_directory && *config.ca_directory) {
		retval = openssl_load_trust_files(ctx, config.ca_directory);
		if (retval < 0)
			goto end;

		if (config.crl_file) {
			/* Load CRL file in PEM format. */
			if ((retval = openssl_load_crl(store, config.crl_file)) < 0) {
				error_printf(_("Could not load CRL from '%s' (%d)\n"),
					config.crl_file,
					retval);
				goto end;
			}
		}

		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
	}

	if (config.ca_file && !wget_strcmp(config.ca_file, "system"))
		config.ca_file = wget_ssl_default_ca_bundle_path();
	/* Load individual CA file, if requested */
	if (config.ca_file && *config.ca_file
		&& !SSL_CTX_load_verify_locations(ctx, config.ca_file, NULL))
	{
		error_printf(_("Could not load CA certificate from file '%s'\n"), config.ca_file);
	}

#ifdef WITH_OCSP
	if (config.ocsp_stapling)
		SSL_CTX_set_tlsext_status_cb(ctx, ocsp_resp_cb);
#endif

	retval = openssl_set_priorities(ctx, config.secure_protocol);

end:
	return retval;
}

static void openssl_deinit(SSL_CTX *ctx)
{
	SSL_CTX_free(ctx);
}

/**
 * Initialize the SSL/TLS engine as a client.
 *
 * This function assumes the caller is an SSL client connecting to a server.
 * The functions wget_ssl_open(), wget_ssl_close() and wget_ssl_deinit() can be called
 * after this.
 *
 * This is where the root certificates get loaded from the folder specified in the
 * `WGET_SSL_CA_DIRECTORY` parameter. If any of the files in that folder cannot be loaded
 * for whatever reason, that file will be silently skipped without harm (a message will be
 * printed to the debug log stream).
 *
 * CLRs and private keys and their certificates are also loaded here.
 *
 * On systems with automatic library constructors/destructors, this function
 * is thread-safe. On other systems it is not thread-safe.
 *
 * This function may be called several times. Only the first call really
 * takes action.
 */
void wget_ssl_init(void)
{
	wget_thread_mutex_lock(mutex);

	if (!init) {
		_ctx = SSL_CTX_new(TLS_client_method());
		if (_ctx && openssl_init(_ctx) == 0) {
			init++;
#ifdef LIBRESSL_VERSION_NUMBER
			debug_printf("LibreSSL initialized\n");
#else
			debug_printf("OpenSSL initialized\n");
#endif
		} else {
			error_printf(_("Could not initialize OpenSSL\n"));
		}
	}

	wget_thread_mutex_unlock(mutex);
}

/**
 * Deinitialize the SSL/TLS engine, after it has been initialized
 * with wget_ssl_init().
 *
 * This function unloads everything that was loaded in wget_ssl_init().
 *
 * On systems with automatic library constructors/destructors, this function
 * is thread-safe. On other systems it is not thread-safe.
 *
 * This function may be called several times. Only the last deinit really
 * takes action.
 */
void wget_ssl_deinit(void)
{
	wget_thread_mutex_lock(mutex);

	if (init == 1)
		openssl_deinit(_ctx);

	if (init > 0)
		init--;

	wget_thread_mutex_unlock(mutex);
}

static int ssl_resume_session(SSL *ssl, const char *hostname)
{
	void *sess = NULL;
	size_t sesslen;
	SSL_SESSION *ssl_session;

	if (!config.tls_session_cache)
		return 0;

	if (wget_tls_session_get(config.tls_session_cache,
			hostname,
			&sess, &sesslen) == 0
		&& sess)
	{
		debug_printf("Found cached session data for host '%s'\n",hostname);
		ssl_session = d2i_SSL_SESSION(NULL,
				(const unsigned char **) &sess,
				(long) sesslen);
		if (!ssl_session) {
			error_printf(_("OpenSSL: Could not parse cached session data.\n"));
			return -1;
		}
#if OPENSSL_VERSION_NUMBER >= 0x10101000 && !defined LIBRESSL_VERSION_NUMBER
		if (!SSL_SESSION_is_resumable(ssl_session))
			return -1;
#endif
		if (!SSL_set_session(ssl, ssl_session)) {
			error_printf(_("OpenSSL: Could not set session data.\n"));
			return -1;
		}

		SSL_SESSION_free(ssl_session);
		return 1;
	}

	return 0;
}

static int ssl_save_session(const SSL *ssl, const char *hostname)
{
	void *sess = NULL;
	unsigned long sesslen;
	SSL_SESSION *ssl_session = SSL_get0_session(ssl);

	if (!ssl_session || !config.tls_session_cache)
		return 0;

	sesslen = i2d_SSL_SESSION(ssl_session, (unsigned char **) &sess);
	if (sesslen) {
		wget_tls_session_db_add(config.tls_session_cache,
			wget_tls_session_new(hostname,
				18 * 3600, /* session valid for 18 hours */
				sess, sesslen));
		OPENSSL_free(sess);
		return 1;
	}

	return 0;
}

static int wait_2_read_and_write(int sockfd, int timeout)
{
	int retval = wget_ready_2_transfer(sockfd,
			timeout,
			WGET_IO_READABLE | WGET_IO_WRITABLE);

	if (retval == 0)
		retval = WGET_E_TIMEOUT;

	return retval;
}

static bool ssl_set_alpn_offering(SSL *ssl, const char *alpn)
{
	int ret = WGET_E_UNKNOWN;
	const char *s, *e;
	char sbuf[32];
	wget_buffer buf;

	wget_buffer_init(&buf, sbuf, sizeof(sbuf));

	for (s = e = alpn; *e; s = e + 1) {
		if ((e = strchrnul(s, ',')) != s) {
			if (e - s > 64) { // let's be reasonable
				debug_printf("ALPN protocol too long %.*s\n", (int) (e - s), s);
				continue;
			}

			debug_printf("ALPN offering %.*s\n", (int) (e - s), s);
			wget_buffer_memset_append(&buf, (e - s) & 0x7F, 1); // length of protocol string
			wget_buffer_memcat(&buf, s, e - s);
		}
	}

	if (buf.length) {
		if (SSL_set_alpn_protos(ssl, (unsigned char *) buf.data, (unsigned) buf.length)) {
			debug_printf("OpenSSL: ALPN: Could not set ALPN offering");
		} else
			ret = WGET_E_SUCCESS;
	}

	wget_buffer_deinit(&buf);

	return ret;
}

static void ssl_set_alpn_selected_protocol(const SSL *ssl, wget_tcp *tcp, wget_tls_stats_data *stats)
{
	const unsigned char *data;
	unsigned int datalen;

	SSL_get0_alpn_selected(ssl, &data, &datalen);

	if (data && datalen) {
		debug_printf("ALPN: Server accepted protocol '%.*s'\n", (int) datalen, data);

		/* Success - Set selected protocol and update stats */
		if (stats)
			stats->alpn_protocol = wget_strmemdup(data, datalen);

		if (datalen == 2 && data[0] == 'h' && data[1] == '2') {
			tcp->protocol = WGET_PROTOCOL_HTTP_2_0;
			if (stats)
				stats->http_protocol = WGET_PROTOCOL_HTTP_2_0;
		}
	}
}

static int get_tls_version(const SSL *ssl)
{
	int version = SSL_version(ssl);

	/*
	 * These values are mapped to the return values of GnuTLS' function
	 * gnutls_protocol_get_version() - integers on a gnutls_protocol_t enum.
	 *
	 * See: https://gitlab.com/gnutls/gnutls/blob/master/lib/includes/gnutls/gnutls.h.in#L736
	 */
	switch (version) {
	case SSL3_VERSION:
		/* SSL v3 */
		return 1;
	case TLS1_VERSION:
		/* TLS 1.0 */
		return 2;
	case TLS1_1_VERSION:
		/* TLS 1.1 */
		return 3;
	case TLS1_2_VERSION:
		/* TLS 1.2 */
		return 4;
#if defined TLS1_3_VERSION && TLS1_2_VERSION != TLS1_3_VERSION
	case TLS1_3_VERSION:
		/* TLS 1.3 */
		return 5;
#endif
	default:
		return -1;
	}
}

/**
 * \param[in] tcp A TCP connection (see wget_tcp_init())
 * \return `WGET_E_SUCCESS` on success or an error code (`WGET_E_*`) on failure
 *
 * Run an SSL/TLS handshake.
 *
 * This functions establishes an SSL/TLS tunnel (performs an SSL/TLS handshake)
 * over an active TCP connection. A pointer to the (internal) SSL/TLS session context
 * can be found in `tcp->ssl_session` after successful execution of this function. This pointer
 * has to be passed to wget_ssl_close() to close the SSL/TLS tunnel.
 *
 * If the handshake cannot be completed in the specified timeout for the provided TCP connection
 * this function fails and returns `WGET_E_TIMEOUT`. You can set the timeout with wget_tcp_set_timeout().
 */
int wget_ssl_open(wget_tcp *tcp)
{
	SSL *ssl = NULL;
	X509_STORE *store;
	int retval, error, resumed;
	struct verification_flags *vflags = NULL;
	wget_tls_stats_data stats = {
		.alpn_protocol = NULL,
		.version = -1,
		.false_start = 0,
		.tfo = 0,
		.resumed = 0,
		.http_protocol = WGET_PROTOCOL_HTTP_1_1,
		.cert_chain_size = 0
	}, *stats_p = NULL;

	if (!tcp || tcp->sockfd < 0)
		return WGET_E_INVALID;
	if (!init)
		wget_ssl_init();

	/* Initiate a new TLS connection from an existing OpenSSL context */
	if (!(ssl = SSL_new(_ctx)) || !SSL_set_fd(ssl, FD_TO_SOCKET(tcp->sockfd))) {
		retval = WGET_E_UNKNOWN;
		goto bail;
	}

	/* Store state flags for the verification callback */
	vflags = wget_malloc(sizeof(struct verification_flags));
	if (!vflags) {
		retval = WGET_E_MEMORY;
		goto bail;
	}

	vflags->ocsp_stapled_cache = NULL;

	store = SSL_CTX_get_cert_store(_ctx);
	if (!store) {
		retval = WGET_E_UNKNOWN;
		goto bail;
	}

	vflags->certstore = store;

#ifdef WITH_OCSP
	vflags->ocsp_stapled_cache = ocsp_create_stapled_response_vector();
	SSL_set_ex_data(ssl, ssl_userdata_idx, (void *) vflags);
#endif


	/* Enable stats logging, if requested */
	if (tls_stats_callback)
		stats_p = &stats;

	/* Enable host name verification, if requested */
	if (config.check_hostname) {
		SSL_set1_host(ssl, tcp->ssl_hostname);
#ifndef LIBRESSL_VERSION_NUMBER
// LibreSSL <= 3.0.2 does not know SSL_set_hostflags()
		SSL_set_hostflags(ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
#endif
	}
#if !defined LIBRESSL_VERSION_NUMBER || !defined X509_CHECK_FLAG_NEVER_CHECK_SUBJECT
// LibreSSL <= 3.0.2 does not know SSL_set_hostflags() nor X509_CHECK_FLAG_NEVER_CHECK_SUBJECT
// OpenSSL < 1.1 doesn't have X509_CHECK_FLAG_NEVER_CHECK_SUBJECT
	else {
		SSL_set_hostflags(ssl, X509_CHECK_FLAG_NEVER_CHECK_SUBJECT);
		info_printf(_("Host name check disabled. Server certificate's subject name will not be checked.\n"));
	}
#endif

#ifdef WITH_OCSP
	if (config.ocsp_stapling) {
		if (SSL_set_tlsext_status_type(ssl, TLSEXT_STATUSTYPE_ocsp))
			debug_printf("Sending 'status_request' extension in handshake\n");
		else
			error_printf(_("Could not set 'status_request' extension\n"));
	}
#endif

	/* Send Server Name Indication (SNI) */
	if (tcp->ssl_hostname && !SSL_set_tlsext_host_name(ssl, tcp->ssl_hostname))
		error_printf(_("SNI could not be sent"));

	/* Send ALPN if requested */
	if (config.alpn && ssl_set_alpn_offering(ssl, config.alpn))
		error_printf(_("ALPN offering could not be sent"));

	/* Resume from a previous SSL/TLS session, if available */
	if ((resumed = ssl_resume_session(ssl, tcp->ssl_hostname)) == 1)
		debug_printf("Will try to resume cached TLS session");
	else if (resumed == 0)
		debug_printf("No cached TLS session available. Will run a full handshake.");
	else
		error_printf(_("Could not get cached TLS session"));

	do {
		/* Wait for socket to become ready */
		if (tcp->connect_timeout &&
			(retval = wait_2_read_and_write(tcp->sockfd, tcp->connect_timeout)) < 0)
			goto bail;

		/* Run TLS handshake */
		retval = SSL_connect(ssl);
		if (retval > 0) {
			error = 0;
			resumed = SSL_session_reused(ssl);
			break;
		}

		error = SSL_get_error(ssl, retval);
	} while (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE);

	if (retval <= 0) {
		/* Error! Tell the user what happened, and exit. */
		if (error == SSL_ERROR_SSL) {
			error_printf(_("Could not complete TLS handshake: %s\n"),
				ERR_reason_error_string(ERR_peek_last_error()));
		}

		/* Return proper error code - Most of the time this will be a cert validation error */
		retval = (ERR_GET_REASON(ERR_peek_last_error()) == SSL_R_CERTIFICATE_VERIFY_FAILED ?
			WGET_E_CERTIFICATE :
			WGET_E_HANDSHAKE);
		goto bail;
	}

	/* Success! */
	debug_printf("Handshake completed%s\n", resumed ? " (resumed session)" : " (full handshake - not resumed)");

	/* Check cert chain against HPKP database */
	if (config.hpkp_cache) {
		if (!check_cert_chain_for_hpkp(SSL_get0_verified_chain(ssl), tcp->ssl_hostname,
					       &tcp->hpkp)) {
			error_printf(_("Public key pinning mismatch\n"));
			retval = WGET_E_HANDSHAKE;
			goto bail;
		}
	}

#ifdef WITH_OCSP
	/*
	 * Now check the (non-stapled) OCSP, if any.
	 * check_cert_chain_for_ocsp() will check whether a cached valid OCSP response exists for every certificate,
	 * and will contact OCSP servers for those that don't have such cached response.
	 * If the server sent stapled OCSP responses, these have been kept in memory as well
	 * and hence we'll not contact OCSP servers for them.
	 */
	if (config.ocsp) {
		if (!check_cert_chain_for_ocsp(SSL_get0_verified_chain(ssl),
					       store,
					       tcp->ssl_hostname,
					       vflags->ocsp_stapled_cache)) {
			error_printf(_("Aborting handshake. Could not verify OCSP chain.\n"));
			retval = WGET_E_HANDSHAKE;
			goto bail;
		}
	}
#endif

	if (vflags->ocsp_stapled_cache)
		ocsp_destroy_stapled_response_vector(&vflags->ocsp_stapled_cache);

	/* Save the current TLS session */
	if (ssl_save_session(ssl, tcp->ssl_hostname))
		debug_printf("TLS session saved in cache");
	else
		debug_printf("TLS session discarded");

	/* Set the protocol selected by the server via ALPN, if any */
	if (config.alpn)
		ssl_set_alpn_selected_protocol(ssl, tcp, stats_p);

	if (stats_p) {
		stats_p->version = get_tls_version(ssl);
		stats_p->hostname = tcp->ssl_hostname;
		stats_p->resumed = resumed;
		stats_p->cert_chain_size = sk_X509_num(SSL_get0_verified_chain(ssl));
		tls_stats_callback(stats_p, tls_stats_ctx);
		xfree(stats_p->alpn_protocol);

#ifdef MSG_FASTOPEN
		stats_p->tfo = wget_tcp_get_tcp_fastopen(tcp);
#endif
	}

	tcp->ssl_session = ssl;
	xfree(vflags);
	return WGET_E_SUCCESS;

bail:
	if (vflags->ocsp_stapled_cache)
		ocsp_destroy_stapled_response_vector(&vflags->ocsp_stapled_cache);
	if (stats_p)
		xfree(stats_p->alpn_protocol);
	xfree(vflags);
	if (ssl)
		SSL_free(ssl);
	return retval;
}

/**
 * \param[in] session The SSL/TLS session (a pointer to it), which is located at the `ssl_session` field
 * of the TCP connection (see wget_ssl_open()).
 *
 * Close an active SSL/TLS tunnel, which was opened with wget_ssl_open().
 *
 * The underlying TCP connection is kept open.
 */
void wget_ssl_close(void **session)
{
	SSL *ssl;
	int retval;

	if (session && *session) {
		ssl = *session;

		do
			retval = SSL_shutdown(ssl);
		while (retval == 0);

		SSL_free(ssl);
		*session = NULL;
	}
}

static int ssl_transfer(int want,
		void *session, int timeout,
		void *buf, int count)
{
	SSL *ssl;
	int fd;

	if (count == 0)
		return 0;
	if ((ssl = session) == NULL)
		return WGET_E_INVALID;
	if ((fd = SOCKET_TO_FD(SSL_get_fd(ssl))) < 0)
		return WGET_E_UNKNOWN;

	if (timeout < -1)
		timeout = -1;

	for (int ops = want;;) {
		int retval;

		if (timeout) {
			/* Wait until file descriptor becomes ready */
			retval = wget_ready_2_transfer(fd, timeout, ops);
			if (retval < 0)
				return retval;
			else if (retval == 0)
				return WGET_E_TIMEOUT;
		}

		/* We assume socket is non-blocking so neither of these should block */
		if (want == WGET_IO_READABLE)
			retval = SSL_read(ssl, buf, count);
		else
			retval = SSL_write(ssl, buf, count);

		if (retval > 0)
			return retval;

		// The OpenSSL docs consider <= 0 an error.
		int error = SSL_get_error(ssl, retval);
		if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
			/* Socket not ready - let's try again (unless timeout was zero) */
			ops = WGET_IO_WRITABLE | WGET_IO_READABLE;

			if (timeout == 0)
				return 0;
		} else {
			/* Not exactly a handshake error, but this is the closest one to signal TLS layer errors */
			return WGET_E_HANDSHAKE;
		}
	}

	// The execution can never get here.
	return WGET_E_UNKNOWN;
}

/**
 * \param[in] session An opaque pointer to the SSL/TLS session (obtained with wget_ssl_open() or wget_ssl_server_open())
 * \param[in] buf Destination buffer where the read data will be placed
 * \param[in] count Length of the buffer \p buf
 * \param[in] timeout The amount of time to wait until data becomes available (in milliseconds)
 * \return The number of bytes read, or a negative value on error.
 *
 * Read data from the SSL/TLS tunnel.
 *
 * This function will read at most \p count bytes, which will be stored
 * in the buffer \p buf.
 *
 * The \p timeout parameter tells how long to wait until some data becomes
 * available to read. A \p timeout value of zero causes this function to return
 * immediately, whereas a negative value will cause it to wait indefinitely.
 * This function returns the number of bytes read, which may be zero if the timeout elapses
 * without any data having become available.
 *
 * If a rehandshake is needed, this function does it automatically and tries
 * to read again.
 */
ssize_t wget_ssl_read_timeout(void *session,
	char *buf, size_t count,
	int timeout)
{
	int retval = ssl_transfer(WGET_IO_READABLE, session, timeout, buf, (int) count);

	if (retval == WGET_E_HANDSHAKE) {
		const char *msg = ERR_reason_error_string(ERR_peek_last_error());
		if (msg)
			error_printf(_("TLS read error: %s\n"), msg);
		retval = WGET_E_UNKNOWN;
	}

	return retval;
}

/**
 * \param[in] session An opaque pointer to the SSL/TLS session (obtained with wget_ssl_open() or wget_ssl_server_open())
 * \param[in] buf Buffer with the data to be sent
 * \param[in] count Length of the buffer \p buf
 * \param[in] timeout The amount of time to wait until data can be sent to the wire (in milliseconds)
 * \return The number of bytes written, or a negative value on error.
 *
 * Send data through the SSL/TLS tunnel.
 *
 * This function will write \p count bytes from \p buf.
 *
 * The \p timeout parameter tells how long to wait until data can be finally sent
 * over the SSL/TLS tunnel. A \p timeout value of zero causes this function to return
 * immediately, whereas a negative value will cause it to wait indefinitely.
 * This function returns the number of bytes sent, which may be zero if the timeout elapses
 * before any data could be sent.
 *
 * If a rehandshake is needed, this function does it automatically and tries
 * to write again.
 */
ssize_t wget_ssl_write_timeout(void *session,
	const char *buf, size_t count,
	int timeout)
{
	int retval = ssl_transfer(WGET_IO_WRITABLE, session, timeout, (void *) buf, (int) count);

	if (retval == WGET_E_HANDSHAKE) {
		error_printf(_("TLS write error: %s\n"),
			ERR_reason_error_string(ERR_peek_last_error()));
		retval = WGET_E_UNKNOWN;
	}

	return retval;
}

/**
 * \param[in] fn A `wget_ssl_stats_callback_tls` callback function to receive TLS statistics data
 * \param[in] ctx Context data given to \p fn
 *
 * Set callback function to be called when TLS statistics are available
 */
void wget_ssl_set_stats_callback_tls(wget_tls_stats_callback fn, void *ctx)
{
	tls_stats_callback = fn;
	tls_stats_ctx = ctx;
}

/**
 * \param[in] fn A `wget_ssl_stats_callback_ocsp` callback function to receive OCSP statistics data
 * \param[in] ctx Context data given to \p fn
 *
 * Set callback function to be called when OCSP statistics are available
 */
void wget_ssl_set_stats_callback_ocsp(wget_ocsp_stats_callback fn, void *ctx)
{
	ocsp_stats_callback = fn;
	ocsp_stats_ctx = ctx;
}

/** @} */
