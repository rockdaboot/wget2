/*
 * Copyright (c) 2019-2024 Free Software Foundation, Inc.
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
 * WolfSSL integration
 *
 * Resources:
 * https://github.com/wolfSSL/wolfssl-examples
 * RFC6066 Transport Layer Security (TLS) Extensions: Extension Definitions (defines OCSP stapling)
 * RFC6960 Online Certificate Status Protocol - OCSP
 * RFC6961 TLS Multiple Certificate Status Request Extension
 *
 * Testing revocation:
 * https://revoked.grc.com/
 * https://test-sspev.verisign.com:2443/test-SSPEV-revoked-verisign.html
 *
 */

#include <config.h>

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#ifdef _WIN32
#  include <w32sock.h>
#else
#  define FD_TO_SOCKET(x) (x)
#  define SOCKET_TO_FD(x) (x)
#endif

#ifndef DEBUG_WOLFSSL
#include <wolfssl/options.h>
#undef DEBUG_WOLFSSL
#else
#include <wolfssl/options.h>
#endif
#include <wolfssl/ssl.h>

#include <wget.h>
#include "private.h"
#include "net.h"
#include "filename.h"

/**
 * \file
 * \brief Functions for establishing and managing SSL/TLS connections
 * \defgroup libwget-ssl SSL/TLS engine
 *
 * @{
 */

static wget_tls_stats_callback
	*tls_stats_callback;
static void
	*tls_stats_ctx;

static wget_ocsp_stats_callback
	*ocsp_stats_callback;
static void
	*ocsp_stats_ctx;

static struct config {
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
		check_certificate : 1,
		report_invalid_cert : 1,
		check_hostname : 1,
		print_info : 1,
		ocsp : 1,
		ocsp_stapling : 1;
} config = {
	.check_certificate = 1,
	.report_invalid_cert = 1,
	.check_hostname = 1,
	.ocsp = 0,
	.ocsp_stapling = 1,
	.ca_type = WGET_SSL_X509_FMT_PEM,
	.cert_type = WGET_SSL_X509_FMT_PEM,
	.key_type = WGET_SSL_X509_FMT_PEM,
	.secure_protocol = "AUTO",
	.ca_directory = "system",
	.ca_file = "system",
#ifdef WITH_LIBNGHTTP2
	.alpn = "h2,http/1.1",
#endif
};

struct session_context {
	const char *
		hostname;
	wget_hpkp_stats_result
		stats_hpkp;
	unsigned char
		ocsp_stapling : 1,
		valid : 1,
		delayed_session_data : 1;
};

static WOLFSSL_CTX
	*ssl_ctx;

#define error_printf_check(...) if (config.report_invalid_cert) wget_error_printf(__VA_ARGS__)

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
	case WGET_SSL_SECURE_PROTOCOL: config.secure_protocol = value; break;
	case WGET_SSL_CA_DIRECTORY: config.ca_directory = value; break;
	case WGET_SSL_CA_FILE: config.ca_file = value; break;
	case WGET_SSL_CERT_FILE: config.cert_file = value; break;
	case WGET_SSL_KEY_FILE: config.key_file = value; break;
	case WGET_SSL_CRL_FILE: config.crl_file = value; break;
	case WGET_SSL_OCSP_SERVER: config.ocsp_server = value; break;
	case WGET_SSL_ALPN: config.alpn = value; break;
	default: error_printf(_("Unknown config key %d (or value must not be a string)\n"), key);
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
	case WGET_SSL_OCSP_CACHE: config.ocsp_cert_cache = (wget_ocsp_db *)value; break;
	case WGET_SSL_SESSION_CACHE: config.tls_session_cache = (wget_tls_session_db *)value; break;
	case WGET_SSL_HPKP_CACHE: config.hpkp_cache = (wget_hpkp_db *)value; break;
	default: error_printf(_("Unknown config key %d (or value must not be an object)\n"), key);
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
 *  - WGET_SSL_REPORT_INVALID_CERT: whether to print (1) errors/warnings regarding certificate validation or not (0)
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
 */
void wget_ssl_set_config_int(int key, int value)
{
	switch (key) {
	case WGET_SSL_CHECK_CERTIFICATE: config.check_certificate = (char)value; break;
	case WGET_SSL_REPORT_INVALID_CERT: config.report_invalid_cert = (char)value; break;
	case WGET_SSL_CHECK_HOSTNAME: config.check_hostname = (char)value; break;
	case WGET_SSL_CA_TYPE: config.ca_type = (char)value; break;
	case WGET_SSL_CERT_TYPE: config.cert_type = (char)value; break;
	case WGET_SSL_KEY_TYPE: config.key_type = (char)value; break;
	case WGET_SSL_PRINT_INFO: config.print_info = (char)value; break;
	case WGET_SSL_OCSP: config.ocsp = (char)value; break;
	case WGET_SSL_OCSP_STAPLING: config.ocsp_stapling = (char)value; break;
	default: error_printf(_("Unknown config key %d (or value must not be an integer)\n"), key);
	}
}

/* This function will verify the peer's certificate, and check
 * if the hostname matches, as well as the activation, expiration dates.
 */
/*
static int verify_certificate_callback(gnutls_session_t session)
{
	unsigned int status, deinit_cert = 0, deinit_issuer = 0;
	const gnutls_datum_t *cert_list = 0;
	unsigned int cert_list_size;
	int ret = -1, err, ocsp_ok = 0, pinning_ok = 0;
	gnutls_x509_crt_t cert = NULL, issuer = NULL;
	const char *hostname;
	const char *tag = config.check_certificate ? _("ERROR") : _("WARNING");
	unsigned nvalid = 0, nrevoked = 0, nignored = 0;

	// read hostname
	struct session_context *ctx = gnutls_session_get_ptr(session);
	hostname = ctx->hostname;

	// This verification function uses the trusted CAs in the credentials
	// structure. So you must have installed one or more CA certificates.
	//
	if (gnutls_certificate_verify_peers3(session, hostname, &status) != GNUTLS_E_SUCCESS) {
//		if (wget_get_logger(WGET_LOGGER_DEBUG))
//			print_info(session);
		error_printf_check(_("%s: Certificate verification error\n"), tag);
		goto out;
	}

//	if (wget_get_logger(WGET_LOGGER_DEBUG))
//		print_info(session);

	if (status & GNUTLS_CERT_REVOKED) {
		if (config.ocsp_cert_cache)
			wget_ocsp_db_add_host(config.ocsp_cert_cache, hostname, 0); // remove entry from cache
		if (ctx->ocsp_stapling) {
			if (gnutls_x509_crt_init(&cert) == GNUTLS_E_SUCCESS) {
				if ((cert_list = gnutls_certificate_get_peers(session, &cert_list_size))) {
					if (gnutls_x509_crt_import(cert, &cert_list[0], GNUTLS_X509_FMT_DER) == GNUTLS_E_SUCCESS) {
						add_cert_to_ocsp_cache(cert, 0);
					}
				}
				gnutls_x509_crt_deinit(cert);
			}
		}
	}

	if (status) {
		gnutls_datum_t out;

		if (gnutls_certificate_verification_status_print(
			status, gnutls_certificate_type_get(session), &out, 0) == GNUTLS_E_SUCCESS)
		{
			error_printf_check("%s: %s\n", tag, out.data); // no translation
			gnutls_free(out.data);
		}

		goto out;
	}

	// Up to here the process is the same for X.509 certificates and
	// OpenPGP keys. From now on X.509 certificates are assumed. This can
	// be easily extended to work with openpgp keys as well.
	//
	if (gnutls_certificate_type_get(session) != GNUTLS_CRT_X509) {
		error_printf_check(_("%s: Certificate must be X.509\n"), tag);
		goto out;
	}

	if (gnutls_x509_crt_init(&cert) != GNUTLS_E_SUCCESS) {
		error_printf_check(_("%s: Error initializing X.509 certificate\n"), tag);
		goto out;
	}
	deinit_cert = 1;

	if (!(cert_list = gnutls_certificate_get_peers(session, &cert_list_size))) {
		error_printf_check(_("%s: No certificate was found!\n"), tag);
		goto out;
	}

	if ((err = gnutls_x509_crt_import(cert, &cert_list[0], GNUTLS_X509_FMT_DER)) != GNUTLS_E_SUCCESS) {
		error_printf_check(_("%s: Failed to parse certificate: %s\n"), tag, gnutls_strerror (err));
		goto out;
	}

	if (!config.check_hostname || (config.check_hostname && hostname && gnutls_x509_crt_check_hostname(cert, hostname)))
		ret = 0;
	else
		goto out;

	// At this point, the cert chain has been found valid regarding the locally available CA certificates and CRLs.
	// Now, we are going to check the revocation status via OCSP
	if (config.ocsp_stapling) {
		if (!ctx->valid && ctx->ocsp_stapling) {
			if (gnutls_ocsp_status_request_is_checked(session, 0)) {
				debug_printf("Server certificate is valid regarding OCSP stapling\n");
//				get_cert_fingerprint(cert, fingerprint, sizeof(fingerprint)); // calc hexadecimal fingerprint string
				add_cert_to_ocsp_cache(cert, 1);
				nvalid = 1;
			}
			else if (gnutls_ocsp_status_request_is_checked(session, GNUTLS_OCSP_SR_IS_AVAIL))
				error_printf_check(_("WARNING: The certificate's (stapled) OCSP status is invalid\n"));
			else if (!config.ocsp)
				error_printf_check(_("WARNING: The certificate's (stapled) OCSP status has not been sent\n"));
		} else if (ctx->valid)
			debug_printf("OCSP: Host '%s' is valid (from cache)\n", hostname);
	}

	for (unsigned it = 0; it < cert_list_size; it++) {
		gnutls_x509_crt_deinit(cert);
		gnutls_x509_crt_init(&cert);

		if ((err = gnutls_x509_crt_import(cert, &cert_list[it], GNUTLS_X509_FMT_DER)) != GNUTLS_E_SUCCESS) {
			error_printf_check(_("%s: Failed to parse certificate[%u]: %s\n"), tag, it, gnutls_strerror (err));
			continue;
		}

		if (cert_verify_hpkp(cert, hostname, session) == 0)
			pinning_ok = 1;

		cert_verify_hpkp(cert, hostname, session);

		if (config.ocsp && it > nvalid) {
			char fingerprint[64 * 2 +1];
			int revoked;

			get_cert_fingerprint(cert, fingerprint, sizeof(fingerprint)); // calc hexadecimal fingerprint string

			if (wget_ocsp_fingerprint_in_cache(config.ocsp_cert_cache, fingerprint, &revoked)) {
				// found cert's fingerprint in cache
				if (revoked) {
					debug_printf("Certificate[%u] of '%s' has been revoked (cached)\n", it, hostname);
					nrevoked++;
				} else {
					debug_printf("Certificate[%u] of '%s' is valid (cached)\n", it, hostname);
					nvalid++;
				}
				continue;
			}

			if (deinit_issuer) {
				gnutls_x509_crt_deinit(issuer);
				deinit_issuer = 0;
			}
			if ((err = gnutls_certificate_get_issuer(credentials, cert, &issuer, 0)) != GNUTLS_E_SUCCESS && it < cert_list_size - 1) {
				gnutls_x509_crt_init(&issuer);
				deinit_issuer = 1;
				if ((err = gnutls_x509_crt_import(issuer, &cert_list[it + 1], GNUTLS_X509_FMT_DER))  != GNUTLS_E_SUCCESS) {
					debug_printf("Decoding error: %s\n", gnutls_strerror(err));
					continue;
				}
			} else if (err  != GNUTLS_E_SUCCESS) {
				debug_printf("Cannot find issuer: %s\n", gnutls_strerror(err));
				continue;
			}

			ocsp_ok = cert_verify_ocsp(cert, issuer);
			debug_printf("check_ocsp_response() returned %d\n", ocsp_ok);

			if (ocsp_ok == 1) {
				debug_printf("Certificate[%u] of '%s' is valid (via OCSP)\n", it, hostname);
				wget_ocsp_db_add_fingerprint(config.ocsp_cert_cache, fingerprint, time(NULL) + 3600, 1); // 1h valid
				nvalid++;
			} else if (ocsp_ok == 0) {
				debug_printf("%s: Certificate[%u] of '%s' has been revoked (via OCSP)\n", tag, it, hostname);
				wget_ocsp_db_add_fingerprint(config.ocsp_cert_cache, fingerprint, time(NULL) + 3600, 0);  // cert has been revoked
				nrevoked++;
			} else {
				debug_printf("WARNING: OCSP response not available or ignored\n");
				nignored++;
			}
		}
	}

	if (config.ocsp && stats_callback_ocsp) {
		wget_ocsp_stats_data stats;
		stats.hostname = hostname;
		stats.nvalid = nvalid;
		stats.nrevoked = nrevoked;
		stats.nignored = nignored;
		stats.stapling = ctx->ocsp_stapling;

		stats_callback_ocsp(&stats);
	}

	if (config.ocsp_stapling || config.ocsp) {
		if (nvalid == cert_list_size) {
			wget_ocsp_db_add_host(config.ocsp_cert_cache, hostname, time(NULL) + 3600); // 1h valid
		} else if (nrevoked) {
			wget_ocsp_db_add_host(config.ocsp_cert_cache, hostname, 0); // remove entry from cache
			ret = -1;
		}
	}

	if (!pinning_ok) {
		error_printf_check(_("%s: Pubkey pinning mismatch!\n"), tag);
		ret = -1;
	}

	// 0: continue handshake
	// else: stop handshake
out:
	if (deinit_cert)
		gnutls_x509_crt_deinit(cert);
	if (deinit_issuer)
		gnutls_x509_crt_deinit(issuer);

	return config.check_certificate ? ret : 0;
}
*/

static int init;
static wget_thread_mutex mutex;

static void tls_exit(void)
{
	if (mutex)
		wget_thread_mutex_destroy(&mutex);
}

INITIALIZER(tls_init)
{
	if (!mutex) {
		wget_thread_mutex_init(&mutex);
#ifdef DEBUG_WOLFSSL
		wolfSSL_Debugging_ON();
#endif // DEBUG_WOLFSSL

		// Initialize paths while in a thread-safe environment (mostly for _WIN32).
		wget_ssl_default_cert_dir();
		wget_ssl_default_ca_bundle_path();

		atexit(tls_exit);
	}
}


/*
static void set_credentials(gnutls_certificate_credentials_t *credentials)
{
	if (config.cert_file && !config.key_file) {
		// Use the private key from the cert file unless otherwise specified.
		config.key_file = config.cert_file;
		config.key_type = config.cert_type;
	}
	else if (!config.cert_file && config.key_file) {
		// Use the cert from the private key file unless otherwise specified.
		config.cert_file = config.key_file;
		config.cert_type = config.key_type;
	}

	if (config.cert_file && config.key_file) {
		if (config.key_type !=config.cert_type) {
			// GnuTLS can't handle this
			error_printf(_("GnuTLS requires the key and the cert to be of the same type.\n"));
		}

		if (gnutls_certificate_set_x509_key_file(*credentials,config.cert_file,config.key_file,key_type(config.key_type)) != GNUTLS_E_SUCCESS)
			error_printf(_("No certificates or keys were found\n"));
	}

	if (config.ca_file) {
		if (gnutls_certificate_set_x509_trust_file(*credentials, config.ca_file, key_type(config.ca_type)) <= 0)
			error_printf(_("No CAs were found in '%s'\n"), config.ca_file);
	}
}
*/

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
	tls_init();

	wget_thread_mutex_lock(mutex);

	if (!init) {
		WOLFSSL_METHOD *method;
		int min_version = -1;
		const char *ciphers = NULL;

#ifdef DEBUG_WOLFSSL
		if (!wget_logger_is_active(wget_get_logger(WGET_LOGGER_DEBUG)))
			wolfSSL_Debugging_OFF();
#endif // DEBUG_WOLFSSL

		debug_printf("WolfSSL init\n");
		wolfSSL_Init();

		if (!wget_strcasecmp_ascii(config.secure_protocol, "SSLv2")) {
			method = SSLv2_client_method();
		} else if (!wget_strcasecmp_ascii(config.secure_protocol, "SSLv3")) {
			method = wolfSSLv23_client_method();
			min_version = WOLFSSL_SSLV3;
		} else if (!wget_strcasecmp_ascii(config.secure_protocol, "TLSv1")) {
			method = wolfSSLv23_client_method();
			min_version = WOLFSSL_TLSV1;
		} else if (!wget_strcasecmp_ascii(config.secure_protocol, "TLSv1_1")) {
			method = wolfSSLv23_client_method();
			min_version = WOLFSSL_TLSV1_1;
		} else if (!wget_strcasecmp_ascii(config.secure_protocol, "TLSv1_2")) {
			method = wolfSSLv23_client_method();
			min_version = WOLFSSL_TLSV1_2;
		} else if (!wget_strcasecmp_ascii(config.secure_protocol, "TLSv1_3")) {
			method = wolfSSLv23_client_method();
			min_version = WOLFSSL_TLSV1_3;
		} else if (!wget_strcasecmp_ascii(config.secure_protocol, "PFS")) {
			method = wolfSSLv23_client_method();
			ciphers = "HIGH:!aNULL:!RC4:!MD5:!SRP:!PSK:!kRSA";
		} else if (!wget_strcasecmp_ascii(config.secure_protocol, "auto")) {
			method = wolfSSLv23_client_method();
			min_version = WOLFSSL_TLSV1_2;
			ciphers = "HIGH:!aNULL:!RC4:!MD5:!SRP:!PSK";
		} else if (*config.secure_protocol) {
			method = wolfSSLv23_client_method();
			ciphers = config.secure_protocol;
		} else {
			error_printf(_("Missing TLS method\n"));
			goto out;
		}

		/* Create and initialize WOLFSSL_CTX */
		if ((ssl_ctx = wolfSSL_CTX_new(method)) == NULL) {
			error_printf(_("Failed to create WOLFSSL_CTX\n"));
			goto out;
		}

		if (min_version != -1)
			wolfSSL_CTX_SetMinVersion(ssl_ctx, min_version);

/*
		int rc;
		char cipher_list[8096];
		rc = wolfSSL_get_ciphers(cipher_list, (int) sizeof(cipher_list));
		debug_printf("%d ciphers found %s (len=%zu)\n", rc, cipher_list, strlen(cipher_list));
*/
		if (ciphers)
			if (!wolfSSL_CTX_set_cipher_list(ssl_ctx, ciphers))
				error_printf(_("WolfSSL: Failed to set ciphers '%s'\n"), ciphers);

		wolfSSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);

		if (config.check_certificate) {
			wolfSSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
			bool system_certs_loaded = false;

#ifdef WOLFSSL_SYS_CA_CERTS
			if (!wget_strcmp(config.ca_directory, "system") || !wget_strcmp(config.ca_file, "system")) {
				if (wolfSSL_CTX_load_system_CA_certs(ssl_ctx) != WOLFSSL_SUCCESS) {
					error_printf(_("Failed to load system certs\n"));
				} else {
					system_certs_loaded = true;
					debug_printf("System certificates loaded\n");
				}
			}
#endif

			const char *dir = config.ca_directory;
			const char *file = config.ca_file;
			debug_printf("Certificates %s %s\n", dir, file);

			if (dir && !system_certs_loaded && !wget_strcmp(dir, "system")) {
				dir = wget_ssl_default_cert_dir();
			}
			if (file && !system_certs_loaded && !wget_strcmp(file, "system")) {
				file = wget_ssl_default_ca_bundle_path();
			}

			if (dir && access(dir, F_OK))
				dir = NULL;
			if (file && access(file, F_OK))
				file = NULL;

			if (dir == NULL && file == NULL) {
				if (!system_certs_loaded)
					error_printf(_("Skipped loading CA certs. SSL verification will likely fail.\n"));
				goto out;
			}

			// Load client certificates into WOLFSSL_CTX
			if (wolfSSL_CTX_load_verify_locations(ssl_ctx, file, dir) != SSL_SUCCESS) {
				error_printf(_("Failed to load CA pem: %s or cert dir: %s, SSL verification will likely fail.\n"), file, dir);
				goto out;
			} else {
				if (dir)
					debug_printf("Certificates loaded from %s\n", dir);
				if (file)
					debug_printf("Certificates loaded from %s\n", file);
			}
		}

/*		if (config.crl_file) {
			WOLFSSL_X509_STORE *store = wolfSSL_CTX_get_cert_store(ssl_ctx);
			WOLFSSL_X509_LOOKUP *lookup;

			if (!(lookup = wolfSSL_X509_STORE_add_lookup(store, wolfSSL_X509_LOOKUP_file()))
				|| (!X509_load_crl_file(lookup, config.crl_file, X509_FILETYPE_PEM)))
				return;

			wolfSSL_X509_STORE_set_flags(store, WOLFSSL_CRL_CHECK | WOLFSSL_CRL_CHECKALL);
		}
*/

out:
		init++;

		debug_printf("WolfSSL init done\n");
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

	if (init == 1) {
		wolfSSL_CTX_free(ssl_ctx); ssl_ctx = NULL;
		wolfSSL_Cleanup();
	}

	if (init > 0) init--;

	wget_thread_mutex_unlock(mutex);
}

static int do_handshake(WOLFSSL *session, int sockfd, int timeout)
{
	int ret;

	// Wait for socket being ready before we call gnutls_handshake().
	// I had problems on a KVM Win7 + CygWin (gnutls 3.2.4-1).
	int rc = wget_ready_2_write(sockfd, timeout);

	if (rc == 0)
		ret = WGET_E_TIMEOUT;
	else
		ret = WGET_E_HANDSHAKE;

	// Perform the TLS handshake
	while (rc > 0) {
		rc = wolfSSL_connect(session);

		if (rc == SSL_SUCCESS) {
			ret = WGET_E_SUCCESS;
			break;
		}

		rc =  wolfSSL_get_error(session, rc);
		debug_printf("wolfSSL_connect2: (%d) (errno=%d) %s\n", rc, errno, wolfSSL_ERR_reason_error_string(rc));

/*			if (rc == GNUTLS_E_CERTIFICATE_ERROR) {
				ret = WGET_E_CERTIFICATE;
			} else if (rc == GNUTLS_E_PUSH_ERROR && (errno == ECONNREFUSED || errno == ENOTCONN)) {
				// ECONNREFUSED: on Linux
				// ENOTCONN: MinGW (in out Gitlab CI runner)
				ret = WGET_E_CONNECT;
			} else if (rc == GNUTLS_E_PULL_ERROR && errno == 61) {
				// ENODATA, but not on OSX/Travis ?
				// We see this with older versions of GnuTLS, e.g. on TravisCI. (Tim, 11.4.2018)
				// It happens when trying to connect to a port without a listener
				ret = WGET_E_CONNECT;
			} else if (rc == GNUTLS_E_PREMATURE_TERMINATION && errno == EAGAIN) {
				// It happens when trying to connect to a closed port
				ret = WGET_E_CONNECT;
			} else if (rc == GNUTLS_E_UNEXPECTED_PACKET_LENGTH && errno == EAGAIN) {
				// We see this with older versions of GnuTLS, e.g. on TravisCI. (Tim, 11.4.2018)
				// It happens when trying to connect to a port without a listener
				ret = WGET_E_CONNECT;
			} else
				ret = WGET_E_HANDSHAKE;
*/
		if (rc == WOLFSSL_ERROR_WANT_WRITE) {
			// wait for writeability
			rc = wget_ready_2_write(sockfd, timeout);
		} else if (rc == WOLFSSL_ERROR_WANT_READ) {
			// wait for readability
			rc = wget_ready_2_read(sockfd, timeout);
		} else {
			ret = WGET_E_CONNECT;
			break;
		}
	}

	return ret;
}

static void ShowX509(WOLFSSL_X509 *x509, const char *hdr)
{
	char *altName;
	char *issuer;
	char *subject;
	byte serial[32];
	int ret;
	int sz = sizeof(serial);

	if (!x509) {
		debug_printf("%s No Cert\n", hdr);
		return;
	}

	issuer = wolfSSL_X509_NAME_oneline(wolfSSL_X509_get_issuer_name(x509), 0, 0);
	subject = wolfSSL_X509_NAME_oneline(wolfSSL_X509_get_subject_name(x509), 0, 0);

	debug_printf("%s issuer : %s subject: %s", hdr, issuer, subject);

	while ((altName = wolfSSL_X509_get_next_altname(x509)))
		debug_printf(" altname = %s\n", altName);

	ret = wolfSSL_X509_get_serial_number(x509, serial, &sz);
	if (ret == WOLFSSL_SUCCESS) {
		char serialMsg[sizeof(serial) * 4 + 1];
		// testsuite has multiple threads writing to stdout, get output
		// message ready to write once
		for (int i = 0; i < sz; i++)
			sprintf(serialMsg + (i * 4), ":%02x ", serial[i]);
		debug_printf(" serial number%s\n", serialMsg);
	}

	XFREE(subject, 0, DYNAMIC_TYPE_OPENSSL);
	XFREE(issuer, 0, DYNAMIC_TYPE_OPENSSL);

	{
		WOLFSSL_BIO* bio;
		char buf[256]; /* should be size of ASN_NAME_MAX */
		int textSz;


		/* print out domain component if certificate has it */
		textSz = wolfSSL_X509_NAME_get_text_by_NID(
			wolfSSL_X509_get_subject_name(x509), NID_domainComponent,
			buf, sizeof(buf));
		if (textSz > 0) {
			debug_printf("Domain Component = %s\n", buf);
		}

		bio = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
		if (bio) {
			wolfSSL_BIO_set_fp(bio, stdout, BIO_NOCLOSE);
			if (wget_logger_is_active(wget_get_logger(WGET_LOGGER_DEBUG)))
				wolfSSL_X509_print(bio, x509);
			wolfSSL_BIO_free(bio);
		}
	}
}

static void ShowX509Chain(WOLFSSL_X509_CHAIN *chain, int count, const char *hdr)
{
//	int i;
//	int length;
//	unsigned char buffer[3072];

	for (int i = 0; i < count; i++) {
//		wolfSSL_get_chain_cert_pem(chain, i, buffer, sizeof(buffer), &length);
//		buffer[length] = 0;
//		debug_printf("\n%s: %d has length %d data = \n%s\n", hdr, i, length, buffer);

		WOLFSSL_X509 *chainX509 = wolfSSL_get_chain_X509(chain, i);
		if (chainX509)
			ShowX509(chainX509, hdr);

		wolfSSL_FreeX509(chainX509);
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
	WOLFSSL *session;
	wget_tls_stats_data stats = {
			.alpn_protocol = NULL,
			.version = -1,
			.false_start = -1,
			.tfo = -1,
			.resumed = 0,
			.http_protocol = WGET_PROTOCOL_HTTP_1_1,
			.cert_chain_size = 0
	};

	int rc, ret = WGET_E_UNKNOWN;
	int sockfd, connect_timeout;
	const char *hostname;
	long long before_millisecs = 0;

	if (!tcp)
		return WGET_E_INVALID;

	if (!init)
		wget_ssl_init();

	hostname = tcp->ssl_hostname;
	sockfd= tcp->sockfd;
	connect_timeout = tcp->connect_timeout;

	if ((session = wolfSSL_new(ssl_ctx)) == NULL) {
		error_printf(_("Failed to create WolfSSL session\n"));
		return -1;
	}

	// RFC 6066 SNI Server Name Indication
	if (hostname)
		wolfSSL_UseSNI(session, WOLFSSL_SNI_HOST_NAME, hostname, (unsigned short) strlen(hostname));

//	if (tcp->tls_false_start)
//		info_printf(_("WolfSSL doesn't support TLS False Start\n"));

	if (config.alpn) {
		size_t len = strlen(config.alpn);
		char alpnbuf[256], *alpn;

		// wolfSSL_UseALPN() destroys the ALPN string (bad design pattern !)
		alpn = wget_strmemcpy_a(alpnbuf, sizeof(alpnbuf), config.alpn, strlen(config.alpn));

		if (wolfSSL_UseALPN(session, alpn, (int) len, WOLFSSL_ALPN_CONTINUE_ON_MISMATCH) == WOLFSSL_SUCCESS) {
			debug_printf("ALPN offering %s\n", config.alpn);
		} else
			debug_printf("WolfSSL: Failed to set ALPN: %s\n", config.alpn);

		if (alpn != alpnbuf)
			xfree(alpn);
	}

	// struct session_context *ctx = wget_calloc(1, sizeof(struct session_context));
	// ctx->hostname = wget_strdup(hostname);

	tcp->ssl_session = session;
//	gnutls_session_set_ptr(session, ctx);
	wolfSSL_set_fd(session, FD_TO_SOCKET(sockfd));

	/* make wolfSSL object nonblocking */
	wolfSSL_set_using_nonblock(session, 1);

	if (tls_stats_callback)
		before_millisecs = wget_get_timemillis();

	ret = do_handshake(session, sockfd, connect_timeout);

	if (tls_stats_callback) {
		long long after_millisecs = wget_get_timemillis();
		stats.tls_secs = after_millisecs - before_millisecs;
		stats.tls_con = 1;
		stats.false_start = 0; // WolfSSL doesn't support False Start (https://www.wolfssl.com/is-tls-false-start-going-to-take-off-2/)
	}

	const char *name;
	int bits;
	WOLFSSL_CIPHER *cipher;
	WOLFSSL_X509 *peer = wolfSSL_get_peer_certificate(session);
	if (peer) {
		ShowX509(peer, "Peer's cert info");
		wolfSSL_FreeX509(peer);
	} else
		debug_printf("Peer has no cert!\n");

	ShowX509(wolfSSL_get_certificate(session), "our cert info:");
	debug_printf("Peer verify result = %ld\n", wolfSSL_get_verify_result(session));
	debug_printf("SSL version %s\n", wolfSSL_get_version(session));
	cipher = wolfSSL_get_current_cipher(session);
//	printf("%s %s%s\n", words[1], (wolfSSL_isQSH(session)) ? "QSH:" : "", wolfSSL_CIPHER_get_name(cipher));
	debug_printf("SSL cipher suite %s\n", wolfSSL_CIPHER_get_name(cipher));
	if ((name = wolfSSL_get_curve_name(session)))
		debug_printf("SSL curve name %s\n", name);
	else if ((bits = wolfSSL_GetDhKey_Sz(session)) > 0)
		debug_printf("SSL DH size %d bits\n", bits);

	if (config.alpn) {
		char *protocol;
		uint16_t protocol_length;

		if (wolfSSL_ALPN_GetProtocol(session, &protocol, &protocol_length) != WOLFSSL_SUCCESS)
			debug_printf("WolfSSL: Failed to connect ALPN\n");
		else {
			debug_printf("WolfSSL: Server accepted ALPN protocol '%.*s'\n", (int) protocol_length, protocol);
			if (tls_stats_callback)
				stats.alpn_protocol = wget_strmemdup(protocol, protocol_length);

			if (protocol_length == 2 && !memcmp(protocol, "h2", 2)) {
				tcp->protocol = WGET_PROTOCOL_HTTP_2_0;
				stats.http_protocol = WGET_PROTOCOL_HTTP_2_0;
			}
		}
	}

	if (ret == WGET_E_SUCCESS) {
		int resumed = wolfSSL_session_reused(session);

		WOLFSSL_X509_CHAIN *chain = (WOLFSSL_X509_CHAIN *) wolfSSL_get_peer_cert_chain(session);
		ShowX509Chain(chain, wolfSSL_get_chain_count(chain), "Certificate chain");

		if (tls_stats_callback) {
			stats.resumed = resumed;
			stats.cert_chain_size = wolfSSL_get_chain_count(chain);

			const char *tlsver = wolfSSL_get_version(session);
			if (!strcmp(tlsver, "TLSv1.2"))
				stats.version = 4;
			else if (!strcmp(tlsver, "TLSv1.3"))
				stats.version = 5;
			else
				stats.version = 1; // SSLv3
		}

		debug_printf("Handshake completed%s\n", resumed ? " (resumed session)" : "");

		if (!resumed && config.tls_session_cache) {
/*			WOLFSSL_SESSION *session_data = wolfSSL_get_session(session);

			if (session_data) {
				int session_data_size = wolfSSL_get_session_cache_memsize();
				char session_data_data[session_data_size];
				if (wolfSSL_memsave_session_cache(session_data_data, session_data_size) == SSL_SUCCESS) {
					wget_tls_session_db_add(config.tls_session_cache,
						wget_tls_session_new(ctx->hostname, 18 * 3600, session_data.data, session_data.size)); // 18h valid
				}
			}
*/
/*			gnutls_datum_t session_data;

			if ((rc = gnutls_session_get_data2(session, &session_data)) == GNUTLS_E_SUCCESS) {
				wget_tls_session_db_add(config.tls_session_cache,
					wget_tls_session_new(ctx->hostname, 18 * 3600, session_data.data, session_data.size)); // 18h valid
				gnutls_free(session_data.data);
			} else
				debug_printf("Failed to get session data: %s", gnutls_strerror(rc));
*/		}
	}

	if ((rc = wolfSSL_connect(session)) != WOLFSSL_SUCCESS) {
		rc = wolfSSL_get_error(session, rc);
		error_printf(_("failed to connect TLS (%d): %s\n"), rc, wolfSSL_ERR_reason_error_string(rc));

		long res = wolfSSL_get_verify_result(session);
		if (res >= 13 && res <= 29)
			return WGET_E_CERTIFICATE;
		else
			return WGET_E_CONNECT;
	}

	if (tls_stats_callback) {
		stats.hostname = hostname;
		tls_stats_callback(&stats, tls_stats_ctx);
		xfree(stats.alpn_protocol);
	}

	// tcp->hpkp = ctx->stats_hpkp;

	if (ret != WGET_E_SUCCESS) {
		if (ret == WGET_E_TIMEOUT)
			debug_printf("Handshake timed out\n");
		// xfree(ctx->hostname);
		// xfree(ctx);
		wolfSSL_free(session);
		tcp->ssl_session = NULL;
	}

	return ret;
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
	if (session && *session) {
		WOLFSSL *s = *session;
		int ret;

		do {
			ret = wolfSSL_shutdown(s);
			ret = wolfSSL_get_error(s, ret);
		} while (ret == WOLFSSL_SHUTDOWN_NOT_DONE);

		if (ret < 0)
			debug_printf("TLS shutdown failed: %s\n", wolfSSL_ERR_reason_error_string(ret));

		wolfSSL_free(s);
		*session = NULL;
	}
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
ssize_t wget_ssl_read_timeout(void *session, char *buf, size_t count, int timeout)
{
	int sockfd = SOCKET_TO_FD( wolfSSL_get_fd(session));
	int rc;

	while ((rc = wolfSSL_read(session, buf, (int) count)) < 0) {
		rc =  wolfSSL_get_error(session, rc);
		debug_printf("wolfSSL_read: (%d) (errno=%d) %s\n", rc, errno, wolfSSL_ERR_reason_error_string(rc));
		if (rc == SSL_ERROR_WANT_READ) {
			if ((rc = wget_ready_2_read(sockfd, timeout)) <= 0)
				break;
		} else
			break;
	}

	return rc < 0 ? -1 : rc;

/*	for (;;) {
		int rc;

		if (gnutls_record_check_pending(session) <= 0 && (rc = wget_ready_2_read(sockfd, timeout)) <= 0)
			return rc;

		nbytes = gnutls_record_recv(session, buf, count);

		// If False Start + Session Resumption are enabled, we get the session data after the first read()
		struct session_context *ctx = gnutls_session_get_ptr(session);
		if (ctx && ctx->delayed_session_data) {
			gnutls_datum_t session_data;

			if ((rc = gnutls_session_get_data2(session, &session_data)) == GNUTLS_E_SUCCESS) {
				debug_printf("Got delayed session data\n");
				ctx->delayed_session_data = 0;
				wget_tls_session_db_add(config.tls_session_cache,
					wget_tls_session_new(ctx->hostname, 18 * 3600, session_data.data, session_data.size)); // 18h valid
				gnutls_free(session_data.data);
			} else
				debug_printf("No delayed session data%s\n", gnutls_strerror(rc));
		}

		if (nbytes == GNUTLS_E_REHANDSHAKE) {
			debug_printf("*** REHANDSHAKE while reading\n");
			if ((nbytes = do_handshake(session, sockfd, timeout)) == 0)
				nbytes = GNUTLS_E_AGAIN; // restart reading
		}
		if (nbytes >= 0 || nbytes != GNUTLS_E_AGAIN)
			break;
	}

	return nbytes < -1 ? -1 : nbytes;
*/
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
ssize_t wget_ssl_write_timeout(void *session, const char *buf, size_t count, int timeout)
{
	int sockfd = SOCKET_TO_FD(wolfSSL_get_fd(session));
	int rc;

	while ((rc = wolfSSL_write(session, buf, (int) count)) < 0) {
		rc =  wolfSSL_get_error(session, rc);
		debug_printf("wolfSSL_write: (%d) (errno=%d) %s\n", rc, errno, wolfSSL_ERR_reason_error_string(rc));
		if (rc == SSL_ERROR_WANT_WRITE) {
			if ((rc = wget_ready_2_write(sockfd, timeout)) <= 0)
				break;
		} else
			break;
	}

	return rc < 0 ? -1 : rc;
/*
	for (;;) {
		ssize_t nbytes;
		int rc;

		if ((rc = wget_ready_2_write(sockfd, timeout)) <= 0)
			return rc;

		if ((nbytes = gnutls_record_send(session, buf, count)) >= 0)
			return nbytes;

		if (nbytes == GNUTLS_E_REHANDSHAKE) {
			debug_printf("*** REHANDSHAKE while writing\n");
			if ((nbytes = do_handshake(session, sockfd, timeout)) == 0)
				continue; // restart writing
		}
		if (nbytes == GNUTLS_E_AGAIN)
			return 0; // indicate timeout

		return -1;
	}
*/
}

/**
 * \param[in] fn A `wget_ssl_stats_callback_tls_t` callback function to receive TLS statistics data
 * \param[in] ctx Context data given to \p fn
 *
 * Set callback function to be called when TLS statistics are available
 */
void wget_ssl_set_stats_callback_tls(wget_tls_stats_callback *fn, void *ctx)
{
	tls_stats_callback = fn;
	tls_stats_ctx = ctx;
}

/**
 * \param[in] fn A `wget_ssl_stats_callback_ocsp_t` callback function to receive OCSP statistics data
 * \param[in] ctx Context data given to \p fn
 *
 * Set callback function to be called when OCSP statistics are available
 */
void wget_ssl_set_stats_callback_ocsp(wget_ocsp_stats_callback *fn, void *ctx)
{
	ocsp_stats_callback = fn;
	ocsp_stats_ctx = ctx;
}

/** @} */
