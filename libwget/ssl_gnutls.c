/*
 * Copyright (c) 2012-2015 Tim Ruehsen
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
 * gnutls SSL/TLS routines
 * - some parts have been copied from GnuTLS example code
 * - OCSP code has been copied from gnutls-cli/ocsptool code
 *
 * Changelog
 * 03.08.2012  Tim Ruehsen  created inspired from gnutls client example
 * 26.08.2012               wget compatibility regarding config options
 * 15.01.2015               added OCSP fix from https://gitorious.org/gnutls/gnutls/commit/11eebe14b232ec198d1446a3720e6ed78d118c4b
 *
 * Resources:
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
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#ifdef WITH_OCSP
#	include <gnutls/ocsp.h>
#endif
#ifdef WITH_LIBDANE
#	include <gnutls/dane.h>
#endif
#include <gnutls/crypto.h>
#include <gnutls/abstract.h>

#include <wget.h>
#include "private.h"
#include "net.h"

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
		ocsp_date : 1,
		ocsp_stapling : 1,
		ocsp_nonce : 1,
		dane : 1;
} config = {
	.check_certificate = 1,
	.report_invalid_cert = 1,
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
	.alpn = "h2,http/1.1",
#endif
};

struct session_context {
	const char *
		hostname;
	wget_hpkp_stats_result
		stats_hpkp;
	uint16_t
		port;
	bool
		ocsp_stapling : 1,
		valid : 1,
		delayed_session_data : 1;
};

static gnutls_certificate_credentials_t
	credentials;
static gnutls_priority_t
	priority_cache;

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
 *  - WGET_SSL_OCSP_CACHE: This option takes a pointer to a \ref wget_ocsp_db
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
 *  - WGET_SSL_REPORT_INVALID_CERT: whether to print (1) errors/warnings regarding certificate verification or not (0)
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
	case WGET_SSL_CHECK_CERTIFICATE: config.check_certificate = (char)value; break;
	case WGET_SSL_REPORT_INVALID_CERT: config.report_invalid_cert = (char)value; break;
	case WGET_SSL_CHECK_HOSTNAME: config.check_hostname = (char)value; break;
	case WGET_SSL_CA_TYPE: config.ca_type = (char)value; break;
	case WGET_SSL_CERT_TYPE: config.cert_type = (char)value; break;
	case WGET_SSL_DANE: config.dane = (char)value; break;
	case WGET_SSL_KEY_TYPE: config.key_type = (char)value; break;
	case WGET_SSL_PRINT_INFO: config.print_info = (char)value; break;
	case WGET_SSL_OCSP: config.ocsp = (char)value; break;
	case WGET_SSL_OCSP_DATE: config.ocsp_date = (char)value; break;
	case WGET_SSL_OCSP_STAPLING: config.ocsp_stapling = (char)value; break;
	case WGET_SSL_OCSP_NONCE: config.ocsp_nonce = value; break;
	default: error_printf(_("Unknown config key %d (or value must not be an integer)\n"), key);
	}
}

static const char *safe_ctime(time_t t, char *buf, size_t size)
{
	struct tm tm;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-y2k"
	if (localtime_r(&t, &tm) && strftime(buf, size, "%c", &tm))
		return buf;
#pragma GCC diagnostic pop

	return "[error]";
}

static void print_x509_certificate_info(gnutls_session_t session)
{
	const char *name;
	char dn[128], timebuf[64];
	unsigned char digest[64];
	unsigned char serial[40];
	size_t dn_size = sizeof(dn);
	size_t digest_size = sizeof (digest);
	size_t serial_size = sizeof(serial);
	time_t expired, activated;
	unsigned int bits;
	int algo;
	unsigned int cert_list_size = 0, ncert;
	const gnutls_datum_t *cert_list;
	gnutls_x509_crt_t cert;
	gnutls_certificate_type_t cert_type;

	cert_list = gnutls_certificate_get_peers(session, &cert_list_size);

	for (ncert = 0; ncert < cert_list_size; ncert++) {
		if ((cert_type = gnutls_certificate_type_get(session)) == GNUTLS_CRT_X509) {

			if (gnutls_x509_crt_init(&cert) != GNUTLS_E_SUCCESS)
				continue;

			if (gnutls_x509_crt_import(cert, &cert_list[ncert], GNUTLS_X509_FMT_DER) != GNUTLS_E_SUCCESS) {
				gnutls_x509_crt_deinit(cert);
				continue;
			}

			info_printf(_("Certificate info [%u]:\n"), ncert);

			activated = gnutls_x509_crt_get_activation_time(cert);
			info_printf(_("  Valid since: %s"), safe_ctime(activated, timebuf, sizeof(timebuf)));

			expired = gnutls_x509_crt_get_expiration_time(cert);
			info_printf(_("  Expires: %s"), safe_ctime(expired, timebuf, sizeof(timebuf)));

			if (!gnutls_fingerprint(GNUTLS_DIG_MD5, &cert_list[ncert], digest, &digest_size)) {
				char digest_hex[sizeof(digest) * 2 + 1];

				wget_memtohex(digest, digest_size, digest_hex, sizeof(digest_hex));

				info_printf(_("  Fingerprint: %s\n"), digest_hex);
			}

			if (!gnutls_x509_crt_get_serial(cert, serial, &serial_size)) {
				char serial_hex[sizeof(serial) * 2 + 1];

				wget_memtohex(serial, serial_size, serial_hex, sizeof(serial_hex));

				info_printf(_("  Serial number: %s\n"), serial_hex);
			}

			algo = gnutls_x509_crt_get_pk_algorithm(cert, &bits);
			name = gnutls_pk_algorithm_get_name(algo);
			info_printf(_("  Public key: %s, %s (%u bits)\n"),
				name ? name : "Unknown",
				gnutls_sec_param_get_name(gnutls_pk_bits_to_sec_param(algo, bits)),
				bits);

			info_printf(_("  Version: #%d\n"), gnutls_x509_crt_get_version(cert));

			dn_size = sizeof(dn);
			gnutls_x509_crt_get_dn(cert, dn, &dn_size);
			info_printf(_("  DN: %s\n"), dn);

			dn_size = sizeof(dn);
			gnutls_x509_crt_get_issuer_dn(cert, dn, &dn_size);
			info_printf(_("  Issuer's DN: %s\n"), dn);

			dn_size = sizeof(dn);
			gnutls_x509_crt_get_issuer_dn_oid(cert, 0, dn, &dn_size);
			info_printf(_("  Issuer's OID: %s\n"), dn);

			dn_size = sizeof(dn);
			gnutls_x509_crt_get_issuer_unique_id(cert, dn, &dn_size);
			info_printf(_("  Issuer's UID: %s\n"), dn);
/*
			dn_size = sizeof(dn);
			gnutls_x509_crt_get_subject_key_id(cert, dn, &dn_size, NULL);
			info_printf(_("  Certificate Subject ID: %s\n"), dn);

			dn_size = sizeof(dn);
			gnutls_x509_crt_get_subject_unique_id(cert, dn, &dn_size);
			info_printf(_("  Certificate Subject UID: %s\n"), dn);
*/
			gnutls_x509_crt_deinit(cert);
		} else {
			info_printf(_("  Unknown certificate type %d\n"), (int) cert_type);
		}
	}
}

static int print_info(gnutls_session_t session)
{
	const char *tmp;
	gnutls_credentials_type_t cred;
	gnutls_kx_algorithm_t kx;
	int dhe = 0;
#if GNUTLS_VERSION_MAJOR >= 3
	int ecdh = 0;
#endif

	kx = gnutls_kx_get(session);

	info_printf(_("----\n"));

	/* Check the authentication type used and switch
	 * to the appropriate.
	 */
	cred = gnutls_auth_get_type(session);
	switch (cred) {
	case GNUTLS_CRD_IA:
		info_printf(_("TLS/IA session\n"));
		break;

	case GNUTLS_CRD_SRP:
#ifdef HAVE_GNUTLS_SRP_SERVER_GET_USERNAME
		info_printf(_("SRP session with username %s\n"), gnutls_srp_server_get_username(session));
#endif
		break;

	case GNUTLS_CRD_PSK:
		/* This returns NULL in server side.
		 */
		if (gnutls_psk_client_get_hint(session) != NULL)
			info_printf(_("PSK authentication. PSK hint '%s'\n"), gnutls_psk_client_get_hint(session));

		/* This returns NULL in client side.
		 */
		if (gnutls_psk_server_get_username(session) != NULL)
			info_printf(_("PSK authentication. Connected as '%s'\n"), gnutls_psk_server_get_username(session));

		if (kx == GNUTLS_KX_DHE_PSK)
			dhe = 1;
#if GNUTLS_VERSION_MAJOR >= 3
		else if (kx == GNUTLS_KX_ECDHE_PSK)
			ecdh = 1;
#endif
		break;

	case GNUTLS_CRD_ANON: /* anonymous authentication */

		info_printf(_("Anonymous authentication.\n"));
		if (kx == GNUTLS_KX_ANON_DH)
			dhe = 1;
#if GNUTLS_VERSION_MAJOR >= 3
		else if (kx == GNUTLS_KX_ANON_ECDH)
			ecdh = 1;
#endif
		break;

	case GNUTLS_CRD_CERTIFICATE: /* certificate authentication */

		/* Check if we have been using ephemeral Diffie-Hellman.
		 */
		if (kx == GNUTLS_KX_DHE_RSA || kx == GNUTLS_KX_DHE_DSS)
			dhe = 1;
#if GNUTLS_VERSION_MAJOR >= 3
		else if (kx == GNUTLS_KX_ECDHE_RSA || kx == GNUTLS_KX_ECDHE_ECDSA)
			ecdh = 1;
#endif

		/* if the certificate list is available, then
		 * print some information about it.
		 */
		print_x509_certificate_info(session);
		break;

	default:
		if ((int) cred == -1)
			info_printf(_("Transport authentication failure\n"));
		else
			info_printf(_("Unsupported credential type %d.\n"), (int) cred);
		break;
	} /* switch */

	info_printf(_("----\n"));

	if (dhe != 0)
		info_printf(_("Ephemeral DH using prime of %d bits\n"), gnutls_dh_get_prime_bits(session));
#if GNUTLS_VERSION_MAJOR >= 3
	else if (ecdh != 0)
		info_printf(_("Ephemeral ECDH using curve %s\n"), gnutls_ecc_curve_get_name(gnutls_ecc_curve_get(session)));
#endif

	/* print the key exchange's algorithm name */
	tmp = gnutls_kx_get_name(kx);
	info_printf(_("Key Exchange: %s\n"), tmp);

	/* print the protocol's name (ie TLS 1.0) */
	tmp = gnutls_protocol_get_name(gnutls_protocol_get_version(session));
	info_printf(_("Protocol: %s\n"), tmp);

	/* print the certificate type of the peer, ie X.509 */
	tmp = gnutls_certificate_type_get_name(gnutls_certificate_type_get(session));
	info_printf(_("Certificate Type: %s\n"), tmp);

	/* print the name of the cipher used, ie 3DES. */
	tmp = gnutls_cipher_get_name(gnutls_cipher_get(session));
	info_printf(_("Cipher: %s\n"), tmp);

	/* Print the MAC algorithms name, ie SHA1 */
	tmp = gnutls_mac_get_name(gnutls_mac_get(session));
	info_printf(_("MAC: %s\n"), tmp);

	info_printf(_("----\n"));

	return 0;
}

#ifdef WITH_OCSP
static int
_generate_ocsp_data(gnutls_x509_crt_t cert, gnutls_x509_crt_t issuer,
		  gnutls_datum_t * rdata, gnutls_datum_t *nonce)
{
	gnutls_ocsp_req_t req;
	int ret = gnutls_ocsp_req_init(&req);

	if (ret < 0) {
		debug_printf("ocsp_req_init: %s", gnutls_strerror(ret));
		return -1;
	}

	ret = gnutls_ocsp_req_add_cert(req, GNUTLS_DIG_SHA1, issuer, cert);
	if (ret < 0) {
		debug_printf("ocsp_req_add_cert: %s", gnutls_strerror(ret));
		goto error;
	}

	if (nonce) {
		ret = gnutls_ocsp_req_set_nonce(req, 0, nonce);
		if (ret < 0) {
			debug_printf("ocsp_req_set_nonce: %s", gnutls_strerror(ret));
			goto error;
		}
	}

	ret = gnutls_ocsp_req_export(req, rdata);
	if (ret) {
		debug_printf("ocsp_req_export: %s", gnutls_strerror(ret));
		goto error;
	}

	ret = 0;
error:
	gnutls_ocsp_req_deinit(req);
	return ret;
}

/* Returns 0 on ok, and -1 on error */
static int send_ocsp_request(const char *server,
		      gnutls_x509_crt_t cert, gnutls_x509_crt_t issuer,
		      wget_buffer **ocsp_data, gnutls_datum_t *nonce)
{
	int ret = -1;
	int server_allocated = 0;
	gnutls_datum_t body;
	wget_iri *iri;
	wget_http_request *req = NULL;

	if (!server) {
		/* try to read URL from issuer certificate */
		gnutls_datum_t data;
		unsigned i = 0;
		int rc;

		do {
			rc = gnutls_x509_crt_get_authority_info_access(cert, i++, GNUTLS_IA_OCSP_URI, &data, NULL);
		} while(rc < 0 && rc != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE);

		if (rc < 0) {
			i = 0;
			do {
				rc = gnutls_x509_crt_get_authority_info_access(issuer, i++, GNUTLS_IA_OCSP_URI, &data, NULL);
			} while(rc < 0 && rc != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE);
		}

		if (rc < 0) {
			debug_printf("Cannot find URL from issuer: %s\n", gnutls_strerror(rc));
			return -1;
		}

		server = wget_strmemdup((char *)data.data, data.size);
		server_allocated = 1;

		xfree(data.data);
	}

	iri = wget_iri_parse(server, NULL);

	if (server_allocated)
		xfree(server);

	if (!iri)
		return -1;

	if (_generate_ocsp_data(cert, issuer, &body, nonce))
		goto out;

	if (!(req = wget_http_create_request(iri, "POST")))
		goto out;

	wget_http_add_header(req, "Accept-Encoding", "identity");
	wget_http_add_header(req, "Accept", "*/*");
	wget_http_add_header(req, "Connection", "close");

	wget_http_connection *conn;
	if (wget_http_open(&conn, iri) == WGET_E_SUCCESS) {
		wget_http_request_set_body(req, "application/ocsp-request", wget_memdup(body.data, body.size), body.size);
		req->debug_skip_body = 1;
		if (wget_http_send_request(conn, req) == 0) {
			wget_http_response *resp;

			if ((resp = wget_http_get_response(conn))) {
				*ocsp_data = resp->body;
				resp->body = NULL;
				wget_http_free_response(&resp);
				ret = 0;
			}
		}
		wget_http_close(&conn);
	}

	xfree(body.data);

out:
	wget_http_free_request(&req);
	wget_iri_free(&iri);
	return ret;
}

static void print_ocsp_verify_res(unsigned int status)
{
	debug_printf("*** Verifying OCSP Response: ");

	if (status) {
		debug_printf("Failure");

		if (status & GNUTLS_OCSP_VERIFY_SIGNER_NOT_FOUND)
			debug_printf(", Signer cert not found");

		if (status & GNUTLS_OCSP_VERIFY_SIGNER_KEYUSAGE_ERROR)
			debug_printf(", Signer cert keyusage error");

		if (status & GNUTLS_OCSP_VERIFY_UNTRUSTED_SIGNER)
			debug_printf(", Signer cert is not trusted");

		if (status & GNUTLS_OCSP_VERIFY_INSECURE_ALGORITHM)
			debug_printf(", Insecure algorithm");

		if (status & GNUTLS_OCSP_VERIFY_SIGNATURE_FAILURE)
			debug_printf(", Signature failure");

		if (status & GNUTLS_OCSP_VERIFY_CERT_NOT_ACTIVATED)
			debug_printf(", Signer cert not yet activated");

		if (status & GNUTLS_OCSP_VERIFY_CERT_EXPIRED)
			debug_printf(", Signer cert expired");

		debug_printf("\n");
	} else
		debug_printf("Success\n");
}

/* three days */
#define OCSP_VALIDITY_SECS (3*60*60*24)

/* Returns:
 *  0: certificate is revoked
 *  1: certificate is ok
 *  -1: dunno
 */
static int check_ocsp_response(gnutls_x509_crt_t cert,
	gnutls_x509_crt_t issuer, wget_buffer *data,
	gnutls_datum_t *nonce)
{
	gnutls_ocsp_resp_t resp;
	int ret = -1, rc;
	unsigned int status, cert_status;
	time_t rtime = 0, vtime = 0, ntime = 0, now;
	char timebuf[64];

	now = time(NULL);

	if ((rc = gnutls_ocsp_resp_init(&resp)) < 0) {
		debug_printf("ocsp_resp_init: %s", gnutls_strerror(rc));
		return -1;
	}

	rc = gnutls_ocsp_resp_import(resp, &(gnutls_datum_t){ .data = (unsigned char *) data->data, .size = (unsigned) data->length });
	if (rc < 0) {
		debug_printf("importing response: %s", gnutls_strerror(rc));
		goto cleanup;
	}

#if GNUTLS_VERSION_NUMBER >= 0x030103
	if ((rc = gnutls_ocsp_resp_check_crt(resp, 0, cert)) < 0) {
		if (rc == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
			debug_printf("got OCSP response with no data (ignoring)\n");
		} else {
			debug_printf("got OCSP response on an unrelated certificate (ignoring)\n");
		}
		goto cleanup;
	}
#endif

	if ((rc = gnutls_ocsp_resp_verify_direct(resp, issuer, &status, 0)) < 0) {
		debug_printf("gnutls_ocsp_resp_verify_direct: %s", gnutls_strerror(rc));
		goto cleanup;
	}

	if (status) {
		print_ocsp_verify_res(status);
		goto cleanup;
	}

	rc = gnutls_ocsp_resp_get_single(resp, 0, NULL, NULL, NULL, NULL,
					  &cert_status, &vtime, &ntime, &rtime, NULL);
	if (rc < 0) {
		debug_printf("reading response: %s", gnutls_strerror(rc));
		goto cleanup;
	}

	if (cert_status == GNUTLS_OCSP_CERT_REVOKED) {
		debug_printf("*** Certificate was revoked at %s", safe_ctime(rtime, timebuf, sizeof(timebuf)));
		ret = 0;
		goto cleanup;
	}

	debug_printf("*** OCSP issued time: %s\n", safe_ctime(vtime, timebuf, sizeof(timebuf)));
	debug_printf("*** OCSP update time  : %s\n", safe_ctime(ntime, timebuf, sizeof(timebuf)));

	if (ntime == -1) {
		if (config.ocsp_date && now - vtime > OCSP_VALIDITY_SECS) {
			debug_printf("*** The OCSP response is old (was issued at: %s) ignoring", safe_ctime(vtime, timebuf, sizeof(timebuf)));
			goto cleanup;
		}
	} else {
		/* there is a newer OCSP answer, don't trust this one */
		if (ntime < now) {
			debug_printf("*** The OCSP response was issued at: %s", safe_ctime(vtime, timebuf, sizeof(timebuf)));
			debug_printf("    but there is a newer issue at %s", safe_ctime(ntime, timebuf, sizeof(timebuf)));
			goto cleanup;
		}
	}

	if (nonce) {
		gnutls_datum_t rnonce;

		rc = gnutls_ocsp_resp_get_nonce(resp, NULL, &rnonce);
		if (rc == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
			debug_printf("*** The OCSP reply did not include the requested nonce.\n");
			goto finish_ok;
		}

		if (rc < 0) {
			debug_printf("could not read response's nonce: %s\n", gnutls_strerror(rc));
			goto cleanup;
		}

		if (config.ocsp_nonce && (rnonce.size != nonce->size || memcmp(nonce->data, rnonce.data, nonce->size) != 0)) {
			debug_printf("nonce in the response doesn't match\n");
			xfree(rnonce.data);
			goto cleanup;
		}

		xfree(rnonce.data);
	}

 finish_ok:
	debug_printf("OCSP server flags certificate not revoked as of %s", safe_ctime(vtime, timebuf, sizeof(timebuf)));
	ret = 1;

cleanup:
	gnutls_ocsp_resp_deinit(resp);
	return ret;
}

/*
 * Calculate fingerprint from certificate
 */
static char *_get_cert_fingerprint(gnutls_x509_crt_t cert, char *fingerprint_hex, size_t length)
{
	unsigned char fingerprint[64];
	size_t fingerprint_size = sizeof(fingerprint);
	int err;

	if ((err = gnutls_x509_crt_get_fingerprint(cert, GNUTLS_DIG_SHA256, fingerprint, &fingerprint_size)) < 0) {
		debug_printf("Failed to get fingerprint: %s\n", gnutls_strerror(err));
		wget_strscpy(fingerprint_hex, "00", length);
	} else {
		wget_memtohex(fingerprint, fingerprint_size, fingerprint_hex, length);
	}

	return fingerprint_hex;
}

/*
 * Add cert to OCSP cache, being either valid or revoked (valid==0)
 */
static void add_cert_to_ocsp_cache(gnutls_x509_crt_t cert, bool valid)
{
	if (config.ocsp_cert_cache) {
		char fingerprint_hex[64 * 2 +1];

		_get_cert_fingerprint(cert, fingerprint_hex, sizeof(fingerprint_hex));
		wget_ocsp_db_add_fingerprint(config.ocsp_cert_cache, fingerprint_hex, time(NULL) + 3600, valid); // 1h valid
	}
}

/* OCSP check for the peer's certificate. Should be called
 * only after the certificate list verification is complete.
 * Returns:
 * 0: certificate is revoked
 * 1: certificate is ok
 * -1: dunno
 */
//static int cert_verify_ocsp(gnutls_session_t session)
static int cert_verify_ocsp(gnutls_x509_crt_t cert, gnutls_x509_crt_t issuer)
{
	wget_buffer *resp = NULL;
	unsigned char noncebuf[23];
	gnutls_datum_t nonce = { noncebuf, sizeof(noncebuf) };
	int ret;

	ret = gnutls_rnd(GNUTLS_RND_NONCE, nonce.data, nonce.size);
	if (ret < 0) {
		debug_printf("gnutls_rnd: %s", gnutls_strerror(ret));
		return -1;
	}

	if (send_ocsp_request(config.ocsp_server, cert, issuer, &resp, &nonce) < 0) {
		debug_printf("Cannot contact OCSP server\n");
		return -1;
	}

	if (!resp) {
		debug_printf("Missing response from OCSP server\n");
		return -1;
	}

	/* verify and check the response for revoked cert */
	ret = check_ocsp_response(cert, issuer, resp, &nonce);
	wget_buffer_free(&resp);

	return ret;
}
#endif // WITH_OCSP

static int cert_verify_hpkp(gnutls_x509_crt_t cert, const char *hostname, gnutls_session_t session)
{
	gnutls_pubkey_t key = NULL;
	int rc, ret = -1;
	struct session_context *ctx = gnutls_session_get_ptr(session);

	if (!config.hpkp_cache)
		return 0;

	gnutls_pubkey_init(&key);

	if ((rc = gnutls_pubkey_import_x509(key, cert, 0)) != GNUTLS_E_SUCCESS) {
		error_printf(_("Failed to import pubkey: %s\n"), gnutls_strerror(rc));
		return 0;
	}

#if GNUTLS_VERSION_NUMBER >= 0x030103
	gnutls_datum_t pubkey;

	if ((rc = gnutls_pubkey_export2(key, GNUTLS_X509_FMT_DER, &pubkey)) != GNUTLS_E_SUCCESS) {
		error_printf(_("Failed to export pubkey: %s\n"), gnutls_strerror(rc));
		ret = 0;
		goto out;
	}

	rc = wget_hpkp_db_check_pubkey(config.hpkp_cache, hostname, pubkey.data, pubkey.size);
	xfree(pubkey.data);
#else
	size_t size = 0;
	void *data = NULL;

	if ((rc = gnutls_pubkey_export(key, GNUTLS_X509_FMT_DER, NULL, &size)) != GNUTLS_E_SHORT_MEMORY_BUFFER) {
		error_printf(_("Failed to export pubkey: %s\n"), gnutls_strerror(rc));
		ret = 0;
		goto out;
	}

	data = wget_malloc(size);

	if ((rc = gnutls_pubkey_export(key, GNUTLS_X509_FMT_DER, data, &size)) == GNUTLS_E_SHORT_MEMORY_BUFFER) {
		error_printf(_("Failed to export pubkey: %s\n"), gnutls_strerror(rc));
		ret = 0;
		goto out;
	}

	rc = wget_hpkp_db_check_pubkey(config.hpkp_cache, hostname, data, size);
	xfree(data);
#endif

	if (rc != -2) {
		if (rc == 0) {
			debug_printf("host has no pubkey pinnings stored in hpkp db\n");
			ctx->stats_hpkp = WGET_STATS_HPKP_NO;
		} else if (rc == 1) {
			debug_printf("pubkey is matching a pinning\n");
			ctx->stats_hpkp = WGET_STATS_HPKP_MATCH;
		} else if (rc == -1) {
			debug_printf("Error while checking pubkey pinning\n");
			ctx->stats_hpkp = WGET_STATS_HPKP_ERROR;
		}
		ret = 0;
	} else
		ctx->stats_hpkp = WGET_STATS_HPKP_NOMATCH;

out:
	gnutls_pubkey_deinit(key);
	return ret; // Pubkey not found
}

static void print_verification_status(gnutls_session_t session, const char *tag, int status) {
	gnutls_datum_t out;

	if (gnutls_certificate_verification_status_print(
		status, gnutls_certificate_type_get(session), &out, 0) == GNUTLS_E_SUCCESS)
	{
		error_printf_check("%s: %s\n", tag, out.data); // no translation
		xfree(out.data);
	}
}

/* This function will verify the peer's certificate, and check
 * if the hostname matches, as well as the activation, expiration dates.
 */
static int verify_certificate_callback(gnutls_session_t session)
{
	unsigned int status, deinit_cert = 0, deinit_issuer = 0;
	const gnutls_datum_t *cert_list = 0;
	unsigned int cert_list_size;
	int ret = -1, err, ocsp_ok = 0, pinning_ok = 0;
	gnutls_x509_crt_t cert = NULL, issuer = NULL;
	const char *tag = config.check_certificate ? _("ERROR") : _("WARNING");
#ifdef WITH_OCSP
	bool skip_server_cert_check = false;
	unsigned nvalid = 0, nrevoked = 0, nignored = 0;
#endif

	// read hostname
	struct session_context *ctx = gnutls_session_get_ptr(session);
	const char *hostname = ctx->hostname;

	/* This verification function uses the trusted CAs in the credentials
	 * structure. So you must have installed one or more CA certificates.
	 */
#if GNUTLS_VERSION_NUMBER >= 0x030104
	if (gnutls_certificate_verify_peers3(session, hostname, &status) != GNUTLS_E_SUCCESS) {
#else
	if (gnutls_certificate_verify_peers2(session, &status) != GNUTLS_E_SUCCESS) {
#endif
//		if (wget_get_logger(WGET_LOGGER_DEBUG))
//			_print_info(session);
		error_printf_check(_("%s: Certificate verification error\n"), tag);
		goto out;
	}

//	if (wget_get_logger(WGET_LOGGER_DEBUG))
//		_print_info(session);

#ifdef WITH_OCSP
	if (status & GNUTLS_CERT_REVOKED) {
		if (config.ocsp_cert_cache)
			wget_ocsp_db_add_host(config.ocsp_cert_cache, hostname, 0); // remove entry from cache
		if (ctx->ocsp_stapling) {
			if (gnutls_x509_crt_init(&cert) == GNUTLS_E_SUCCESS) {
				if ((cert_list = gnutls_certificate_get_peers(session, &cert_list_size))) {
					if (gnutls_x509_crt_import(cert, &cert_list[0], GNUTLS_X509_FMT_DER) == GNUTLS_E_SUCCESS) {
						add_cert_to_ocsp_cache(cert, false);
					}
				}
				gnutls_x509_crt_deinit(cert);
			}
		}
	}
#endif

#if GNUTLS_VERSION_NUMBER >= 0x030104
#ifdef WITH_LIBDANE
	// If CA cert verification failed due to missing certificates, we try DANE verification (if requested by the user).
	if (status) {
		if (!config.dane) {
			print_verification_status(session, tag, status);
			goto out;
		}
		if (status != (GNUTLS_CERT_INVALID | GNUTLS_CERT_SIGNER_NOT_FOUND)) {
			print_verification_status(session, tag, status);
			goto out;
		}

		// GNUTLS_CERT_SIGNER_NOT_FOUND indicates that no matching CA cert exists.

		unsigned verify = 0;

		int rc = dane_verify_session_crt(NULL, session, hostname, "tcp", ctx->port, 0,
			DANE_VFLAG_FAIL_IF_NOT_CHECKED,
			&verify);

		if (rc < 0) {
			debug_printf("DANE verification error for %s: %s\n", hostname, dane_strerror(rc));
			goto out;
		} else if (verify) {
			gnutls_datum_t out;
			rc = dane_verification_status_print(verify, &out, 0);
			if (rc < 0) {
				error_printf(_("DANE verification print error for %s: %s\n"), hostname, dane_strerror(rc));
			} else {
				error_printf(_("DANE verification failed for %s: %s\n"), hostname, out.data);
			}
			gnutls_free(out.data);
			goto out;
		} else {
			debug_printf("DANE verification: %s\n", dane_strerror(rc));
		}
	}
#else
	if (status) {
		print_verification_status(session, tag, status);
		goto out;
	}
#endif
#else
	if (status) {
		if (status & GNUTLS_CERT_INVALID)
			error_printf_check(_("%s: The certificate is not trusted.\n"), tag);
		if (status & GNUTLS_CERT_REVOKED)
			error_printf_check(_("%s: The certificate has been revoked.\n"), tag);
		if (status & GNUTLS_CERT_SIGNER_NOT_FOUND)
			error_printf_check(_("%s: The certificate doesn't have a known issuer.\n"), tag);
		if (status & GNUTLS_CERT_SIGNER_NOT_CA)
			error_printf_check(_("%s: The certificate signer was not a CA.\n"), tag);
		if (status & GNUTLS_CERT_INSECURE_ALGORITHM)
			error_printf_check(_("%s: The certificate was signed using an insecure algorithm.\n"), tag);
		if (status & GNUTLS_CERT_NOT_ACTIVATED)
			error_printf_check(_("%s: The certificate is not yet activated.\n"), tag);
		if (status & GNUTLS_CERT_EXPIRED)
			error_printf_check(_("%s: The certificate has expired.\n"), tag);
#if GNUTLS_VERSION_NUMBER >= 0x030100
		if (status & GNUTLS_CERT_SIGNATURE_FAILURE)
			error_printf_check(_("%s: The certificate signature is invalid.\n"), tag);
		if (status & GNUTLS_CERT_UNEXPECTED_OWNER)
			error_printf_check(_("%s: The certificate's owner does not match hostname '%s'.\n"), tag, hostname);
#endif

		// any other reason
		if (status & ~(GNUTLS_CERT_INVALID|GNUTLS_CERT_REVOKED|GNUTLS_CERT_SIGNER_NOT_FOUND|
			GNUTLS_CERT_SIGNER_NOT_CA|GNUTLS_CERT_INSECURE_ALGORITHM|GNUTLS_CERT_NOT_ACTIVATED|
			GNUTLS_CERT_EXPIRED
#if GNUTLS_VERSION_NUMBER >= 0x030100
			|GNUTLS_CERT_SIGNATURE_FAILURE
			|GNUTLS_CERT_UNEXPECTED_OWNER
#endif
			))
			error_printf_check(_("%s: The certificate could not be verified (0x%X).\n"), tag, status);

		goto out;
	}
#endif

	/* Up to here the process is the same for X.509 certificates and
	 * OpenPGP keys. From now on X.509 certificates are assumed. This can
	 * be easily extended to work with openpgp keys as well.
	 */
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
#ifdef WITH_OCSP
	if (config.ocsp_stapling) {
		if (!ctx->valid && ctx->ocsp_stapling) {
#if GNUTLS_VERSION_NUMBER >= 0x030103
			if (gnutls_ocsp_status_request_is_checked(session, 0)) {
				debug_printf("Server certificate is valid regarding OCSP stapling\n");
//				_get_cert_fingerprint(cert, fingerprint, sizeof(fingerprint)); // calc hexadecimal fingerprint string
				add_cert_to_ocsp_cache(cert, true);
				nvalid = 1;
				skip_server_cert_check = true;
			}
#if GNUTLS_VERSION_NUMBER >= 0x030400
			else if (gnutls_ocsp_status_request_is_checked(session, GNUTLS_OCSP_SR_IS_AVAIL)) {
				error_printf_check(_("WARNING: The certificate's (stapled) OCSP status is invalid\n"));
				skip_server_cert_check = true;
			}
#endif
			else if (!config.ocsp) {
				debug_printf("OCSP stapling is not supported by '%s'\n", hostname);
			} else {
				error_printf_check(_("WARNING: OCSP stapling is not supported by '%s', but OCSP validation has been requested.\n"), hostname);
				error_printf_check(_("WARNING: This implies a privacy leak: the client sends the certificate serial ID over HTTP to the CA.\n"));
			}
#endif
		} else if (ctx->valid)
			debug_printf("OCSP: Host '%s' is valid (from cache)\n", hostname);
	}
#endif

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

#ifdef WITH_OCSP
		if (!config.ocsp || (skip_server_cert_check && it == 0))
			continue;

		char fingerprint[64 * 2 +1];
		_get_cert_fingerprint(cert, fingerprint, sizeof(fingerprint)); // calc hexadecimal fingerprint string

		int revoked;
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
			wget_ocsp_db_add_fingerprint(config.ocsp_cert_cache, fingerprint, time(NULL) + 3600, true); // 1h valid
			nvalid++;
		} else if (ocsp_ok == 0) {
			debug_printf("%s: Certificate[%u] of '%s' has been revoked (via OCSP)\n", tag, it, hostname);
			wget_ocsp_db_add_fingerprint(config.ocsp_cert_cache, fingerprint, time(NULL) + 3600, false);  // cert has been revoked
			nrevoked++;
		} else {
			debug_printf("WARNING: OCSP response not available or ignored\n");
			nignored++;
		}
#endif
	}

#ifdef WITH_OCSP
	if (config.ocsp && ocsp_stats_callback) {
		wget_ocsp_stats_data stats;
		stats.hostname = hostname;
		stats.nvalid = nvalid;
		stats.nrevoked = nrevoked;
		stats.nignored = nignored;
		stats.stapling = ctx->ocsp_stapling;

		ocsp_stats_callback(&stats, ocsp_stats_ctx);
	}

	if (config.ocsp_stapling || config.ocsp) {
		if (nvalid == cert_list_size) {
			wget_ocsp_db_add_host(config.ocsp_cert_cache, hostname, time(NULL) + 3600); // 1h valid
		} else if (nrevoked) {
			wget_ocsp_db_add_host(config.ocsp_cert_cache, hostname, 0); // remove entry from cache
			ret = -1;
		}
	}
#endif

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

		// Initialize paths while in a thread-safe environment (mostly for _WIN32).
		wget_ssl_default_cert_dir();
		wget_ssl_default_ca_bundle_path();

		atexit(tls_exit);
	}
}

static int key_type(int type)
{
	if (type == WGET_SSL_X509_FMT_DER)
		return GNUTLS_X509_FMT_DER;

	return GNUTLS_X509_FMT_PEM;
}

// ssl_init() is thread safe

static void set_credentials(gnutls_certificate_credentials_t creds)
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
		if (config.key_type != config.cert_type) {
			// GnuTLS can't handle this
			error_printf(_("GnuTLS requires the key and the cert to be of the same type.\n"));
		}

		if (gnutls_certificate_set_x509_key_file(creds, config.cert_file, config.key_file, key_type(config.key_type)) != GNUTLS_E_SUCCESS)
			error_printf(_("No certificates or keys were found\n"));
	}

	if (config.ca_file && !wget_strcmp(config.ca_file, "system"))
		config.ca_file = wget_ssl_default_ca_bundle_path();
	if (config.ca_file) {
		if (gnutls_certificate_set_x509_trust_file(creds, config.ca_file, key_type(config.ca_type)) <= 0)
			error_printf(_("No CAs were found in '%s'\n"), config.ca_file);
	}
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
	tls_init();

	wget_thread_mutex_lock(mutex);

	if (!init) {
		int rc, ncerts = -1;

		debug_printf("GnuTLS init\n");
		gnutls_global_init();
		gnutls_certificate_allocate_credentials(&credentials);
		gnutls_certificate_set_verify_function(credentials, verify_certificate_callback);

		if (config.ca_directory && *config.ca_directory && config.check_certificate) {
#if GNUTLS_VERSION_NUMBER >= 0x03000d
			if (!strcmp(config.ca_directory, "system")) {
				ncerts = gnutls_certificate_set_x509_system_trust(credentials);
				if (ncerts < 0)
					debug_printf("GnuTLS system certificate store error %d\n", ncerts);
				else
					debug_printf("GnuTLS system certificate store is empty\n");
			}
#endif

			if (ncerts < 0) {
				DIR *dir;

				ncerts = 0;

				if (!strcmp(config.ca_directory, "system"))
					config.ca_directory = wget_ssl_default_cert_dir();

				if ((dir = opendir(config.ca_directory))) {
					struct dirent *dp;

					while ((dp = readdir(dir))) {
						size_t len = strlen(dp->d_name);

						if (len >= 4 && !wget_strncasecmp_ascii(dp->d_name + len - 4, ".pem", 4)) {
							char *fname = wget_aprintf("%s/%s", config.ca_directory, dp->d_name);

							if (!fname) {
								error_printf(_("Failed to allocate file name for cert '%s/%s'\n"), config.ca_directory, dp->d_name);
								continue;
							}

							struct stat st;
							if (stat(fname, &st) == 0 && S_ISREG(st.st_mode)) {
								debug_printf("GnuTLS loading %s\n", fname);
								if ((rc = gnutls_certificate_set_x509_trust_file(credentials, fname, GNUTLS_X509_FMT_PEM)) <= 0)
									debug_printf("Failed to load cert '%s': (%d)\n", fname, rc);
								else
									ncerts += rc;
							}

							xfree(fname);
						}
					}

					closedir(dir);
				} else {
					error_printf(_("Failed to opendir %s\n"), config.ca_directory);
				}
			}
		}

		if (config.crl_file) {
			if ((rc = gnutls_certificate_set_x509_crl_file(credentials, config.crl_file, GNUTLS_X509_FMT_PEM)) <= 0)
				error_printf(_("Failed to load CRL '%s': (%d)\n"), config.crl_file, rc);
		}

		set_credentials(credentials);

		debug_printf("Certificates loaded: %d\n", ncerts);

		if (config.secure_protocol) {
			const char *priorities = NULL;

			if (!wget_strcasecmp_ascii(config.secure_protocol, "PFS")) {
				priorities = "PFS:-VERS-SSL3.0";
				// -RSA to force DHE/ECDHE key exchanges to have Perfect Forward Secrecy (PFS))
				if ((rc = gnutls_priority_init(&priority_cache, priorities, NULL)) != GNUTLS_E_SUCCESS) {
					priorities = "NORMAL:-RSA:-VERS-SSL3.0";
					rc = gnutls_priority_init(&priority_cache, priorities, NULL);
				}
			} else {
#if GNUTLS_VERSION_NUMBER >= 0x030603
#define TLS13_PRIO ":+VERS-TLS1.3"
#else
#define TLS13_PRIO ""
#endif
				if (!wget_strncasecmp_ascii(config.secure_protocol, "SSL", 3))
					priorities = "NORMAL:-VERS-TLS-ALL:+VERS-SSL3.0";
				else if (!wget_strcasecmp_ascii(config.secure_protocol, "TLSv1"))
					priorities = "NORMAL:-VERS-SSL3.0" TLS13_PRIO;
				else if (!wget_strcasecmp_ascii(config.secure_protocol, "TLSv1_1"))
					priorities = "NORMAL:-VERS-SSL3.0:-VERS-TLS1.0" TLS13_PRIO;
				else if (!wget_strcasecmp_ascii(config.secure_protocol, "TLSv1_2"))
					priorities = "NORMAL:-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1" TLS13_PRIO;
				else if (!wget_strcasecmp_ascii(config.secure_protocol, "TLSv1_3"))
					priorities = "NORMAL:-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1:-VERS-TLS1.2" TLS13_PRIO;
				else if (!wget_strcasecmp_ascii(config.secure_protocol, "auto")) {
					/* use system default, priorities = NULL */
				} else if (*config.secure_protocol)
					priorities = config.secure_protocol;

				rc = gnutls_priority_init(&priority_cache, priorities, NULL);
			}

			if (rc != GNUTLS_E_SUCCESS)
				error_printf(_("GnuTLS: Unsupported priority string '%s': %s\n"), priorities ? priorities : "(null)", gnutls_strerror(rc));
		} else {
			// use GnuTLS defaults, which might hold insecure ciphers
			if ((rc = gnutls_priority_init(&priority_cache, NULL, NULL)))
				error_printf(_("GnuTLS: Unsupported default priority 'NULL': %s\n"), gnutls_strerror(rc));
		}

		init++;

		debug_printf("GnuTLS init done\n");
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
		gnutls_certificate_free_credentials(credentials);
		gnutls_priority_deinit(priority_cache);
		gnutls_global_deinit();
	}

	if (init > 0) init--;

	wget_thread_mutex_unlock(mutex);
}

static int do_handshake(gnutls_session_t session, int sockfd, int timeout)
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
		rc = gnutls_handshake(session);

		if (rc == GNUTLS_E_SUCCESS) {
			ret = WGET_E_SUCCESS;
			break;
		}

		if (gnutls_error_is_fatal(rc)) {
			debug_printf("gnutls_handshake: (%d) %s (errno=%d)\n", rc, gnutls_strerror(rc),errno);

			if (rc == GNUTLS_E_CERTIFICATE_ERROR) {
				ret = WGET_E_CERTIFICATE;
			} else if (rc == GNUTLS_E_PUSH_ERROR && (errno == ECONNREFUSED || errno == ENOTCONN)) {
				/*
				 * ECONNREFUSED: on Linux
				 * ENOTCONN: MinGW (in out Gitlab CI runner)
				 */
				ret = WGET_E_CONNECT;
			} else if (rc == GNUTLS_E_PULL_ERROR && errno == 61 /* ENODATA, but not on OSX/Travis ? */) {
				// We see this with older versions of GnuTLS, e.g. on TravisCI. (Tim, 11.4.2018)
				// It happens when trying to connect to a port without a listener
				ret = WGET_E_CONNECT;
#ifdef GNUTLS_E_PREMATURE_TERMINATION
			} else if (rc == GNUTLS_E_PREMATURE_TERMINATION && errno == EAGAIN) {
				// It happens when trying to connect to a closed port
				ret = WGET_E_CONNECT;
#endif
			} else if (rc == GNUTLS_E_UNEXPECTED_PACKET_LENGTH && errno == EAGAIN) {
				// We see this with older versions of GnuTLS, e.g. on TravisCI. (Tim, 11.4.2018)
				// It happens when trying to connect to a port without a listener
				ret = WGET_E_CONNECT;
			} else
				ret = WGET_E_HANDSHAKE;

			break;
		}

		if (gnutls_record_get_direction(session)) {
			// wait for writeability
			rc = wget_ready_2_write(sockfd, timeout);
		} else {
			// wait for readability
			rc = wget_ready_2_read(sockfd, timeout);
		}
	}

#if GNUTLS_VERSION_NUMBER >= 0x030500
	if (ret == WGET_E_SUCCESS)
		debug_printf("TLS False Start: %s\n",
			(gnutls_session_get_flags(session) & GNUTLS_SFLAGS_FALSE_START) ? "on" : "off");
#endif

	return ret;
}

#ifdef MSG_FASTOPEN
#include <sys/socket.h>
#include <sys/uio.h> // writev
#include <netdb.h>
#include <errno.h>
static ssize_t ssl_writev(gnutls_transport_ptr_t *p, const giovec_t *iov, int iovcnt)
{
	wget_tcp *tcp = (wget_tcp *) p;
	ssize_t ret;

	// info_printf("%s: %d %zu\n", __func__, iovcnt, iov[0].iov_len);
	if (tcp->first_send) {
		struct msghdr hdr = {
			.msg_name = tcp->connect_addrinfo->ai_addr,
			.msg_namelen = tcp->connect_addrinfo->ai_addrlen,
			.msg_iov = (struct iovec *) iov,
			.msg_iovlen = iovcnt,
		};

//		ret = sendto(tcp->sockfd, iov[0].iov_base, iov[0].iov_len, MSG_FASTOPEN,
//				tcp->connect_addrinfo->ai_addr, tcp->connect_addrinfo->ai_addrlen);
		ret = sendmsg(tcp->sockfd, &hdr, MSG_FASTOPEN);
		if (ret < 0) {
			if (errno == EINPROGRESS) {
				errno = EAGAIN; // GnuTLS does not handle EINPROGRESS
			} else if (errno == EOPNOTSUPP) {
				// fallback from fastopen, e.g. when fastopen is disabled in system
				debug_printf("Fallback from TCP Fast Open... TFO is disabled at system level\n");
				tcp->tcp_fastopen = 0;
				ret = connect(tcp->sockfd, tcp->connect_addrinfo->ai_addr, tcp->connect_addrinfo->ai_addrlen);
				if (errno == ENOTCONN || errno == EINPROGRESS)
					errno = EAGAIN;
			}
		}

		tcp->first_send = 0;
	} else {
		ret = writev(tcp->sockfd, (struct iovec *) iov, iovcnt);
	}
	// info_printf("errno=%d ret=%d\n", errno, ret);

	// after the first write we set back the transport push function and the transport pointer to standard functions
#ifdef HAVE_GNUTLS_TRANSPORT_GET_INT
	// since GnuTLS 3.1.9, avoid warnings about illegal pointer conversion
	gnutls_transport_set_int(tcp->ssl_session, tcp->sockfd);
#else
	gnutls_transport_set_ptr(tcp->ssl_session, (gnutls_transport_ptr_t)(ptrdiff_t)tcp->sockfd);
#endif

#if defined __clang__
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wcast-function-type"
#endif
	gnutls_transport_set_vec_push_function(tcp->ssl_session, (ssize_t (*) (gnutls_transport_ptr_t, const giovec_t * iov, int iovcnt)) writev);
#if defined __clang__
  #pragma clang diagnostic pop
#endif

	return ret;
}
#endif

#ifdef _WIN32
static ssize_t win32_send(gnutls_transport_ptr_t p, const void *buf, size_t size)
{
	int sockfd = (int) (ptrdiff_t) p;

	return send(sockfd, buf, size, 0);
}
static ssize_t win32_recv(gnutls_transport_ptr_t p, void *buf, size_t size)
{
	int sockfd = (int) (ptrdiff_t) p;

	return recv(sockfd, buf, size, 0);
}
#endif

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
	gnutls_session_t session;
	wget_tls_stats_data stats = {
			.alpn_protocol = NULL,
			.version = -1,
			.false_start = -1,
			.tfo = -1,
			.resumed = 0,
			.http_protocol = WGET_PROTOCOL_HTTP_1_1,
			.cert_chain_size = 0
	};

	int ret = WGET_E_UNKNOWN;
	int rc, sockfd, connect_timeout;
	const char *hostname;
	long long before_millisecs = 0;

	if (!tcp)
		return WGET_E_INVALID;

	struct session_context *ctx = wget_calloc(1, sizeof(struct session_context));
	if (!ctx)
		return WGET_E_MEMORY;

	if (!init)
		wget_ssl_init();

	hostname = tcp->ssl_hostname;
	sockfd= tcp->sockfd;
	connect_timeout = tcp->connect_timeout;

	unsigned int flags = GNUTLS_CLIENT;

#if GNUTLS_VERSION_NUMBER >= 0x030500
#if GNUTLS_VERSION_NUMBER >= 0x030605
	flags |= GNUTLS_AUTO_REAUTH | GNUTLS_POST_HANDSHAKE_AUTH;
#endif

	if (tcp->tls_false_start) {
		debug_printf("TLS False Start requested\n");

		flags |= GNUTLS_NONBLOCK | GNUTLS_ENABLE_FALSE_START;

		gnutls_init(&session, flags);
	} else {
		flags |= GNUTLS_NONBLOCK;

		gnutls_init(&session, flags);
	}
#elif defined GNUTLS_NONBLOCK
	if (tcp->tls_false_start)
		error_printf(_("TLS False Start requested but libwget built with insufficient GnuTLS version\n"));
	flags |= GNUTLS_NONBLOCK;
	gnutls_init(&session, flags);
#else
	// very old gnutls version, likely to not work.
	if (tcp->tls_false_start)
		error_printf(_("TLS False Start requested but libwget built with insufficient GnuTLS version\n"));
	gnutls_init(&session, flags);
#endif

	if ((rc = gnutls_priority_set(session, priority_cache)) != GNUTLS_E_SUCCESS)
		error_printf(_("GnuTLS: Failed to set priorities: %s\n"), gnutls_strerror(rc));

	if (!wget_strcasecmp_ascii(config.secure_protocol, "auto"))
		gnutls_session_enable_compatibility_mode(session);

	// RFC 6066 SNI Server Name Indication
	if (hostname) {
		gnutls_server_name_set(session, GNUTLS_NAME_DNS, hostname, strlen(hostname));
		debug_printf("SNI %s\n", hostname);
	}
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, credentials);

	ctx->hostname = wget_strdup(hostname);
	ctx->port = tcp->remote_port;

#ifdef WITH_OCSP
	// If we know the cert chain for the hostname being valid at the moment,
	// we don't ask for OCSP stapling to avoid unneeded IP traffic.
	// In the unlikely case that the server's certificate chain changed right now,
	// we fallback to OCSP responder request later (if enabled).
	if (hostname) {
		if (!(ctx->valid = wget_ocsp_hostname_is_valid(config.ocsp_host_cache, hostname))) {
#if GNUTLS_VERSION_NUMBER >= 0x030103
			if ((rc = gnutls_ocsp_status_request_enable_client(session, NULL, 0, NULL)) == GNUTLS_E_SUCCESS) {
				debug_printf("OCSP stapling requested for %s\n", hostname);
				ctx->ocsp_stapling = 1;
			} else
				error_printf("GnuTLS: %s\n", gnutls_strerror(rc)); // no translation
#endif
		}
	}
#else
	if (config.ocsp || config.ocsp_stapling)
		error_printf(_("WARNING: OCSP is not available in this version of GnuTLS.\n"));
#endif

#if GNUTLS_VERSION_NUMBER >= 0x030200
	if (config.alpn) {
		unsigned nprot;
		const char *e, *s;

		for (nprot = 0, s = e = config.alpn; *e; s = e + 1)
			if ((e = strchrnul(s, ',')) != s)
				nprot++;

		if (nprot) {
			gnutls_datum_t data[16];

			for (nprot = 0, s = e = config.alpn; *e && nprot < countof(data); s = e + 1) {
				if ((e = strchrnul(s, ',')) != s) {
					data[nprot].data = (unsigned char *) s;
					data[nprot].size = (unsigned) (e - s);
					debug_printf("ALPN offering %.*s\n", (int) data[nprot].size, data[nprot].data);
					nprot++;
				}
			}

			if ((rc = gnutls_alpn_set_protocols(session, data, nprot, 0)))
				debug_printf("GnuTLS: Set ALPN: %s\n", gnutls_strerror(rc));
		}
	}
#endif

	tcp->ssl_session = session;
	gnutls_session_set_ptr(session, ctx);

#ifdef MSG_FASTOPEN
	if ((rc = wget_tcp_get_tcp_fastopen(tcp))) {
		if (tls_stats_callback)
			stats.tfo = (char)rc;

		// prepare for TCP FASTOPEN... sendmsg() instead of connect/write on first write
		gnutls_transport_set_vec_push_function(session, (ssize_t (*)(gnutls_transport_ptr_t, const giovec_t *iov, int iovcnt)) ssl_writev);
		gnutls_transport_set_ptr(session, tcp);
	} else {
#endif

#ifdef _WIN32
	gnutls_transport_set_push_function(session, (gnutls_push_func) win32_send);
	gnutls_transport_set_pull_function(session, (gnutls_pull_func) win32_recv);
#endif

#ifdef HAVE_GNUTLS_TRANSPORT_GET_INT
	// since GnuTLS 3.1.9, avoid warnings about illegal pointer conversion
	gnutls_transport_set_int(session, sockfd);
#else
	gnutls_transport_set_ptr(session, (gnutls_transport_ptr_t)(ptrdiff_t)sockfd);
#endif

#ifdef MSG_FASTOPEN
	}
#endif

	{
		void *data;
		size_t size;

		if (wget_tls_session_get(config.tls_session_cache, ctx->hostname, &data, &size) == 0) {
			debug_printf("found cached session data for %s\n", ctx->hostname);
			if ((rc = gnutls_session_set_data(session, data, size)) != GNUTLS_E_SUCCESS)
				error_printf(_("GnuTLS: Failed to set session data: %s\n"), gnutls_strerror(rc));
			xfree(data);
		}
	}

	if (tls_stats_callback)
		before_millisecs = wget_get_timemillis();

	ret = do_handshake(session, sockfd, connect_timeout);

	if (tls_stats_callback) {
		long long after_millisecs = wget_get_timemillis();
		stats.tls_secs = after_millisecs - before_millisecs;
		stats.tls_con = 1;
#if GNUTLS_VERSION_NUMBER >= 0x030500
		stats.false_start = (gnutls_session_get_flags(session) & GNUTLS_SFLAGS_FALSE_START) != 0;
#endif
	}

#if GNUTLS_VERSION_NUMBER >= 0x030200
	if (config.alpn) {
		gnutls_datum_t protocol;
		if ((rc = gnutls_alpn_get_selected_protocol(session, &protocol))) {
			debug_printf("GnuTLS: Get ALPN: %s\n", gnutls_strerror(rc));
			if (!strstr(config.alpn,"http/1.1"))
				ret = WGET_E_CONNECT;
		} else {
			debug_printf("ALPN: Server accepted protocol '%.*s'\n", (int) protocol.size, protocol.data);
			if (tls_stats_callback)
				stats.alpn_protocol = wget_strmemdup(protocol.data, protocol.size);

			if (!memcmp(protocol.data, "h2", 2)) {
				tcp->protocol = WGET_PROTOCOL_HTTP_2_0;
				if (tls_stats_callback)
					stats.http_protocol = WGET_PROTOCOL_HTTP_2_0;
			}
		}
	}
#endif

	if (config.print_info)
		print_info(session);

	if (ret == WGET_E_SUCCESS) {
		int resumed = gnutls_session_is_resumed(session);

		if (tls_stats_callback) {
			stats.resumed = resumed;
			stats.version = gnutls_protocol_get_version(session);
			gnutls_certificate_get_peers(session, (unsigned int *)&(stats.cert_chain_size));
		}

		debug_printf("Handshake completed%s\n", resumed ? " (resumed session)" : "");

		if (!resumed && config.tls_session_cache) {
			if (tcp->tls_false_start) {
				ctx->delayed_session_data = 1;
			} else {
				gnutls_datum_t session_data;

				if ((rc = gnutls_session_get_data2(session, &session_data)) == GNUTLS_E_SUCCESS) {
					wget_tls_session_db_add(config.tls_session_cache,
						wget_tls_session_new(ctx->hostname, 18 * 3600, session_data.data, session_data.size)); // 18h valid
					xfree(session_data.data);
				} else
					debug_printf("Failed to get session data: %s", gnutls_strerror(rc));
			}
		}
	}

	if (tls_stats_callback) {
		stats.hostname = hostname;
		tls_stats_callback(&stats, tls_stats_ctx);
		xfree(stats.alpn_protocol);
	}

	tcp->hpkp = ctx->stats_hpkp;

	if (ret != WGET_E_SUCCESS) {
		if (ret == WGET_E_TIMEOUT)
			debug_printf("Handshake timed out\n");
		xfree(ctx->hostname);
		xfree(ctx);
		gnutls_deinit(session);
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
		gnutls_session_t s = *session;
		struct session_context *ctx = gnutls_session_get_ptr(s);
		int ret;

		do
			ret = gnutls_bye(s, GNUTLS_SHUT_WR);
		while (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN);

		if (ret < 0)
			debug_printf("TLS shutdown failed: %s\n", gnutls_strerror(ret));

		gnutls_deinit(s);
		*session = NULL;

		xfree(ctx->hostname);
		xfree(ctx);
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
#ifdef HAVE_GNUTLS_TRANSPORT_GET_INT
	// since GnuTLS 3.1.9, avoid warnings about illegal pointer conversion
	int sockfd = gnutls_transport_get_int(session);
#else
	int sockfd = (int)(ptrdiff_t)gnutls_transport_get_ptr(session);
#endif

// #if GNUTLS_VERSION_NUMBER >= 0x030107
#if 0
	// GnuTLS <= 3.4.5 becomes slow with large timeouts (see loop in gnutls_system_recv_timeout()).
	// A fix is proposed for 3.5.x, as well as a value for indefinite timeouts (-1).
	ssize_t nbytes;

	gnutls_record_set_timeout(session, timeout);

	for (;;) {
		if ((nbytes = gnutls_record_recv(session, buf, count)) >= 0)
			return nbytes;

		if (nbytes == GNUTLS_E_REHANDSHAKE) {
			debug_printf("*** REHANDSHAKE while reading\n");
			if ((nbytes = do_handshake(session, sockfd, timeout)) == 0)
				continue; /* restart reading */
		}

		if (nbytes == GNUTLS_E_AGAIN)
			return 0; // indicate timeout

		return -1;
	}

	return -1;
#else
	ssize_t nbytes;

	for (;;) {
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
				xfree(session_data.data);
			} else
				debug_printf("No delayed session data%s\n", gnutls_strerror(rc));
		}

		if (nbytes == GNUTLS_E_REHANDSHAKE) {
			debug_printf("*** REHANDSHAKE while reading\n");
			if ((nbytes = do_handshake(session, sockfd, timeout)) == 0)
				nbytes = GNUTLS_E_AGAIN; /* restart reading */
		}
		if (nbytes >= 0 || nbytes != GNUTLS_E_AGAIN)
			break;
	}

	return nbytes < -1 ? -1 : nbytes;
#endif
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
#ifdef HAVE_GNUTLS_TRANSPORT_GET_INT
	// since GnuTLS 3.1.9, avoid warnings about illegal pointer conversion
	int sockfd = gnutls_transport_get_int(session);
#else
	int sockfd = (int)(ptrdiff_t)gnutls_transport_get_ptr(session);
#endif

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
				continue; /* restart writing */
		}
		if (nbytes == GNUTLS_E_AGAIN)
			return 0; // indicate timeout

		return -1;
	}
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
