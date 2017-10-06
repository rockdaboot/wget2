/*
 * Copyright(c) 2012-2015 Tim Ruehsen
 * Copyright(c) 2015-2016 Free Software Foundation, Inc.
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

#ifdef WITH_GNUTLS

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#ifdef HAVE_GNUTLS_OCSP_H
#	include <gnutls/ocsp.h>
#endif
#include <gnutls/crypto.h>
#include <gnutls/abstract.h>

#include <wget.h>
#include "private.h"
#include "net.h"

typedef struct
{
	const char
		*hostname,
		*version,
		*alpn_protocol;
	long long
		tls_secs; //milliseconds
	int
		cert_chain_size;
	char
		tcp_protocol,
		false_start,
		tfo;
	bool
		tls_con,
		resumed;
} _stats_data_t;

typedef struct
{
	const char
		*hostname;
	int
		nvalid,
		nrevoked,
		nignored;
} _ocsp_stats_data_t;

static wget_stats_callback_t stats_callback;
static bool
	ocsp_stats,
	tls_stats;

static struct _config {
	const char
		*secure_protocol,
		*direct_options,
		*ca_directory,
		*ca_file,
		*cert_file,
		*key_file,
		*crl_file,
		*ocsp_server,
		*alpn;
	wget_ocsp_db_t
		*ocsp_cert_cache,
		*ocsp_host_cache;
	wget_tls_session_db_t
		*tls_session_cache;
	wget_hpkp_db_t
		*hpkp_cache;
	char
		ca_type,
		cert_type,
		key_type;
	bool
		check_certificate : 1,
		check_hostname : 1,
		print_info : 1,
		ocsp : 1,
		ocsp_stapling : 1;
} _config = {
	.check_certificate = 1,
	.check_hostname = 1,
#ifdef HAVE_GNUTLS_OCSP_H
	.ocsp = 1,
	.ocsp_stapling = 1,
#endif
	.ca_type = WGET_SSL_X509_FMT_PEM,
	.cert_type = WGET_SSL_X509_FMT_PEM,
	.key_type = WGET_SSL_X509_FMT_PEM,
	.secure_protocol = "AUTO",
	.ca_directory = "system",
#ifdef WITH_LIBNGHTTP2
	.alpn = "h2,http/1.1",
#endif
};

struct _session_context {
	const char *
		hostname;
	wget_hpkp_stats_t
		stats_hpkp;
	unsigned char
		ocsp_stapling : 1,
		valid : 1,
		delayed_session_data : 1;
};

static gnutls_certificate_credentials_t
	_credentials;
static gnutls_priority_t
	_priority_cache;

void wget_ssl_set_config_string(int key, const char *value)
{
	switch (key) {
	case WGET_SSL_SECURE_PROTOCOL: _config.secure_protocol = value; break;
	case WGET_SSL_DIRECT_OPTIONS: _config.direct_options = value; break;
	case WGET_SSL_CA_DIRECTORY: _config.ca_directory = value; break;
	case WGET_SSL_CA_FILE: _config.ca_file = value; break;
	case WGET_SSL_CERT_FILE: _config.cert_file = value; break;
	case WGET_SSL_KEY_FILE: _config.key_file = value; break;
	case WGET_SSL_CRL_FILE: _config.crl_file = value; break;
	case WGET_SSL_OCSP_SERVER: _config.ocsp_server = value; break;
	case WGET_SSL_ALPN: _config.alpn = value; break;
	default: error_printf(_("Unknown config key %d (or value must not be a string)\n"), key);
	}
}

void wget_ssl_set_config_object(int key, void *value)
{
	switch (key) {
	case WGET_SSL_OCSP_CACHE: _config.ocsp_cert_cache = (wget_ocsp_db_t *)value; break;
	case WGET_SSL_SESSION_CACHE: _config.tls_session_cache = (wget_tls_session_db_t *)value; break;
	case WGET_SSL_HPKP_CACHE: _config.hpkp_cache = (wget_hpkp_db_t *)value; break;
	default: error_printf(_("Unknown config key %d (or value must not be an object)\n"), key);
	}
}

void wget_ssl_set_config_int(int key, int value)
{
	switch (key) {
	case WGET_SSL_CHECK_CERTIFICATE: _config.check_certificate = (char)value; break;
	case WGET_SSL_CHECK_HOSTNAME: _config.check_hostname = (char)value; break;
	case WGET_SSL_CA_TYPE: _config.ca_type = (char)value; break;
	case WGET_SSL_CERT_TYPE: _config.cert_type = (char)value; break;
	case WGET_SSL_KEY_TYPE: _config.key_type = (char)value; break;
	case WGET_SSL_PRINT_INFO: _config.print_info = (char)value; break;
	case WGET_SSL_OCSP: _config.ocsp = (char)value; break;
	case WGET_SSL_OCSP_STAPLING: _config.ocsp_stapling = (char)value; break;
	default: error_printf(_("Unknown config key %d (or value must not be an integer)\n"), key);
	}
}

static void _print_x509_certificate_info(gnutls_session_t session)
{
	const char *name;
	char dn[128];
	unsigned char digest[20];
	unsigned char serial[40];
	size_t dn_size = sizeof(dn);
	size_t digest_size = sizeof (digest);
	size_t serial_size = sizeof(serial);
	time_t expiret, activet;
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

			activet = gnutls_x509_crt_get_activation_time(cert);
			info_printf(_("  Valid since: %s"), ctime(&activet));

			expiret = gnutls_x509_crt_get_expiration_time(cert);
			info_printf(_("  Expires: %s"), ctime(&expiret));

			if (!gnutls_fingerprint(GNUTLS_DIG_MD5, &cert_list[ncert], digest, &digest_size)) {
				char digest_hex[digest_size * 2 + 1];

				wget_memtohex(digest, digest_size, digest_hex, sizeof(digest_hex));

				info_printf(_("  Fingerprint: %s\n"), digest_hex);
			}

			if (!gnutls_x509_crt_get_serial(cert, serial, &serial_size)) {
				char serial_hex[digest_size * 2 + 1];

				wget_memtohex(digest, digest_size, serial_hex, sizeof(serial_hex));

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
			info_printf("  DN: %s\n", dn);

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

static int _print_info(gnutls_session_t session)
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
		_print_x509_certificate_info(session);
		break;

	default:
		info_printf(_("Unsupported authentication %d.\n"), (int) cred);
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

#ifdef HAVE_GNUTLS_OCSP_H
static int
_generate_ocsp_data(gnutls_x509_crt_t cert, gnutls_x509_crt_t issuer,
		  gnutls_datum_t * rdata, gnutls_datum_t *nonce)
{
	gnutls_ocsp_req_t req;
	int ret = gnutls_ocsp_req_init(&req);

	if (ret < 0) {
		error_printf("ocsp_req_init: %s", gnutls_strerror(ret));
		return -1;
	}

	ret = gnutls_ocsp_req_add_cert(req, GNUTLS_DIG_SHA1, issuer, cert);
	if (ret < 0) {
		error_printf("ocsp_req_add_cert: %s", gnutls_strerror(ret));
		goto error;
	}

	if (nonce) {
		ret = gnutls_ocsp_req_set_nonce(req, 0, nonce);
		if (ret < 0) {
			error_printf("ocsp_req_set_nonce: %s", gnutls_strerror(ret));
			goto error;
		}
	}

	ret = gnutls_ocsp_req_export(req, rdata);
	if (ret) {
		error_printf("ocsp_req_export: %s", gnutls_strerror(ret));
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
		      wget_buffer_t **ocsp_data, gnutls_datum_t *nonce)
{
	int ret = -1, rc;
	int server_allocated = 0;
	gnutls_datum_t body;
	wget_iri_t *iri;
	wget_http_request_t *req;

	if (!server) {
		/* try to read URL from issuer certificate */
		gnutls_datum_t data;
		unsigned i = 0;

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

		gnutls_free(data.data);
	}

	iri = wget_iri_parse(server, NULL);

	if (server_allocated)
		xfree(server);

	if (!iri)
		return -1;

	_generate_ocsp_data(cert, issuer, &body, nonce);

	req = wget_http_create_request(iri, "POST");
	wget_http_add_header(req, "Accept-Encoding", "identity");
	wget_http_add_header(req, "Accept", "*/*");
	wget_http_add_header(req, "Connection", "close");

	wget_http_connection_t *conn;
	if ((rc = wget_http_open(&conn, iri)) == WGET_E_SUCCESS) {
		wget_http_request_set_body(req, "application/ocsp-request", wget_memdup(body.data, body.size), body.size);
		req->debug_skip_body = 1;
		if (wget_http_send_request(conn, req) == 0) {
			wget_http_response_t *resp;

			if ((resp = wget_http_get_response(conn))) {
				*ocsp_data = resp->body;
				resp->body = NULL;
				wget_http_free_response(&resp);
				ret = 0;
			}
		}
		wget_http_close(&conn);
	}

	wget_http_free_request(&req);
	wget_iri_free(&iri);
	gnutls_free(body.data);
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
	gnutls_x509_crt_t issuer, wget_buffer_t *data,
	gnutls_datum_t *nonce)
{
	gnutls_ocsp_resp_t resp;
	int ret = -1, rc;
	unsigned int status, cert_status;
	time_t rtime, vtime, ntime, now;

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
		debug_printf("*** Certificate was revoked at %s", ctime(&rtime));
		ret = 0;
		goto cleanup;
	}

	if (ntime == -1) {
		if (now - vtime > OCSP_VALIDITY_SECS) {
			debug_printf("*** The OCSP response is old (was issued at: %s) ignoring", ctime(&vtime));
			goto cleanup;
		}
	} else {
		/* there is a newer OCSP answer, don't trust this one */
		if (ntime < now) {
			debug_printf("*** The OCSP response was issued at: %s, but there is a newer issue at %s",
				ctime(&vtime), ctime(&ntime));
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

		if (rnonce.size != nonce->size || memcmp(nonce->data, rnonce.data, nonce->size) != 0) {
			debug_printf("nonce in the response doesn't match\n");
			gnutls_free(rnonce.data);
			goto cleanup;
		}

		gnutls_free(rnonce.data);
	}

 finish_ok:
	debug_printf("OCSP server flags certificate not revoked as of %s", ctime(&vtime));
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
		wget_strlcpy(fingerprint_hex, "00", length);
	} else {
		wget_memtohex(fingerprint, fingerprint_size, fingerprint_hex, length);
	}

	return fingerprint_hex;
}

/*
 * Add cert to OCSP cache, being either valid or revoked (valid==0)
 */
static void _add_cert_to_ocsp_cache(gnutls_x509_crt_t cert, int valid)
{
	if (_config.ocsp_cert_cache) {
		char fingerprint_hex[64 * 2 +1];

		_get_cert_fingerprint(cert, fingerprint_hex, sizeof(fingerprint_hex));
		wget_ocsp_db_add_fingerprint(_config.ocsp_cert_cache, fingerprint_hex, time(NULL) + 3600, valid); // 1h valid
	}
}

/* OCSP check for the peer's certificate. Should be called
 * only after the certificate list verication is complete.
 * Returns:
 * 0: certificate is revoked
 * 1: certificate is ok
 * -1: dunno
 */
//static int cert_verify_ocsp(gnutls_session_t session)
static int cert_verify_ocsp(gnutls_x509_crt_t cert, gnutls_x509_crt_t issuer)
{
	wget_buffer_t *resp = NULL;
	unsigned char noncebuf[23];
	gnutls_datum_t nonce = { noncebuf, sizeof(noncebuf) };
	int ret;

	ret = gnutls_rnd(GNUTLS_RND_NONCE, nonce.data, nonce.size);
	if (ret < 0) {
		debug_printf("gnutls_rnd: %s", gnutls_strerror(ret));
		return -1;
	}

	if (send_ocsp_request(NULL, cert, issuer, &resp, &nonce) < 0) {
		debug_printf("Cannot contact OCSP server\n");
		return -1;
	}

	/* verify and check the response for revoked cert */
	ret = check_ocsp_response(cert, issuer, resp, &nonce);
	wget_buffer_free(&resp);

	return ret;
}
#endif // HAVE_GNUTLS_OCSP_H

static int _cert_verify_hpkp(gnutls_x509_crt_t cert, const char *hostname, gnutls_session_t session)
{
	gnutls_pubkey_t key = NULL;
	int rc, ret = -1;
	struct _session_context *ctx = gnutls_session_get_ptr(session);

	if (!_config.hpkp_cache)
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

	rc = wget_hpkp_db_check_pubkey(_config.hpkp_cache, hostname, pubkey.data, pubkey.size);
	gnutls_free(pubkey.data);
#else
	size_t size = 0;
	void *data = NULL;

	if ((rc = gnutls_pubkey_export(key, GNUTLS_X509_FMT_DER, NULL, &size)) != GNUTLS_E_SHORT_MEMORY_BUFFER) {
		error_printf(_("Failed to export pubkey: %s\n"), gnutls_strerror(rc));
		ret = 0;
		goto out;
	}

	data = xmalloc(size);

	if ((rc = gnutls_pubkey_export(key, GNUTLS_X509_FMT_DER, data, &size)) == GNUTLS_E_SHORT_MEMORY_BUFFER) {
		error_printf(_("Failed to export pubkey: %s\n"), gnutls_strerror(rc));
		ret = 0;
		goto out;
	}

	rc = wget_hpkp_db_check_pubkey(_config.hpkp_cache, hostname, data, size);
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
			error_printf("Error while checking pubkey pinning\n");
			ctx->stats_hpkp = WGET_STATS_HPKP_ERROR;
		}
		ret = 0;
	} else
		ctx->stats_hpkp = WGET_STATS_HPKP_NOMATCH;

out:
	gnutls_pubkey_deinit(key);
	return ret; // Pubkey not found
}

/* This function will verify the peer's certificate, and check
 * if the hostname matches, as well as the activation, expiration dates.
 */
static int _verify_certificate_callback(gnutls_session_t session)
{
	unsigned int status, deinit_cert = 0, deinit_issuer = 0;
	const gnutls_datum_t *cert_list = 0;
	unsigned int cert_list_size;
	int ret = -1, err, ocsp_ok = 0, pinning_ok = 0;
	gnutls_x509_crt_t cert = NULL, issuer = NULL;
	const char *hostname;
	const char *tag = _config.check_certificate ? _("ERROR") : _("WARNING");
#ifdef HAVE_GNUTLS_OCSP_H
	unsigned nvalid = 0, nrevoked = 0, nignored = 0;
#endif

	// read hostname
	struct _session_context *ctx = gnutls_session_get_ptr(session);
	hostname = ctx->hostname;

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
		error_printf(_("%s: Certificate verification error\n"), tag);
		goto out;
	}

//	if (wget_get_logger(WGET_LOGGER_DEBUG))
//		_print_info(session);

#ifdef HAVE_GNUTLS_OCSP_H
	if (status & GNUTLS_CERT_REVOKED) {
		if (_config.ocsp_cert_cache)
			wget_ocsp_db_add_host(_config.ocsp_cert_cache, hostname, 0); // remove entry from cache
		if (ctx->ocsp_stapling) {
			if (gnutls_x509_crt_init(&cert) == GNUTLS_E_SUCCESS) {
				if ((cert_list = gnutls_certificate_get_peers(session, &cert_list_size))) {
					if (gnutls_x509_crt_import(cert, &cert_list[0], GNUTLS_X509_FMT_DER) == GNUTLS_E_SUCCESS) {
						_add_cert_to_ocsp_cache(cert, 0);
					}
				}
				gnutls_x509_crt_deinit(cert);
			}
		}
	}
#endif

#if GNUTLS_VERSION_NUMBER >= 0x030104
	if (status) {
		gnutls_datum_t out;

		if (gnutls_certificate_verification_status_print(
			status, gnutls_certificate_type_get(session), &out, 0) == GNUTLS_E_SUCCESS)
		{
			error_printf("%s: %s\n", tag, out.data);
			gnutls_free(out.data);
		}

		goto out;
	}
#else
	if (status) {
		if (status & GNUTLS_CERT_INVALID)
			error_printf(_("%s: The certificate is not trusted.\n"), tag);
		if (status & GNUTLS_CERT_REVOKED)
			error_printf(_("%s: The certificate has been revoked.\n"), tag);
		if (status & GNUTLS_CERT_SIGNER_NOT_FOUND)
			error_printf(_("%s: The certificate hasn't got a known issuer.\n"), tag);
		if (status & GNUTLS_CERT_SIGNER_NOT_CA)
			error_printf(_("%s: The certificate signer was not a CA.\n"), tag);
		if (status & GNUTLS_CERT_INSECURE_ALGORITHM)
			error_printf(_("%s: The certificate was signed using an insecure algorithm.\n"), tag);
		if (status & GNUTLS_CERT_NOT_ACTIVATED)
			error_printf(_("%s: The certificate is not yet activated.\n"), tag);
		if (status & GNUTLS_CERT_EXPIRED)
			error_printf(_("%s: The certificate has expired.\n"), tag);
#if GNUTLS_VERSION_NUMBER >= 0x030100
		if (status & GNUTLS_CERT_SIGNATURE_FAILURE)
			error_printf(_("%s: The certificate signature is invalid.\n"), tag);
		if (status & GNUTLS_CERT_UNEXPECTED_OWNER)
			error_printf(_("%s: The certificate's owner does not match hostname '%s'.\n"), tag, hostname);
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
			error_printf(_("%s: The certificate could not be verified (0x%X).\n"), tag, status);

		goto out;
	}
#endif

	/* Up to here the process is the same for X.509 certificates and
	 * OpenPGP keys. From now on X.509 certificates are assumed. This can
	 * be easily extended to work with openpgp keys as well.
	 */
	if (gnutls_certificate_type_get(session) != GNUTLS_CRT_X509) {
		error_printf(_("%s: Certificate must be X.509\n"), tag);
		goto out;
	}

	if (gnutls_x509_crt_init(&cert) != GNUTLS_E_SUCCESS) {
		error_printf(_("%s: Error initializing X.509 certificate\n"), tag);
		goto out;
	}
	deinit_cert = 1;

	if (!(cert_list = gnutls_certificate_get_peers(session, &cert_list_size))) {
		error_printf(_("%s: No certificate was found!\n"), tag);
		goto out;
	}

	if ((err = gnutls_x509_crt_import(cert, &cert_list[0], GNUTLS_X509_FMT_DER)) != GNUTLS_E_SUCCESS) {
		error_printf(_("%s: Failed to parse certificate: %s\n"), tag, gnutls_strerror (err));
		goto out;
	}

	if (!_config.check_hostname || (_config.check_hostname && hostname && gnutls_x509_crt_check_hostname(cert, hostname)))
		ret = 0;
	else
		goto out;

	// At this point, the cert chain has been found valid regarding the locally available CA certificates and CRLs.
	// Now, we are going to check the revocation status via OCSP
#ifdef HAVE_GNUTLS_OCSP_H
	if (_config.ocsp_stapling) {
		if (!ctx->valid && ctx->ocsp_stapling) {
#if GNUTLS_VERSION_NUMBER >= 0x030103
			if (gnutls_ocsp_status_request_is_checked(session, 0)) {
				debug_printf("Server certificate is valid regarding OCSP stapling\n");
//				_get_cert_fingerprint(cert, fingerprint, sizeof(fingerprint)); // calc hexadecimal fingerprint string
				_add_cert_to_ocsp_cache(cert, 1);
				nvalid = 1;
			}
#if GNUTLS_VERSION_NUMBER >= 0x030400
			else if (gnutls_ocsp_status_request_is_checked(session, GNUTLS_OCSP_SR_IS_AVAIL))
				error_printf(_("WARNING: The certificate's (stapled) OCSP status is invalid\n"));
#endif
			else if (!_config.ocsp)
				error_printf(_("WARNING: The certificate's (stapled) OCSP status has not been sent\n"));
#endif
		} else if (ctx->valid)
			debug_printf("OCSP: Host '%s' is valid (from cache)\n", hostname);
	}
#endif

	for (unsigned it = 0; it < cert_list_size; it++) {
		if (deinit_cert)
			gnutls_x509_crt_deinit(cert);

		gnutls_x509_crt_init(&cert);

		if ((err = gnutls_x509_crt_import(cert, &cert_list[it], GNUTLS_X509_FMT_DER)) != GNUTLS_E_SUCCESS) {
			error_printf(_("%s: Failed to parse certificate[%u]: %s\n"), tag, it, gnutls_strerror (err));
			continue;
		}

		if (_cert_verify_hpkp(cert, hostname, session) == 0)
			pinning_ok = 1;

		_cert_verify_hpkp(cert, hostname, session);

#ifdef HAVE_GNUTLS_OCSP_H
		if (_config.ocsp && it > nvalid) {
			char fingerprint[64 * 2 +1];
			int revoked;

			_get_cert_fingerprint(cert, fingerprint, sizeof(fingerprint)); // calc hexadecimal fingerprint string

			if (wget_ocsp_fingerprint_in_cache(_config.ocsp_cert_cache, fingerprint, &revoked)) {
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
			if ((err = gnutls_certificate_get_issuer(_credentials, cert, &issuer, 0)) != GNUTLS_E_SUCCESS && it < cert_list_size - 1) {
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
				wget_ocsp_db_add_fingerprint(_config.ocsp_cert_cache, fingerprint, time(NULL) + 3600, 1); // 1h valid
				nvalid++;
			} else if (ocsp_ok == 0) {
				debug_printf(_("%s: Certificate[%u] of '%s' has been revoked (via OCSP)\n"), tag, it, hostname);
				wget_ocsp_db_add_fingerprint(_config.ocsp_cert_cache, fingerprint, time(NULL) + 3600, 0);  // cert has been revoked
				nrevoked++;
			} else {
				debug_printf("WARNING: OCSP response not available or ignored\n");
				nignored++;
			}
		}
#endif
	}

#ifdef HAVE_GNUTLS_OCSP_H
	if (_config.ocsp && ocsp_stats) {
		_ocsp_stats_data_t stats;
		stats.hostname = hostname;
		stats.nvalid = nvalid;
		stats.nrevoked = nrevoked;
		stats.nignored = nignored;

		stats_callback(WGET_STATS_TYPE_OCSP, &stats);
	}

	if (_config.ocsp_stapling || _config.ocsp) {
		if (nvalid == cert_list_size) {
			wget_ocsp_db_add_host(_config.ocsp_cert_cache, hostname, time(NULL) + 3600); // 1h valid
		} else if (nrevoked) {
			wget_ocsp_db_add_host(_config.ocsp_cert_cache, hostname, 0); // remove entry from cache
			ret = -1;
		}
	}
#endif

	if (!pinning_ok) {
		error_printf(_("%s: Pubkey pinning mismatch!\n"), tag);
		ret = -1;
	}

	// 0: continue handshake
	// else: stop handshake
out:
	if (deinit_cert)
		gnutls_x509_crt_deinit(cert);
	if (deinit_issuer)
		gnutls_x509_crt_deinit(issuer);

	return _config.check_certificate ? ret : 0;
}

static int _init;
static wget_thread_mutex_t _mutex = WGET_THREAD_MUTEX_INITIALIZER;

static _GL_INLINE int _key_type(int type)
{
	if (type == WGET_SSL_X509_FMT_DER)
		return GNUTLS_X509_FMT_DER;

	return GNUTLS_X509_FMT_PEM;
}

// ssl_init() is thread safe

static void _set_credentials(gnutls_certificate_credentials_t *credentials)
{
	if (_config.cert_file && !_config.key_file) {
		// Use the private key from the cert file unless otherwise specified.
		_config.key_file = _config.cert_file;
		_config.key_type = _config.cert_type;
	}
	else if (!_config.cert_file && _config.key_file) {
		// Use the cert from the private key file unless otherwise specified.
		_config.cert_file = _config.key_file;
		_config.cert_type = _config.key_type;
	}

	if (_config.cert_file && _config.key_file) {
		if (_config.key_type != _config.cert_type) {
			// GnuTLS can't handle this
			error_printf(_("GnuTLS requires the key and the cert to be of the same type.\n"));
		}

		if (gnutls_certificate_set_x509_key_file(*credentials, _config.cert_file, _config.key_file, _key_type(_config.key_type)) != GNUTLS_E_SUCCESS)
			error_printf(_("No certificates or keys were found\n"));
	}

	if (_config.ca_file) {
		if (gnutls_certificate_set_x509_trust_file(*credentials, _config.ca_file, _key_type(_config.ca_type)) <= 0)
			error_printf(_("No CAs were found in '%s'\n"), _config.ca_file);
	}
}

void wget_ssl_init(void)
{
	wget_thread_mutex_lock(&_mutex);

	if (!_init) {
		int rc, ncerts = -1;

		debug_printf("GnuTLS init\n");
		gnutls_global_init();
		gnutls_certificate_allocate_credentials(&_credentials);
		gnutls_certificate_set_verify_function(_credentials, _verify_certificate_callback);

		if (_config.ca_directory && *_config.ca_directory && _config.check_certificate) {
#if GNUTLS_VERSION_NUMBER >= 0x03000d
			if (!strcmp(_config.ca_directory, "system"))
				ncerts = gnutls_certificate_set_x509_system_trust(_credentials);
#else
			if (!strcmp(_config.ca_directory, "system"))
				_config.ca_directory = "/etc/ssl/certs";
#endif

			if (ncerts < 0) {
				DIR *dir;

				ncerts = 0;

				if ((dir = opendir(_config.ca_directory))) {
					struct dirent *dp;
					size_t dirlen = strlen(_config.ca_directory);

					while ((dp = readdir(dir))) {
						size_t len = strlen(dp->d_name);

						if (len >= 4 && !wget_strncasecmp_ascii(dp->d_name + len - 4, ".pem", 4)) {
							struct stat st;
							char fname[dirlen + 1 + len + 1];

							snprintf(fname, sizeof(fname), "%s/%s", _config.ca_directory, dp->d_name);
							if (stat(fname, &st) == 0 && S_ISREG(st.st_mode)) {
								debug_printf("GnuTLS loading %s\n", fname);
								if ((rc = gnutls_certificate_set_x509_trust_file(_credentials, fname, GNUTLS_X509_FMT_PEM)) <= 0)
									debug_printf("Failed to load cert '%s': (%d)\n", fname, rc);
								else
									ncerts += rc;
							}
						}
					}

					closedir(dir);
				} else {
					error_printf(_("Failed to opendir %s\n"), _config.ca_directory);
				}
			}
		}

		if (_config.crl_file) {
			if ((rc = gnutls_certificate_set_x509_crl_file(_credentials, _config.crl_file, GNUTLS_X509_FMT_PEM)) <= 0)
				error_printf("Failed to load CRL '%s': (%d)\n", _config.crl_file, rc);
		}

		_set_credentials(&_credentials);

		debug_printf("Certificates loaded: %d\n", ncerts);

		if (_config.secure_protocol || _config.direct_options) {
			const char *priorities = NULL;

			if (_config.direct_options) {
				priorities = _config.direct_options;
				rc = gnutls_priority_init(&_priority_cache, priorities, NULL);
			} else if (!wget_strcasecmp_ascii(_config.secure_protocol, "PFS")) {
				priorities = "PFS:-VERS-SSL3.0";
				// -RSA to force DHE/ECDHE key exchanges to have Perfect Forward Secrecy (PFS))
				if ((rc = gnutls_priority_init(&_priority_cache, priorities, NULL)) != GNUTLS_E_SUCCESS) {
					priorities = "NORMAL:-RSA:-VERS-SSL3.0";
					rc = gnutls_priority_init(&_priority_cache, priorities, NULL);
				}
			} else {
				if (!wget_strncasecmp_ascii(_config.secure_protocol, "SSL", 3))
					priorities = "NORMAL:-VERS-TLS-ALL:+VERS-SSL3.0";
				else if (!wget_strcasecmp_ascii(_config.secure_protocol, "TLSv1"))
					priorities = "NORMAL:-VERS-SSL3.0";
				else if (!wget_strcasecmp_ascii(_config.secure_protocol, "auto")) {
					/* use system default, priorities = NULL */
				} else if (*_config.secure_protocol)
					priorities = _config.secure_protocol;

				rc = gnutls_priority_init(&_priority_cache, priorities, NULL);
			}

			if (rc != GNUTLS_E_SUCCESS)
				error_printf("GnuTLS: Unsupported priority string '%s': %s\n", priorities ? "(null)" : priorities, gnutls_strerror(rc));
		} else {
			// use GnuTLS defaults, which might hold insecure ciphers
			if ((rc = gnutls_priority_init(&_priority_cache, NULL, NULL)))
				error_printf("GnuTLS: Unsupported default priority 'NULL': %s\n", gnutls_strerror(rc));
		}

		_init++;

		debug_printf("GnuTLS init done\n");
	}

	wget_thread_mutex_unlock(&_mutex);
}

// ssl_deinit() is thread safe and may be called several times
// only the last deinit really takes action

void wget_ssl_deinit(void)
{
	wget_thread_mutex_lock(&_mutex);

	if (_init == 1) {
		gnutls_certificate_free_credentials(_credentials);
		gnutls_priority_deinit(_priority_cache);
		gnutls_global_deinit();
	}

	if (_init > 0) _init--;

	wget_thread_mutex_unlock(&_mutex);
}

static int _do_handshake(gnutls_session_t session, int sockfd, int timeout)
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
			debug_printf("gnutls_handshake: (%d) %s\n", rc, gnutls_strerror(rc));

			if (rc == GNUTLS_E_CERTIFICATE_ERROR)
				ret = WGET_E_CERTIFICATE;
			else
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
#if HAVE_SYS_SOCKET_H
#	include <sys/socket.h>
#elif HAVE_WS2TCPIP_H
#	include <ws2tcpip.h>
#endif
#if HAVE_SYS_UIO_H
#include <sys/uio.h> // writev
#endif
#include <netdb.h>
#include <errno.h>
static ssize_t _ssl_writev(gnutls_transport_ptr_t *p, const giovec_t *iov, int iovcnt)
{
	wget_tcp_t *tcp = (wget_tcp_t *) p;
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

	gnutls_transport_set_vec_push_function(tcp->ssl_session, (ssize_t (*) (gnutls_transport_ptr_t, const giovec_t * iov, int iovcnt)) writev);

	return ret;
}
#endif

#ifdef _WIN32
static ssize_t _win32_send(gnutls_transport_ptr_t p, const void *buf, size_t size)
{
	int sockfd = (int) (ptrdiff_t) p;

	return send(sockfd, buf, size, 0);
}
static ssize_t _win32_recv(gnutls_transport_ptr_t p, void *buf, size_t size)
{
	int sockfd = (int) (ptrdiff_t) p;

	return recv(sockfd, buf, size, 0);
}
#endif

int wget_ssl_open(wget_tcp_t *tcp)
{
	gnutls_session_t session;
	_stats_data_t stats = {
			.version = NULL,
			.alpn_protocol = NULL,
			.false_start = -1,
			.tfo = -1,
			.resumed = 0,
			.tcp_protocol = WGET_PROTOCOL_HTTP_1_1,
			.cert_chain_size = 0
	};

	int ret = WGET_E_UNKNOWN;
	int rc, sockfd, connect_timeout;
	const char *hostname;
	long long before_millisecs = 0;

	if (!tcp)
		return WGET_E_INVALID;

	if (!_init)
		wget_ssl_init();

	hostname = tcp->ssl_hostname;
	sockfd= tcp->sockfd;
	connect_timeout = tcp->connect_timeout;

#if GNUTLS_VERSION_NUMBER >= 0x030500
	if (tcp->tls_false_start) {
		debug_printf("TLS False Start requested\n");
		gnutls_init(&session, GNUTLS_CLIENT | GNUTLS_NONBLOCK | GNUTLS_ENABLE_FALSE_START);
	} else
		gnutls_init(&session, GNUTLS_CLIENT | GNUTLS_NONBLOCK);
#elif defined GNUTLS_NONBLOCK
	if (tcp->tls_false_start)
		error_printf("TLS False Start requested but Wget built with insufficient GnuTLS version\n");
	gnutls_init(&session, GNUTLS_CLIENT | GNUTLS_NONBLOCK);
#else
	// very old gnutls version, likely to not work.
	if (tcp->tls_false_start)
		error_printf("TLS False Start requested but Wget built with insufficient GnuTLS version\n");
	gnutls_init(&session, GNUTLS_CLIENT);
#endif

	if ((rc = gnutls_priority_set(session, _priority_cache)) != GNUTLS_E_SUCCESS)
		error_printf("GnuTLS: Failed to set priorities: %s\n", gnutls_strerror(rc));

	if (!wget_strcasecmp_ascii(_config.secure_protocol, "auto"))
		gnutls_session_enable_compatibility_mode(session);

	// RFC 6066 SNI Server Name Indication
	if (hostname)
		gnutls_server_name_set(session, GNUTLS_NAME_DNS, hostname, strlen(hostname));
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, _credentials);

	struct _session_context *ctx = wget_calloc(1, sizeof(struct _session_context));
	ctx->hostname = wget_strdup(hostname);

#ifdef HAVE_GNUTLS_OCSP_H
	// If we know the cert chain for the hostname being valid at the moment,
	// we don't ask for OCSP stapling to avoid unneeded IP traffic.
	// In the unlikely case that the server's certificate chain changed right now,
	// we fallback to OCSP responder request later.
	if (hostname) {
		if (!(ctx->valid = !!wget_ocsp_hostname_is_valid(_config.ocsp_host_cache, hostname))) {
#if GNUTLS_VERSION_NUMBER >= 0x030103
			if ((rc = gnutls_ocsp_status_request_enable_client(session, NULL, 0, NULL)) == GNUTLS_E_SUCCESS)
				ctx->ocsp_stapling = 1;
			else
				error_printf("GnuTLS: %s\n", gnutls_strerror(rc));
#endif
		}
	}
#else
	if (_config.ocsp || _config.ocsp_stapling)
		error_printf("WARNING: OCSP is not available in this version of GnuTLS.\n");
#endif

#if GNUTLS_VERSION_NUMBER >= 0x030200
	if (_config.alpn) {
		unsigned nprot;
		const char *e, *s;

		for (nprot = 0, s = e = _config.alpn; *e; s = e + 1)
			if ((e = strchrnul(s, ',')) != s)
				nprot++;

		gnutls_datum_t data[nprot];

		for (nprot = 0, s = e = _config.alpn; *e; s = e + 1) {
			if ((e = strchrnul(s, ',')) != s) {
				data[nprot].data = (unsigned char *) s;
				data[nprot].size = (unsigned) (e - s);
				debug_printf("ALPN offering %.*s\n", (int) data[nprot].size, data[nprot].data);
				nprot++;
			}
		}

		if ((rc = gnutls_alpn_set_protocols(session, data, nprot, 0)))
			error_printf("GnuTLS: Set ALPN: %s\n", gnutls_strerror(rc));
	}
#endif

	tcp->ssl_session = session;
	gnutls_session_set_ptr(session, ctx);

#ifdef MSG_FASTOPEN
	if ((rc = wget_tcp_get_tcp_fastopen(tcp))) {
		if (tls_stats)
			stats.tfo = (char)rc;

		// prepare for TCP FASTOPEN... sendmsg() instead of connect/write on first write
		gnutls_transport_set_vec_push_function(session, (ssize_t (*)(gnutls_transport_ptr_t, const giovec_t *iov, int iovcnt)) _ssl_writev);
		gnutls_transport_set_ptr(session, tcp);
	} else {
#endif

#ifdef _WIN32
	gnutls_transport_set_push_function(session, (gnutls_push_func) _win32_send);
	gnutls_transport_set_pull_function(session, (gnutls_pull_func) _win32_recv);
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

		if (wget_tls_session_get(_config.tls_session_cache, ctx->hostname, &data, &size) == 0) {
			debug_printf("found cached session data for %s\n", ctx->hostname);
			if ((rc = gnutls_session_set_data(session, data, size)) != GNUTLS_E_SUCCESS)
				error_printf("GnuTLS: Failed to set session data: %s\n", gnutls_strerror(rc));
			xfree(data);
		}
	}

	if (tls_stats)
		before_millisecs = wget_get_timemillis();

	ret = _do_handshake(session, sockfd, connect_timeout);

	if (tls_stats) {
		long long after_millisecs = wget_get_timemillis();
		stats.tls_secs = after_millisecs - before_millisecs;
		stats.tls_con = 1;
#if GNUTLS_VERSION_NUMBER >= 0x030500
		stats.false_start = gnutls_session_get_flags(session) & GNUTLS_SFLAGS_FALSE_START;
#endif
	}

#if GNUTLS_VERSION_NUMBER >= 0x030200
	if (_config.alpn) {
		gnutls_datum_t protocol;
		if ((rc = gnutls_alpn_get_selected_protocol(session, &protocol)))
			debug_printf("GnuTLS: Get ALPN: %s\n", gnutls_strerror(rc));
		else {
			debug_printf("ALPN: Server accepted protocol '%.*s'\n", (int) protocol.size, protocol.data);
			if (tls_stats)
				stats.alpn_protocol = wget_strmemdup(protocol.data, protocol.size);

			if (!memcmp(protocol.data, "h2", 2)) {
				tcp->protocol = WGET_PROTOCOL_HTTP_2_0;
				if (tls_stats)
					stats.tcp_protocol = WGET_PROTOCOL_HTTP_2_0;
			}
		}
	}
#endif

	if (_config.print_info)
		_print_info(session);

	if (ret == WGET_E_SUCCESS) {
		int resumed = gnutls_session_is_resumed(session);

		if (tls_stats) {
			stats.resumed = resumed;
			stats.version = gnutls_protocol_get_name(gnutls_protocol_get_version(session));
			gnutls_certificate_get_peers(session, (unsigned int *)&(stats.cert_chain_size));
		}

		debug_printf("Handshake completed%s\n", resumed ? " (resumed session)" : "");

		if (!resumed && _config.tls_session_cache) {
			if (tcp->tls_false_start) {
				ctx->delayed_session_data = 1;
			} else {
				gnutls_datum_t session_data;

				if ((rc = gnutls_session_get_data2(session, &session_data)) == GNUTLS_E_SUCCESS) {
					wget_tls_session_db_add(_config.tls_session_cache,
						wget_tls_session_new(ctx->hostname, 18 * 3600, session_data.data, session_data.size)); // 18h valid
					gnutls_free(session_data.data);
				} else
					debug_printf("Failed to get session data: %s", gnutls_strerror(rc));
			}
		}
	}

	if (tls_stats) {
		stats.hostname = hostname;
		stats_callback(WGET_STATS_TYPE_TLS, &stats);
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

void wget_ssl_close(void **session)
{
	if (session && *session) {
		gnutls_session_t s = *session;
		struct _session_context *ctx = gnutls_session_get_ptr(s);
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
			if ((nbytes = _do_handshake(session, sockfd, timeout)) == 0)
				continue; /* restart reading */
		}

		if (nbytes == GNUTLS_E_AGAIN)
			return 0; // indicate timeout

		return -1;
	}

	return -1;
#else
	int rc;
	ssize_t nbytes;

	for (;;) {
		if (gnutls_record_check_pending(session) <= 0 &&
			(rc = wget_ready_2_read(sockfd, timeout)) <= 0)
			return rc;

		nbytes = gnutls_record_recv(session, buf, count);

		// If False Start + Session Resumption are enabled, we get the session data after the first read()
		struct _session_context *ctx = gnutls_session_get_ptr(session);
		if (ctx && ctx->delayed_session_data) {
			gnutls_datum_t session_data;

			if ((rc = gnutls_session_get_data2(session, &session_data)) == GNUTLS_E_SUCCESS) {
				debug_printf("Got delayed session data\n");
				ctx->delayed_session_data = 0;
				wget_tls_session_db_add(_config.tls_session_cache,
					wget_tls_session_new(ctx->hostname, 18 * 3600, session_data.data, session_data.size)); // 18h valid
				gnutls_free(session_data.data);
			} else
				debug_printf("No delayed session data%s\n", gnutls_strerror(rc));
		}

		if (nbytes == GNUTLS_E_REHANDSHAKE) {
			debug_printf("*** REHANDSHAKE while reading\n");
			if ((nbytes = _do_handshake(session, sockfd, timeout)) == 0)
				nbytes = GNUTLS_E_AGAIN; /* restart reading */
		}
		if (nbytes >= 0 || nbytes != GNUTLS_E_AGAIN)
			break;
	}

	return nbytes < -1 ? -1 : nbytes;
#endif
}

ssize_t wget_ssl_write_timeout(void *session, const char *buf, size_t count, int timeout)
{
	ssize_t nbytes;
	int rc;
#ifdef HAVE_GNUTLS_TRANSPORT_GET_INT
	// since GnuTLS 3.1.9, avoid warnings about illegal pointer conversion
	int sockfd = gnutls_transport_get_int(session);
#else
	int sockfd = (int)(ptrdiff_t)gnutls_transport_get_ptr(session);
#endif

	for (;;) {
		if ((rc = wget_ready_2_write(sockfd, timeout)) <= 0)
			return rc;

		if ((nbytes = gnutls_record_send(session, buf, count)) >= 0)
			return nbytes;

		if (nbytes == GNUTLS_E_REHANDSHAKE) {
			debug_printf("*** REHANDSHAKE while writing\n");
			if ((nbytes = _do_handshake(session, sockfd, timeout)) == 0)
				continue; /* restart writing */
		}
		if (nbytes == GNUTLS_E_AGAIN)
			return 0; // indicate timeout

		return -1;
	}
}

/**
 * \param[in] fn A `wget_stats_callback_t` callback function used to collect TLS statistics
 *
 * Set callback function to be called once TLS statistics for a host are collected
 */
void wget_tcp_set_stats_tls(wget_stats_callback_t fn)
{
	stats_callback = fn;
	tls_stats = (stats_callback != NULL);
}

/**
 * \param[in] type A `wget_tls_stats_t` constant representing TLS statistical info to return
 * \param[in] _stats An internal  pointer sent to callback function
 * \return TLS statistical info in question
 *
 * Get the specific TLS statistics information
 */
const void *wget_tcp_get_stats_tls(wget_tls_stats_t type, const void *_stats)
{
	const _stats_data_t *stats = (_stats_data_t *) _stats;

	switch(type) {
	case WGET_STATS_TLS_HOSTNAME:
		return stats->hostname;
	case WGET_STATS_TLS_VERSION:
		return stats->version;
	case WGET_STATS_TLS_FALSE_START:
		return &(stats->false_start);
	case WGET_STATS_TLS_TFO:
		return &(stats->tfo);
	case WGET_STATS_TLS_ALPN_PROTO:
		return stats->alpn_protocol;
	case WGET_STATS_TLS_CON:
		return &(stats->tls_con);
	case WGET_STATS_TLS_RESUMED:
		return &(stats->resumed);
	case WGET_STATS_TLS_TCP_PROTO:
		return &(stats->tcp_protocol);
	case WGET_STATS_TLS_CERT_CHAIN_SIZE:
		return &(stats->cert_chain_size);
	case WGET_STATS_TLS_SECS:
		return &(stats->tls_secs);
	default:
		return NULL;
	}
}

/**
 * \param[in] fn A `wget_stats_callback_t` callback function used to collect OCSP statistics
 *
 * Set callback function to be called once OCSP statistics for a host are collected
 */
void wget_tcp_set_stats_ocsp(wget_stats_callback_t fn)
{
	stats_callback = fn;
	ocsp_stats = (stats_callback != NULL);
}

/**
 * \param[in] type A `wget_ocsp_stats_t` constant representing OCSP statistical info to return
 * \param[in] _stats An internal  pointer sent to callback function
 * \return OCSP statistical info in question
 *
 * Get the specific OCSP statistics information
 */
const void *wget_tcp_get_stats_ocsp(wget_ocsp_stats_t type, const void *_stats)
{
	const _ocsp_stats_data_t *stats = (_ocsp_stats_data_t *) _stats;

	switch(type) {
	case WGET_STATS_OCSP_HOSTNAME:
		return stats->hostname;
	case WGET_STATS_OCSP_VALID:
		return &(stats->nvalid);
	case WGET_STATS_OCSP_REVOKED:
		return &(stats->nrevoked);
	case WGET_STATS_OCSP_IGNORED:
		return &(stats->nignored);
	default:
		return NULL;
	}
}

#else // WITH_GNUTLS

#include <stddef.h>

#include <wget.h>
#include "private.h"

#pragma GCC diagnostic ignored "-Wunused-parameter"
void wget_ssl_set_config_string(int key, const char *value) { }
void wget_ssl_set_config_object(int key, void *value) { }
void wget_ssl_set_config_int(int key, int value) { }
void wget_ssl_init(void) { }
void wget_ssl_deinit(void) { }
int wget_ssl_open(wget_tcp_t *tcp) { return WGET_E_TLS_DISABLED; }
void wget_ssl_close(void **session) { }
ssize_t wget_ssl_read_timeout(void *session, char *buf, size_t count, int timeout) { return 0; }
ssize_t wget_ssl_write_timeout(void *session, const char *buf, size_t count, int timeout) { return 0; }
void wget_ssl_server_init(void) { }
void wget_ssl_server_deinit(void) { }
int wget_ssl_server_open(wget_tcp_t *tcp) { return WGET_E_TLS_DISABLED; }
void wget_ssl_server_close(void **session) { }
void wget_tcp_set_stats_tls(const wget_stats_callback_t fn) { }
const void *wget_tcp_get_stats_tls(const wget_tls_stats_t type, const void *stats) { return NULL;}
void wget_tcp_set_stats_ocsp(const wget_stats_callback_t fn) { }
const void *wget_tcp_get_stats_ocsp(const wget_ocsp_stats_t type, const void *stats) { return NULL;}

#endif // WITH_GNUTLS
