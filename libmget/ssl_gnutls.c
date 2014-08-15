/*
 * Copyright(c) 2012 Tim Ruehsen
 *
 * This file is part of libmget.
 *
 * Libmget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Libmget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libmget.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * gnutls SSL/TLS routines
 *
 * Changelog
 * 03.08.2012  Tim Ruehsen  created inspired from gnutls client example
 * 26.08.2012               mget compatibility regarding config options
 *
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#ifdef WITH_GNUTLS

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

/*
#ifdef WIN32
#	include <winsock2.h>
#elif defined(HAVE_POLL_H)
#	include <sys/poll.h>
#else
#	include <sys/select.h>
#endif
*/
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include <libmget.h>
#include "private.h"

static struct _config {
	const char
		*secure_protocol,
		*direct_options,
		*ca_directory,
		*ca_file,
		*cert_file,
		*key_file;
	char
		check_certificate,
		check_hostname,
		ca_type,
		cert_type,
		key_type,
		print_info;
} _config = {
	.check_certificate=1,
	.ca_type = MGET_SSL_X509_FMT_PEM,
	.cert_type = MGET_SSL_X509_FMT_PEM,
	.key_type = MGET_SSL_X509_FMT_PEM,
	.secure_protocol = "AUTO",
	.ca_directory = "system"
};

static gnutls_certificate_credentials_t
	_credentials;
static gnutls_priority_t
	_priority_cache;

void mget_ssl_set_config_string(int key, const char *value)
{
	switch (key) {
	case MGET_SSL_SECURE_PROTOCOL: _config.secure_protocol = value; break;
	case MGET_SSL_DIRECT_OPTIONS: _config.direct_options = value; break;
	case MGET_SSL_CA_DIRECTORY: _config.ca_directory = value; break;
	case MGET_SSL_CA_FILE: _config.ca_file = value; break;
	case MGET_SSL_CERT_FILE: _config.cert_file = value; break;
	case MGET_SSL_KEY_FILE: _config.key_file = value; break;
	default: error_printf(_("Unknown config key %d (or value must not be a string)\n"), key);
	}
}

void mget_ssl_set_config_int(int key, int value)
{
	switch (key) {
	case MGET_SSL_CHECK_CERTIFICATE: _config.check_certificate = (char)value; break;
	case MGET_SSL_CHECK_HOSTNAME: _config.check_hostname = (char)value; break;
	case MGET_SSL_CA_TYPE: _config.ca_type = (char)value; break;
	case MGET_SSL_CERT_TYPE: _config.cert_type = (char)value; break;
	case MGET_SSL_KEY_TYPE: _config.key_type = (char)value; break;
	case MGET_SSL_PRINT_INFO: _config.print_info = (char)value; break;
	default: error_printf(_("Unknown config key %d (or value must not be an integer)\n"), key);
	}
}

static void _print_x509_certificate_info(gnutls_session_t session)
{
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

			gnutls_x509_crt_init(&cert);
			gnutls_x509_crt_import(cert, &cert_list[ncert], GNUTLS_X509_FMT_DER);

			info_printf(_("Certificate info [%u]:\n"), ncert);

			activet = gnutls_x509_crt_get_activation_time(cert);
			info_printf(_("  Certificate is valid since: %s"), ctime(&activet));

			expiret = gnutls_x509_crt_get_expiration_time(cert);
			info_printf(_("  Certificate expires: %s"), ctime(&expiret));

			if (!gnutls_fingerprint(GNUTLS_DIG_MD5, &cert_list[ncert], digest, &digest_size)) {
				char digest_hex[digest_size * 2 + 1];

				mget_memtohex(digest, digest_size, digest_hex, sizeof(digest_hex));

				info_printf(_("  Certificate fingerprint: %s\n"), digest_hex);
			}

			if (!gnutls_x509_crt_get_serial(cert, serial, &serial_size)) {
				char serial_hex[digest_size * 2 + 1];

				mget_memtohex(digest, digest_size, serial_hex, sizeof(serial_hex));

				info_printf(_("  Certificate serial number: %s\n"), serial_hex);
			}

			info_printf(_("  Certificate public key: "));
			algo = gnutls_x509_crt_get_pk_algorithm(cert, &bits);
			if (algo == GNUTLS_PK_RSA) {
				info_printf(_("RSA\n    "));
				info_printf(ngettext("- Modulus: %d bit\n", "- Modulus: %d bits\n", bits), bits);
			} else if (algo == GNUTLS_PK_DSA) {
				info_printf(_("DSA\n    "));
				info_printf(ngettext("- Exponent: %d bit\n", "- Exponent: %d bits\n", bits), bits);
			} else
				info_printf(_("UNKNOWN\n"));

			info_printf(_("  Certificate version: #%d\n"), gnutls_x509_crt_get_version(cert));

			dn_size = sizeof(dn);
			gnutls_x509_crt_get_dn(cert, dn, &dn_size);
			info_printf("  DN: %s\n", dn);

			dn_size = sizeof(dn);
			gnutls_x509_crt_get_issuer_dn(cert, dn, &dn_size);
			info_printf(_("  Certificate Issuer's DN: %s\n"), dn);

			dn_size = sizeof(dn);
			gnutls_x509_crt_get_issuer_dn_oid(cert, 0, dn, &dn_size);
			info_printf(_("  Certificate Issuer's OID: %s\n"), dn);

			dn_size = sizeof(dn);
			gnutls_x509_crt_get_issuer_unique_id(cert, dn, &dn_size);
			info_printf(_("  Certificate Issuer's UID: %s\n"), dn);
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
			info_printf(_("  Unknown certificate type %d\n"), cert_type);
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

	/* print the key exchange's algorithm name
	 */
	kx = gnutls_kx_get(session);
	tmp = gnutls_kx_get_name(kx);
	info_printf(_("----\nKey Exchange: %s\n"), tmp);

	/* Check the authentication type used and switch
	 * to the appropriate.
	 */
	cred = gnutls_auth_get_type(session);
	switch (cred) {
	case GNUTLS_CRD_IA:
		info_printf(_("TLS/IA session\n"));
		break;

	case GNUTLS_CRD_SRP:
		info_printf(_("SRP session with username %s\n"), gnutls_srp_server_get_username(session));
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

	} /* switch */

	if (dhe != 0)
		info_printf(_("Ephemeral DH using prime of %d bits\n"), gnutls_dh_get_prime_bits(session));
#if GNUTLS_VERSION_MAJOR >= 3
	else if (ecdh != 0)
		info_printf(_("Ephemeral ECDH using curve %s\n"), gnutls_ecc_curve_get_name(gnutls_ecc_curve_get(session)));
#endif

	/* print the protocol's name (ie TLS 1.0)
	 */
	tmp = gnutls_protocol_get_name(gnutls_protocol_get_version(session));
	info_printf(_("Protocol: %s\n"), tmp);

	/* print the certificate type of the peer.
	 * ie X.509
	 */
	tmp = gnutls_certificate_type_get_name(gnutls_certificate_type_get(session));
	info_printf(_("Certificate Type: %s\n"), tmp);

	/* print the compression algorithm (if any)
	 */
	tmp = gnutls_compression_get_name(gnutls_compression_get(session));
	info_printf(_("Compression: %s\n"), tmp);

	/* print the name of the cipher used.
	 * ie 3DES.
	 */
	tmp = gnutls_cipher_get_name(gnutls_cipher_get(session));
	info_printf(_("Cipher: %s\n"), tmp);

	/* Print the MAC algorithms name.
	 * ie SHA1
	 */
	tmp = gnutls_mac_get_name(gnutls_mac_get(session));
	info_printf(_("MAC: %s\n"), tmp);

	return 0;
}

/* This function will verify the peer's certificate, and check
 * if the hostname matches, as well as the activation, expiration dates.
 */
static int _verify_certificate_callback(gnutls_session_t session)
{
	unsigned int status;
	const gnutls_datum_t *cert_list;
	unsigned int cert_list_size;
	int ret = 0, err;
	gnutls_x509_crt_t cert;
	const char *hostname;
	const char *tag = _config.check_certificate ? _("ERROR") : _("WARNING");

	// read hostname
	hostname = gnutls_session_get_ptr(session);

	/* This verification function uses the trusted CAs in the credentials
	 * structure. So you must have installed one or more CA certificates.
	 */
	if (gnutls_certificate_verify_peers2(session, &status) < 0) {
//		if (mget_get_logger(MGET_LOGGER_DEBUG))
//			_print_info(session);
		error_printf(_("%s: Certificate verification error\n"), tag);
		ret = -1;
		goto out;
	}

//	if (mget_get_logger(MGET_LOGGER_DEBUG))
//		_print_info(session);

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

		ret = -1;
		goto out;
	}

	/* Up to here the process is the same for X.509 certificates and
	 * OpenPGP keys. From now on X.509 certificates are assumed. This can
	 * be easily extended to work with openpgp keys as well.
	 */
	if (gnutls_certificate_type_get(session) != GNUTLS_CRT_X509) {
		error_printf(_("%s: Certificate must be X.509\n"), tag);
		ret = -1;
		goto out;
	}

	if (gnutls_x509_crt_init(&cert) < 0) {
		error_printf(_("%s: Error initializing X.509 certificate\n"), tag);
		ret = -1;
		goto out;
	}

	if ((cert_list = gnutls_certificate_get_peers(session, &cert_list_size))) {
		unsigned int it;
		time_t now = time(NULL);

		for (it = 0; it < cert_list_size && ret == 0; it++) {
			if (!(err = gnutls_x509_crt_import(cert, &cert_list[it], GNUTLS_X509_FMT_DER))) {
				if (now < gnutls_x509_crt_get_activation_time (cert)) {
					error_printf(_("%s: The certificate is not yet activated\n"), tag);
					ret = -1;
				}
				else if (now >= gnutls_x509_crt_get_expiration_time (cert)) {
					error_printf(_("%s: The certificate has expired\n"), tag);
					ret = -1;
				}
			} else {
				error_printf(_("%s: Failed to parse certificate: %s\n"), tag, gnutls_strerror (err));
				ret = -1;
			}

			if (it == 0 && (!hostname || !gnutls_x509_crt_check_hostname(cert, hostname))) {
				error_printf(_("%s: The certificate's owner does not match hostname '%s'\n"), tag, hostname);
				if (_config.check_hostname)
					ret = -1;
			}
		}
	} else {
		error_printf(_("%s: No certificate was found!\n"), tag);
		ret = -1;
	}

	gnutls_x509_crt_deinit(cert);

	// 0: continue handshake
	// else: stop handshake
out:
	return _config.check_certificate ? ret : 0;
}

static int _init, _server_init;
static mget_thread_mutex_t _mutex = MGET_THREAD_MUTEX_INITIALIZER;

static inline int _key_type(int type)
{
	if (type == MGET_SSL_X509_FMT_DER)
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
			error_printf(_("No CAs were found\n"));
	}
}

void mget_ssl_init(void)
{
	mget_thread_mutex_lock(&_mutex);

	if (!_init) {
		debug_printf("GnuTLS init\n");
		gnutls_global_init();
		gnutls_certificate_allocate_credentials(&_credentials);
		gnutls_certificate_set_verify_function(_credentials, _verify_certificate_callback);

		if (_config.ca_directory && *_config.ca_directory && _config.check_certificate) {
			int ncerts = -1;

#if GNUTLS_VERSION_MAJOR >= 3
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

						if (len >= 4 && !strncasecmp(dp->d_name + len - 4, ".pem", 4)) {
							struct stat st;
							char fname[dirlen + 1 + len + 1];

							snprintf(fname, sizeof(fname), "%s/%s", _config.ca_directory, dp->d_name);
							if (stat(fname, &st) == 0 && S_ISREG(st.st_mode)) {
								int rc;

								debug_printf("GnuTLS loading %s\n", fname);
								if ((rc = gnutls_certificate_set_x509_trust_file(_credentials, fname, GNUTLS_X509_FMT_PEM)) <= 0)
									debug_printf("Failed to load certs: (%d)\n", rc);
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

			debug_printf("Certificates loaded: %d\n", ncerts);
		}

		_set_credentials(&_credentials);

		if (_config.secure_protocol || _config.direct_options) {
			const char *priorities = NULL;
			int ret;

			if (_config.direct_options) {
				ret = gnutls_priority_init(&_priority_cache, _config.direct_options, NULL);
			} else if (!strcasecmp(_config.secure_protocol, "PFS")) {
				priorities = "PFS";
				// -RSA to force DHE/ECDHE key exchanges to have Perfect Forward Secrecy (PFS))
				if ((ret = gnutls_priority_init(&_priority_cache, priorities, NULL)) != GNUTLS_E_SUCCESS) {
					priorities = "NORMAL:-RSA";
					ret = gnutls_priority_init(&_priority_cache, priorities, NULL);
				}
			} else {
				if (!strncasecmp(_config.secure_protocol, "SSL", 3))
					priorities = "NORMAL:-VERS-TLS-ALL:+VERS-SSL3.0";
				else if (!strcasecmp(_config.secure_protocol, "TLSv1"))
					priorities = "NORMAL:-VERS-SSL3.0";
				else if (!strcasecmp(_config.secure_protocol, "auto"))
					priorities = "NORMAL:%COMPAT";
				else if (*_config.secure_protocol)
					priorities = _config.secure_protocol;
				
				if (priorities) {
					ret = gnutls_priority_init(&_priority_cache, priorities, NULL);
				} else {
					// use GnuTLS defaults, which might hold insecure ciphers
					ret = 0;
				}
			}

			if (ret < 0)
				error_printf("GnuTLS: Unsupported priority string '%s': %s\n", priorities, gnutls_strerror(ret));
		}

		_init++;

		debug_printf("GnuTLS init done\n");
	}

	mget_thread_mutex_unlock(&_mutex);
}

// ssl_deinit() is thread safe and may be called several times
// only the last deinit really takes action

void mget_ssl_deinit(void)
{
	mget_thread_mutex_lock(&_mutex);

	if (_init == 1) {
		gnutls_certificate_free_credentials(_credentials);
		gnutls_priority_deinit(_priority_cache);
		gnutls_global_deinit();
	}

	if (_init > 0) _init--;

	mget_thread_mutex_unlock(&_mutex);
}

/*
#ifdef POLLIN
static int _ready_2_transfer(gnutls_session_t session, int timeout, int mode)
{
	// 0: no timeout / immediate
	// -1: INFINITE timeout
	if (timeout) {
		int sockfd = (int)(ptrdiff_t)gnutls_transport_get_ptr(session);
		int rc;

		if (mode == MGET_IO_READABLE)
			mode = POLLIN;
		else
			mode = POLLOUT;

		// wait for socket to be ready to read
		struct pollfd pollfd[1] = {
			{ sockfd, mode, 0}};

		if ((rc = poll(pollfd, 1, timeout)) <= 0)
			return rc;

		if (!(pollfd[0].revents & mode))
			return -1;
	}

	return 1;
}
#else
static int _ready_2_transfer(int fd, int timeout, int mode)
{
	// 0: no timeout / immediate
	// -1: INFINITE timeout
	// >0: number of milliseconds to wait
	if (timeout) {
		fd_set fdset;
		struct timeval tmo = { timeout / 1000, (timeout % 1000) * 1000 };
		int rc;

		FD_ZERO(&fdset);
		FD_SET(fd, &fdset);

		if (mode == MGET_IO_READABLE) {
			rc = select(fd + 1, &fdset, NULL, NULL, &tmo);
		} else {
			rc = select(fd + 1, NULL, &fdset, NULL, &tmo);
		}

		if (rc <= 0)
			return rc;
	}

	return 1;
}
#endif
*/

void *mget_ssl_open(int sockfd, const char *hostname, int connect_timeout)
{
	gnutls_session_t session;
	int ret;

	if (!_init)
		mget_ssl_init();

#ifdef GNUTLS_NONBLOCK
	gnutls_init(&session, GNUTLS_CLIENT | GNUTLS_NONBLOCK);
#else
	// very old gnutls version, likely to not work.
	gnutls_init(&session, GNUTLS_CLIENT);
#endif

	gnutls_priority_set(session, _priority_cache);
	gnutls_session_set_ptr(session, (void *)hostname);
	// RFC 6066 SNI Server Name Indication
	if (hostname)
		gnutls_server_name_set(session, GNUTLS_NAME_DNS, hostname, strlen(hostname));
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, _credentials);
	gnutls_transport_set_ptr(session, (gnutls_transport_ptr_t)(ptrdiff_t)sockfd);

	// Wait for socket being ready before we call gnutls_handshake().
	// I had problems on a KVM Win7 + CygWin (gnutls 3.2.4-1).
	ret = mget_ready_2_write(sockfd, connect_timeout);

	// Perform the TLS handshake
	for (;;) {
		ret = gnutls_handshake(session);
		if (ret == 0 || gnutls_error_is_fatal(ret)) {
			if (ret == 0)
				ret = 1;
			break;
		}

		if (gnutls_record_get_direction(session)) {
			// wait for writeability
			ret = mget_ready_2_write(sockfd, connect_timeout);
		} else {
			// wait for readability
			ret = mget_ready_2_read(sockfd, connect_timeout);
		}

		if (ret <= 0)
			break;
	}

	if (_config.print_info)
		_print_info(session);

	if (ret <= 0) {
		if (ret)
			debug_printf("Handshake failed (%d)\n", ret);
		else
			debug_printf("Handshake timed out\n");

		error_printf("GnuTLS: %s\n", gnutls_strerror(ret));

		gnutls_deinit(session);
		return NULL;
	}

	debug_printf("Handshake completed\n");

	return session;
}

void mget_ssl_close(void **session)
{
	if (session && *session) {
		gnutls_session_t s = *session;

		gnutls_bye(s, GNUTLS_SHUT_RDWR);
		gnutls_deinit(s);
		*session = NULL;
	}
}

static gnutls_certificate_credentials_t
	_server_credentials;
static gnutls_priority_t
	_server_priority_cache;

void mget_ssl_server_init(void)
{
	mget_thread_mutex_lock(&_mutex);

	if (!_server_init) {
		int ret;

		debug_printf("GnuTLS server init\n");
		gnutls_global_init();

		gnutls_certificate_allocate_credentials(&_server_credentials);
		_set_credentials(&_server_credentials);

		/* Generate Diffie-Hellman parameters - for use with DHE
		 * kx algorithms. When short bit length is used, it might
		 * be wise to regenerate parameters often.
		 */
/*		static gnutls_dh_params_t dh_params;
		unsigned int bits = gnutls_sec_param_to_pk_bits(GNUTLS_PK_DH, GNUTLS_SEC_PARAM_LEGACY); // since 3.0.13

		gnutls_dh_params_init(&dh_params);
		gnutls_dh_params_generate2(dh_params, bits);
*/
		if ((ret = gnutls_priority_init(&_server_priority_cache, "PERFORMANCE", NULL)) < 0)
			error_printf("GnuTLS: Unsupported server priority string '%s': %s\n", "PERFORMANCE", gnutls_strerror(ret));

		_server_init++;

		debug_printf("GnuTLS server init done\n");
	}

	mget_thread_mutex_unlock(&_mutex);
}

void mget_ssl_server_deinit(void)
{
	mget_thread_mutex_lock(&_mutex);

	if (_server_init == 1) {
		gnutls_certificate_free_credentials(_server_credentials);
		gnutls_priority_deinit(_server_priority_cache);
		gnutls_global_deinit();
	}

	if (_server_init > 0) _server_init--;

	mget_thread_mutex_unlock(&_mutex);
}

void *mget_ssl_server_open(int sockfd, int connect_timeout)
{
	gnutls_session_t session;

	if (!_init)
		mget_ssl_server_init();

#ifdef GNUTLS_NONBLOCK
	gnutls_init(&session, GNUTLS_SERVER | GNUTLS_NONBLOCK);
#else
	// very old gnutls version, likely to not work.
	gnutls_init(&session, GNUTLS_SERVER);
#endif

	gnutls_priority_set(session, _server_priority_cache);
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, _server_credentials);

	/* We don't request any certificate from the client.
	 * If we did we would need to verify it.
	 */
	gnutls_certificate_server_set_request(session, GNUTLS_CERT_IGNORE);

	// gnutls_transport_set_int(session, sockfd);
	gnutls_transport_set_ptr(session, (gnutls_transport_ptr_t)(ptrdiff_t)sockfd);

	// Wait for socket being ready before we call gnutls_handshake().
	// I had problems on a KVM Win7 + CygWin (gnutls 3.2.4-1).
	int ret = mget_ready_2_write(sockfd, connect_timeout);

	// Perform the TLS handshake
	for (;;) {
		ret = gnutls_handshake(session);
		if (ret == 0 || gnutls_error_is_fatal(ret)) {
			if (ret == 0)
				ret = 1;
			break;
		}

		if (gnutls_record_get_direction(session)) {
			// wait for writeability
			ret = mget_ready_2_write(sockfd, connect_timeout);
		} else {
			// wait for readability
			ret = mget_ready_2_read(sockfd, connect_timeout);
		}
	}

	if (ret <= 0) {
		if (ret)
			debug_printf("Server handshake failed (%d)\n", ret);
		else
			debug_printf("Server handshake timed out\n");

		error_printf("GnuTLS Server: %s\n", gnutls_strerror(ret));

		gnutls_deinit(session);
		return NULL;
	}

	debug_printf("Server handshake completed\n");

	return session;
}

void mget_ssl_server_close(void **session)
{
	if (session && *session) {
		gnutls_session_t s = *session;

		gnutls_bye(s, GNUTLS_SHUT_RDWR);
		gnutls_deinit(s);
		*session = NULL;
	}
}

ssize_t mget_ssl_read_timeout(void *session, char *buf, size_t count, int timeout)
{
	ssize_t nbytes;
	int rc;

	for (;;) {
		if (gnutls_record_check_pending(session) <= 0 &&
			(rc = mget_ready_2_read((int)(ptrdiff_t)gnutls_transport_get_ptr(session), timeout)) <= 0)
			return rc;

		nbytes=gnutls_record_recv(session, buf, count);

		if (nbytes >= 0 || nbytes != GNUTLS_E_AGAIN)
			break;
	}

	return nbytes < -1 ? -1 : nbytes;
}

ssize_t mget_ssl_write_timeout(void *session, const char *buf, size_t count, int timeout)
{
	int rc;

	if ((rc = mget_ready_2_write((int)(ptrdiff_t)gnutls_transport_get_ptr(session), timeout)) <= 0)
		return rc;

	return gnutls_record_send(session, buf, count);
}

#else // WITH_GNUTLS

#include <stddef.h>

#include <libmget.h>
#include "private.h"

void mget_ssl_set_config_string(int key, const char *value) { }
void mget_ssl_set_config_int(int key, int value) { }
void mget_ssl_init(void) { }
void mget_ssl_deinit(void) { }
void *mget_ssl_open(int sockfd, const char *hostname, int connect_timeout) { return NULL; }
void mget_ssl_close(void **session) { }
ssize_t mget_ssl_read_timeout(void *session, char *buf, size_t count, int timeout) { return 0; }
ssize_t mget_ssl_write_timeout(void *session, const char *buf, size_t count, int timeout) { return 0; }
void mget_ssl_server_init(void) { }
void mget_ssl_server_deinit(void) { }
void *mget_ssl_server_open(int sockfd, int connect_timeout) { return NULL; }
void mget_ssl_server_close(void **session) { }

#endif // WITH_GNUTLS
