#include <config.h>

#include <errno.h>
#include <wget.h>
#include <nghttp2/nghttp2.h>
#include "private.h"
#include "http.h"

struct http2_stream_context {
	wget_http_connection
		*conn;
	wget_http_response
		*resp;
	wget_decompressor
		*decompressor;
};

static ssize_t send_callback(nghttp2_session *session WGET_GCC_UNUSED,
	const uint8_t *data, size_t length, int flags WGET_GCC_UNUSED, void *user_data)
{
	wget_http_connection *conn = (wget_http_connection *)user_data;
	ssize_t rc;

	// debug_printf("writing... %zd\n", length);
	if ((rc = wget_tcp_write(conn->tcp, (const char *)data, length)) <= 0) {
		// An error will be written by the wget_tcp_write function.
		// debug_printf("write rc %d, errno=%d\n", rc, errno);
		return rc ? NGHTTP2_ERR_CALLBACK_FAILURE : NGHTTP2_ERR_WOULDBLOCK;
	}
	// debug_printf("write rc %d\n",rc);

	return rc;
}

static void print_frame_type(int type, const char tag, int streamid)
{
	static const char *name[] = {
		[NGHTTP2_DATA] = "DATA",
		[NGHTTP2_HEADERS] = "HEADERS",
		[NGHTTP2_PRIORITY] = "PRIORITY",
		[NGHTTP2_RST_STREAM] = "RST_STREAM",
		[NGHTTP2_SETTINGS] = "SETTINGS",
		[NGHTTP2_PUSH_PROMISE] = "PUSH_PROMISE",
		[NGHTTP2_PING] = "PING",
		[NGHTTP2_GOAWAY] = "GOAWAY",
		[NGHTTP2_WINDOW_UPDATE] = "WINDOW_UPDATE",
		[NGHTTP2_CONTINUATION] = "CONTINUATION"
	};

	if ((unsigned) type < countof(name)) {
		// Avoid printing frame info for DATA frames
		if (type != NGHTTP2_DATA)
			debug_printf("[FRAME %d] %c %s\n", streamid, tag, name[type]);
	} else
		debug_printf("[FRAME %d] %c Unknown type %d\n", streamid, tag, type);
}

static int on_frame_send_callback(nghttp2_session *session WGET_GCC_UNUSED,
	const nghttp2_frame *frame, void *user_data WGET_GCC_UNUSED)
{
	print_frame_type(frame->hd.type, '>', frame->hd.stream_id);

	if (frame->hd.type == NGHTTP2_HEADERS) {
		const nghttp2_nv *nva = frame->headers.nva;

		for (unsigned i = 0; i < frame->headers.nvlen; i++)
			debug_printf("[FRAME %d] > %.*s: %.*s\n", frame->hd.stream_id,
				(int)nva[i].namelen, nva[i].name, (int)nva[i].valuelen, nva[i].value);
	}

	return 0;
}

static int on_frame_recv_callback(nghttp2_session *session,
	const nghttp2_frame *frame, void *user_data WGET_GCC_UNUSED)
{
	print_frame_type(frame->hd.type, '<', frame->hd.stream_id);

	// header callback after receiving all header tags
	if (frame->hd.type == NGHTTP2_HEADERS) {
		struct http2_stream_context *ctx = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
		wget_http_response *resp = ctx ? ctx->resp : NULL;

		if (resp) {
			if (resp->header && resp->req->header_callback) {
				resp->req->header_callback(resp, resp->req->header_user_data);
			}

			http_fix_broken_server_encoding(resp);

			if (!ctx->decompressor) {
				ctx->decompressor = wget_decompress_open(resp->content_encoding,
									 http_get_body_cb, resp);
				wget_decompress_set_error_handler(ctx->decompressor, http_decompress_error_handler_cb);
			}
		}
	}
	else if (frame->hd.type == NGHTTP2_GOAWAY) {
		struct http2_stream_context *ctx = nghttp2_session_get_stream_user_data(session, frame->goaway.last_stream_id);
		wget_http_connection *conn = ctx ? ctx->conn : NULL;

		if (conn) {
			conn->goaway = true;
		}
	}

	return 0;
}

static int on_header_callback(nghttp2_session *session,
	const nghttp2_frame *frame, const uint8_t *name, size_t namelen,
	const uint8_t *value, size_t valuelen,
	uint8_t flags WGET_GCC_UNUSED, void *user_data WGET_GCC_UNUSED)
{
	struct http2_stream_context *ctx = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
	wget_http_response *resp = ctx ? ctx->resp : NULL;

	if (!resp)
		return 0;

	if (resp->req->response_keepheader || resp->req->header_callback) {
		if (!resp->header)
			resp->header = wget_buffer_alloc(1024);
	}

	if (frame->hd.type == NGHTTP2_HEADERS) {
		if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
			debug_printf("%.*s: %.*s\n", (int) namelen, name, (int) valuelen, value);

			if (resp->header)
				wget_buffer_printf_append(resp->header, "%.*s: %.*s\n", (int) namelen, name, (int) valuelen, value);

			wget_http_parse_header_line(resp, (char *) name, namelen, (char *) value, valuelen);
		}
	}

	return 0;
}

/*
 * This function is called to indicate that a stream is closed.
 */
static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
	uint32_t error_code WGET_GCC_UNUSED, void *user_data)
{
	struct http2_stream_context *ctx = nghttp2_session_get_stream_user_data(session, stream_id);

	debug_printf("closing stream %d\n", stream_id);
	if (ctx) {
		wget_http_connection *conn = (wget_http_connection *) user_data;

		ctx->resp->response_end = wget_get_timemillis(); // Final transmission time.

		wget_vector_add(conn->received_http2_responses, ctx->resp);
		wget_decompress_close(ctx->decompressor);
		nghttp2_session_set_stream_user_data(session, stream_id, NULL);
		xfree(ctx);
	}

	return 0;
}
/*
 * The implementation of nghttp2_on_data_chunk_recv_callback type. We
 * use this function to print the received response body.
 */
static int on_data_chunk_recv_callback(nghttp2_session *session,
	uint8_t flags WGET_GCC_UNUSED, int32_t stream_id,
	const uint8_t *data, size_t len,	void *user_data WGET_GCC_UNUSED)
{
	struct http2_stream_context *ctx = nghttp2_session_get_stream_user_data(session, stream_id);

	if (ctx) {
		// debug_printf("[INFO] C <---------------------------- S%d (DATA chunk - %zu bytes)\n", stream_id, len);
		// debug_printf("nbytes %zu\n", len);

		ctx->resp->req->first_response_start = wget_get_timemillis();

		ctx->resp->cur_downloaded += len;
		wget_decompress(ctx->decompressor, (char *) data, len);
	}
	return 0;
}

static void setup_nghttp2_callbacks(nghttp2_session_callbacks *callbacks)
{
	nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
	nghttp2_session_callbacks_set_on_frame_send_callback(callbacks, on_frame_send_callback);
	nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv_callback);
	nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close_callback);
	nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_data_chunk_recv_callback);
	nghttp2_session_callbacks_set_on_header_callback(callbacks, on_header_callback);
}

int wget_http2_open(wget_http_connection *conn)
{
	int rc;
	nghttp2_session_callbacks *callbacks;

	if (nghttp2_session_callbacks_new(&callbacks)) {
		error_printf(_("Failed to create HTTP2 callbacks\n"));
		return WGET_E_INVALID;
	}

	setup_nghttp2_callbacks(callbacks);
	rc = nghttp2_session_client_new(&conn->http2_session, callbacks, conn);
	nghttp2_session_callbacks_del(callbacks);

	if (rc) {
		error_printf(_("Failed to create HTTP2 client session (%d)\n"), rc);
		return WGET_E_INVALID;
	}

	nghttp2_settings_entry iv[] = {
		// {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100},
		{NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 1 << 30}, // prevent window size changes
		{NGHTTP2_SETTINGS_ENABLE_PUSH, 0}, // avoid push messages from server
	};

	if ((rc = nghttp2_submit_settings(conn->http2_session, NGHTTP2_FLAG_NONE, iv, countof(iv)))) {
		error_printf(_("Failed to submit HTTP2 client settings (%d)\n"), rc);
		return WGET_E_INVALID;
	}

#if NGHTTP2_VERSION_NUM >= 0x010c00
	// without this we experience slow downloads on fast networks
	if ((rc = nghttp2_session_set_local_window_size(conn->http2_session, NGHTTP2_FLAG_NONE, 0, 1 << 30)))
		debug_printf("Failed to set HTTP2 connection level window size (%d)\n", rc);
#endif

	conn->received_http2_responses = wget_vector_create(16, NULL);

	return rc;
}

void wget_http2_close(wget_http_connection **conn)
{
	if ((*conn)->http2_session) {
		int rc = nghttp2_session_terminate_session((*conn)->http2_session, NGHTTP2_NO_ERROR);
		if (rc)
			error_printf(_("Failed to terminate HTTP2 session (%d)\n"), rc);
		nghttp2_session_del((*conn)->http2_session);
	}
	wget_vector_clear_nofree((*conn)->received_http2_responses);
	wget_vector_free(&(*conn)->received_http2_responses);
}

static ssize_t data_prd_read_callback(
	nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length,
	uint32_t *data_flags, nghttp2_data_source *source, void *user_data WGET_GCC_UNUSED)
{
	struct http2_stream_context *ctx = nghttp2_session_get_stream_user_data(session, stream_id);
	const char *bodyp = source->ptr;

	if (!ctx)
		return NGHTTP2_ERR_CALLBACK_FAILURE;

//	debug_printf("[INFO] C ----------------------------> S (DATA post body), length:%zu %zu\n", length, ctx->resp->req->body_length);

	size_t len = ctx->resp->req->body_length - (bodyp - ctx->resp->req->body);

	if (len > length)
		len = length;

	memcpy(buf, bodyp, len);
	source->ptr = (char *) (bodyp + len);

	if (!len)
		*data_flags = NGHTTP2_DATA_FLAG_EOF;

	return len;
}

static void init_nv(nghttp2_nv *nv, const char *name, const char *value)
{
	nv->name = (uint8_t *)name;
	nv->namelen = strlen(name);
	nv->value = (uint8_t *)value;
	nv->valuelen = strlen(value);
	nv->flags = NGHTTP2_NV_FLAG_NONE;
}

int wget_http2_send_request(wget_http_connection *conn, wget_http_request *req)
{
	char length_str[32];
	nghttp2_nv *nvs, *nvp;
	char *resource;

	if (!(nvs = wget_malloc(sizeof(nghttp2_nv) * (4 + wget_vector_size(req->headers))))) {
		error_printf(_("Failed to allocate nvs[%d]\n"), 4 + wget_vector_size(req->headers));
		return -1;
	}

	if (!(resource = wget_malloc(req->esc_resource.length + 2))) {
		xfree(nvs);
		error_printf(_("Failed to allocate resource[%zu]\n"), req->esc_resource.length + 2);
		return -1;
	}

	resource[0] = '/';
	memcpy(resource + 1, req->esc_resource.data, req->esc_resource.length + 1);
	init_nv(&nvs[0], ":method", req->method);
	init_nv(&nvs[1], ":path", resource);
	init_nv(&nvs[2], ":scheme", "https");
	// init_nv(&nvs[3], ":authority", req->esc_host.data);
	nvp = &nvs[4];

	for (int it = 0; it < wget_vector_size(req->headers); it++) {
		wget_http_header_param *param = wget_vector_get(req->headers, it);
		if (!param)
			continue;
		if (!wget_strcasecmp_ascii(param->name, "Connection"))
			continue;
		if (!wget_strcasecmp_ascii(param->name, "Transfer-Encoding"))
			continue;
		if (!wget_strcasecmp_ascii(param->name, "Host")) {
			init_nv(&nvs[3], ":authority", param->value);
			continue;
		}

		init_nv(nvp++, param->name, param->value);
	}

	if (req->body_length) {
		wget_snprintf(length_str, sizeof(length_str), "%zu", req->body_length);
		init_nv(nvp++, "Content-Length", length_str);
	}

	struct http2_stream_context *ctx = wget_calloc(1, sizeof(struct http2_stream_context));
	if (!ctx) {
		return -1;
	}
	// HTTP/2.0 has the streamid as a link to request and connection.
	ctx->conn = conn;
	ctx->resp = wget_calloc(1, sizeof(wget_http_response));
	if (!ctx->resp) {
		xfree(ctx);
		return -1;
	}
	ctx->resp->req = req;
	ctx->resp->major = 2;
	// we do not get a Keep-Alive header in HTTP2 - let's assume the connection stays open
	ctx->resp->keep_alive = 1;
	req->request_start = wget_get_timemillis();

	if (req->body_length) {
		nghttp2_data_provider data_prd;
		data_prd.source.ptr = (void *) req->body;
		debug_printf("body length: %zu %zu\n", req->body_length, ctx->resp->req->body_length);
		data_prd.read_callback = data_prd_read_callback;
		req->stream_id = nghttp2_submit_request(conn->http2_session, NULL, nvs, nvp - nvs, &data_prd, ctx);
	} else {
		// nghttp2 does strdup of name+value and lowercase conversion of 'name'
		req->stream_id = nghttp2_submit_request(conn->http2_session, NULL, nvs, nvp - nvs, NULL, ctx);
	}

	xfree(resource);
	xfree(nvs);

	if (req->stream_id < 0) {
		error_printf(_("Failed to submit HTTP2 request\n"));
		wget_http_free_response(&ctx->resp);
		xfree(ctx);
		return -1;
	}

	conn->pending_http2_requests++;

	debug_printf("HTTP2 stream id %d\n", req->stream_id);

	return 0;
}

wget_http_response *wget_http2_get_response_cb(wget_http_connection *conn, wget_server_stats_callback *server_stats_callback)
{
	char *buf;
	size_t bufsize;
	ssize_t nbytes;
	wget_http_response *resp = NULL;

	debug_printf("  ##  pending_requests = %d\n", conn->pending_http2_requests);
	if (conn->pending_http2_requests > 0)
		conn->pending_http2_requests--;
	else
		return NULL;

	// reuse generic connection buffer
	buf = conn->buf->data;
	bufsize = conn->buf->size;

	while (!wget_vector_size(conn->received_http2_responses) && !http_connection_is_aborted(conn)) {
		int rc;

		while (nghttp2_session_want_write(conn->http2_session) && nghttp2_session_send(conn->http2_session) == 0)
			;

		if ((nbytes = wget_tcp_read(conn->tcp, buf, bufsize)) <= 0) {
			debug_printf("failed to receive: %d (nbytes=%ld)\n", errno, (long) nbytes);
			if (nbytes == -1)
				break;

			// nbytes == 0 has been seen on Win11, continue looping
		}

		if ((nbytes = nghttp2_session_mem_recv(conn->http2_session, (uint8_t *) buf, nbytes)) < 0) {
			rc = (int) nbytes;
			debug_printf("mem_recv failed: %d %s\n", rc, nghttp2_strerror(rc));
			break;
		}

		// debug_printf("  ##  loop responses=%d rc=%d nbytes=%zd\n", wget_vector_size(conn->received_http2_responses), rc, nbytes);
	}

	resp = wget_vector_get(conn->received_http2_responses, 0); // should use double linked lists here

	if (server_stats_callback)
		server_stats_callback(conn, resp);

	if (resp) {
		debug_printf("  ##  response status %d\n", resp->code);
		wget_vector_remove_nofree(conn->received_http2_responses, 0);
	}

	return resp;
}
