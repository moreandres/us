/*
  Copyright (c) 2016 Andres More (more.andres@gmail.com)

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <argp.h>
#include <dlfcn.h>
#include <sqlite3.h>
#include <assert.h>
#include <errno.h>
#include <error.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <dirent.h>

#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>

#include <microhttpd.h>
#include <wjelement.h>
#include <wjreader.h>

#include <config.h>
#include "uthash.h"
#include "utils.h"

void signal_handler(const int signal)
{
	LOG("%d", signal);
}

/* TODO: argument parsing */
/* TODO: dynamic callbacks loader using dlopen */
/* TODO: doxygen */
/* TODO: valgrind */
/* TODO: storage */

/* service/resource/get/request.json */
/* service/resource/get/response.json */

typedef struct method {
	char *name;
	WJElement request;
	WJElement response;
	UT_hash_handle hh;
} method_t;

typedef struct resource {
	char *name;
	method_t *methods;
	UT_hash_handle hh;
} resource_t;

typedef struct service {
	char *name;
	resource_t *resources;
} service_t;

WJElement document_create(char *path)
{
	WJElement element = NULL;
	WJReader reader = NULL;
	FILE *file = fopen(path, "r");

	if (file) {
		reader = WJROpenFILEDocument(file, NULL, 0);
		if (reader)
			element = WJEOpenDocument(reader, NULL, NULL, NULL);
	}
	return element;
}

method_t *method_create(char *path)
{
	int res = -1;
	method_t *method = (method_t *) calloc(1, sizeof(method_t));

	if (method) {
		method->name = strdup(basename(path));
		if (method->name) {
			char *string = NULL;

			res = asprintf(&string, "%s/request.json", path);
			assert(res);
			method->request = document_create(string);
			free(string);

			res = asprintf(&string, "%s/response.json", path);
			method->response = document_create(string);
			free(string);
		}
	}
	return method;
}

resource_t *resource_create(const char *path)
{
	resource_t *resource = calloc(1, sizeof(resource_t));

	if (resource) {
		resource->name = strdup(basename(path));
		if (resource->name) {
			DIR *dir = opendir(path);

			if (dir) {

				int res = -1;
				struct dirent *tmp = NULL;

				while ((tmp = readdir(dir))) {
					char *string = NULL;

					res =
					    asprintf(&string, "%s/%s", path,
						     tmp->d_name);
					assert(res);
					method_t *method =
					    method_create(string);

					HASH_ADD_KEYPTR(hh, resource->methods,
							method->name,
							strlen(method->name),
							method);
					free(string);

				}
				closedir(dir);
			}
		}
	}

	return resource;
}

service_t *service_create(const char *path)
{
	service_t *service = calloc(1, sizeof(service_t));

	if (service) {
		service->name = strdup(basename(path));
		if (service->name) {
			DIR *dir = opendir(path);

			if (dir) {
				int res = -1;
				struct dirent *tmp = NULL;

				while ((tmp = readdir(dir))) {

					char *string = NULL;

					res =
					    asprintf(&string, "%s/%s", path,
						     tmp->d_name);
					assert(res);

					resource_t *resource =
					    resource_create(string);

					HASH_ADD_KEYPTR(hh, service->resources,
							resource->name,
							strlen(resource->name),
							resource);
					free(string);
				}
				res = closedir(dir);
			}
		}
	}

	return service;
}

void method_destroy(method_t *method)
{
	WJECloseDocument(method->request);
	WJECloseDocument(method->response);
	free(method->name);
	free(method);
}

void resource_destroy(resource_t *resource)
{
	method_t *method = NULL;
	method_t *tmp = NULL;
	method_t *methods = resource->methods;

	HASH_ITER(hh, methods, method, tmp) {
		HASH_DEL(methods, method);
		method_destroy(method);
	}

	free(resource);
}

void service_destroy(service_t *service)
{
	resource_t *resource = NULL;
	resource_t *tmp = NULL;
	resource_t *resources = service->resources;

	HASH_ITER(hh, resources, resource, tmp) {
		HASH_DEL(resources, resource);
		resource_destroy(resource);
	}

	free(service);
}

/*
  load_service(); load_resources(); load_schema(); load_json(); load_file();
 */

/*
  [ resource, request schema, response schema, stats (count, avg latency, error rate) ]
*/

/* handle health -> OK, stats; log_stats() */

/*
  handle_connection -> parse_request -> validate_request -> validate_method -> process_request -> handle_get handle_post handle_delete handle_put handle_patch -> handle_options -> handle_head -> handle_other
 */

#define PORT 8888

#define REALM     "\"Maintenance\""
#define USER      "a legitimate user"
#define PASSWORD  "and his password"

#define SERVERKEYFILE "server.key"
#define SERVERCERTFILE "server.pem"

static char *string_to_base64(const char *message)
{
	const char *lookup =
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	unsigned long l;
	int i;
	char *tmp;
	size_t length = strlen(message);

	tmp = malloc(length * 2);
	if (tmp == NULL)
		return tmp;

	tmp[0] = 0;

	for (i = 0; i < length; i += 3) {
		l = (((unsigned long)message[i]) << 16)
		    | (((i + 1) < length)
		       ? (((unsigned long)message[i + 1]) << 8) : 0)
		    | (((i + 2) < length) ? ((unsigned long)message[i + 2]) :
		       0);

		strncat(tmp, &lookup[(l >> 18) & 0x3F], 1);
		strncat(tmp, &lookup[(l >> 12) & 0x3F], 1);

		if (i + 1 < length)
			strncat(tmp, &lookup[(l >> 6) & 0x3F], 1);
		if (i + 2 < length)
			strncat(tmp, &lookup[l & 0x3F], 1);
	}

	if (length % 3)
		strncat(tmp, "===", 3 - length % 3);

	return tmp;
}

static long get_file_size(const char *filename)
{
	FILE *fp;

	fp = fopen(filename, "rb");
	if (fp) {
		long size;

		if ((fseek(fp, 0, SEEK_END) != 0) || (-1 == (size = ftell(fp))))
			size = 0;

		fclose(fp);

		return size;
	} else
		return 0;
}

static char *load_file(const char *filename)
{
	FILE *fp;
	char *buffer;
	long size;

	size = get_file_size(filename);
	if (size == 0)
		return NULL;

	fp = fopen(filename, "rb");
	if (!fp)
		return NULL;

	buffer = malloc(size);
	if (!buffer) {
		fclose(fp);
		return NULL;
	}

	if (size != fread(buffer, 1, size, fp)) {
		free(buffer);
		buffer = NULL;
	}

	fclose(fp);
	return buffer;
}

static int
ask_for_authentication(struct MHD_Connection *connection, const char *realm)
{
	int ret;
	struct MHD_Response *response;
	char *headervalue;
	const char *strbase = "Basic realm=";

	response = MHD_create_response_from_buffer(0, NULL,
						   MHD_RESPMEM_PERSISTENT);
	if (!response)
		return MHD_NO;

	headervalue = malloc(strlen(strbase) + strlen(realm) + 1);
	if (!headervalue)
		return MHD_NO;

	strcpy(headervalue, strbase);
	strcat(headervalue, realm);

	ret =
	    MHD_add_response_header(response, "WWW-Authenticate", headervalue);
	free(headervalue);
	if (!ret) {
		MHD_destroy_response(response);
		return MHD_NO;
	}

	ret = MHD_queue_response(connection, MHD_HTTP_UNAUTHORIZED, response);

	MHD_destroy_response(response);

	return ret;
}

static int
is_authenticated(struct MHD_Connection *connection,
		 const char *username, const char *password)
{
	const char *headervalue;
	char *expected_b64, *expected;
	const char *strbase = "Basic ";
	int authenticated;

	headervalue =
	    MHD_lookup_connection_value(connection, MHD_HEADER_KIND,
					"Authorization");
	if (headervalue == NULL)
		return 0;
	if (strncmp(headervalue, strbase, strlen(strbase)) != 0)
		return 0;

	expected = malloc(strlen(username) + 1 + strlen(password) + 1);
	if (expected == NULL)
		return 0;

	strcpy(expected, username);
	strcat(expected, ":");
	strcat(expected, password);

	expected_b64 = string_to_base64(expected);
	free(expected);
	if (expected_b64 == NULL)
		return 0;

	authenticated =
	    (strcmp(headervalue + strlen(strbase), expected_b64) == 0);

	free(expected_b64);

	return authenticated;
}

static int secret_page(struct MHD_Connection *connection)
{
	int ret;
	struct MHD_Response *response;
	const char *page = "<html><body>A secret.</body></html>";

	response =
	    MHD_create_response_from_buffer(strlen(page), (void *)page,
					    MHD_RESPMEM_PERSISTENT);
	if (!response)
		return MHD_NO;

	ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
	MHD_destroy_response(response);

	return ret;
}

static int
answer_to_connection(void *cls, struct MHD_Connection *connection,
		     const char *url, const char *method,
		     const char *version, const char *upload_data,
		     size_t *upload_data_size, void **con_cls)
{
	if (0 != strcmp(method, "GET"))
		return MHD_NO;
	if (*con_cls == NULL) {
		*con_cls = connection;
		return MHD_YES;
	}

	if (!is_authenticated(connection, USER, PASSWORD))
		return ask_for_authentication(connection, REALM);

	return secret_page(connection);
}

int main(void)
{
	service_t *service = service_create(".");

	service_destroy(service);

	struct MHD_Daemon *daemon;
	char *key_pem;
	char *cert_pem;

	key_pem = load_file(SERVERKEYFILE);
	cert_pem = load_file(SERVERCERTFILE);

	if ((key_pem == NULL) || (cert_pem == NULL)) {
		LOG("The key/certificate files could not be read");
		return 1;
	}

	daemon =
	    MHD_start_daemon(MHD_USE_SELECT_INTERNALLY | MHD_USE_SSL, PORT,
			     NULL, NULL, &answer_to_connection, NULL,
			     MHD_OPTION_HTTPS_MEM_KEY, key_pem,
			     MHD_OPTION_HTTPS_MEM_CERT, cert_pem,
			     MHD_OPTION_END);
	if (daemon == NULL) {
		printf("%s\n", cert_pem);

		free(key_pem);
		free(cert_pem);

		return 1;
	}

	getchar();

	MHD_stop_daemon(daemon);
	free(key_pem);
	free(cert_pem);

	return 0;
}
