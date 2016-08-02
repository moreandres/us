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
	LOG("creating document %p", path);

	WJElement element = NULL;
	WJReader reader = NULL;
	FILE *file = fopen(path, "r");

	if (!file) {
		LOG("could not open file %p", path);
		return NULL;
	}

	reader = WJROpenFILEDocument(file, NULL, 0);
	if (!reader) {
		LOG("could not create file reader");
		int res = fclose(file);
		if (!res)
			LOG("could not close file");
		return NULL;
	}

	element = WJEOpenDocument(reader, NULL, NULL, NULL);
	XplBool bool = WJRCloseDocument(reader);

	if (!bool)
		LOG("could not close file reader");
	int res = fclose(file);

	if (!res)
		LOG("could not close file");

	if (!element) {
		LOG("could not read element");
		return NULL;
	}

	WJEDump(element);

	return element;
}

int method_read(method_t *method, char *path)
{
	LOG("reading method");

	char *string = NULL;

	int res = -1;

	res = asprintf(&string, "%s/request.json", path);
	if (!res) {
		LOG("could not allocate request path");
		return ENOMEM;
	}

	method->request = document_create(string);
	free(string);
	if (!method->request) {
		LOG("could not create request document");
		return EINVAL;
	}

	res = asprintf(&string, "%s/response.json", path);
	if (!res) {
		LOG("could not allocate response path");
		return ENOMEM;
	}

	method->response = document_create(string);
	free(string);
	if (!method->request) {
		LOG("could not create request document");
		return EINVAL;
	}

	return EXIT_SUCCESS;
}

method_t *method_create(char *path)
{
	LOG("creating method %s", path);

	method_t *method = (method_t *) calloc(1, sizeof(method_t));

	if (!method) {
		LOG("could not allocate method");
		return NULL;
	}

	method->name = strdup(basename(path));
	if (!method->name) {
		LOG("could not allocate method name");
		free(method);
		return NULL;
	}

	int res = method_read(method, path);

	if (!res) {
		LOG("could not read method");
		free(method->name);
		free(method);
		return NULL;
	}

	return method;
}

int resource_read(resource_t *resource, DIR *dir)
{
	LOG("reading resource %p %p", resource, dir);

	struct dirent *tmp = NULL;

	while ((tmp = readdir(dir))) {

		char *string = NULL;

		int res =
			asprintf(&string, "%s/%s",
				 resource->name, tmp->d_name);
		if (!res) {
			LOG("could not allocate method name");
			return ENOMEM;
		}
		method_t *method = method_create(string);

		if (!method) {
			LOG("could not create method %s", string);
			free(string);
			return EINVAL;
		}

		HASH_ADD_KEYPTR(hh, resource->methods,
				method->name,
				strlen(method->name),
				method);
	}

	return EXIT_SUCCESS;
}

resource_t *resource_create(const char *path)
{
	LOG("", path);

	resource_t *resource = calloc(1, sizeof(resource_t));
	if (!resource) {
		LOG("Could not allocate resource: %s", strerror(errno));
		return NULL;
	}

	resource->name = strdup(basename(path));
	if (!(resource->name)) {
		LOG("Could not allocate resource name: %s", strerror(errno));
		free(resource);
		return NULL;
	}

	DIR *dir = opendir(path);

	if (!dir) {
		LOG("Could not open dir %p", path);
		free(resource->name);
		free(resource);
		return NULL;
	}

	int res = resource_read(resource, dir);

	if (!res)
		LOG("could not read resource");

	res = closedir(dir);
	if (!res)
		LOG("could not close dir");

	return resource;
}

int service_parse(service_t *service, DIR *dir)
{
	LOG("");

	struct dirent *tmp = NULL;

	while ((tmp = readdir(dir))) {

		char *string = NULL;
		int res = asprintf(&string, "%s/%s", service->name, tmp->d_name);
		if (res == -1) {
			LOG("Could not allocate resource name");
			return ENOMEM;
		}

		LOG("Reading resource %s", string);

		resource_t *resource = resource_create(string);

		if (!resource) {
			LOG("Could not create resource %s", string);
			free(string);
			return EINVAL;
		}
		free(string);

		HASH_ADD_KEYPTR(hh, service->resources,
				resource->name,
				strlen(resource->name),
				resource);
	}

	return EXIT_SUCCESS;
}

service_t *service_create(const char *path)
{
	LOG("");

	service_t *service = calloc(1, sizeof(service_t));
	if (!service) {
		LOG("Could not allocate service: %s", strerror(errno));
		return NULL;
	}

	service->name = strdup(basename(path));
	if (!(service->name)) {
		LOG("Could not allocate service name");
		free(service);
		return NULL;
	}

	DIR *dir = opendir(path);
	if (!dir) {
		LOG("Could not open dir %p", path);
		free(service->name);
		free(service);
		return NULL;
	}

	LOG("Parsing service %s", service->name);
	int res = service_parse(service, dir);
	if (!res) {
		LOG("Could not parse service");
		free(service->name);
		free(service);		
		res = closedir(dir);
		if (res)
			LOG("Could not close dir %p", path);
		return NULL;
	}

	res = closedir(dir);
	if (res)
		LOG("Could not close dir %p", path);

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
	LOG("");
	
	FILE *fp = fopen(filename, "rb");
	if (!fp) {
		LOG("Could not open %s: %s", filename, strerror(errno));
		return 0;
	}
	
	long size = 0;

	if ((fseek(fp, 0, SEEK_END) != 0)
	    || (-1 == (size = ftell(fp)))) {
		LOG("Could not seek end %s: %s",
		    filename, strerror(errno));
		size = 0;
	}
	fclose(fp);

	LOG("File size is %d", size);
	
	return size;
}

static char *load_file(const char *filename)
{
	LOG("");
	
	long size = get_file_size(filename);
	if (size == 0) {
		LOG("Could not get file size %s", filename);
		return NULL;
	}
	
	FILE *fp = fopen(filename, "rb");
	if (!fp) {
		LOG("Could not open file %s: %s",
		    filename, strerror(errno));
		return NULL;
	}

	char *buffer = calloc(size, sizeof(char));
	if (!buffer) {
		LOG("Could not allocate buffer: %s", strerror(errno));
		fclose(fp);
		return NULL;
	}

	if (size != fread(buffer, 1, size, fp)) {
		LOG("Could not read into buffer: %s", strerror(errno));
		free(buffer);
		buffer = NULL;
	}

	int res = fclose(fp);
	if (!res)
		LOG("Could not close file: %s", strerror(errno));
	
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

int invalid_response(struct MHD_Connection *connection)
{
	const char *data = "<html><body><p>Error!</p></body></html>";
	struct MHD_Response *response = MHD_create_response_from_buffer(strlen(data),
									data,
									MHD_RESPMEM_PERSISTENT);
	if (!response) {
		LOG("could not create response");
		return MHD_NO;
	}

	int res = MHD_queue_response(connection, 200, response);

	if (!res) {
		LOG("could not queue response");
		return MHD_NO;
	}

	MHD_destroy_response(response);

	return MHD_YES;
}

int invalid_payload(struct MHD_Connection *connection)
{
	const char *data = "<html><body><p>Error!</p></body></html>";
	struct MHD_Response *response = MHD_create_response_from_buffer(strlen(data),
									data,
									MHD_RESPMEM_PERSISTENT);
	if (!response) {
		LOG("could not create response");
		return MHD_NO;
	}

	int res = MHD_queue_response(connection, 200, response);

	if (!res) {
		LOG("could not queue response");
		return MHD_NO;
	}

	MHD_destroy_response(response);

	return MHD_YES;
}

int handle_response(struct MHD_Connection *connection)
{
	if (!is_valid_payload(connection))
		return invalid_payload(connection);

	const char *data = "<html><body><p>Error!</p></body></html>";
	struct MHD_Response *response = MHD_create_response_from_buffer(strlen(data),
									data,
									MHD_RESPMEM_PERSISTENT);
	if (!response) {
		LOG("could not create response");
		return MHD_NO;
	}

	int res = MHD_queue_response(connection, 200, response);

	if (!res) {
		LOG("could not queue response");
		return MHD_NO;
	}

	MHD_destroy_response(response);

	return MHD_YES;
}

int is_valid(const char *url, const char *method)
{
	assert(url);
	assert(method);

	return MHD_NO;
}

int is_valid_payload(struct MHD_Connection *connection)
{
	return MHD_NO;
}

static int connection_handler(void *cls, struct MHD_Connection *connection,
			      const char *url, const char *method,
			      const char *version, const char *upload_data,
			      size_t *upload_data_size, void **con_cls)
{
	LOG("handling connection %s %s %s", url, method, version);

	if (*con_cls == NULL) {
		*con_cls = connection;
		return MHD_YES;
	}

	if (!is_valid(url, method))
		return invalid_response(connection);

	if (!is_authenticated(connection, USER, PASSWORD))
		return ask_for_authentication(connection, REALM);

	return handle_response(connection);
}

int main(int argc, char *argv[])
{
	LOG("");

	LOG("Loading key");
	char *key = load_file(SERVERKEYFILE);
	if (!key) {
		LOG("Could not load key file");
		return EXIT_FAILURE;
	}

	LOG("Loading certificate");
	char *cert = load_file(SERVERCERTFILE);
	if (!key) {
		LOG("Could not load certificate file");
		free(key);
		return EXIT_FAILURE;
	}

	/* what about key password? */

	LOG("Creating service");
	service_t *service = service_create(".");
	if (!service) {
		LOG("Could not create service");
		free(cert);
		free(key);
		return EXIT_FAILURE;
	}

	/* pre populate reusable responses */

	int options = MHD_USE_EPOLL_LINUX_ONLY | MHD_USE_SSL | MHD_USE_TCP_FASTOPEN | MHD_USE_SELECT_INTERNALLY | MHD_USE_DEBUG;
	struct MHD_Daemon *daemon = MHD_start_daemon(options, PORT,
						     NULL, NULL, &connection_handler, service,
						     MHD_OPTION_HTTPS_MEM_KEY, key,
						     MHD_OPTION_HTTPS_MEM_CERT, cert,
			     MHD_OPTION_CONNECTION_TIMEOUT, 60,
			     MHD_OPTION_THREAD_POOL_SIZE, 32,
			     MHD_OPTION_END);
	if (daemon == NULL) {
		LOG("could not start MHD daemon");
		free(key);
		free(cert);
		return EXIT_FAILURE;
	}

	MHD_stop_daemon(daemon);
	free(key);
	free(cert);

	service_destroy(service);

	return EXIT_SUCCESS;
}
