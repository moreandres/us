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
#include <zlog.h>

#include <config.h>
#include "utils.h"

#define LOG(level, fmt, args...) do {			\
    printf("%s:%d:%s", __FILE__, __LINE__, __func__);	\
    printf(fmt, ## args); printf("\n"); } while (0)

#define LOG_TRACE 1

void signal_handler(int signal)
{
  LOG(LOG_TRACE, "%d", signal);
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
	while (tmp = readdir(dir))
	  res = resource_create(strncat(path, tmp->d_name));
	
	res = closedir(dir);
      }
    }
  }
  
  return service;
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
	while (tmp = readdir(dir)) {
	  char *string = NULL;
	  
	  res = asprintf(&string, "%s/%s", path, tmp->d_name);
	  assert(res);
	  method_t *method = method_create(string);
	  HASH_ADD_KEYPTR(hh, resource->methods,
			  method->name, strlen(method->name), method);
	  free(string);
	  
	}
	closedir(dir);
      }
    }
  }
  
  return resource;
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

void service_destroy(service_t * service)
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

int load_service()
{
  int res = 0;
  
  service_t *service = service_create(".");

  service_destroy(service);

  return res;
}

/*
  load_service(); load_resources(); load_schema(); load_json(); load_file();
 */

/*
  [ resource, request schema, response schema, stats (count, avg latency, error rate) ]
*/

#define PORT 8888

/* handle health -> OK, stats; log_stats() */

int answer_to_connection(void *cls, struct MHD_Connection *connection,
			 const char *url,
			 const char *method, const char *version,
			 const char *upload_data,
			 size_t *upload_data_size, void **con_cls)
{
  LOG(LOG_TRACE, "%s %s %s %s %ld", url, method, version, upload_data, *upload_data_size);

  assert(cls);
  assert(con_cls);
  
	const char *page = "<html><body>Hello, browser!</body></html>";
	struct MHD_Response *response;
	int ret;

	response = MHD_create_response_from_buffer(strlen(page),
						   (void *)page,
						   MHD_RESPMEM_PERSISTENT);
	ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
	MHD_destroy_response(response);

	return ret;
}

/*
  handle_connection -> parse_request -> validate_request -> validate_method -> process_request -> handle_get handle_post handle_delete handle_put handle_patch -> handle_options -> handle_head -> handle_other
 */

#define SERVERKEYFILE "/etc/server.key"
#define SERVERCERTFILE "/etc/server.crt"

int main(int argc, char *argv[])
{

	assert(argc >= 0);
	assert(argv != NULL);

	struct MHD_Daemon *daemon;

	char *key_pem;
	char *cert_pem;

	key_pem = (SERVERKEYFILE);
	cert_pem = (SERVERCERTFILE);

	if ((key_pem == NULL) || (cert_pem == NULL)) {
		printf("The key/certificate files could not be read.\n");
		return 1;
	}

	/*
	   daemon = MHD_start_daemon (MHD_USE_SELECT_INTERNALLY | MHD_USE_SSL,
	   PORT, NULL, NULL,
	   &answer_to_connection, NULL,
	   MHD_OPTION_HTTPS_MEM_KEY, key_pem,
	   MHD_OPTION_HTTPS_MEM_CERT, cert_pem,
	   MHD_OPTION_END);
	   if (NULL == daemon) {
	   printf("%s\n", cert_pem);
	   free (key_pem);
	   free (cert_pem);
	   return 1;
	   }
	 */
	daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY,
				  PORT, NULL, NULL,
				  &answer_to_connection, NULL, MHD_OPTION_END);
	if (daemon == NULL)
		return 1;

	getchar();

	MHD_stop_daemon(daemon);

	zlog_fini();

	return EXIT_SUCCESS;
}
