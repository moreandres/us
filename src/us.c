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

#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <argp.h>
#include <dlfcn.h>
#include <sqlite3.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

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

void signal_handler(int signal)
{
  assert(signal);
}

// TODO: argument parsing
// TODO: unit testing setup: check
// TODO: system testing?
// TODO: logging
// TODO: JSON parsing
// TODO: HTTPS server: GNU Libmicrohttpd
// TODO: dynamic callbacks loader using dlopen
// TODO: doxygen
// TODO: checkpatch
// TODO: valgrind
// TODO: storage

// service/resource/get/request.json
// service/resource/get/response.json

#define PORT 8888

int answer_to_connection2(void *cls, struct MHD_Connection *connection, 
                          const char *url, 
                          const char *method, const char *version, 
                          const char *upload_data, 
                          size_t *upload_data_size, void **con_cls)
{
  const char *page  = "<html><body>Hello, browser!</body></html>";
  struct MHD_Response *response;
  int ret;

  response = MHD_create_response_from_buffer (strlen (page),
					      (void*) page,
					      MHD_RESPMEM_PERSISTENT);
  ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
  MHD_destroy_response (response);
  
  return ret;
}

int print_out_key (void *cls, enum MHD_ValueKind kind, 
                   const char *key, const char *value)
{
  printf ("%s: %s\n", key, value);
  return MHD_YES;
}

static int 
answer_to_connection (void *cls, struct MHD_Connection *connection, 
                      const char *url, 
		      const char *method, const char *version, 
		      const char *upload_data, 
                      size_t *upload_data_size, void **con_cls)
{
  printf("New %s request for %s using version %s\n",
	 method, url, version);
  MHD_get_connection_values(connection,
			    MHD_HEADER_KIND,
			    &print_out_key,
			    NULL);
 
  return MHD_NO;
}

#define SERVERKEYFILE "/etc/server.key"
#define SERVERCERTFILE "/etc/server.crt"

int main(int argc, char *argv[]) {

  assert(argc >= 0);
  assert(argv != NULL);

  int rc;
  zlog_category_t *c;

  rc = zlog_init("/etc/zlog.conf");
  if (rc) {
    printf("zlog_init failed\n");
    return -1;
  }

  c = zlog_get_category("core");
  if (!c) {
    printf("get cat fail\n");
    zlog_fini();
    return -2;
  }
  
  zlog_info(c, "hello, zlog");

  struct MHD_Daemon *daemon;

  char *key_pem;
  char *cert_pem;
  
  key_pem = (SERVERKEYFILE);
  cert_pem = (SERVERCERTFILE);

  if ((key_pem == NULL) || (cert_pem == NULL))
    {
      printf ("The key/certificate files could not be read.\n");
      return 1;
    }
  
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
  getchar (); 

  MHD_stop_daemon (daemon);

  zlog_fini();
  
  return EXIT_SUCCESS;
}
