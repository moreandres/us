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
#include <string.h>

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

	/*
	  term/quit: daemon, zlog
	 */

	/*
	  sigusr: stats
	 */
}

/* TODO: argument parsing */
/* TODO: dynamic callbacks loader using dlopen */
/* TODO: doxygen */
/* TODO: valgrind */
/* TODO: storage */

/* service/resource/get/request.json */
/* service/resource/get/response.json */

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
	WJElement doc = NULL;
	WJElement person = NULL;

	doc = WJEObject(NULL, NULL, WJE_NEW);
	WJEString(doc, "name", WJE_SET, "Serenity");
	WJEString(doc, "class", WJE_SET, "firefly");
	WJEArray(doc, "crew", WJE_SET);

	WJEObject(doc, "crew[$]", WJE_NEW);
	WJEString(doc, "crew[-1].name", WJE_SET, "Malcolm Reynolds");
	WJEString(doc, "crew[-1].job", WJE_SET, "captain");
	WJEInt64(doc, "crew[-1].born", WJE_SET, 2468);

	WJEObject(doc, "crew[$]", WJE_NEW);
	WJEString(doc, "crew[-1].name", WJE_SET, "Kaywinnet Lee Fry");
	WJEString(doc, "crew[-1].job", WJE_SET, "mechanic");
	WJEInt64(doc, "crew[-1].born", WJE_SET, 2494);

	WJEObject(doc, "crew[$]", WJE_NEW);
	WJEString(doc, "crew[-1].name", WJE_SET, "Jayne Cobb");
	WJEString(doc, "crew[-1].job", WJE_SET, "public relations");
	WJEInt64(doc, "crew[-1].born", WJE_SET, 2485);

	WJEBool(doc, "shiny", WJE_SET, TRUE);

	WJEInt64(doc, "crew[].born == 2468", WJE_SET, 2486);	/* note: awesome! */
	WJECloseDocument(WJEGet(doc, "shiny", NULL));

	const char *page = "<html><body>Hello, browser!</body></html>";
	struct MHD_Response *response;
	int ret;

	response = MHD_create_response_from_buffer(strlen(page),
						   (void *)page,
						   MHD_RESPMEM_PERSISTENT);
	ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
	MHD_destroy_response(response);

	WJEDump(doc);
	WJECloseDocument(doc);

	return ret;
}

int print_out_key(void *cls, enum MHD_ValueKind kind,
		  const char *key, const char *value)
{
	printf("%s: %s\n", key, value);
	return MHD_YES;
}

static int
answer_to_connection2(void *cls, struct MHD_Connection *connection,
		      const char *url,
		      const char *method,
		      const char *version,
		      const char *upload_data,
		      size_t *upload_data_size, void **con_cls)
{
	printf("New %s request for %s using version %s\n",
	       method, url, version);
	MHD_get_connection_values(connection,
				  MHD_HEADER_KIND, &print_out_key, NULL);

	return MHD_NO;
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
