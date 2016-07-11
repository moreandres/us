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
#include "utils.h"

#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <microhttpd.h>
#include <wjelement.h>
#include <zlog.h>

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

int load_service(void)
{
  return 0;
}

int add_resource()
{
  return 0;
}


// service/resource/get/request.json
// service/resource/get/response.json

#include <sys/time.h>
#include <time.h>

int set_signal_handler(void)
{
  return 0;
}

int main(int argc, char *argv[]) {

  assert(argc >= 0);
  assert(argv != NULL);

  return 0;
}
