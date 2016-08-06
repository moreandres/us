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

#ifndef __US_H__
#define __US_H__

#include <wjelement.h>
#include <dirent.h>
#include <signal.h>

typedef struct method method_t;
typedef struct resource resource_t;
typedef struct service service_t;
typedef struct response response_t;

void signal_handler(const int signal);
WJElement document_create(char *path);
char *string_to_base64(const char *message);
size_t get_file_size(const char *filename);
char *load_file(const char *filename);

method_t *method_create(char *path);
int method_parse(method_t *method, char *path);
void method_destroy(method_t *method);

resource_t *resource_create(const char *path);
int resource_read(resource_t *resource, DIR *dir);
void resource_destroy(resource_t *resource);

service_t *service_create(const char *path);
void service_destroy(service_t *service);
int service_parse(service_t *service, DIR *dir);

#endif
