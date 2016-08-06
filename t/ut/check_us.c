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

#include <config.h>
#include <criterion/criterion.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include "utils.h"
#include "us.h"

Test(signal, handler)
{
	signal_handler(SIGINT);
	signal_handler(SIGQUIT);
}

Test(document, create)
{
	cr_assert(NULL == document_create(NULL),
		  "document_create on NULL returns NULL");
	cr_assert(NULL == document_create("/invalid"),
		  "document_create on invalid path returns NULL");
}

Test(utils, string_to_base64)
{
	cr_assert(NULL == string_to_base64(NULL),
		  "string_to_base64 on NULL returns NULL");

	char *string = "this is a test";
	char *base64 = "dGhpcyBpcyBhIHRlc3Q=";
	cr_assert_str_eq(base64, string_to_base64(string),
			 "string_to_base64 on NULL returns NULL");
}

Test(utils, get_file_size)
{
	cr_assert(0 == get_file_size(NULL),
		  "get_file_size on NULL returns zero");
}

Test(utils, load_file)
{
	cr_assert(NULL == load_file(NULL),
		"load_file on NULL returns NULL");
}

Test(method, create)
{
	cr_assert(NULL == method_create(NULL),
		  "method_create on NULL returns NULL");
	cr_assert(NULL == method_create("/invalid/invalid"),
		  "method_create on invalid path returns NULL");
}

Test(method, parse)
{
	cr_assert(EINVAL == method_parse(NULL, NULL),
		  "method_create on NULL returns EINVAL");
}

Test(method, destroy)
{
	method_destroy(NULL);
	cr_assert(1, "method_destroy on NULL returns NULL");
}

Test(resource, create)
{
	cr_assert(NULL == resource_create(NULL),
		  "resource_create on NULL returns NULL");
}
		
Test(resource, read)
{
	cr_assert(EINVAL == resource_read(NULL, NULL),
		  "resource_read on NULL returns EINVAL");
}

Test(resource, destroy)
{
	resource_destroy(NULL);
	cr_assert(1, "resource_destroy on NULL completes");
}

Test(service, create)
{
	cr_assert(NULL != service_create(NULL),
		  "service_create on NULL returns NULL");
}

Test(service, parse)
{
	cr_assert(EINVAL == service_parse(NULL, NULL),
		 "service_parse on NULL returns EINVAL");
}

Test(service, destroy)
{
	service_destroy(NULL);
	cr_assert(1, "service_destroy on NULL completes");
}
