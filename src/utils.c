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

#include <errno.h>
#include <error.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include "utils.h"

char *timestamp(int size)
{
  assert(size >= 0);

  char *buffer = calloc(size, sizeof(char));

  assert(buffer);
  
  struct timeval tv;
  time_t time;

  int res = gettimeofday(&tv, NULL);
  if (res)
    error(EXIT_FAILURE, errno, "could not get time");
  
  time = tv.tv_sec;

  int count = strftime(buffer, size, "%m%d%y-%H%M%S", localtime(&time));
  if (count == 0)
    error(EXIT_FAILURE, errno, "could not format timestamp");

  return buffer;
}
