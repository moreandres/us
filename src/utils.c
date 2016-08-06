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
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "utils.h"

double stamp(void)
{
	struct timeval tv;
	int res = gettimeofday(&tv, NULL);
	if (res) {
		printf("could not get time: %s", strerror(errno));
		return -1;
	}
	
	return (tv.tv_sec + tv.tv_usec / 1000000.0);
}
