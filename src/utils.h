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

/**
 * Utilities
 */

#ifndef __UTILS_H__
#define __UTILS_H__

#include <stdio.h>
#include <errno.h>

/**
 * @return epoch as a double
 */

double stamp(void);

#define LOG(fmt, args...)						\
	do {								\
		printf("[%f] ", stamp());				\
		printf("%s:%d:%s() ", __FILE__, __LINE__, __func__);	\
		printf(fmt, ## args);					\
		printf("\n");						\
	} while (0)

#endif /* __UTILS_H__ */
