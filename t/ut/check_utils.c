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

#include <config.h>
#include <criterion/criterion.h>
#include <unistd.h>
#include "utils.h"

Test(stamp, epoch1)
{
	cr_assert(stamp() > 0, "stamp returns greater than zero");
}

Test(stamp, epoch2)
{
	double begin = stamp();
	sleep(1);
	double end = stamp();
		
	cr_assert(end - begin > 0, "stamps diff is greater than zero");
}

// LOG shows something in stderr

// signal handler handles
