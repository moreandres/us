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
#include <config.h>
#include <check.h>
#include "../../src/us.h"

START_TEST(test_signal_handler_valid)
{
  signal_handler(1);
}
END_TEST

START_TEST(test_signal_handler_invalid)
{
  signal_handler(-1);
}
END_TEST

Suite * us_suite(void)
{
	Suite *s = suite_create("us");
	TCase *tc_signal_handler = tcase_create("signal_handler");

	tcase_add_test(tc_signal_handler, test_signal_handler_valid);
	tcase_add_test(tc_signal_handler, test_signal_handler_invalid);
	suite_add_tcase(s, tc_signal_handler);

	return s;
}

int main(void)
{
	int number_failed;
	Suite *s;
	SRunner *sr;

	s = us_suite();
	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
