#! /usr/bin/bash 

# Copyright (c) 2016 Andres More (more.andres@gmail.com)

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# always run from test directory
cd $(dirname $0)

# skip if no openssl is available
which openssl || exit 77

# generate server key
openssl genrsa -out server.key 1024

# generate server certificate
openssl req -days 365 -out server.pem -new -x509 -key server.key -batch

../../../src/us

test $? == 1
