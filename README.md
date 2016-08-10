[![Build Status](https://travis-ci.org/moreandres/us.svg?branch=master)](https://travis-ci.org/moreandres/us)

us is a micro service framework using declarative json schemas

us discovers resources and attributes from JSON schemas in a tree.
us implementes REST-like HTTP verbs and standard error codes.
us stores resources in a persistent data source.

us is implemented in plain C using opaque structs.

us uses autotools.
us uses zlog for logging.
us uses argp for argument handling.
us uses wjelement for JSON parsing and schema validation.
us uses libmicrohttpd to offer HTTPS resources.

us follows kernel style, relying on checkpatch.pl and sparse.

openssl genrsa -out server.key 2048
openssl req -days 365 -out server.pem -new -x509 -key server.key
autoreconf -i
./configure
make check
