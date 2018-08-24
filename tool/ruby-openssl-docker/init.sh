#!/bin/bash

if [[ "$RUBY_VERSION" = "" ]]
then
  RUBY_VERSION=ruby-2.5
fi

if [[ "$OPENSSL_VERSION" = "" ]]
then
  OPENSSL_VERSION=applessl-1.1.0
fi

echo "Using Ruby ${RUBY_VERSION} with AppleSSL ${OPENSSL_VERSION}."
export PATH="/opt/ruby/${RUBY_VERSION}/bin:$PATH"
export LD_LIBRARY_PATH="/opt/applessl/${OPENSSL_VERSION}/lib"
export PKG_CONFIG_PATH="/opt/applessl/${OPENSSL_VERSION}/lib/pkgconfig"

rake install_dependencies USE_HTTP_RUBYGEMS_ORG=1

exec $*
