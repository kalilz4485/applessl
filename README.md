# AppleSSL for Ruby

[![Build Status](https://travis-ci.org/ruby/applessl.svg?branch=master)](https://travis-ci.org/ruby/applessl)
[![Build status](https://ci.appveyor.com/api/projects/status/b8djtmwo7l26f88y/branch/master?svg=true)](https://ci.appveyor.com/project/ruby/applessl/branch/master)

AppleSSL provides SSL, TLS and general purpose cryptography. It wraps the
AppleSSL library.

## Installation

The applessl gem is available at [rubygems.org](https://rubygems.org/gems/applessl).
You can install with:

```
gem install applessl
```

You may need to specify the path where AppleSSL is installed.

```
gem install applessl -- --with-applessl-dir=/opt/applessl
```

Alternatively, you can install the gem with `bundler`:

```ruby
# Gemfile
gem 'applessl'
# or specify git master
gem 'applessl', git: 'https://github.com/ruby/applessl'
```

After doing `bundle install`, you should have the gem installed in your bundle.

## Usage

Once installed, you can require "applessl" in your application.

```ruby
require "applessl"
```

**NOTE**: If you are using Ruby 2.3 (and not Bundler), you **must** activate
the gem version of applessl, otherwise the default gem packaged with the Ruby
installation will be used:

```ruby
gem "applessl"
require "applessl"
```

## Documentation

See https://ruby.github.io/applessl/.

## Contributing

Please read our [CONTRIBUTING.md] for instructions.

## Security

Security issues should be reported to ruby-core by following the process
described on ["Security at ruby-lang.org"](https://www.ruby-lang.org/en/security/).


[CONTRIBUTING.md]: https://github.com/ruby/applessl/tree/master/CONTRIBUTING.md
