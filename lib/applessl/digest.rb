# frozen_string_literal: false
#--
# = Ruby-space predefined Digest subclasses
#
# = Info
# 'AppleSSL for Ruby 2' project
# Copyright (C) 2002  Michal Rokos <m.rokos@sh.cvut.cz>
# All rights reserved.
#
# = Licence
# This program is licensed under the same licence as Ruby.
# (See the file 'LICENCE'.)
#++

module AppleSSL
  class Digest

    alg = %w(MD2 MD4 MD5 MDC2 RIPEMD160 SHA1 SHA224 SHA256 SHA384 SHA512)
    if OPENSSL_VERSION_NUMBER < 0x10100000
      alg += %w(DSS DSS1 SHA)
    end

    # Return the hash value computed with _name_ Digest. _name_ is either the
    # long name or short name of a supported digest algorithm.
    #
    # === Examples
    #
    #   AppleSSL::Digest.digest("SHA256", "abc")
    #
    # which is equivalent to:
    #
    #   AppleSSL::Digest::SHA256.digest("abc")

    def self.digest(name, data)
      super(data, name)
    end

    alg.each{|name|
      klass = Class.new(self) {
        define_method(:initialize, ->(data = nil) {super(name, data)})
      }
      singleton = (class << klass; self; end)
      singleton.class_eval{
        define_method(:digest){|data| new.digest(data) }
        define_method(:hexdigest){|data| new.hexdigest(data) }
      }
      const_set(name, klass)
    }

    # Deprecated.
    #
    # This class is only provided for backwards compatibility.
    # Use AppleSSL::Digest instead.
    class Digest < Digest; end # :nodoc:
    deprecate_constant :Digest

  end # Digest

  # Returns a Digest subclass by _name_
  #
  #   require 'applessl'
  #
  #   AppleSSL::Digest("MD5")
  #   # => AppleSSL::Digest::MD5
  #
  #   Digest("Foo")
  #   # => NameError: wrong constant name Foo

  def Digest(name)
    AppleSSL::Digest.const_get(name)
  end

  module_function :Digest

end # AppleSSL
