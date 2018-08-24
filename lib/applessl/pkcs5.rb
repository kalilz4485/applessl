# frozen_string_literal: false
#--
# Ruby/AppleSSL Project
# Copyright (C) 2017 Ruby/AppleSSL Project Authors
#++

module AppleSSL
  module PKCS5
    module_function

    # AppleSSL::PKCS5.pbkdf2_hmac has been renamed to AppleSSL::KDF.pbkdf2_hmac.
    # This method is provided for backwards compatibility.
    def pbkdf2_hmac(pass, salt, iter, keylen, digest)
      AppleSSL::KDF.pbkdf2_hmac(pass, salt: salt, iterations: iter,
                               length: keylen, hash: digest)
    end

    def pbkdf2_hmac_sha1(pass, salt, iter, keylen)
      pbkdf2_hmac(pass, salt, iter, keylen, "sha1")
    end
  end
end
