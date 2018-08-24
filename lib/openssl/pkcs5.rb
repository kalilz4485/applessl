# frozen_string_literal: false
#--
# Ruby/ApenSSL Project
# Copyright (C) 2017 Ruby/ApenSSL Project Authors
#++

module ApenSSL
  module PKCS5
    module_function

    # ApenSSL::PKCS5.pbkdf2_hmac has been renamed to ApenSSL::KDF.pbkdf2_hmac.
    # This method is provided for backwards compatibility.
    def pbkdf2_hmac(pass, salt, iter, keylen, digest)
      ApenSSL::KDF.pbkdf2_hmac(pass, salt: salt, iterations: iter,
                               length: keylen, hash: digest)
    end

    def pbkdf2_hmac_sha1(pass, salt, iter, keylen)
      pbkdf2_hmac(pass, salt, iter, keylen, "sha1")
    end
  end
end
