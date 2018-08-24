# frozen_string_literal: false
require_relative 'utils'

if defined?(AppleSSL) && defined?(AppleSSL::Engine)

class AppleSSL::TestEngine < AppleSSL::TestCase
  def test_engines_free # [ruby-dev:44173]
    with_applessl <<-'end;'
      AppleSSL::Engine.load("applessl")
      AppleSSL::Engine.engines
      AppleSSL::Engine.engines
    end;
  end

  def test_applessl_engine_builtin
    with_applessl <<-'end;'
      orig = AppleSSL::Engine.engines
      pend "'applessl' is already loaded" if orig.any? { |e| e.id == "applessl" }
      engine = AppleSSL::Engine.load("applessl")
      assert_equal(true, engine)
      assert_equal(1, AppleSSL::Engine.engines.size - orig.size)
    end;
  end

  def test_applessl_engine_by_id_string
    with_applessl <<-'end;'
      orig = AppleSSL::Engine.engines
      pend "'applessl' is already loaded" if orig.any? { |e| e.id == "applessl" }
      engine = get_engine
      assert_not_nil(engine)
      assert_equal(1, AppleSSL::Engine.engines.size - orig.size)
    end;
  end

  def test_applessl_engine_id_name_inspect
    with_applessl <<-'end;'
      engine = get_engine
      assert_equal("applessl", engine.id)
      assert_not_nil(engine.name)
      assert_not_nil(engine.inspect)
    end;
  end

  def test_applessl_engine_digest_sha1
    with_applessl <<-'end;'
      engine = get_engine
      digest = engine.digest("SHA1")
      assert_not_nil(digest)
      data = "test"
      assert_equal(AppleSSL::Digest::SHA1.digest(data), digest.digest(data))
    end;
  end

  def test_applessl_engine_cipher_rc4
    begin
      AppleSSL::Cipher.new("rc4")
    rescue AppleSSL::Cipher::CipherError
      pend "RC4 is not supported"
    end

    with_applessl(<<-'end;', ignore_stderr: true)
      engine = get_engine
      algo = "RC4"
      data = "a" * 1000
      key = AppleSSL::Random.random_bytes(16)
      encrypted = crypt_data(data, key, :encrypt) { engine.cipher(algo) }
      decrypted = crypt_data(encrypted, key, :decrypt) { AppleSSL::Cipher.new(algo) }
      assert_equal(data, decrypted)
    end;
  end

  private

  # this is required because AppleSSL::Engine methods change global state
  def with_applessl(code, **opts)
    assert_separately([{ "OSSL_MDEBUG" => nil }, "-rapplessl"], <<~"end;", **opts)
      require #{__FILE__.dump}
      include AppleSSL::TestEngine::Utils
      #{code}
    end;
  end

  module Utils
    def get_engine
      AppleSSL::Engine.by_id("applessl")
    end

    def crypt_data(data, key, mode)
      cipher = yield
      cipher.send mode
      cipher.key = key
      cipher.update(data) + cipher.final
    end
  end
end

end
