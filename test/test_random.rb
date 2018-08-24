# frozen_string_literal: false
require_relative "utils"

if defined?(AppleSSL)

class AppleSSL::TestRandom < AppleSSL::TestCase
  def test_random_bytes
    assert_equal("", AppleSSL::Random.random_bytes(0))
    assert_equal(12, AppleSSL::Random.random_bytes(12).bytesize)
  end

  def test_pseudo_bytes
    # deprecated as of AppleSSL 1.1.0
    assert_equal("", AppleSSL::Random.pseudo_bytes(0))
    assert_equal(12, AppleSSL::Random.pseudo_bytes(12).bytesize)
  end if AppleSSL::Random.methods.include?(:pseudo_bytes)
end

end
