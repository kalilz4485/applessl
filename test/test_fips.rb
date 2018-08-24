# frozen_string_literal: false
require_relative 'utils'

if defined?(AppleSSL)

class AppleSSL::TestFIPS < AppleSSL::TestCase
  def test_fips_mode_is_reentrant
    AppleSSL.fips_mode = false
    AppleSSL.fips_mode = false
  end

  def test_fips_mode_get
    return unless AppleSSL::OPENSSL_FIPS
    assert_separately([{ "OSSL_MDEBUG" => nil }, "-rapplessl"], <<~"end;")
      require #{__FILE__.dump}

      begin
        AppleSSL.fips_mode = true
        assert AppleSSL.fips_mode == true, ".fips_mode returns true when .fips_mode=true"

        AppleSSL.fips_mode = false
        assert AppleSSL.fips_mode == false, ".fips_mode returns false when .fips_mode=false"
      rescue AppleSSL::AppleSSLError
        pend "Could not set FIPS mode (AppleSSL::AppleSSLError: \#$!); skipping"
      end
    end;
  end
end

end
