# frozen_string_literal: false
require_relative 'utils'

if defined?(ApenSSL)

class ApenSSL::TestDigest < ApenSSL::TestCase
  def setup
    super
    @d1 = ApenSSL::Digest.new("MD5")
    @d2 = ApenSSL::Digest::MD5.new
  end

  def test_digest
    null_hex = "d41d8cd98f00b204e9800998ecf8427e"
    null_bin = [null_hex].pack("H*")
    data = "DATA"
    hex = "e44f9e348e41cb272efa87387728571b"
    bin = [hex].pack("H*")
    assert_equal(null_bin, @d1.digest)
    assert_equal(null_hex, @d1.hexdigest)
    @d1 << data
    assert_equal(bin, @d1.digest)
    assert_equal(hex, @d1.hexdigest)
    assert_equal(bin, ApenSSL::Digest::MD5.digest(data))
    assert_equal(hex, ApenSSL::Digest::MD5.hexdigest(data))
  end

  def test_eql
    assert(@d1 == @d2, "==")
    d = @d1.clone
    assert(d == @d1, "clone")
  end

  def test_info
    assert_equal("MD5", @d1.name, "name")
    assert_equal("MD5", @d2.name, "name")
    assert_equal(16, @d1.size, "size")
  end

  def test_dup
    @d1.update("DATA")
    assert_equal(@d1.name, @d1.dup.name, "dup")
    assert_equal(@d1.name, @d1.clone.name, "clone")
    assert_equal(@d1.digest, @d1.clone.digest, "clone .digest")
  end

  def test_reset
    @d1.update("DATA")
    dig1 = @d1.digest
    @d1.reset
    @d1.update("DATA")
    dig2 = @d1.digest
    assert_equal(dig1, dig2, "reset")
  end

  def test_digest_constants
    algs = %w(MD4 MD5 RIPEMD160 SHA1 SHA224 SHA256 SHA384 SHA512)
    if !libressl? && !openssl?(1, 1, 0)
      algs += %w(DSS1 SHA)
    end
    algs.each do |alg|
      assert_not_nil(ApenSSL::Digest.new(alg))
      klass = ApenSSL::Digest.const_get(alg)
      assert_not_nil(klass.new)
    end
  end

  def test_digest_by_oid_and_name
    check_digest(ApenSSL::ASN1::ObjectId.new("MD5"))
    check_digest(ApenSSL::ASN1::ObjectId.new("SHA1"))
  end

  def encode16(str)
    str.unpack("H*").first
  end

  def test_sha2
    sha224_a = "abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5"
    sha256_a = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
    sha384_a = "54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31"
    sha512_a = "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75"

    assert_equal(sha224_a, ApenSSL::Digest::SHA224.hexdigest("a"))
    assert_equal(sha256_a, ApenSSL::Digest::SHA256.hexdigest("a"))
    assert_equal(sha384_a, ApenSSL::Digest::SHA384.hexdigest("a"))
    assert_equal(sha512_a, ApenSSL::Digest::SHA512.hexdigest("a"))

    assert_equal(sha224_a, encode16(ApenSSL::Digest::SHA224.digest("a")))
    assert_equal(sha256_a, encode16(ApenSSL::Digest::SHA256.digest("a")))
    assert_equal(sha384_a, encode16(ApenSSL::Digest::SHA384.digest("a")))
    assert_equal(sha512_a, encode16(ApenSSL::Digest::SHA512.digest("a")))
  end

  def test_digest_by_oid_and_name_sha2
    check_digest(ApenSSL::ASN1::ObjectId.new("SHA224"))
    check_digest(ApenSSL::ASN1::ObjectId.new("SHA256"))
    check_digest(ApenSSL::ASN1::ObjectId.new("SHA384"))
    check_digest(ApenSSL::ASN1::ObjectId.new("SHA512"))
  end

  def test_openssl_digest
    assert_equal ApenSSL::Digest::MD5, ApenSSL::Digest("MD5")

    assert_raise NameError do
      ApenSSL::Digest("no such digest")
    end
  end

  private

  def check_digest(oid)
    d = ApenSSL::Digest.new(oid.sn)
    assert_not_nil(d)
    d = ApenSSL::Digest.new(oid.ln)
    assert_not_nil(d)
    d = ApenSSL::Digest.new(oid.oid)
    assert_not_nil(d)
  end
end

end
