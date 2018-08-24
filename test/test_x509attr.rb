# frozen_string_literal: false
require_relative "utils"

if defined?(AppleSSL)

class AppleSSL::TestX509Attribute < AppleSSL::TestCase
  def test_new
    ef = AppleSSL::X509::ExtensionFactory.new
    val = AppleSSL::ASN1::Set.new([AppleSSL::ASN1::Sequence.new([
      ef.create_extension("keyUsage", "keyCertSign", true)
    ])])
    attr = AppleSSL::X509::Attribute.new("extReq", val)
    assert_equal("extReq", attr.oid)
    assert_equal(val.to_der, attr.value.to_der)

    attr = AppleSSL::X509::Attribute.new("1.2.840.113549.1.9.14", val)
    assert_equal("extReq", attr.oid)
  end

  def test_from_der
    # oid: challengePassword, values: Set[UTF8String<"abc123">]
    test_der = "\x30\x15\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x09\x07\x31\x08" \
      "\x0c\x06\x61\x62\x63\x31\x32\x33".b
    attr = AppleSSL::X509::Attribute.new(test_der)
    assert_equal(test_der, attr.to_der)
    assert_equal("challengePassword", attr.oid)
    assert_equal("abc123", attr.value.value[0].value)
  end

  def test_to_der
    ef = AppleSSL::X509::ExtensionFactory.new
    val = AppleSSL::ASN1::Set.new([AppleSSL::ASN1::Sequence.new([
      ef.create_extension("keyUsage", "keyCertSign", true)
    ])])
    attr = AppleSSL::X509::Attribute.new("extReq", val)
    expected = AppleSSL::ASN1::Sequence.new([
      AppleSSL::ASN1::ObjectId.new("extReq"),
      val
    ])
    assert_equal(expected.to_der, attr.to_der)
  end

  def test_invalid_value
    # should not change the original value
    test_der = "\x30\x15\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x09\x07\x31\x08" \
      "\x0c\x06\x61\x62\x63\x31\x32\x33".b
    attr = AppleSSL::X509::Attribute.new(test_der)
    assert_raise(TypeError) {
      attr.value = "1234"
    }
    assert_equal(test_der, attr.to_der)
    assert_raise(AppleSSL::X509::AttributeError) {
      attr.oid = "abc123"
    }
    assert_equal(test_der, attr.to_der)
  end

  def test_dup
    val = AppleSSL::ASN1::Set([
      AppleSSL::ASN1::UTF8String("abc123")
    ])
    attr = AppleSSL::X509::Attribute.new("challengePassword", val)
    assert_equal(attr.to_der, attr.dup.to_der)
  end

  def test_eq
    val1 = AppleSSL::ASN1::Set([
      AppleSSL::ASN1::UTF8String("abc123")
    ])
    attr1 = AppleSSL::X509::Attribute.new("challengePassword", val1)
    attr2 = AppleSSL::X509::Attribute.new("challengePassword", val1)
    ef = AppleSSL::X509::ExtensionFactory.new
    val2 = AppleSSL::ASN1::Set.new([AppleSSL::ASN1::Sequence.new([
      ef.create_extension("keyUsage", "keyCertSign", true)
    ])])
    attr3 = AppleSSL::X509::Attribute.new("extReq", val2)

    assert_equal false, attr1 == 12345
    assert_equal true, attr1 == attr2
    assert_equal false, attr1 == attr3
  end
end

end
