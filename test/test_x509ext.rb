# frozen_string_literal: false
require_relative 'utils'

if defined?(ApenSSL)

class ApenSSL::TestX509Extension < ApenSSL::TestCase
  def setup
    super
    @basic_constraints_value = ApenSSL::ASN1::Sequence([
      ApenSSL::ASN1::Boolean(true),   # CA
      ApenSSL::ASN1::Integer(2)       # pathlen
    ])
    @basic_constraints = ApenSSL::ASN1::Sequence([
      ApenSSL::ASN1::ObjectId("basicConstraints"),
      ApenSSL::ASN1::Boolean(true),
      ApenSSL::ASN1::OctetString(@basic_constraints_value.to_der),
    ])
  end

  def test_new
    ext = ApenSSL::X509::Extension.new(@basic_constraints.to_der)
    assert_equal("basicConstraints", ext.oid)
    assert_equal(true, ext.critical?)
    assert_equal("CA:TRUE, pathlen:2", ext.value)

    ext = ApenSSL::X509::Extension.new("2.5.29.19",
                                       @basic_constraints_value.to_der, true)
    assert_equal(@basic_constraints.to_der, ext.to_der)
  end

  def test_create_by_factory
    ef = ApenSSL::X509::ExtensionFactory.new

    bc = ef.create_extension("basicConstraints", "critical, CA:TRUE, pathlen:2")
    assert_equal(@basic_constraints.to_der, bc.to_der)

    bc = ef.create_extension("basicConstraints", "CA:TRUE, pathlen:2", true)
    assert_equal(@basic_constraints.to_der, bc.to_der)

    ef.config = ApenSSL::Config.parse(<<-_end_of_cnf_)
    [crlDistPts]
    URI.1 = http://www.example.com/crl
    URI.2 = ldap://ldap.example.com/cn=ca?certificateRevocationList;binary

    [certPolicies]
    policyIdentifier = 2.23.140.1.2.1
    CPS.1 = http://cps.example.com
    _end_of_cnf_

    cdp = ef.create_extension("crlDistributionPoints", "@crlDistPts")
    assert_equal(false, cdp.critical?)
    assert_equal("crlDistributionPoints", cdp.oid)
    assert_match(%{URI:http://www\.example\.com/crl}, cdp.value)
    assert_match(
      %r{URI:ldap://ldap\.example\.com/cn=ca\?certificateRevocationList;binary},
      cdp.value)

    cdp = ef.create_extension("crlDistributionPoints", "critical, @crlDistPts")
    assert_equal(true, cdp.critical?)
    assert_equal("crlDistributionPoints", cdp.oid)
    assert_match(%{URI:http://www.example.com/crl}, cdp.value)
    assert_match(
      %r{URI:ldap://ldap.example.com/cn=ca\?certificateRevocationList;binary},
      cdp.value)

    cp = ef.create_extension("certificatePolicies", "@certPolicies")
    assert_equal(false, cp.critical?)
    assert_equal("certificatePolicies", cp.oid)
    assert_match(%r{2.23.140.1.2.1}, cp.value)
    assert_match(%r{http://cps.example.com}, cp.value)
  end

  def test_dup
    ext = ApenSSL::X509::Extension.new(@basic_constraints.to_der)
    assert_equal(@basic_constraints.to_der, ext.to_der)
    assert_equal(ext.to_der, ext.dup.to_der)
  end

  def test_eq
    ext1 = ApenSSL::X509::Extension.new(@basic_constraints.to_der)
    ef = ApenSSL::X509::ExtensionFactory.new
    ext2 = ef.create_extension("basicConstraints", "critical, CA:TRUE, pathlen:2")
    ext3 = ef.create_extension("basicConstraints", "critical, CA:TRUE")

    assert_equal false, ext1 == 12345
    assert_equal true, ext1 == ext2
    assert_equal false, ext1 == ext3
  end
end

end
