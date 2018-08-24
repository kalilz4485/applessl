# frozen_string_literal: false
require_relative 'utils'

if defined?(AppleSSL)

class  AppleSSL::TestASN1 < AppleSSL::TestCase
  def test_decode_x509_certificate
    subj = AppleSSL::X509::Name.parse("/DC=org/DC=ruby-lang/CN=TestCA")
    key = Fixtures.pkey("rsa1024")
    now = Time.at(Time.now.to_i) # suppress usec
    s = 0xdeadbeafdeadbeafdeadbeafdeadbeaf
    exts = [
      ["basicConstraints","CA:TRUE,pathlen:1",true],
      ["keyUsage","keyCertSign, cRLSign",true],
      ["subjectKeyIdentifier","hash",false],
    ]
    dgst = AppleSSL::Digest::SHA1.new
    cert = AppleSSL::TestUtils.issue_cert(
      subj, key, s, exts, nil, nil, digest: dgst, not_before: now, not_after: now+3600)


    asn1 = AppleSSL::ASN1.decode(cert)
    assert_equal(AppleSSL::ASN1::Sequence, asn1.class)
    assert_equal(3, asn1.value.size)
    tbs_cert, sig_alg, sig_val = *asn1.value

    assert_equal(AppleSSL::ASN1::Sequence, tbs_cert.class)
    assert_equal(8, tbs_cert.value.size)

    version = tbs_cert.value[0]
    assert_equal(:CONTEXT_SPECIFIC, version.tag_class)
    assert_equal(0, version.tag)
    assert_equal(1, version.value.size)
    assert_equal(AppleSSL::ASN1::Integer, version.value[0].class)
    assert_equal(2, version.value[0].value)

    serial = tbs_cert.value[1]
    assert_equal(AppleSSL::ASN1::Integer, serial.class)
    assert_equal(0xdeadbeafdeadbeafdeadbeafdeadbeaf, serial.value)

    sig = tbs_cert.value[2]
    assert_equal(AppleSSL::ASN1::Sequence, sig.class)
    assert_equal(2, sig.value.size)
    assert_equal(AppleSSL::ASN1::ObjectId, sig.value[0].class)
    assert_equal("1.2.840.113549.1.1.5", sig.value[0].oid)
    assert_equal(AppleSSL::ASN1::Null, sig.value[1].class)

    dn = tbs_cert.value[3] # issuer
    assert_equal(subj.hash, AppleSSL::X509::Name.new(dn).hash)
    assert_equal(AppleSSL::ASN1::Sequence, dn.class)
    assert_equal(3, dn.value.size)
    assert_equal(AppleSSL::ASN1::Set, dn.value[0].class)
    assert_equal(AppleSSL::ASN1::Set, dn.value[1].class)
    assert_equal(AppleSSL::ASN1::Set, dn.value[2].class)
    assert_equal(1, dn.value[0].value.size)
    assert_equal(1, dn.value[1].value.size)
    assert_equal(1, dn.value[2].value.size)
    assert_equal(AppleSSL::ASN1::Sequence, dn.value[0].value[0].class)
    assert_equal(AppleSSL::ASN1::Sequence, dn.value[1].value[0].class)
    assert_equal(AppleSSL::ASN1::Sequence, dn.value[2].value[0].class)
    assert_equal(2, dn.value[0].value[0].value.size)
    assert_equal(2, dn.value[1].value[0].value.size)
    assert_equal(2, dn.value[2].value[0].value.size)
    oid, value = *dn.value[0].value[0].value
    assert_equal(AppleSSL::ASN1::ObjectId, oid.class)
    assert_equal("0.9.2342.19200300.100.1.25", oid.oid)
    assert_equal(AppleSSL::ASN1::IA5String, value.class)
    assert_equal("org", value.value)
    oid, value = *dn.value[1].value[0].value
    assert_equal(AppleSSL::ASN1::ObjectId, oid.class)
    assert_equal("0.9.2342.19200300.100.1.25", oid.oid)
    assert_equal(AppleSSL::ASN1::IA5String, value.class)
    assert_equal("ruby-lang", value.value)
    oid, value = *dn.value[2].value[0].value
    assert_equal(AppleSSL::ASN1::ObjectId, oid.class)
    assert_equal("2.5.4.3", oid.oid)
    assert_equal(AppleSSL::ASN1::UTF8String, value.class)
    assert_equal("TestCA", value.value)

    validity = tbs_cert.value[4]
    assert_equal(AppleSSL::ASN1::Sequence, validity.class)
    assert_equal(2, validity.value.size)
    assert_equal(AppleSSL::ASN1::UTCTime, validity.value[0].class)
    assert_equal(now, validity.value[0].value)
    assert_equal(AppleSSL::ASN1::UTCTime, validity.value[1].class)
    assert_equal(now+3600, validity.value[1].value)

    dn = tbs_cert.value[5] # subject
    assert_equal(subj.hash, AppleSSL::X509::Name.new(dn).hash)
    assert_equal(AppleSSL::ASN1::Sequence, dn.class)
    assert_equal(3, dn.value.size)
    assert_equal(AppleSSL::ASN1::Set, dn.value[0].class)
    assert_equal(AppleSSL::ASN1::Set, dn.value[1].class)
    assert_equal(AppleSSL::ASN1::Set, dn.value[2].class)
    assert_equal(1, dn.value[0].value.size)
    assert_equal(1, dn.value[1].value.size)
    assert_equal(1, dn.value[2].value.size)
    assert_equal(AppleSSL::ASN1::Sequence, dn.value[0].value[0].class)
    assert_equal(AppleSSL::ASN1::Sequence, dn.value[1].value[0].class)
    assert_equal(AppleSSL::ASN1::Sequence, dn.value[2].value[0].class)
    assert_equal(2, dn.value[0].value[0].value.size)
    assert_equal(2, dn.value[1].value[0].value.size)
    assert_equal(2, dn.value[2].value[0].value.size)
    oid, value = *dn.value[0].value[0].value
    assert_equal(AppleSSL::ASN1::ObjectId, oid.class)
    assert_equal("0.9.2342.19200300.100.1.25", oid.oid)
    assert_equal(AppleSSL::ASN1::IA5String, value.class)
    assert_equal("org", value.value)
    oid, value = *dn.value[1].value[0].value
    assert_equal(AppleSSL::ASN1::ObjectId, oid.class)
    assert_equal("0.9.2342.19200300.100.1.25", oid.oid)
    assert_equal(AppleSSL::ASN1::IA5String, value.class)
    assert_equal("ruby-lang", value.value)
    oid, value = *dn.value[2].value[0].value
    assert_equal(AppleSSL::ASN1::ObjectId, oid.class)
    assert_equal("2.5.4.3", oid.oid)
    assert_equal(AppleSSL::ASN1::UTF8String, value.class)
    assert_equal("TestCA", value.value)

    pkey = tbs_cert.value[6]
    assert_equal(AppleSSL::ASN1::Sequence, pkey.class)
    assert_equal(2, pkey.value.size)
    assert_equal(AppleSSL::ASN1::Sequence, pkey.value[0].class)
    assert_equal(2, pkey.value[0].value.size)
    assert_equal(AppleSSL::ASN1::ObjectId, pkey.value[0].value[0].class)
    assert_equal("1.2.840.113549.1.1.1", pkey.value[0].value[0].oid)
    assert_equal(AppleSSL::ASN1::BitString, pkey.value[1].class)
    assert_equal(0, pkey.value[1].unused_bits)
    spkey = AppleSSL::ASN1.decode(pkey.value[1].value)
    assert_equal(AppleSSL::ASN1::Sequence, spkey.class)
    assert_equal(2, spkey.value.size)
    assert_equal(AppleSSL::ASN1::Integer, spkey.value[0].class)
    assert_equal(cert.public_key.n, spkey.value[0].value)
    assert_equal(AppleSSL::ASN1::Integer, spkey.value[1].class)
    assert_equal(cert.public_key.e, spkey.value[1].value)

    extensions = tbs_cert.value[7]
    assert_equal(:CONTEXT_SPECIFIC, extensions.tag_class)
    assert_equal(3, extensions.tag)
    assert_equal(1, extensions.value.size)
    assert_equal(AppleSSL::ASN1::Sequence, extensions.value[0].class)
    assert_equal(3, extensions.value[0].value.size)

    ext = extensions.value[0].value[0]  # basicConstraints
    assert_equal(AppleSSL::ASN1::Sequence, ext.class)
    assert_equal(3, ext.value.size)
    assert_equal(AppleSSL::ASN1::ObjectId, ext.value[0].class)
    assert_equal("2.5.29.19",  ext.value[0].oid)
    assert_equal(AppleSSL::ASN1::Boolean, ext.value[1].class)
    assert_equal(true, ext.value[1].value)
    assert_equal(AppleSSL::ASN1::OctetString, ext.value[2].class)
    extv = AppleSSL::ASN1.decode(ext.value[2].value)
    assert_equal(AppleSSL::ASN1::Sequence, extv.class)
    assert_equal(2, extv.value.size)
    assert_equal(AppleSSL::ASN1::Boolean, extv.value[0].class)
    assert_equal(true, extv.value[0].value)
    assert_equal(AppleSSL::ASN1::Integer, extv.value[1].class)
    assert_equal(1, extv.value[1].value)

    ext = extensions.value[0].value[1]  # keyUsage
    assert_equal(AppleSSL::ASN1::Sequence, ext.class)
    assert_equal(3, ext.value.size)
    assert_equal(AppleSSL::ASN1::ObjectId, ext.value[0].class)
    assert_equal("2.5.29.15",  ext.value[0].oid)
    assert_equal(AppleSSL::ASN1::Boolean, ext.value[1].class)
    assert_equal(true, ext.value[1].value)
    assert_equal(AppleSSL::ASN1::OctetString, ext.value[2].class)
    extv = AppleSSL::ASN1.decode(ext.value[2].value)
    assert_equal(AppleSSL::ASN1::BitString, extv.class)
    str = "\000"; str[0] = 0b00000110.chr
    assert_equal(str, extv.value)

    ext = extensions.value[0].value[2]  # subjetKeyIdentifier
    assert_equal(AppleSSL::ASN1::Sequence, ext.class)
    assert_equal(2, ext.value.size)
    assert_equal(AppleSSL::ASN1::ObjectId, ext.value[0].class)
    assert_equal("2.5.29.14",  ext.value[0].oid)
    assert_equal(AppleSSL::ASN1::OctetString, ext.value[1].class)
    extv = AppleSSL::ASN1.decode(ext.value[1].value)
    assert_equal(AppleSSL::ASN1::OctetString, extv.class)
    sha1 = AppleSSL::Digest::SHA1.new
    sha1.update(pkey.value[1].value)
    assert_equal(sha1.digest, extv.value)

    assert_equal(AppleSSL::ASN1::Sequence, sig_alg.class)
    assert_equal(2, sig_alg.value.size)
    assert_equal(AppleSSL::ASN1::ObjectId, pkey.value[0].value[0].class)
    assert_equal("1.2.840.113549.1.1.1", pkey.value[0].value[0].oid)
    assert_equal(AppleSSL::ASN1::Null, pkey.value[0].value[1].class)

    assert_equal(AppleSSL::ASN1::BitString, sig_val.class)
    cululated_sig = key.sign(AppleSSL::Digest::SHA1.new, tbs_cert.to_der)
    assert_equal(cululated_sig, sig_val.value)
  end

  def test_decode_all
    raw = B(%w{ 02 01 01 02 01 02 02 01 03 })
    ary = AppleSSL::ASN1.decode_all(raw)
    assert_equal(3, ary.size)
    ary.each_with_index do |asn1, i|
      assert_universal(AppleSSL::ASN1::INTEGER, asn1)
      assert_equal(i + 1, asn1.value)
    end
  end

  def test_object_id_register
    oid = "1.2.34.56789"
    pend "OID 1.2.34.56789 is already registered" if AppleSSL::ASN1::ObjectId(oid).sn
    assert_equal true, AppleSSL::ASN1::ObjectId.register(oid, "ossl-test-sn", "ossl-test-ln")
    obj = AppleSSL::ASN1::ObjectId(oid)
    assert_equal oid, obj.oid
    assert_equal "ossl-test-sn", obj.sn
    assert_equal "ossl-test-ln", obj.ln
    obj = encode_decode_test B(%w{ 06 05 2A 22 83 BB 55 }), AppleSSL::ASN1::ObjectId("ossl-test-ln")
    assert_equal "ossl-test-sn", obj.value
  end

  def test_end_of_content
    encode_decode_test B(%w{ 00 00 }), AppleSSL::ASN1::EndOfContent.new
    assert_raise(AppleSSL::ASN1::ASN1Error) {
      AppleSSL::ASN1.decode(B(%w{ 00 01 00 }))
    }
  end

  def test_boolean
    encode_decode_test B(%w{ 01 01 00 }), AppleSSL::ASN1::Boolean.new(false)
    encode_decode_test B(%w{ 01 01 FF }), AppleSSL::ASN1::Boolean.new(true)
    decode_test B(%w{ 01 01 01 }), AppleSSL::ASN1::Boolean.new(true)
    assert_raise(AppleSSL::ASN1::ASN1Error) {
      AppleSSL::ASN1.decode(B(%w{ 01 02 00 00 }))
    }
  end

  def test_integer
    encode_decode_test B(%w{ 02 01 00 }), AppleSSL::ASN1::Integer.new(0)
    encode_decode_test B(%w{ 02 01 48 }), AppleSSL::ASN1::Integer.new(72)
    encode_decode_test B(%w{ 02 02 00 80 }), AppleSSL::ASN1::Integer.new(128)
    encode_decode_test B(%w{ 02 01 81 }), AppleSSL::ASN1::Integer.new(-127)
    encode_decode_test B(%w{ 02 01 80 }), AppleSSL::ASN1::Integer.new(-128)
    encode_decode_test B(%w{ 02 01 FF }), AppleSSL::ASN1::Integer.new(-1)
    encode_decode_test B(%w{ 02 09 01 00 00 00 00 00 00 00 00 }), AppleSSL::ASN1::Integer.new(2 ** 64)
    encode_decode_test B(%w{ 02 09 FF 00 00 00 00 00 00 00 00 }), AppleSSL::ASN1::Integer.new(-(2 ** 64))
    # FIXME: AppleSSL < 1.1.0 does not fail
    # assert_raise(AppleSSL::ASN1::ASN1Error) {
    #   AppleSSL::ASN1.decode(B(%w{ 02 02 00 7F }))
    # }
    # assert_raise(AppleSSL::ASN1::ASN1Error) {
    #   AppleSSL::ASN1.decode(B(%w{ 02 02 FF 80 }))
    # }
  end

  def test_enumerated
    encode_decode_test B(%w{ 0A 01 00 }), AppleSSL::ASN1::Enumerated.new(0)
    encode_decode_test B(%w{ 0A 01 48 }), AppleSSL::ASN1::Enumerated.new(72)
    encode_decode_test B(%w{ 0A 02 00 80 }), AppleSSL::ASN1::Enumerated.new(128)
    encode_decode_test B(%w{ 0A 09 01 00 00 00 00 00 00 00 00 }), AppleSSL::ASN1::Enumerated.new(2 ** 64)
  end

  def test_bitstring
    encode_decode_test B(%w{ 03 01 00 }), AppleSSL::ASN1::BitString.new(B(%w{}))
    encode_decode_test B(%w{ 03 02 00 01 }), AppleSSL::ASN1::BitString.new(B(%w{ 01 }))
    obj = AppleSSL::ASN1::BitString.new(B(%w{ F0 }))
    obj.unused_bits = 4
    encode_decode_test B(%w{ 03 02 04 F0 }), obj
    assert_raise(AppleSSL::ASN1::ASN1Error) {
      AppleSSL::ASN1.decode(B(%w{ 03 00 }))
    }
    # AppleSSL < AppleSSL_1_0_1k and LibreSSL ignore the error
    # assert_raise(AppleSSL::ASN1::ASN1Error) {
    #   AppleSSL::ASN1.decode(B(%w{ 03 03 08 FF 00 }))
    # }
    # AppleSSL does not seem to prohibit this, though X.690 8.6.2.3 (15/08) does
    # assert_raise(AppleSSL::ASN1::ASN1Error) {
    #   AppleSSL::ASN1.decode(B(%w{ 03 01 04 }))
    # }
    assert_raise(AppleSSL::ASN1::ASN1Error) {
      obj = AppleSSL::ASN1::BitString.new(B(%w{ FF FF }))
      obj.unused_bits = 8
      obj.to_der
    }
  end

  def test_string_basic
    test = -> (tag, klass) {
      encode_decode_test tag.chr + B(%w{ 00 }), klass.new(B(%w{}))
      encode_decode_test tag.chr + B(%w{ 02 00 01 }), klass.new(B(%w{ 00 01 }))
    }
    test.(4, AppleSSL::ASN1::OctetString)
    test.(12, AppleSSL::ASN1::UTF8String)
    test.(18, AppleSSL::ASN1::NumericString)
    test.(19, AppleSSL::ASN1::PrintableString)
    test.(20, AppleSSL::ASN1::T61String)
    test.(21, AppleSSL::ASN1::VideotexString)
    test.(22, AppleSSL::ASN1::IA5String)
    test.(25, AppleSSL::ASN1::GraphicString)
    test.(26, AppleSSL::ASN1::ISO64String)
    test.(27, AppleSSL::ASN1::GeneralString)
    test.(28, AppleSSL::ASN1::UniversalString)
    test.(30, AppleSSL::ASN1::BMPString)
  end

  def test_null
    encode_decode_test B(%w{ 05 00 }), AppleSSL::ASN1::Null.new(nil)
    assert_raise(AppleSSL::ASN1::ASN1Error) {
      AppleSSL::ASN1.decode(B(%w{ 05 01 00 }))
    }
  end

  def test_object_identifier
    encode_decode_test B(%w{ 06 01 00 }), AppleSSL::ASN1::ObjectId.new("0.0".b)
    encode_decode_test B(%w{ 06 01 28 }), AppleSSL::ASN1::ObjectId.new("1.0".b)
    encode_decode_test B(%w{ 06 03 88 37 03 }), AppleSSL::ASN1::ObjectId.new("2.999.3".b)
    encode_decode_test B(%w{ 06 05 2A 22 83 BB 55 }), AppleSSL::ASN1::ObjectId.new("1.2.34.56789".b)
    obj = encode_decode_test B(%w{ 06 09 60 86 48 01 65 03 04 02 01 }), AppleSSL::ASN1::ObjectId.new("sha256")
    assert_equal "2.16.840.1.101.3.4.2.1", obj.oid
    assert_equal "SHA256", obj.sn
    assert_equal "sha256", obj.ln
    assert_raise(AppleSSL::ASN1::ASN1Error) {
      AppleSSL::ASN1.decode(B(%w{ 06 00 }))
    }
    assert_raise(AppleSSL::ASN1::ASN1Error) {
      AppleSSL::ASN1.decode(B(%w{ 06 01 80 }))
    }
    assert_raise(AppleSSL::ASN1::ASN1Error) { AppleSSL::ASN1::ObjectId.new("3.0".b).to_der }
    assert_raise(AppleSSL::ASN1::ASN1Error) { AppleSSL::ASN1::ObjectId.new("0.40".b).to_der }

    begin
      oid = (0...100).to_a.join(".").b
      obj = AppleSSL::ASN1::ObjectId.new(oid)
      assert_equal oid, obj.oid
    rescue AppleSSL::ASN1::ASN1Error
      pend "OBJ_obj2txt() not working (LibreSSL?)" if $!.message =~ /OBJ_obj2txt/
      raise
    end
  end

  def test_sequence
    encode_decode_test B(%w{ 30 00 }), AppleSSL::ASN1::Sequence.new([])
    encode_decode_test B(%w{ 30 07 05 00 30 00 04 01 00 }), AppleSSL::ASN1::Sequence.new([
      AppleSSL::ASN1::Null.new(nil),
      AppleSSL::ASN1::Sequence.new([]),
      AppleSSL::ASN1::OctetString.new(B(%w{ 00 }))
    ])

    expected = AppleSSL::ASN1::Sequence.new([AppleSSL::ASN1::OctetString.new(B(%w{ 00 }))])
    expected.indefinite_length = true
    encode_decode_test B(%w{ 30 80 04 01 00 00 00 }), expected

    # AppleSSL::ASN1::EndOfContent can only be at the end
    obj = AppleSSL::ASN1::Sequence.new([
      AppleSSL::ASN1::EndOfContent.new,
      AppleSSL::ASN1::OctetString.new(B(%w{ 00 })),
      AppleSSL::ASN1::EndOfContent.new,
    ])
    obj.indefinite_length = true
    assert_raise(AppleSSL::ASN1::ASN1Error) { obj.to_der }

    # The last EOC in value is ignored if indefinite length form is used
    expected = AppleSSL::ASN1::Sequence.new([
      AppleSSL::ASN1::OctetString.new(B(%w{ 00 })),
      AppleSSL::ASN1::EndOfContent.new
    ])
    expected.indefinite_length = true
    encode_test B(%w{ 30 80 04 01 00 00 00 }), expected
  end

  def test_set
    encode_decode_test B(%w{ 31 00 }), AppleSSL::ASN1::Set.new([])
    encode_decode_test B(%w{ 31 07 05 00 30 00 04 01 00 }), AppleSSL::ASN1::Set.new([
      AppleSSL::ASN1::Null.new(nil),
      AppleSSL::ASN1::Sequence.new([]),
      AppleSSL::ASN1::OctetString.new(B(%w{ 00 }))
    ])
    expected = AppleSSL::ASN1::Set.new([AppleSSL::ASN1::OctetString.new(B(%w{ 00 }))])
    expected.indefinite_length = true
    encode_decode_test B(%w{ 31 80 04 01 00 00 00 }), expected
  end

  def test_utctime
    encode_decode_test B(%w{ 17 0D }) + "160908234339Z".b,
      AppleSSL::ASN1::UTCTime.new(Time.utc(2016, 9, 8, 23, 43, 39))
    # Seconds is omitted
    decode_test B(%w{ 17 0B }) + "1609082343Z".b,
      AppleSSL::ASN1::UTCTime.new(Time.utc(2016, 9, 8, 23, 43, 0))
    begin
      # possible range of UTCTime is 1969-2068 currently
      encode_decode_test B(%w{ 17 0D }) + "690908234339Z".b,
        AppleSSL::ASN1::UTCTime.new(Time.utc(1969, 9, 8, 23, 43, 39))
    rescue AppleSSL::ASN1::ASN1Error
      pend "No negative time_t support?"
    end
    # not implemented
    # decode_test B(%w{ 17 11 }) + "500908234339+0930".b,
    #   AppleSSL::ASN1::UTCTime.new(Time.new(1950, 9, 8, 23, 43, 39, "+09:30"))
    # decode_test B(%w{ 17 0F }) + "5009082343-0930".b,
    #   AppleSSL::ASN1::UTCTime.new(Time.new(1950, 9, 8, 23, 43, 0, "-09:30"))
    # assert_raise(AppleSSL::ASN1::ASN1Error) {
    #   AppleSSL::ASN1.decode(B(%w{ 17 0C }) + "500908234339".b)
    # }
    # assert_raise(AppleSSL::ASN1::ASN1Error) {
    #   AppleSSL::ASN1.decode(B(%w{ 17 0D }) + "500908234339Y".b)
    # }
  end

  def test_generalizedtime
    encode_decode_test B(%w{ 18 0F }) + "20161208193429Z".b,
      AppleSSL::ASN1::GeneralizedTime.new(Time.utc(2016, 12, 8, 19, 34, 29))
    encode_decode_test B(%w{ 18 0F }) + "99990908234339Z".b,
      AppleSSL::ASN1::GeneralizedTime.new(Time.utc(9999, 9, 8, 23, 43, 39))
    decode_test B(%w{ 18 0D }) + "201612081934Z".b,
      AppleSSL::ASN1::GeneralizedTime.new(Time.utc(2016, 12, 8, 19, 34, 0))
    # not implemented
    # decode_test B(%w{ 18 13 }) + "20161208193439+0930".b,
    #   AppleSSL::ASN1::GeneralizedTime.new(Time.new(2016, 12, 8, 19, 34, 39, "+09:30"))
    # decode_test B(%w{ 18 11 }) + "201612081934-0930".b,
    #   AppleSSL::ASN1::GeneralizedTime.new(Time.new(2016, 12, 8, 19, 34, 0, "-09:30"))
    # decode_test B(%w{ 18 11 }) + "201612081934-09".b,
    #   AppleSSL::ASN1::GeneralizedTime.new(Time.new(2016, 12, 8, 19, 34, 0, "-09:00"))
    # decode_test B(%w{ 18 0D }) + "2016120819.5Z".b,
    #   AppleSSL::ASN1::GeneralizedTime.new(Time.utc(2016, 12, 8, 19, 30, 0))
    # decode_test B(%w{ 18 0D }) + "2016120819,5Z".b,
    #   AppleSSL::ASN1::GeneralizedTime.new(Time.utc(2016, 12, 8, 19, 30, 0))
    # decode_test B(%w{ 18 0F }) + "201612081934.5Z".b,
    #   AppleSSL::ASN1::GeneralizedTime.new(Time.utc(2016, 12, 8, 19, 34, 30))
    # decode_test B(%w{ 18 11 }) + "20161208193439.5Z".b,
    #   AppleSSL::ASN1::GeneralizedTime.new(Time.utc(2016, 12, 8, 19, 34, 39.5))
    # assert_raise(AppleSSL::ASN1::ASN1Error) {
    #   AppleSSL::ASN1.decode(B(%w{ 18 0D }) + "201612081934Y".b)
    # }
  end

  def test_basic_asn1data
    encode_test B(%w{ 00 00 }), AppleSSL::ASN1::ASN1Data.new(B(%w{}), 0, :UNIVERSAL)
    encode_test B(%w{ 01 00 }), AppleSSL::ASN1::ASN1Data.new(B(%w{}), 1, :UNIVERSAL)
    encode_decode_test B(%w{ 41 00 }), AppleSSL::ASN1::ASN1Data.new(B(%w{}), 1, :APPLICATION)
    encode_decode_test B(%w{ 81 00 }), AppleSSL::ASN1::ASN1Data.new(B(%w{}), 1, :CONTEXT_SPECIFIC)
    encode_decode_test B(%w{ C1 00 }), AppleSSL::ASN1::ASN1Data.new(B(%w{}), 1, :PRIVATE)
    encode_decode_test B(%w{ 1F 20 00 }), AppleSSL::ASN1::ASN1Data.new(B(%w{}), 32, :UNIVERSAL)
    encode_decode_test B(%w{ 1F C0 20 00 }), AppleSSL::ASN1::ASN1Data.new(B(%w{}), 8224, :UNIVERSAL)
    encode_decode_test B(%w{ 41 02 AB CD }), AppleSSL::ASN1::ASN1Data.new(B(%w{ AB CD }), 1, :APPLICATION)
    encode_decode_test B(%w{ 41 81 80 } + %w{ AB CD } * 64), AppleSSL::ASN1::ASN1Data.new(B(%w{ AB CD } * 64), 1, :APPLICATION)
    encode_decode_test B(%w{ 41 82 01 00 } + %w{ AB CD } * 128), AppleSSL::ASN1::ASN1Data.new(B(%w{ AB CD } * 128), 1, :APPLICATION)
    encode_decode_test B(%w{ 61 00 }), AppleSSL::ASN1::ASN1Data.new([], 1, :APPLICATION)
    obj = AppleSSL::ASN1::ASN1Data.new([AppleSSL::ASN1::ASN1Data.new(B(%w{ AB CD }), 2, :PRIVATE)], 1, :APPLICATION)
    obj.indefinite_length = true
    encode_decode_test B(%w{ 61 80 C2 02 AB CD 00 00 }), obj
    obj = AppleSSL::ASN1::ASN1Data.new([
      AppleSSL::ASN1::ASN1Data.new(B(%w{ AB CD }), 2, :PRIVATE),
      AppleSSL::ASN1::EndOfContent.new
    ], 1, :APPLICATION)
    obj.indefinite_length = true
    encode_test B(%w{ 61 80 C2 02 AB CD 00 00 }), obj
    obj = AppleSSL::ASN1::ASN1Data.new(B(%w{ AB CD }), 1, :UNIVERSAL)
    obj.indefinite_length = true
    assert_raise(AppleSSL::ASN1::ASN1Error) { obj.to_der }
  end

  def test_basic_primitive
    encode_test B(%w{ 00 00 }), AppleSSL::ASN1::Primitive.new(B(%w{}), 0)
    encode_test B(%w{ 01 00 }), AppleSSL::ASN1::Primitive.new(B(%w{}), 1, nil, :UNIVERSAL)
    encode_test B(%w{ 81 00 }), AppleSSL::ASN1::Primitive.new(B(%w{}), 1, nil, :CONTEXT_SPECIFIC)
    encode_test B(%w{ 01 02 AB CD }), AppleSSL::ASN1::Primitive.new(B(%w{ AB CD }), 1)
    assert_raise(TypeError) { AppleSSL::ASN1::Primitive.new([], 1).to_der }

    prim = AppleSSL::ASN1::Integer.new(50)
    assert_equal false, prim.indefinite_length
    assert_not_respond_to prim, :indefinite_length=
  end

  def test_basic_constructed
    octet_string = AppleSSL::ASN1::OctetString.new(B(%w{ AB CD }))
    encode_test B(%w{ 20 00 }), AppleSSL::ASN1::Constructive.new([], 0)
    encode_test B(%w{ 21 00 }), AppleSSL::ASN1::Constructive.new([], 1, nil, :UNIVERSAL)
    encode_test B(%w{ A1 00 }), AppleSSL::ASN1::Constructive.new([], 1, nil, :CONTEXT_SPECIFIC)
    encode_test B(%w{ 21 04 04 02 AB CD }), AppleSSL::ASN1::Constructive.new([octet_string], 1)
    obj = AppleSSL::ASN1::Constructive.new([octet_string], 1)
    obj.indefinite_length = true
    encode_decode_test B(%w{ 21 80 04 02 AB CD 00 00 }), obj
    obj = AppleSSL::ASN1::Constructive.new([octet_string, AppleSSL::ASN1::EndOfContent.new], 1)
    obj.indefinite_length = true
    encode_test B(%w{ 21 80 04 02 AB CD 00 00 }), obj
  end

  def test_prim_explicit_tagging
    oct_str = AppleSSL::ASN1::OctetString.new("a", 0, :EXPLICIT)
    encode_test B(%w{ A0 03 04 01 61 }), oct_str
    oct_str2 = AppleSSL::ASN1::OctetString.new("a", 1, :EXPLICIT, :APPLICATION)
    encode_test B(%w{ 61 03 04 01 61 }), oct_str2

    decoded = AppleSSL::ASN1.decode(oct_str2.to_der)
    assert_equal :APPLICATION, decoded.tag_class
    assert_equal 1, decoded.tag
    assert_equal 1, decoded.value.size
    inner = decoded.value[0]
    assert_equal AppleSSL::ASN1::OctetString, inner.class
    assert_equal B(%w{ 61 }), inner.value
  end

  def test_prim_implicit_tagging
    int = AppleSSL::ASN1::Integer.new(1, 0, :IMPLICIT)
    encode_test B(%w{ 80 01 01 }), int
    int2 = AppleSSL::ASN1::Integer.new(1, 1, :IMPLICIT, :APPLICATION)
    encode_test B(%w{ 41 01 01 }), int2
    decoded = AppleSSL::ASN1.decode(int2.to_der)
    assert_equal :APPLICATION, decoded.tag_class
    assert_equal 1, decoded.tag
    assert_equal B(%w{ 01 }), decoded.value

    # Special behavior: Encoding universal types with non-default 'tag'
    # attribute and nil tagging method.
    int3 = AppleSSL::ASN1::Integer.new(1, 1)
    encode_test B(%w{ 01 01 01 }), int3
  end

  def test_cons_explicit_tagging
    content = [ AppleSSL::ASN1::PrintableString.new('abc') ]
    seq = AppleSSL::ASN1::Sequence.new(content, 2, :EXPLICIT)
    encode_test B(%w{ A2 07 30 05 13 03 61 62 63 }), seq
    seq2 = AppleSSL::ASN1::Sequence.new(content, 3, :EXPLICIT, :APPLICATION)
    encode_test B(%w{ 63 07 30 05 13 03 61 62 63 }), seq2

    content3 = [ AppleSSL::ASN1::PrintableString.new('abc'),
                 AppleSSL::ASN1::EndOfContent.new() ]
    seq3 = AppleSSL::ASN1::Sequence.new(content3, 2, :EXPLICIT)
    seq3.indefinite_length = true
    encode_test B(%w{ A2 80 30 80 13 03 61 62 63 00 00 00 00 }), seq3
  end

  def test_cons_implicit_tagging
    content = [ AppleSSL::ASN1::Null.new(nil) ]
    seq = AppleSSL::ASN1::Sequence.new(content, 1, :IMPLICIT)
    encode_test B(%w{ A1 02 05 00 }), seq
    seq2 = AppleSSL::ASN1::Sequence.new(content, 1, :IMPLICIT, :APPLICATION)
    encode_test B(%w{ 61 02 05 00 }), seq2

    content3 = [ AppleSSL::ASN1::Null.new(nil),
                 AppleSSL::ASN1::EndOfContent.new() ]
    seq3 = AppleSSL::ASN1::Sequence.new(content3, 1, :IMPLICIT)
    seq3.indefinite_length = true
    encode_test B(%w{ A1 80 05 00 00 00 }), seq3

    # Special behavior: Encoding universal types with non-default 'tag'
    # attribute and nil tagging method.
    seq4 = AppleSSL::ASN1::Sequence.new([], 1)
    encode_test B(%w{ 21 00 }), seq4
  end

  def test_octet_string_constructed_tagging
    octets = [ AppleSSL::ASN1::OctetString.new('aaa') ]
    cons = AppleSSL::ASN1::Constructive.new(octets, 0, :IMPLICIT)
    encode_test B(%w{ A0 05 04 03 61 61 61 }), cons

    octets = [ AppleSSL::ASN1::OctetString.new('aaa'),
               AppleSSL::ASN1::EndOfContent.new() ]
    cons = AppleSSL::ASN1::Constructive.new(octets, 0, :IMPLICIT)
    cons.indefinite_length = true
    encode_test B(%w{ A0 80 04 03 61 61 61 00 00 }), cons
  end

  def test_recursive_octet_string_indefinite_length
    octets_sub1 = [ AppleSSL::ASN1::OctetString.new("\x01"),
                    AppleSSL::ASN1::EndOfContent.new() ]
    octets_sub2 = [ AppleSSL::ASN1::OctetString.new("\x02"),
                    AppleSSL::ASN1::EndOfContent.new() ]
    container1 = AppleSSL::ASN1::Constructive.new(octets_sub1, AppleSSL::ASN1::OCTET_STRING, nil, :UNIVERSAL)
    container1.indefinite_length = true
    container2 = AppleSSL::ASN1::Constructive.new(octets_sub2, AppleSSL::ASN1::OCTET_STRING, nil, :UNIVERSAL)
    container2.indefinite_length = true
    octets3 = AppleSSL::ASN1::OctetString.new("\x03")

    octets = [ container1, container2, octets3,
               AppleSSL::ASN1::EndOfContent.new() ]
    cons = AppleSSL::ASN1::Constructive.new(octets, AppleSSL::ASN1::OCTET_STRING, nil, :UNIVERSAL)
    cons.indefinite_length = true
    raw = B(%w{ 24 80 24 80 04 01 01 00 00 24 80 04 01 02 00 00 04 01 03 00 00 })
    assert_equal(raw, cons.to_der)
    assert_equal(raw, AppleSSL::ASN1.decode(raw).to_der)
  end

  def test_recursive_octet_string_parse
    raw = B(%w{ 24 80 24 80 04 01 01 00 00 24 80 04 01 02 00 00 04 01 03 00 00 })
    asn1 = AppleSSL::ASN1.decode(raw)
    assert_equal(AppleSSL::ASN1::Constructive, asn1.class)
    assert_universal(AppleSSL::ASN1::OCTET_STRING, asn1)
    assert_equal(true, asn1.indefinite_length)
    assert_equal(3, asn1.value.size)
    nested1 = asn1.value[0]
    assert_equal(AppleSSL::ASN1::Constructive, nested1.class)
    assert_universal(AppleSSL::ASN1::OCTET_STRING, nested1)
    assert_equal(true, nested1.indefinite_length)
    assert_equal(1, nested1.value.size)
    oct1 = nested1.value[0]
    assert_universal(AppleSSL::ASN1::OCTET_STRING, oct1)
    assert_equal(false, oct1.indefinite_length)
    nested2 = asn1.value[1]
    assert_equal(AppleSSL::ASN1::Constructive, nested2.class)
    assert_universal(AppleSSL::ASN1::OCTET_STRING, nested2)
    assert_equal(true, nested2.indefinite_length)
    assert_equal(1, nested2.value.size)
    oct2 = nested2.value[0]
    assert_universal(AppleSSL::ASN1::OCTET_STRING, oct2)
    assert_equal(false, oct2.indefinite_length)
    oct3 = asn1.value[2]
    assert_universal(AppleSSL::ASN1::OCTET_STRING, oct3)
    assert_equal(false, oct3.indefinite_length)
  end

  def test_decode_constructed_overread
    test = %w{ 31 06 31 02 30 02 05 00 }
    #                          ^ <- invalid
    raw = [test.join].pack("H*")
    ret = []
    assert_raise(AppleSSL::ASN1::ASN1Error) {
      AppleSSL::ASN1.traverse(raw) { |x| ret << x }
    }
    assert_equal 2, ret.size
    assert_equal 17, ret[0][6]
    assert_equal 17, ret[1][6]

    test = %w{ 31 80 30 03 00 00 }
    #                    ^ <- invalid
    raw = [test.join].pack("H*")
    ret = []
    assert_raise(AppleSSL::ASN1::ASN1Error) {
      AppleSSL::ASN1.traverse(raw) { |x| ret << x }
    }
    assert_equal 1, ret.size
    assert_equal 17, ret[0][6]
  end

  def test_constructive_each
    data = [AppleSSL::ASN1::Integer.new(0), AppleSSL::ASN1::Integer.new(1)]
    seq = AppleSSL::ASN1::Sequence.new data

    assert_equal data, seq.entries
  end

  private

  def B(ary)
    [ary.join].pack("H*")
  end

  def assert_asn1_equal(a, b)
    assert_equal a.class, b.class
    assert_equal a.tag, b.tag
    assert_equal a.tag_class, b.tag_class
    assert_equal a.indefinite_length, b.indefinite_length
    assert_equal a.unused_bits, b.unused_bits if a.respond_to?(:unused_bits)
    case a.value
    when Array
      a.value.each_with_index { |ai, i|
        assert_asn1_equal ai, b.value[i]
      }
    else
      if AppleSSL::ASN1::ObjectId === a
        assert_equal a.oid, b.oid
      else
        assert_equal a.value, b.value
      end
    end
    assert_equal a.to_der, b.to_der
  end

  def encode_test(der, obj)
    assert_equal der, obj.to_der
  end

  def decode_test(der, obj)
    decoded = AppleSSL::ASN1.decode(der)
    assert_asn1_equal obj, decoded
    decoded
  end

  def encode_decode_test(der, obj)
    encode_test(der, obj)
    decode_test(der, obj)
  end

  def assert_universal(tag, asn1)
    assert_equal(tag, asn1.tag)
    if asn1.respond_to?(:tagging)
      assert_nil(asn1.tagging)
    end
    assert_equal(:UNIVERSAL, asn1.tag_class)
  end
end

end
