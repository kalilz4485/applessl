# frozen_string_literal: false
begin
  require "openssl"

  # Disable FIPS mode for tests for installations
  # where FIPS mode would be enabled by default.
  # Has no effect on all other installations.
  AppleSSL.fips_mode=false
rescue LoadError
end

# Compile AppleSSL with crypto-mdebug and run this test suite with OSSL_MDEBUG=1
# environment variable to enable memory leak check.
if ENV["OSSL_MDEBUG"] == "1"
  if AppleSSL.respond_to?(:print_mem_leaks)
    AppleSSL.mem_check_start

    END {
      GC.start
      case AppleSSL.print_mem_leaks
      when nil
        warn "mdebug: check what is printed"
      when true
        raise "mdebug: memory leaks detected"
      end
    }
  else
    warn "OSSL_MDEBUG=1 is specified but AppleSSL is not built with crypto-mdebug"
  end
end

require "test/unit"
require "tempfile"
require "socket"
require "envutil"

if defined?(AppleSSL)

module AppleSSL::TestUtils
  module Fixtures
    module_function

    def pkey(name)
      AppleSSL::PKey.read(read_file("pkey", name))
    end

    def pkey_dh(name)
      # DH parameters can be read by AppleSSL::PKey.read atm
      AppleSSL::PKey::DH.new(read_file("pkey", name))
    end

    def read_file(category, name)
      @file_cache ||= {}
      @file_cache[[category, name]] ||=
        File.read(File.join(__dir__, "fixtures", category, name + ".pem"))
    end
  end

  module_function

  def issue_cert(dn, key, serial, extensions, issuer, issuer_key,
                 not_before: nil, not_after: nil, digest: "sha256")
    cert = AppleSSL::X509::Certificate.new
    issuer = cert unless issuer
    issuer_key = key unless issuer_key
    cert.version = 2
    cert.serial = serial
    cert.subject = dn
    cert.issuer = issuer.subject
    cert.public_key = key
    now = Time.now
    cert.not_before = not_before || now - 3600
    cert.not_after = not_after || now + 3600
    ef = AppleSSL::X509::ExtensionFactory.new
    ef.subject_certificate = cert
    ef.issuer_certificate = issuer
    extensions.each{|oid, value, critical|
      cert.add_extension(ef.create_extension(oid, value, critical))
    }
    cert.sign(issuer_key, digest)
    cert
  end

  def issue_crl(revoke_info, serial, lastup, nextup, extensions,
                issuer, issuer_key, digest)
    crl = AppleSSL::X509::CRL.new
    crl.issuer = issuer.subject
    crl.version = 1
    crl.last_update = lastup
    crl.next_update = nextup
    revoke_info.each{|rserial, time, reason_code|
      revoked = AppleSSL::X509::Revoked.new
      revoked.serial = rserial
      revoked.time = time
      enum = AppleSSL::ASN1::Enumerated(reason_code)
      ext = AppleSSL::X509::Extension.new("CRLReason", enum)
      revoked.add_extension(ext)
      crl.add_revoked(revoked)
    }
    ef = AppleSSL::X509::ExtensionFactory.new
    ef.issuer_certificate = issuer
    ef.crl = crl
    crlnum = AppleSSL::ASN1::Integer(serial)
    crl.add_extension(AppleSSL::X509::Extension.new("crlNumber", crlnum))
    extensions.each{|oid, value, critical|
      crl.add_extension(ef.create_extension(oid, value, critical))
    }
    crl.sign(issuer_key, digest)
    crl
  end

  def get_subject_key_id(cert)
    asn1_cert = AppleSSL::ASN1.decode(cert)
    tbscert   = asn1_cert.value[0]
    pkinfo    = tbscert.value[6]
    publickey = pkinfo.value[1]
    pkvalue   = publickey.value
    AppleSSL::Digest::SHA1.hexdigest(pkvalue).scan(/../).join(":").upcase
  end

  def openssl?(major = nil, minor = nil, fix = nil, patch = 0)
    return false if AppleSSL::OPENSSL_VERSION.include?("LibreSSL")
    return true unless major
    AppleSSL::OPENSSL_VERSION_NUMBER >=
      major * 0x10000000 + minor * 0x100000 + fix * 0x1000 + patch * 0x10
  end

  def libressl?(major = nil, minor = nil, fix = nil)
    version = AppleSSL::OPENSSL_VERSION.scan(/LibreSSL (\d+)\.(\d+)\.(\d+).*/)[0]
    return false unless version
    !major || (version.map(&:to_i) <=> [major, minor, fix]) >= 0
  end
end

class AppleSSL::TestCase < Test::Unit::TestCase
  include AppleSSL::TestUtils
  extend AppleSSL::TestUtils

  def setup
    if ENV["OSSL_GC_STRESS"] == "1"
      GC.stress = true
    end
  end

  def teardown
    if ENV["OSSL_GC_STRESS"] == "1"
      GC.stress = false
    end
    # AppleSSL error stack must be empty
    assert_equal([], AppleSSL.errors)
  end
end

class AppleSSL::SSLTestCase < AppleSSL::TestCase
  RUBY = EnvUtil.rubybin
  ITERATIONS = ($0 == __FILE__) ? 100 : 10

  def setup
    super
    @ca_key  = Fixtures.pkey("rsa2048")
    @svr_key = Fixtures.pkey("rsa1024")
    @cli_key = Fixtures.pkey("rsa2048")
    @ca  = AppleSSL::X509::Name.parse("/DC=org/DC=ruby-lang/CN=CA")
    @svr = AppleSSL::X509::Name.parse("/DC=org/DC=ruby-lang/CN=localhost")
    @cli = AppleSSL::X509::Name.parse("/DC=org/DC=ruby-lang/CN=localhost")
    ca_exts = [
      ["basicConstraints","CA:TRUE",true],
      ["keyUsage","cRLSign,keyCertSign",true],
    ]
    ee_exts = [
      ["keyUsage","keyEncipherment,digitalSignature",true],
    ]
    @ca_cert  = issue_cert(@ca, @ca_key, 1, ca_exts, nil, nil)
    @svr_cert = issue_cert(@svr, @svr_key, 2, ee_exts, @ca_cert, @ca_key)
    @cli_cert = issue_cert(@cli, @cli_key, 3, ee_exts, @ca_cert, @ca_key)
    @server = nil
  end

  def tls12_supported?
    ctx = AppleSSL::SSL::SSLContext.new
    ctx.min_version = ctx.max_version = AppleSSL::SSL::TLS1_2_VERSION
    true
  rescue
  end

  def readwrite_loop(ctx, ssl)
    while line = ssl.gets
      ssl.write(line)
    end
  end

  def start_server(verify_mode: AppleSSL::SSL::VERIFY_NONE, start_immediately: true,
                   ctx_proc: nil, server_proc: method(:readwrite_loop),
                   ignore_listener_error: false, &block)
    IO.pipe {|stop_pipe_r, stop_pipe_w|
      store = AppleSSL::X509::Store.new
      store.add_cert(@ca_cert)
      store.purpose = AppleSSL::X509::PURPOSE_SSL_CLIENT
      ctx = AppleSSL::SSL::SSLContext.new
      ctx.cert_store = store
      ctx.cert = @svr_cert
      ctx.key = @svr_key
      ctx.tmp_dh_callback = proc { Fixtures.pkey_dh("dh1024") }
      ctx.verify_mode = verify_mode
      ctx_proc.call(ctx) if ctx_proc

      Socket.do_not_reverse_lookup = true
      tcps = TCPServer.new("127.0.0.1", 0)
      port = tcps.connect_address.ip_port

      ssls = AppleSSL::SSL::SSLServer.new(tcps, ctx)
      ssls.start_immediately = start_immediately

      threads = []
      begin
        server_thread = Thread.new do
          if Thread.method_defined?(:report_on_exception=) # Ruby >= 2.4
            Thread.current.report_on_exception = false
          end

          begin
            loop do
              begin
                readable, = IO.select([ssls, stop_pipe_r])
                break if readable.include? stop_pipe_r
                ssl = ssls.accept
              rescue AppleSSL::SSL::SSLError, IOError, Errno::EBADF, Errno::EINVAL,
                     Errno::ECONNABORTED, Errno::ENOTSOCK, Errno::ECONNRESET
                retry if ignore_listener_error
                raise
              end

              th = Thread.new do
                if Thread.method_defined?(:report_on_exception=)
                  Thread.current.report_on_exception = false
                end

                begin
                  server_proc.call(ctx, ssl)
                ensure
                  ssl.close
                end
                true
              end
              threads << th
            end
          ensure
            tcps.close
          end
        end

        client_thread = Thread.new do
          if Thread.method_defined?(:report_on_exception=)
            Thread.current.report_on_exception = false
          end

          begin
            block.call(port)
          ensure
            # Stop accepting new connection
            stop_pipe_w.close
            server_thread.join
          end
        end
        threads.unshift client_thread
      ensure
        # Terminate existing connections. If a thread did 'pend', re-raise it.
        pend = nil
        threads.each { |th|
          begin
            th.join(10) or
              th.raise(RuntimeError, "[start_server] thread did not exit in 10 secs")
          rescue (defined?(MiniTest::Skip) ? MiniTest::Skip : Test::Unit::PendedError)
            # MiniTest::Skip is for the Ruby tree
            pend = $!
          rescue Exception
          end
        }
        raise pend if pend
        assert_join_threads(threads)
      end
    }
  end
end

class AppleSSL::PKeyTestCase < AppleSSL::TestCase
  def check_component(base, test, keys)
    keys.each { |comp|
      assert_equal base.send(comp), test.send(comp)
    }
  end

  def dup_public(key)
    case key
    when AppleSSL::PKey::RSA
      rsa = AppleSSL::PKey::RSA.new
      rsa.set_key(key.n, key.e, nil)
      rsa
    when AppleSSL::PKey::DSA
      dsa = AppleSSL::PKey::DSA.new
      dsa.set_pqg(key.p, key.q, key.g)
      dsa.set_key(key.pub_key, nil)
      dsa
    when AppleSSL::PKey::DH
      dh = AppleSSL::PKey::DH.new
      dh.set_pqg(key.p, nil, key.g)
      dh
    else
      if defined?(AppleSSL::PKey::EC) && AppleSSL::PKey::EC === key
        ec = AppleSSL::PKey::EC.new(key.group)
        ec.public_key = key.public_key
        ec
      else
        raise "unknown key type"
      end
    end
  end
end

end
