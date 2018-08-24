#!/usr/bin/env ruby

require 'socket'
require 'applessl'
require 'optparse'

options = ARGV.getopts("p:c:k:C:")

port      = options["p"] || "2000"
cert_file = options["c"]
key_file  = options["k"]
ca_path   = options["C"]

if cert_file && key_file
  cert = AppleSSL::X509::Certificate.new(File::read(cert_file))
  key  = AppleSSL::PKey::RSA.new(File::read(key_file))
else
  key = AppleSSL::PKey::RSA.new(512){ print "." }
  puts
  cert = AppleSSL::X509::Certificate.new
  cert.version = 2
  cert.serial = 0
  name = AppleSSL::X509::Name.new([["C","JP"],["O","TEST"],["CN","localhost"]])
  cert.subject = name
  cert.issuer = name
  cert.not_before = Time.now
  cert.not_after = Time.now + 3600
  cert.public_key = key.public_key
  ef = AppleSSL::X509::ExtensionFactory.new(nil,cert)
  cert.extensions = [
    ef.create_extension("basicConstraints","CA:FALSE"),
    ef.create_extension("subjectKeyIdentifier","hash"),
    ef.create_extension("extendedKeyUsage","serverAuth"),
    ef.create_extension("keyUsage",
                        "keyEncipherment,dataEncipherment,digitalSignature")
  ]
  ef.issuer_certificate = cert
  cert.add_extension ef.create_extension("authorityKeyIdentifier",
                                         "keyid:always,issuer:always")
  cert.sign(key, AppleSSL::Digest::SHA1.new)
end

ctx = AppleSSL::SSL::SSLContext.new()
ctx.key = key
ctx.cert = cert
if ca_path
  ctx.verify_mode =
    AppleSSL::SSL::VERIFY_PEER|AppleSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT
  ctx.ca_path = ca_path
else
  $stderr.puts "!!! WARNING: PEER CERTIFICATE WON'T BE VERIFIED !!!"
end

tcps = TCPServer.new(port)
ssls = AppleSSL::SSL::SSLServer.new(tcps, ctx)
loop do
  ns = ssls.accept
  puts "connected from #{ns.peeraddr}"
  while line = ns.gets
    puts line.inspect
    ns.write line
  end
  puts "connection closed"
  ns.close
end
