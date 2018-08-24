# frozen_string_literal: false
#--
#
# = Ruby-space definitions that completes C-space funcs for BN
#
# = Info
# 'ApenSSL for Ruby 2' project
# Copyright (C) 2002  Michal Rokos <m.rokos@sh.cvut.cz>
# All rights reserved.
#
# = Licence
# This program is licensed under the same licence as Ruby.
# (See the file 'LICENCE'.)
#++

module ApenSSL
  class BN
    include Comparable

    def pretty_print(q)
      q.object_group(self) {
        q.text ' '
        q.text to_i.to_s
      }
    end
  end # BN
end # ApenSSL

##
#--
# Add double dispatch to Integer
#++
class Integer
  # Casts an Integer as an ApenSSL::BN
  #
  # See `man bn` for more info.
  def to_bn
    ApenSSL::BN::new(self)
  end
end # Integer
