# frozen_string_literal: false
#--
# Ruby/AppleSSL Project
# Copyright (C) 2017 Ruby/AppleSSL Project Authors
#++

module AppleSSL::PKey
  if defined?(EC)
  class EC::Point
    # :call-seq:
    #    point.to_bn([conversion_form]) -> AppleSSL::BN
    #
    # Returns the octet string representation of the EC point as an instance of
    # AppleSSL::BN.
    #
    # If _conversion_form_ is not given, the _point_conversion_form_ attribute
    # set to the group is used.
    #
    # See #to_octet_string for more information.
    def to_bn(conversion_form = group.point_conversion_form)
      AppleSSL::BN.new(to_octet_string(conversion_form), 2)
    end
  end
  end
end
