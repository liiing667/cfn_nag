require 'spec_helper'
require 'cfn-model'
require 'cfn-nag/custom_rules/SecurityGroupEgressPortRangeRule'

describe SecurityGroupEgressPortRangeRule do
  context 'security group with egress rules open to port range' do
    it 'returns offending logical resource id' do
      cfn_model = CfnParser.new.parse read_test_template('json/security_group/egress_with_port_range.json')

      actual_logical_resource_ids = SecurityGroupEgressPortRangeRule.new.audit_impl cfn_model
      expected_logical_resource_ids = %w[sgOpenEgress securityGroupEgress]

      expect(actual_logical_resource_ids).to eq expected_logical_resource_ids
    end
  end

  context 'when a false Fn::If branch yields an empty egress entry' do
    it 'skips the empty entry without raising' do
      cfn_model = CfnParser.new.parse(
        read_test_template('yaml/security_group/pesky_if.yml'),
        nil, true, '{"MicroInt":false}'
      )

      expect { SecurityGroupEgressPortRangeRule.new.audit_impl(cfn_model) }.not_to raise_error
    end
  end
end
