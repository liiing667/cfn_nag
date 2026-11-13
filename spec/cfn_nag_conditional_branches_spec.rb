# frozen_string_literal: true

require 'spec_helper'
require 'cfn-nag/cfn_nag_config'
require 'cfn-nag/cfn_nag'
require 'cfn-nag/cfn_nag_logging'
require 'cfn-nag/custom_rules/RDSDBInstanceMasterUsernameRule'
require 'cfn-nag/custom_rules/RDSDBInstanceStorageEncryptedRule'
require 'cfn-nag/custom_rules/RDSInstanceDeletionProtectionRule'
require 'cfn-nag/custom_rules/RDSInstancePubliclyAccessibleRule'
require 'cfn-nag/custom_rules/RDSDBInstanceMasterUserPasswordRule'
require 'cfn-nag/custom_rules/SecurityGroupIngressCidrNon32Rule'
require 'cfn-nag/custom_rules/SecurityGroupMissingEgressRule'
require 'cfn-nag/custom_rules/SecurityGroupRuleDescriptionRule'
require 'cfn-nag/custom_rules/SecurityGroupIngressOpenToWorldRule'

describe CfnNag do
  before(:each) do
    CfnNagLogging.configure_logging(debug: false)
    @cfn_nag = CfnNag.new(config: CfnNagConfig.new)
  end

  context 'when violations are hidden behind a false Fn::If branch' do
    it 'audits the plaintext password in the false branch and merges by resource and rule' do
      template_name = 'json/rds_instance/db_instance_password_in_if_branch.json'

      expected_aggregate_results = [
        {
          filename: test_template_path(template_name),
          file_results: {
            failure_count: 5,
            violations: [
              rule_violation(RDSDBInstanceMasterUsernameRule, 'DbInstance'),
              rule_violation(RDSDBInstanceStorageEncryptedRule, 'DbInstance'),
              rule_violation(RDSInstanceDeletionProtectionRule, 'DbInstance'),
              rule_violation(RDSInstancePubliclyAccessibleRule, 'DbInstance'),
              rule_violation(RDSDBInstanceMasterUserPasswordRule, 'DbInstance')
            ]
          }
        }
      ]

      actual_aggregate_results =
        @cfn_nag.audit_aggregate_across_files(
          input_path: test_template_path(template_name)
        )

      expect(actual_aggregate_results).to eq expected_aggregate_results
    end

    it 'audits the open security group ingress in the false branch and merges by resource and rule' do
      template_name = 'json/security_group/security_group_open_to_world_in_if_branch.json'

      expected_aggregate_results = [
        {
          filename: test_template_path(template_name),
          file_results: {
            failure_count: 1,
            violations: [
              rule_violation(SecurityGroupIngressCidrNon32Rule, 'ConditionalSecurityGroup'),
              rule_violation(SecurityGroupMissingEgressRule, 'ConditionalSecurityGroup'),
              rule_violation(SecurityGroupRuleDescriptionRule, 'ConditionalSecurityGroup'),
              rule_violation(SecurityGroupIngressOpenToWorldRule, 'ConditionalSecurityGroup')
            ]
          }
        }
      ]

      actual_aggregate_results =
        @cfn_nag.audit_aggregate_across_files(
          input_path: test_template_path(template_name)
        )

      expect(actual_aggregate_results).to eq expected_aggregate_results
    end

    def rule_violation(rule_class, logical_resource_id)
      rule_class.new.violation([logical_resource_id], [20], ['resource'])
    end
  end
end
