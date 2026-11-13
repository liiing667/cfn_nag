# frozen_string_literal: true

require_relative 'condition_branch_evaluator'
require_relative 'violation_merger'
require_relative 'violation_filtering'

# Runs the rule set against every reachable condition branch of a template
# and merges the resulting violations by rule id, so a resource-rule pair is
# reported exactly once even when it is only reachable on a false branch.
class ConditionBranchAuditor
  include ViolationFiltering

  def initialize(config:)
    @config = config
  end

  def audit(cloudformation_string, parameter_values_string, condition_values_string)
    violation_collections =
      ConditionBranchEvaluator.new.branch_values(cloudformation_string,
                                                 condition_values_string).map do |branch_values_string|
        audit_branch(cloudformation_string, parameter_values_string, branch_values_string)
      end

    ViolationMerger.new.merge(violation_collections)
  end

  private

  def audit_branch(cloudformation_string, parameter_values_string, condition_values_string)
    cfn_model = CfnParser.new.parse cloudformation_string,
                                    parameter_values_string,
                                    true,
                                    condition_values_string
    CustomRuleLoader.rule_arguments = @config.rule_arguments
    branch_violations = @config.custom_rule_loader.execute_custom_rules(
      cfn_model,
      @config.custom_rule_loader.rule_definitions
    )

    branch_violations = filter_violations(branch_violations)
    mark_line_numbers_and_element_types(branch_violations, cfn_model)
  end

  def filter_violations(violations)
    violations = filter_violations_by_profile(
      profile_definition: @config.profile_definition,
      rule_definitions: @config.custom_rule_loader.rule_definitions,
      violations: violations
    )

    # deny list must win over profile
    filter_violations_by_deny_list(
      deny_list_definition: @config.deny_list_definition,
      rule_definitions: @config.custom_rule_loader.rule_definitions,
      violations: violations
    )
  rescue StandardError => deny_list_or_profile_parse_error
    violations << Violation.fatal_violation(deny_list_or_profile_parse_error.to_s)
    violations
  end

  def mark_line_numbers_and_element_types(violations, cfn_model)
    violations.each do |violation|
      violation.logical_resource_ids.each do |logical_resource_id|
        violation.line_numbers << cfn_model.line_numbers[logical_resource_id]
        violation.element_types << cfn_model.element_types[logical_resource_id]
      end
    end

    violations
  end
end
