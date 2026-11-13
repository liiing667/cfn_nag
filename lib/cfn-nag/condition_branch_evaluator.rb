# frozen_string_literal: true

require 'json'
require 'yaml'

# Builds the condition value payloads needed to audit every reachable
# Fn::If branch. cfn-model defaults every condition to true when no values
# are supplied, so an additional all-false pass is required to reach the
# false branches without changing behavior for explicitly provided values.
class ConditionBranchEvaluator
  def branch_values(cloudformation_string, condition_values_string)
    return [condition_values_string] unless condition_values_string.nil?

    condition_names = extract_condition_names(cloudformation_string)
    return [nil] if condition_names.empty?

    [
      nil,
      condition_names.each_with_object({}) { |name, values| values[name] = false }.to_json
    ]
  end

  private

  def extract_condition_names(cloudformation_string)
    cfn_hash = YAML.safe_load(cloudformation_string)
    return [] unless cfn_hash.is_a?(Hash) && cfn_hash['Conditions'].is_a?(Hash)

    cfn_hash['Conditions'].keys
  rescue StandardError
    []
  end
end
