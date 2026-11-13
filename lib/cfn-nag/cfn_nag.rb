# frozen_string_literal: true

require_relative 'custom_rule_loader'
require_relative 'rule_registry'
require_relative 'template_discovery'
require_relative 'condition_branch_auditor'
require_relative 'result_view/stdout_results'
require_relative 'result_view/simple_stdout_results'
require_relative 'result_view/colored_stdout_results'
require_relative 'result_view/json_results'
require_relative 'result_view/sarif_results'
require 'cfn-model'

# Top-level CfnNag class for running profiles
class CfnNag
  DEFAULT_TEMPLATE_PATTERN = '..*\.json$|..*\.yaml$|..*\.yml$|..*\.template$'

  def initialize(config:)
    @config = config
  end

  ##
  # Given a file or directory path, emit aggregate results to stdout
  #
  # Return an aggregate failure count (for exit code usage)
  #
  def audit_aggregate_across_files_and_render_results(input_path:,
                                                      output_format: 'txt',
                                                      parameter_values_path: nil,
                                                      condition_values_path: nil,
                                                      template_pattern: DEFAULT_TEMPLATE_PATTERN)

    aggregate_results = audit_aggregate_across_files input_path: input_path,
                                                     parameter_values_path: parameter_values_path,
                                                     condition_values_path: condition_values_path,
                                                     template_pattern: template_pattern

    render_results(aggregate_results: aggregate_results,
                   output_format: output_format)

    aggregate_results.inject(0) do |total_failure_count, results|
      if @config.fail_on_warnings
        total_failure_count + results[:file_results][:violations].length
      else
        total_failure_count + results[:file_results][:failure_count]
      end
    end
  end

  ##
  # Given a file or directory path, return aggregate results
  #
  def audit_aggregate_across_files(input_path:,
                                   parameter_values_path: nil,
                                   condition_values_path: nil,
                                   template_pattern: DEFAULT_TEMPLATE_PATTERN)
    parameter_values_string = parameter_values_path.nil? ? nil : File.read(parameter_values_path)
    condition_values_string = condition_values_path.nil? ? nil : File.read(condition_values_path)

    templates = TemplateDiscovery.new.discover_templates(input_json_path: input_path,
                                                         template_pattern: template_pattern)
    aggregate_results = []
    templates.each do |template|
      aggregate_results << {
        filename: template,
        file_results: audit(cloudformation_string: File.read(template),
                            parameter_values_string: parameter_values_string,
                            condition_values_string: condition_values_string)
      }
    end
    aggregate_results
  end

  ##
  # Given cloudformation json/yml, run all the rules against it
  #
  # Optionally include JSON with Parameters key to substitute into
  # cfn_model.parameters
  #
  # Return a hash with failure count
  #
  def audit(cloudformation_string:, parameter_values_string: nil, condition_values_string: nil)
    begin
      violations = ConditionBranchAuditor.new(config: @config).audit(
        cloudformation_string, parameter_values_string, condition_values_string
      )
    rescue RuleRepoException, Psych::SyntaxError, ParserError => fatal_error
      violations = [Violation.fatal_violation(fatal_error.to_s)]
    rescue JSON::ParserError => json_parameters_error
      error = "JSON Parameter values parse error: #{json_parameters_error}"
      violations = [Violation.fatal_violation(error)]
    end

    violations = prune_fatal_violations(violations) if @config.ignore_fatal
    audit_result(violations)
  end

  def prune_fatal_violations(violations)
    violations.reject { |violation| violation.id == 'FATAL' }
  end

  def render_results(aggregate_results:,
                     output_format:)
    results_renderer(output_format).new.render(aggregate_results, @config.custom_rule_loader.rule_definitions)
  end

  private

  def audit_result(violations)
    {
      failure_count: Violation.count_failures(violations),
      violations: violations
    }
  end

  def results_renderer(output_format)
    registry = {
      'colortxt' => ColoredStdoutResults,
      'txt' => SimpleStdoutResults,
      'json' => JsonResults,
      'sarif' => SarifResults
    }
    registry[output_format]
  end
end
