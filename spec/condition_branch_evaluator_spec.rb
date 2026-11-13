# frozen_string_literal: true

require 'cfn-nag/condition_branch_evaluator'

describe ConditionBranchEvaluator do
  before(:each) do
    @condition_branch_evaluator = ConditionBranchEvaluator.new
  end

  describe '#branch_values' do
    context 'when explicit condition values are supplied' do
      it 'preserves the single-pass condition payload' do
        condition_values_string = '{"UseSnapshot":true}'

        branch_values = @condition_branch_evaluator.branch_values(template, condition_values_string)

        expect(branch_values).to eq [condition_values_string]
      end
    end

    context 'when the template defines conditions but no values are supplied' do
      it 'returns the default pass and an all-false pass covering every condition' do
        branch_values = @condition_branch_evaluator.branch_values(template, nil)

        expect(branch_values.size).to eq 2
        expect(branch_values.first).to be_nil
        expect(JSON.parse(branch_values.last)).to eq(
          'UseSnapshot' => false,
          'RestrictIngress' => false
        )
      end
    end

    context 'when the template defines no conditions' do
      it 'only returns the default pass' do
        template_without_conditions = {
          'Resources' => {
            'Bucket' => { 'Type' => 'AWS::S3::Bucket' }
          }
        }.to_json

        branch_values = @condition_branch_evaluator.branch_values(template_without_conditions, nil)

        expect(branch_values).to eq [nil]
      end
    end

    context 'when the template cannot be parsed' do
      it 'falls back to the default pass instead of raising' do
        branch_values = @condition_branch_evaluator.branch_values('not: valid: yaml: content', nil)

        expect(branch_values).to eq [nil]
      end
    end

    def template
      {
        'Conditions' => {
          'UseSnapshot' => { 'Fn::Equals' => [{ 'Ref' => 'Restore' }, 'true'] },
          'RestrictIngress' => { 'Fn::Equals' => [{ 'Ref' => 'Environment' }, 'prod'] }
        },
        'Resources' => {
          'DbInstance' => { 'Type' => 'AWS::RDS::DBInstance' }
        }
      }.to_json
    end
  end
end
