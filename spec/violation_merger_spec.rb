# frozen_string_literal: true

require 'cfn-nag/violation_merger'

describe ViolationMerger do
  before(:each) do
    @violation_merger = ViolationMerger.new
  end

  describe '#merge' do
    context 'when the same rule fires on different resources across branches' do
      it 'combines the resource ids into a single violation' do
        true_branch_violation = violation(%w[ResourceA], [1], %w[resource])
        false_branch_violation = violation(%w[ResourceB], [2], %w[resource])

        merged_violations = @violation_merger.merge([
                                                      [true_branch_violation],
                                                      [false_branch_violation]
                                                    ])

        expect(merged_violations.size).to eq 1
        expect(merged_violations.first.id).to eq 'F1'
        expect(merged_violations.first.logical_resource_ids).to eq %w[ResourceA ResourceB]
        expect(merged_violations.first.line_numbers).to eq [1, 2]
        expect(merged_violations.first.element_types).to eq %w[resource resource]
      end
    end

    context 'when the same rule fires on the same resource across branches' do
      it 'keeps a single resource id and aligned line number' do
        true_branch_violation = violation(%w[ResourceA], [1], %w[resource])
        false_branch_violation = violation(%w[ResourceA], [1], %w[resource])

        merged_violations = @violation_merger.merge([
                                                      [true_branch_violation],
                                                      [false_branch_violation]
                                                    ])

        expect(merged_violations.size).to eq 1
        expect(merged_violations.first.logical_resource_ids).to eq %w[ResourceA]
        expect(merged_violations.first.line_numbers).to eq [1]
        expect(merged_violations.first.element_types).to eq %w[resource]
      end
    end

    context 'when distinct rules fire across branches' do
      it 'keeps one violation per rule id' do
        failure_violation = violation(%w[ResourceA], [1], %w[resource], id: 'F1')
        warning_violation = violation(%w[ResourceB], [2], %w[resource],
                                      id: 'W2', type: Violation::WARNING)

        merged_violations = @violation_merger.merge([
                                                      [failure_violation],
                                                      [warning_violation]
                                                    ])

        expect(merged_violations.map(&:id)).to eq %w[F1 W2]
      end
    end

    context 'when a branch has no violations' do
      it 'still reports the violations from the other branch' do
        branch_violation = violation(%w[ResourceA], [1], %w[resource])

        merged_violations = @violation_merger.merge([
                                                      [branch_violation],
                                                      []
                                                    ])

        expect(merged_violations.size).to eq 1
        expect(merged_violations.first.logical_resource_ids).to eq %w[ResourceA]
      end
    end

    def violation(logical_resource_ids, line_numbers, element_types,
                  id: 'F1', type: Violation::FAILING_VIOLATION)
      Violation.new(id: id,
                    name: 'MyRule',
                    type: type,
                    message: 'rule message',
                    logical_resource_ids: logical_resource_ids,
                    line_numbers: line_numbers,
                    element_types: element_types)
    end
  end
end
