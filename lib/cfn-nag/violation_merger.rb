# frozen_string_literal: true

require_relative 'violation'

# Merges violations collected while auditing different condition branches.
# A single Violation is emitted per rule id, carrying the union of the
# logical resource ids (and their aligned line numbers / element types)
# reported by any reachable branch.
class ViolationMerger
  def merge(violation_collections)
    merged_violations = {}

    violation_collections.flatten.each do |violation|
      if merged_violations.key?(violation.id)
        merge_violation(merged_violations[violation.id], violation)
      else
        merged_violations[violation.id] = duplicate_violation(violation)
      end
    end

    merged_violations.values
  end

  private

  def merge_violation(target, source)
    source.logical_resource_ids.each_with_index do |logical_resource_id, index|
      next if target.logical_resource_ids.include?(logical_resource_id)

      target.logical_resource_ids << logical_resource_id
      target.line_numbers << source.line_numbers[index]
      target.element_types << source.element_types[index]
    end
  end

  def duplicate_violation(violation)
    Violation.new(
      id: violation.id,
      name: violation.name,
      type: violation.type,
      message: violation.message,
      logical_resource_ids: violation.logical_resource_ids.dup,
      line_numbers: violation.line_numbers.dup,
      element_types: violation.element_types.dup
    )
  end
end
