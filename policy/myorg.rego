#
# METADATA
# description: |-
#   Verify "myorg-task" does not exist in a build
#
package policy.myorg

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib


# METADATA
# title: myorg-task does not exist
# description: |-
#   This policy enforces that a task named "myorg-task" does not exist in a build
# custom:
#   short_name: myorg_task_missing
#   failure_msg: myorg-task missing from build pipeline
deny contains result if {
  count({task | some task in input.predicate.buildConfig.tasks; task.name == "myorg-task"}) == 0
  result := lib.result_helper(rego.metadata.chain(), [])
  #result := "myorg-task not found"
}

