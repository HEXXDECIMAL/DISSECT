// Migrated from malcontent: discover/browser/agent.yara

rule user_agent_data: low {
  meta:
    description = "gets browser user-agent"
    confidence  = "0.66"

  strings:
$ref = "navigator.userAgentData.get"
  condition:
    any of them
}
