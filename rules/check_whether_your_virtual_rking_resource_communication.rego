package rules.check_whether_your_virtual_rking_resource_communication

__rego__metadoc__ := {
	"custom": {
		"controls": {
			"VM": [
				"VM_1.0"
			]
		},
		"severity": "Medium"
	},
	"description": "Document: Technology Engineering - Virtual Machine - Best Practice - Version: 1",
	"id": "1.0",
	"title": "Check whether your virtual machine instances are integrated with an VPC to ensure secure networking and resource communication.",
}

# Please write your OPA rule here
resource_type = "aws_instance"

default allow = false

allow {
	input.subnet_id != null
}

