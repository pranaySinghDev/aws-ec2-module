locals {
  extract_resource_name = lower("${var.common_name_prefix}-${var.environment}")
}

#Get Latest Amazon Linux AMI
data "aws_ami" "amazon-2" {
  most_recent = true

  filter {
    name = "name"
    values = ["amzn2-ami-hvm-*-x86_64-ebs"]
  }
  owners = ["amazon"]
}

resource "aws_iam_policy" "eks_policy" {
  name        = "${local.extract_resource_name}-EKSAccess"
  path        = "/"
  description = "EKS management policy for bastion host"
  policy      = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "eks:*",
        "ec2:Describe*",
        "iam:ListRoles",
        "autoscaling:Describe*",
        "cloudformation:Describe*"
      ],
      "Resource": "*"
    }
  ]
}
EOF
}
resource "aws_iam_role" "bastion-iam-role" {
  name = "${local.extract_resource_name}-bastion-iam-role"

  managed_policy_arns = ["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore", "arn:aws:iam::aws:policy/AmazonS3FullAccess"]

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}
resource "aws_iam_role_policy_attachment" "eks_policy_attachment" {
  role       = aws_iam_role.bastion-iam-role.name
  policy_arn = aws_iam_policy.eks_policy.arn
}
resource "aws_iam_instance_profile" "bastion-iam-instance-profile" {
  name = "${local.extract_resource_name}-bastion-iam-instance-profile"
  role = aws_iam_role.bastion-iam-role.name
}

resource "aws_instance" "bastion" {
  ami                  = data.aws_ami.amazon-2.id
  instance_type        = "t3.micro"
  iam_instance_profile = aws_iam_instance_profile.bastion-iam-instance-profile.name
  subnet_id            = var.subnet-app-a-id
  associate_public_ip_address = false

  vpc_security_group_ids = [
    var.app-sg-id,
    var.postgres_security_group_id
  ]

  root_block_device {
    volume_size           = "8"
    volume_type           = "gp2"
    encrypted             = true
    delete_on_termination = true
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens = "required"
  }

  user_data = <<-EOL
  #!/bin/bash -xe
  sudo yum remove -y awscli
  curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
  unzip awscliv2.zip
  sudo ./aws/install
  curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
  chmod +x kubectl
  sudo mv kubectl /usr/local/bin
  aws eks update-kubeconfig --region ${var.region} --name ${var.cluster_name}
  sudo amazon-linux-extras install postgresql10 -y
  sudo yum install socat -y
  EOL

  tags = merge(
    {
      "Name" = format("%s", "${local.extract_resource_name}-bastion")
    },
    {
      environment = var.environment
    },
    var.tags,
  )
}