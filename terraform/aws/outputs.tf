output "instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.main.id
}

output "instance_public_ip" {
  description = "Public IP address of the EC2 instance"
  value       = aws_instance.main.public_ip
}

output "instance_private_ip" {
  description = "Private IP address of the EC2 instance"
  value       = aws_instance.main.private_ip
}

output "api_gateway_id" {
  description = "API Gateway REST API ID"
  value       = aws_api_gateway_rest_api.main.id
}

output "api_gateway_url" {
  description = "API Gateway invoke URL"
  value       = aws_api_gateway_deployment.main.invoke_url
}

output "frontend_url" {
  description = "Frontend application URL"
  value       = "http://${aws_instance.main.public_ip}"
}

output "backend_url" {
  description = "Backend API URL"
  value       = "http://${aws_instance.main.public_ip}:3001"
}

output "api_via_gateway_url" {
  description = "API URL via API Gateway"
  value       = "${aws_api_gateway_deployment.main.invoke_url}/api"
}

output "ssh_connection" {
  description = "SSH connection command"
  value       = "ssh -i ~/.ssh/vulnshop ec2-user@${aws_instance.main.public_ip}"
}

output "s3_bucket" {
  description = "Deployment S3 bucket"
  value       = aws_s3_bucket.deployment.bucket
}

output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.main.id
} 