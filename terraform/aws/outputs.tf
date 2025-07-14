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

output "instance_public_dns" {
  description = "Public DNS name of the EC2 instance"
  value       = aws_instance.main.public_dns
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
  description = "Frontend application URL (using DNS name)"
  value       = "http://${aws_instance.main.public_dns}"
}

output "frontend_url_ip" {
  description = "Frontend application URL (using IP)"
  value       = "http://${aws_instance.main.public_ip}"
}

output "backend_url" {
  description = "Backend API URL (using DNS name)"
  value       = "http://${aws_instance.main.public_dns}:3001"
}

output "api_via_gateway_url" {
  description = "API URL via API Gateway"
  value       = "${aws_api_gateway_deployment.main.invoke_url}/api"
}

output "ssh_connection" {
  description = "SSH connection command (using DNS name)"
  value       = "ssh -i ~/.ssh/vulnshop ec2-user@${aws_instance.main.public_dns}"
}

output "s3_bucket" {
  description = "Deployment S3 bucket"
  value       = aws_s3_bucket.deployment.bucket
}

output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.main.id
}

output "deployment_summary" {
  description = "Deployment summary with all access URLs"
  value = {
    website_dns_url = "http://${aws_instance.main.public_dns}"
    website_ip_url  = "http://${aws_instance.main.public_ip}"
    api_direct_url  = "http://${aws_instance.main.public_dns}:3001/api"
    api_gateway_url = "${aws_api_gateway_deployment.main.invoke_url}/api"
    ssh_access      = "ssh -i ~/.ssh/vulnshop ec2-user@${aws_instance.main.public_dns}"
  }
} 