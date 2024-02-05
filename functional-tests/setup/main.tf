resource "aws_s3_bucket" "cdn_app" {
  bucket = "omega-testbucket-app-x"

  tags = {
    TestResource = true
  }
}


output "bucket_name" {
  value = aws_s3_bucket.cdn_app.id
}
