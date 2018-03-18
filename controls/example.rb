# encoding: utf-8
# copyright: 2017, The Authors

title 'sample section'

# IAM Check
control "user-check" do
  impact 0.5
  title 'Check My IAM user'

  describe aws_iam_user(username: 'anthonyrees') do
    it { should exist }
    it { should_not have_mfa_enabled }
  end
end

# S3 checks
control "bjcpublic-check" do
  impact 0.5
  title 'Check My public S3 bucket'


  describe aws_s3_bucket(bucket_name: 'bjcpublic') do
    it { should exist }
    it { should be_public }
    its('region') { should eq 'us-west-2' }
  end
end

# Security Groups

control "all-open-check" do
  impact 0.5
  title 'Check My all open security group.'

  describe aws_security_group(group_name: 'all-open') do
    it { should exist }
    its('vpc_id') { should cmp 'vpc-a966e6cc' }
  end
  
end

control "Validate SGs on VPC" do
  impact 0.7
  title 'Ensure expected security groups all exist.'

  describe aws_security_groups.where( vpc_id: 'vpc-a966e6cc') do
    its('group_ids') { should include('sg-1cea9178')}
    its('group_ids') { should include('sg-26eb0b42')}
    its('group_ids') { should include('sg-0f35f46b')}
  end

end

# Workstation check

control "workstation-check" do
  impact 1.0
  title 'Check the bjc workstation'

  describe aws_ec2_instance(name: 'bjc-demo Workstation') do
    it { should exist }
    it { should be_running }
    its('image_id') { should eq 'ami-6bb13613' }
    its('tags') { should include(key: 'TTL', value: cmp <= '1000') }
  end
end