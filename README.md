#Notes:
# releasing this because my laptop has probably been compromised .
# The script was created out of pure frustation of having to manually update my security group entries before I can connect to my AWS instances.
# This script creates two security groups in your AWS Account namely "RDP" and "SSH"
# It also enumerates all instances your default AWS region , and ensures that the appropriate security group is linked to each of these instances at all times.
# The SSH Group will be linked to Linux instances ,while the RDP Security Group remains linked to your windows instances.
# Because I wanted these conditions to be monitored constantly ,the script was implemented as a loop .
# This also means that the powershell window this script is executed in , should remain open at all times.
# It also maintains a consistent pemission entry for your public IP address in each of these security groups .
# In windows the script should be executed as Administrator , in Linux as Root
# This version is region specific , and you are required to manually perform the initial cofiguration for the AWS Powershell tools .
# https://docs.aws.amazon.com/powershell/latest/userguide/specifying-your-aws-credentials.html#specifying-your-aws-credentials-use.
# The script runs on both Windows and Linux , provided that Powershell is installed in your linux environment .
# None of the code is stolen , or taken from anywhere on the internet .
# each line has been painstakingly written by me .
# And I will take a polygraph to prove it .

