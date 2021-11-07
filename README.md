
<p1> #Notes: </p1>
<div>
<p2 class="small"> 
# Releasing this because my laptop has probably been compromised .<br>
# The script was created out of pure frustation of having to manually update my security group entries before I can connect to my AWS instances.<br>
# This script creates two security groups in your AWS Account namely "RDP" and "SSH" <br>
# It also enumerates all instances your default AWS region , and ensures that the appropriate security group is linked to each of these instances at all        times.<br>
# The SSH Group will be linked to Linux instances ,while the RDP Security Group remains linked to your windows instances.<br>
# Because I wanted these conditions to be monitored constantly ,the script was implemented as a loop .<br>
# This also means that the powershell window this script is executed in , should remain open at all times.<br>
# It also maintains a consistent pemission entry for your public IP address in each of these security groups.<br>
# In windows the script should be executed as Administrator , in Linux as Root.<br>
# This version is region specific , and you are required to manually perform the initial cofiguration for the AWS Powershell tools.<br>
# https://docs.aws.amazon.com/powershell/latest/userguide/specifying-your-aws-credentials.html#specifying-your-aws-credentials-use.<br>
# The script runs on both Windows and Linux , provided that Powershell is installed in your linux environment.<br>
# None of the code is stolen , or taken from anywhere on the internet.<br>
# each line has been painstakingly written by me.<br>
# And I will take a polygraph to prove it.</p2> <br>
</div>

