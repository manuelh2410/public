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



Do
{


       Write-host START LOG
       Get-Date
       #Set-PSDebug -Trace 2
       #Start-Sleep -Seconds 120




      Write-Host "Checking OS Type"

   IF ($IsWindows -Like "True")

      {
       DO{
                   write-host Inspecting Registry [AWSIP] registry key  [<<outer loop>>]
                   if(Test-Path -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP')
                       {write-host [AWSIP] registry key is present}
                   else
                       {
                         New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP"
                         New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\config"
                         $RDPGroup = New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -Name "RDPGroup" -Value "0"
                         $SSHGroup = New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -Name "SSHGroup" -Value "0"
                         $RDPRuleID = New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -Name "RDPRULEID" -Value "0"
                         $SSHRuleID = New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -Name "SSHRULEID" -Value "0"
                         $NEWRDPGroup = New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -Name "NEWRDPGroup" -Value "0"
                         $NEWSSHGroup = New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -Name "NEWSSHGroup" -Value "0"
                         $OLDIP = New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -Name "OLDIP" -Value "0"  -PropertyType "String"
                         $MYIP = New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -Name "MYIP" -Value "0"  -PropertyType "String"
                       }
         } until ( (Test-Path -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP') -like "True")
      }


   IF ($IsWindows -Like "False")
                  {
                   Do{
                    if(Test-Path -Path '/var/log/AWSIP')
                    {write-host [AWSIP] folders are present}
                     else
                         {

                          New-Item -Path "/var/log" -Name "AWSIP" -ItemType "directory"
                          New-Item -Path "/var/log/AWSIP" -Name "config" -ItemType "directory"


                          chmod -R +0777 "/var/log/AWSIP"

                          New-Item -Path "/var/log/AWSIP/config" -Name "RDPGroup.log" -ItemType "file"
                          New-Item -Path "/var/log/AWSIP/config" -Name "SSHGroup.log" -ItemType "file"
                          New-Item -Path "/var/log/AWSIP/config" -Name "NEWRDPGroup.log" -ItemType "file"
                          New-Item -Path "/var/log/AWSIP/config" -Name "NEWSSHGroup.log" -ItemType "file"
                          New-Item -Path "/var/log/AWSIP/config" -Name "SSHRULEID.log" -ItemType "file"
                          New-Item -Path "/var/log/AWSIP/config" -Name "RDPRULEID.log" -ItemType "file"
                          New-Item -Path "/var/log/AWSIP/config" -Name "OLDIP.log" -ItemType "file"
                          New-Item -Path "/var/log/AWSIP/config" -Name "MYIP.log" -ItemType "file"



                          chmod -R +0777 "/var/log/AWSIP"


                          set-content -Path  /var/log/AWSIP/config/RDPGroup.log  -Value 0
                          set-content -Path  /var/log/AWSIP/config/SSHGroup.log  -Value 0
                          set-content -Path  /var/log/AWSIP/config/NEWRDPGroup.log  -Value 0
                          set-content -Path  /var/log/AWSIP/config/NEWSSHGroup.log  -Value 0
                          set-content -Path  /var/log/AWSIP/config/SSHRULEID.log  -Value 0
                          set-content -Path  /var/log/AWSIP/config/RDPRULEID.log  -Value 0
                          set-content -Path  /var/log/AWSIP/config/OLDIP.log -Value 0
                          set-content -Path  /var/log/AWSIP/config/MYIP.log -Value 0

                          $RDPGroup = get-content -Path  /var/log/AWSIP/config/RDPGroup.log
                          $SSHGroup = get-content -Path  /var/log/AWSIP/config/SSHGroup.log
                          $NEWRDPGroup = get-content -Path  /var/log/AWSIP/config/NEWRDPGroup.log
                          $NEWSSHGroup = get-content -Path  /var/log/AWSIP/config/NEWSSHGroup.log
                          $OLDIP = get-content -Path  /var/log/AWSIP/config/OLDIP.log
                          $MYIP = get-content -Path  /var/log/AWSIP/config/MYIP.log
                         }
                   } until ((Test-Path -Path '/var/log/AWSIP') -like "True")
                  }





 Write-host AWS Powershell Tools  availability check [<<outer loop>>]

       $versions = {4,5,5.1}
       #\\\\\\\\\\\\\\\\\\\\\\\\\\\\



           IF ((Get-Module -ListAvailable).Name -notcontains "AWSPowerShell" -or "AWSPowerShell.NetCore")
                 {
                     DO
                     {
                         if (($PSVersionTable).PSEdition -like "core" -and (($PSVersionTable).PSversion.Major -ge "6") -or
                             (($PSVersionTable).PSEdition -like "desktop" -and (($PSVersionTable).PSversion.Major -in $versions)) -and ((Get-Module -ListAvailable).Name -notcontains "AWSPowerShell.NetCore"))

                            {


                                          DO {

                                                 Write-Host installing AWSPowerShell.NetCore
                                                 Install-Module -name AWSPowerShell.NetCore -Scope  AllUsers -force
                                                 Write-Host importing AWSPowerShell.NetCore
                                                 Import-Module -name AWSPowerShell.NetCore -Scope  Global -force

                                             } until ((Get-Module -ListAvailable).Name -contains "AWSPowerShell.NetCore")

                                              IF ((Get-Module -ListAvailable).Name -contains "AWSPowerShell.NetCore")
                                                  {write-host AWSPowerShell.NetCore Support Added}


                            }


                         if ((($PSVersionTable).PSEdition -like "desktop") -and (($PSVersionTable).PSversion.Major -eq "3") -and
                            ((Get-Module -ListAvailable).Name -contains "AWSPowerShell"))
                           {

                                 Write-Host attempting initial import AWSPowerShell
                                 Import-Module -name AWSPowerShell -Scope  Global -force


                                      Write-Host installing AWSPowerShell Module
                                         Do {
                                             try
                                               {
                                                 Install-Module -name AWSPowerShell -Scope  AllUsers -force
                                               }
                                                 catch {
                                                         Do {

                                                             Write-Host Getting PS-Get Module
                                                             invoke-webrequest -Uri https://psg-prod-eastus.azureedge.net/packages/powershellget.2.2.5.nupkg -OutFile 'c:\temp\AWSPowerShell.zip'
                                                             Expand-archive "C:\temp\AWSPowerShell.zip" "C:\temp\AWSPowerShell"
                                                             Move-item "C:\temp\AWSPowerShell\PowerShellGet.psd1" "C:\Program Files\WindowsPowerShell\Modules"
                                                             Import-Module -Name PowerShellGet -Scope Global -Force
                                                             Update-Module -Name PowerShellGet
                                                             } until ((Get-Module -ListAvailable).Name -contains "PowerShellGet")
                                                       }

                                           } until ((Get-Module -ListAvailable).Name -contains "AWSPowerShell")

                           }
                     } until ((Get-Module -ListAvailable).Name -contains"AWSPowerShell" -or "AWSPowerShell.NetCore")

                 }

                 IF ((Get-Module -ListAvailable).Name -contains "AWSPowerShell")
                    {Import-Module -name AWSPowerShell -Scope  Global -force
                     Write-Host importing AWSPowerShell} elseif
                    ((Get-Module -ListAvailable).Name -contains "AWSPowerShell.NetCore")
                    {Import-Module -name AWSPowerShell.NetCore -Scope  Global -force
                     Write-Host importing AWSPowerShell.NetCore}



       #1st Run
       If (($SSHGroup -and $RDPGroup -eq '0') -and ($NEWRDPGroup -and $NEWRDPGROUP-eq '0') -and ($OLDIP -and $MYIP -eq '0'))
       {set-variable -name FIRSTRUN -value "1"} else {set-variable -name FIRSTRUN -value "0"}




      write-host checking current public ip      [<<outer loop>>]

      Do  {
           try{
               write-host "checking API-1"
               $webip = Invoke-RestMethod -Uri 'https://ip.seeip.org?format=json'
               }
               catch {
                     write-host "checking API-2"
                      $webip = Invoke-RestMethod -Uri 'https://api.ipify.org?format=text'
                      }
                      Finally{
                             write-host "checking API-3"
                             $webip = Invoke-RestMethod -Uri 'https://checkip.amazonaws.com?format=json'
                             }
           }
      until ($webip -like "*.*")



      $Sub = "/32"
      $MyIP = $webip.trim()+$sub


    IF ($IsWindows -Like "True")
       {
        SET-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -Name "MYIP" -Value "$MYIP"
       }
       IF ($IsWindows -Like "False")
            {
             Set-content -Path  /var/log/AWSIP/config/MYIP.log -Value $MYIP
            }



#//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
IF ((Get-Module -ListAvailable).Name -contains "AWSPowerShell" -or "AWSPowerShell.NetCore")
      {
             if (($RDPGROUP -eq '1') -and ($SSHGroup -eq '1'))
                {
                  $instances = ((Get-EC2Instance).Instances).InstanceID
            write-host Instances enumerated  [<<outer loop>>]


                  $RDP = (Get-EC2SecurityGroup -GroupName "RDP").GroupId
                  $SSH = (Get-EC2SecurityGroup -GroupName "SSH").GroupId

            Write-host "START Instance vs SG Group evaluation"
               Foreach ($instance in $instances)
                {
                  IF(((Get-EC2Instance -InstanceId $instance).Instances.securitygroups.GroupName -notcontains "RDP") -or  ((Get-EC2Instance -InstanceId $instance).Instances.securitygroups.GroupName -notcontains "SSH"))

                    { write-host Evaluating Groups for instance $instance
                      Do
                        {


                                         if (((Get-EC2Instance -InstanceId $instance).Instances.securitygroups.GroupName -notcontains "SSH") -and ((get-ec2instance $instance).Instances.Platform -notcontains "Windows" ))

            								    {write-host NO_SSH_GROUP LINKED TO Linux_INSTANCE $instance

                                                  Do{

                                                    $instanceGroups = ((Get-EC2InstanceAttribute -InstanceId $instance -Attribute groupSet).Groups).Groupid

                                                    $commandstring = ($SSH,$instanceGroups) -split ' '
                                                    Edit-EC2InstanceAttribute -InstanceId $instance -Group $commandstring
                                                    } until((Get-EC2Instance -InstanceId $instance).Instances.securitygroups.GroupName -contains "SSH")
            									}
            									  if((Get-EC2Instance -InstanceId $instance).Instances.securitygroups.GroupName -contains "SSH") {write-host SSH-GROUP linked to $instance}






                                           if (((Get-EC2Instance -InstanceId $instance).Instances.securitygroups.GroupName -notcontains "RDP") -and  ((get-ec2instance $instance).Instances.Platform -contains "Windows" ))

            		                           {write-host NO_RDP_GROUP LINKED TO Windows_INSTANCE $instance      [>>inner loop<<]

                            					 Do{

                                                    $instanceGroups = ((Get-EC2InstanceAttribute -InstanceId $instance -Attribute groupSet).Groups).Groupid

                                                    $commandstring = ($RDP,$instanceGroups) -split ' '

                                                    Edit-EC2InstanceAttribute -InstanceId $instance -Group $commandstring
            										} until((Get-EC2Instance -InstanceId $instance).Instances.securitygroups.GroupName -contains "RDP")
            				       			   }
            								   if((Get-EC2Instance -InstanceId $instance).Instances.securitygroups.GroupName -contains "RDP") {write-host RDP-GROUP linked to $instance}


            		    } until (((Get-EC2Instance -InstanceId $instance).Instances.securitygroups.GroupName -contains "RDP") -or ((Get-EC2Instance -InstanceId $instance).Instances.securitygroups.GroupName -contains "SSH"))
            write-host "END Instance vs Group remediation"   [>>inner loop<<]
                    } write-host "END Instance vs Group evaluation" $instance    [>>inner loop<<]
                }

             }



                #OLDIP
                #OS Check:
                IF ($IsWindows -Like "True")

                   {
                     If ($FirstRun -eq '1')
                        {$OLDIP = (GET-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -Name "OLDIP").OLDIP}
                        IF(($MYIP -ne $OLDIP) -and ($MYIP -ne "0") -and ($OLDIP -ne "0"))

                        {write-host IP ADDRESSES out of SYNC!!!!! [outer loop]} elseif
                        (($MYIP -eq $OLDIP) -and ($MYIP -ne "0")-and($OLDIP -ne "0"))
                        {write-host IP ADDRESSES IN SYNC [<<outer loop>>]}
                   }

                 IF ($IsWindows -Like "False")

                    {
                       $OLDIP = (get-content -Path  /var/log/AWSIP/config/OLDIP.log)
                       IF(($MYIP -ne $OLDIP) -and ($MYIP -ne "0")-and($OLDIP -ne "0"))

                       {write-host IP ADDRESSES out of SYNC!!!!! [outer loop]} elseif
                       (($MYIP -eq $OLDIP) -and ($MYIP -ne "0")-and($OLDIP -ne "0"))
                       {write-host IP ADDRESSES IN SYNC [<<outer loop>>]}
                    }



               IF($IsWindows -Like "True")
                   {

                    $RDPGROUP = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -name "RDPGroup").RDPGROUP
                    $SSHGROUP = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -name "SSHGroup").SSHGROUP
                   }

               IF ($IsWindows -Like "False")
                  {

                    $SSHGroup = (get-content -Path  /var/log/AWSIP/config/SSHGroup.log)
                    $RDPGroup = (get-content -Path  /var/log/AWSIP/config/RDPGroup.log)
                  }


                 If (($RDPGroup -or $SSHGroup -eq '0') -or ($FIRSTRUN -eq '1'))
                 {

                 Do
                 {
                    Do
                     {
                     Try
                     {
                     $OLDRDPGroup = (Get-EC2SecurityGroup -GroupName RDP).GroupId
                     }
                     Catch
                     {
                     write-host RDP GROUP DOES NOT EXIST,Creating.............[RDP Group Creation loop] [>>Inner loop<<]
                     $NEWRDPGroup = New-EC2SecurityGroup -GroupName RDP -Description "Windows remote Access"
                     }
                     finally
                     {
                     if ($NEWRDPGroup -like "sg-*")
                     {write-host  RDP Group Exists [RDP Group Creation loop]  [>>Inner loop<<]}
                      }


                     }until (($NEWRDPGroup -like "sg-*") -or ($OLDRDPGroup -like "sg-*"))


                    Do
                     {
                      Try
                       {
                         $OLDSSHGroup = (Get-EC2SecurityGroup -GroupName SSH).GroupId
                       }
                       Catch
                       {
                         write-host SSH GROUP DOES NOT EXIST,Creating.............[SSH Group Creation loop] [>>Inner loop<<]
                         $NEWSSHGroup = New-EC2SecurityGroup -GroupName SSH -Description "Linux remote Access"
                       }
                       finally
                       {
                         if ($NEWSSHGroup -like "sg-*")
                            {write-host  SSH Group Exists. [SSH Group Creation loop]  [>>Inner loop<<]}
                       }

                     }until (($NEWSSHGroup -like "sg-*") -or ($OLDSSHGroup -like "sg-*"))

                  } until ((($NEWRDPGroup -like "sg-*") -and ($NEWSSHGroup -like "sg-*")) -or (($OLDRDPGroup -like "sg-*") -and ($OLDSSHGroup -like "sg-*")))


                 IF ($IsWindows -Like "True")
                     #Windows:
                     {
                      IF  ((($OLDSSHGroup -like "sg-*") -or ($NEWSSHGroup -like "sg-*")) -and (Get-EC2SecurityGroup -GroupName "SSH").GroupId -like "sg-*")
                          {SET-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -Name "SSHGroup" -Value "1"}
                      IF  ($NEWSSHGroup -like "sg-*")
                          {SET-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -Name "NEWSSHGroup" -Value "1"}


                      IF  ((($OLDRDPGroup -like "sg-*") -or ($NEWRDPGroup -like "sg-*")) -and (Get-EC2SecurityGroup -GroupName "RDP").GroupId -like "sg-*")
                          {SET-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -Name "RDPGroup" -Value "1"}
                          IF  ($NEWRDPGroup -like "sg-*")
                          {SET-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -Name "NEWRDPGroup" -Value "1"}
                     }

                    IF ($IsWindows -Like "False")
                      #Linux:
                      {
                        IF ((($OLDSSHGroup -like "sg-*") -or ($NEWSSHGroup -like "sg-*")) -and (Get-EC2SecurityGroup -GroupName "SSH").GroupId -like "sg-*")
                            {$SSHGroup = set-content -Path  /var/log/AWSIP/config/SSHGroup.log  -Value "1"} else
                            {$SSHGroup = set-content -Path  /var/log/AWSIP/config/SSHGroup.log  -Value "0"}
                        IF  ($NEWSSHGroup -like "sg-*")
                            {$NEWSSHGroup = set-content -Path  /var/log/AWSIP/config/NEWSSHGroup.log  -Value "1"}


                        IF ((($OLDRDPGroup -like "sg-*") -or ($NEWRDPGroup -like "sg-*")) -and (Get-EC2SecurityGroup -GroupName "RDP").GroupId -like "sg-*")
                            {$RDPGroup = set-content -Path  /var/log/AWSIP/config/RDPGroup.log  -Value "1"} else
                            {$RDPGroup = set-content -Path  /var/log/AWSIP/config/RDPGroup.log  -Value "0"}

                        IF ($NEWRDPGroup -like "sg-*")
                           {$NEWRDPGroup = set-content -Path  /var/log/AWSIP/config/NEWRDPGroup.log  -Value "1"}
                      }
                }

            #///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



                 If ($IsWindows -Like "True")
                    {

                     $RDPGROUP = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -name "RDPGroup").RDPGroup
                     $SSHGROUP = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -name "SSHGroup").SSHGroup
                     $NEWRDPGROUP = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -name "NEWRDPGroup").NEWRDPGroup
                     $NEWSSHGROUP = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -name "NEWSSHGroup").NEWSSHGroup
                     $RDP = (Get-EC2SecurityGroup -GroupName "RDP").GroupId
                     $SSH = (Get-EC2SecurityGroup -GroupName "SSH").GroupId
                     $OLDIP = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -name "OLDIP").OLDIP
                    }

                 IF ($IsWindows -Like "False")
                    {

                     $RDPGroup = get-content -Path  /var/log/AWSIP/config/RDPGroup.log
                     $SSHGroup = get-content -Path  /var/log/AWSIP/config/SSHGroup.log
                     $NEWRDPGroup = get-content -Path  /var/log/AWSIP/config/NEWRDPGroup.log
                     $NEWSSHGroup = get-content -Path  /var/log/AWSIP/config/NEWSSHGroup.log
                     $RDP = (Get-EC2SecurityGroup -GroupName "RDP").GroupId
                     $SSH = (Get-EC2SecurityGroup -GroupName "SSH").GroupId
                     $OLDIP = get-content -Path  /var/log/AWSIP/config/OLDIP.log
                    }

                    #
                    #TAG /Filter Config

                    #TAG
                    $Tag = New-Object Amazon.EC2.Model.Tag
                    $Tag.Key = "AWSIP"
                    $Tag.Value = "manuel"
                    #
                    $Tagspec = New-Object Amazon.EC2.Model.TagSpecification
                    $Tagspec.Tags = $Tag
                    $Tagspec.ResourceType = "security-group-rule"
                    #
                    #Filter
                    $filter = New-Object Amazon.EC2.Model.Filter
                    $filter.name = "tag:AWSIP"
                    $filter.value = "manuel"
                    #
                     If ((($OLDIP -ne $MYIP) -and ($NEWRDPGroup -eq "1") -and ($NEWSSHGroup -eq "1")) -or ($FIRSTRUN -eq '1') )
                    {
                    #
                    Write-host NEW Groups Adding Permssions
                    $ip1 = @{ IpProtocol="tcp"; FromPort="22"; ToPort="22"; IpRanges="$MYIP"}
                    $ip2 = @{ IpProtocol="tcp"; FromPort="3389"; ToPort="3389"; IpRanges="$MYIP"}
                    $SSHRuleID = (GRANT-EC2SecurityGroupIngress -GroupID $SSH -IpPermission @( $ip1 ) -TagSpecification $Tagspec -select SecurityGroupRules).SecurityGroupRuleId
                    $RDPRuleID = (GRANT-EC2SecurityGroupIngress -GroupID $RDP -IpPermission @( $ip2 ) -TagSpecification $Tagspec -select SecurityGroupRules).SecurityGroupRuleId
                    }
                    elseif
                    ((($OLDIP -ne $MYIP) -and ($RDPGROUP -and $SSHGROUP -eq "1") -and ($FIRSTRUN -eq '0')))
                    {
                    #
                    Write-host Groups Exist  Removing Old Permissions before Adding Permissions

                    REVOKE-EC2SecurityGroupIngress -GroupID $SSH -SecurityGroupRuleId $SSHRule
                    REVOKE-EC2SecurityGroupIngress -GroupID $RDP -SecurityGroupRuleId $RDPRule
                    #
                    Write-host Adding Permissions After Removal
                    $ip1 = @{ IpProtocol="tcp"; FromPort="22"; ToPort="22"; IpRanges="$MYIP"}
                    $ip2 = @{ IpProtocol="tcp"; FromPort="3389"; ToPort="3389"; IpRanges="$MYIP"}
                    $SSHRuleID = (GRANT-EC2SecurityGroupIngress -GroupID $SSH -IpPermission @( $ip1 ) -TagSpecification $Tagspec -select SecurityGroupRules).SecurityGroupRuleId
                    $RDPRuleID = (GRANT-EC2SecurityGroupIngress -GroupID $RDP -IpPermission @( $ip2 ) -TagSpecification $Tagspec -select SecurityGroupRules).SecurityGroupRuleId
                    }
                        #SETOLIP
                        #
                        IF ($IsWindows -Like "True")
                           {
                             try  {
                                   if ((Get-EC2SecurityGrouprule -filter $filter).CidrIpv4[0] -like "*.*.*.*/*")
                                      {
                                       $OLDIP = (Get-EC2SecurityGrouprule -filter $filter).CidrIpv4[0]
                                       SET-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -Name "OLDIP" -Value "$OLDIP"
                                      }
                                  }
                                   catch
                                        {
                                          Write-host Adding Permissions After Removal
                                          $ip1 = @{ IpProtocol="tcp"; FromPort="22"; ToPort="22"; IpRanges="$MYIP"}
                                          $ip2 = @{ IpProtocol="tcp"; FromPort="3389"; ToPort="3389"; IpRanges="$MYIP"}
                                          $SSHRuleID = (GRANT-EC2SecurityGroupIngress -GroupID $SSH -IpPermission @( $ip1 ) -TagSpecification $Tagspec -select SecurityGroupRules).SecurityGroupRuleId
                                          $RDPRuleID = (GRANT-EC2SecurityGroupIngress -GroupID $RDP -IpPermission @( $ip2 ) -TagSpecification $Tagspec -select SecurityGroupRules).SecurityGroupRuleId
                                          SET-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -Name "SSHRULEID" -Value $SSHRuleID
                                          SET-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -Name "RDPRULEID" -Value $RDPRuleID
                                        }
                           }

                        IF ($IsWindows -Like "False")
                          {
                            try  {
                                  if ((Get-EC2SecurityGrouprule -filter $filter).CidrIpv4[0] -like "*.*.*.*/*")
                                     {
                                      $OLDIP = (Get-EC2SecurityGrouprule -filter $filter).CidrIpv4[0]
                                      set-content -Path  /var/log/AWSIP/config/OLDIP.log -Value "$OLDIP"
                                     }
                                 }
                                  catch{
                                        Write-host Adding Permissions After Removal
                                        $ip1 = @{ IpProtocol="tcp"; FromPort="22"; ToPort="22"; IpRanges="$MYIP"}
                                        $ip2 = @{ IpProtocol="tcp"; FromPort="3389"; ToPort="3389"; IpRanges="$MYIP"}
                                        $SSHRuleID = (GRANT-EC2SecurityGroupIngress -GroupID $SSH -IpPermission @( $ip1 ) -TagSpecification $Tagspec -select SecurityGroupRules).SecurityGroupRuleId
                                        $RDPRuleID = (GRANT-EC2SecurityGroupIngress -GroupID $RDP -IpPermission @( $ip2 ) -TagSpecification $Tagspec -select SecurityGroupRules).SecurityGroupRuleId
                                        set-content -Path  /var/log/AWSIP/config/SSHRULEID.log -Value $SSHRuleID
                                        set-content -Path  /var/log/AWSIP/config/RDPRULEID.log -Value $RDPRuleID
                                       }
                           }

                 #
                IF($IsWindows -Like "True")
                {

                 If ($RDPGroup -eq '1' -and $SSHGRoup -eq '1' -and $FirstRun -eq '0')
                    {
                     Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -Name "NEWRDPGroup" -Value "0"
                     Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -Name "NEWSSHGroup" -Value "0"
                     Set-Variable -name NEWRDPGroup -Value '0'
                     Set-Variable -name NEWSSHGroup -Value '0'
                    }
                }
                 IF ($IsWindows -Like "False")
                    {
                      if($RDPGroup -eq '1' -and $SSHGRoup -eq '1' -and $FirstRun -eq '0')
                      {
                      set-content -Path  /var/log/AWSIP/config/NEWRDPGroup.log  -Value '0'
                      set-content -Path  /var/log/AWSIP/config/NEWSSHGroup.log  -Value '0'
                      Set-Variable -name NEWRDPGroup -Value '0'
                      Set-Variable -name NEWSSHGroup -Value '0'
                      }
                    }


      }
} until ($MYIP -like "finish")

#//////////////////////////////////\\\\\\\\\\\\\\\\\\\//////////////////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\////////////////////////////\\\\\\\\\
