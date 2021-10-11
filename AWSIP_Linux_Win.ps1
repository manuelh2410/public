#Notes:
# releasing this because my laptop has probably been compromised .
# The script was created out of pure frustation of having to manually update my security group entries before I can connect to my AWS instances.
# This script creates two security groups in your AWS Account namely "RDP" and "SSH"
# It also enumerates all instances your default AWS region , and ensures that both security groups are linked to each of these instances at all times.
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
       Start-Sleep -Seconds 120




      Write-Host "Checking OS Type"

   IF ($IsWindows -Like "True")

       {
                   write-host Inspecting Registry [AWSIP] registry key  [<<outer loop>>]
                   if(Test-Path -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP')
                       {write-host [AWSIP] registry key is present}
                   else
                       {
                         New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP"
                         New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\config"
                         $RDPGroup = New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -Name "RDPGroup" -Value "0"
                         $SSHGroup = New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -Name "SSHGroup" -Value "0"
                         $NEWRDPGroup = New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -Name "NEWRDPGroup" -Value "0"
                         $NEWSSHGroup = New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -Name "NEWSSHGroup" -Value "0"
                         $OLDIP = New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -Name "OLDIP" -Value "0"  -PropertyType "String"
                         $MYIP = New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -Name "MYIP" -Value "0"  -PropertyType "String"
                       }
        }
   ELSE
                   {
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
                          New-Item -Path "/var/log/AWSIP/config" -Name "OLDIP.log" -ItemType "file"
                          New-Item -Path "/var/log/AWSIP/config" -Name "MYIP.log" -ItemType "file"



                          chmod -R +0777 "/var/log/AWSIP"


                          set-content -Path  /var/log/AWSIP/config/RDPGroup.log  -Value 0
                          set-content -Path  /var/log/AWSIP/config/SSHGroup.log  -Value 0
                          set-content -Path  /var/log/AWSIP/config/NEWRDPGroup.log  -Value 0
                          set-content -Path  /var/log/AWSIP/config/NEWSSHGroup.log  -Value 0
                          set-content -Path  /var/log/AWSIP/config/OLDIP.log -Value 0
                          set-content -Path  /var/log/AWSIP/config/MYIP.log -Value 0

                          $RDPGroup = get-content -Path  /var/log/AWSIP/config/RDPGroup.log
                          $SSHGroup = get-content -Path  /var/log/AWSIP/config/SSHGroup.log
                          $NEWRDPGroup = get-content -Path  /var/log/AWSIP/config/NEWRDPGroup.log
                          $NEWSSHGroup = get-content -Path  /var/log/AWSIP/config/NEWSSHGroup.log
                          $OLDIP = get-content -Path  /var/log/AWSIP/config/OLDIP.log
                          $MYIP = get-content -Path  /var/log/AWSIP/config/MYIP.log
                         }
                   }




       Write-host AWS Powershell Tools  availability check [<<outer loop>>]

       $versions = {4,5,5.1}
       #\\\\\\\\\\\\\\\\\\\\\\\\\\\\

     if ((($PSVersionTable).PSEdition -like "core") -and (($PSVersionTable).PSversion.Major -ge "6"))
          {
           try {

                 Write-Host attempting initial import AWSPowerShell.NetCore
                  Import-Module -name AWSPowerShell.NetCore -Scope  Global -force
               }
            catch {
                   Do {

                       Write-Host installing AWSPowerShell.NetCore
                       Install-Module -name AWSPowerShell.NetCore -Scope  AllUsers -force
                       } until (((Get-Module -ListAvailable).Name) -contains "AWSPowerShell.NetCore")
                  }
                  if( (( Get-Module -ListAvailable).Name) -contains "AWSPowerShell.NetCore")
                    {write-host AWSPowerShell.NetCore Support Added}
       }


       if ((($PSVersionTable).PSEdition -like "desktop") -and (($PSVersionTable).PSversion.Major -in $versions))
          {
           try {

                 Write-Host attempting initial import AWSPowerShell.NetCore
                 Import-Module -name AWSPowerShell.NetCore -Scope  Global -force
               }
               Catch {
                       Do{
                           Write-Host installing AWSPowerShell.NetCore
                           Install-Module -name AWSPowerShell.NetCore -Scope  AllUsers -force
                         } until (((Get-Module -ListAvailable).Name) -contains "AWSPowerShell.NetCore")
                      }
          }




       if ((($PSVersionTable).PSEdition -like "desktop")  -and (($PSVersionTable).PSversion.Major -eq "3"))
          {

           Write-Host attempting initial import AWSPowerShell
           try {
               Import-Module -name AWSPowerShell -Scope  Global -force
               }
                Catch { Write-Host installing AWSPowerShell Module
                       DO {
                           try
                              {
                               Install-Module -name AWSPowerShell -Scope  AllUsers -force
                              }
                               Catch {
                                       Do {

                                           Write-Host Getting PS-Get Module
                                           invoke-webrequest -Uri https://psg-prod-eastus.azureedge.net/packages/powershellget.2.2.5.nupkg -OutFile 'c:\temp\AWSPowerShell.zip'
                                           Expand-archive "C:\temp\AWSPowerShell.zip" "C:\temp\AWSPowerShell"
                                           Move-item "C:\temp\AWSPowerShell\PowerShellGet.psd1" "C:\Program Files\WindowsPowerShell\Modules"
                                           Import-Module -Name PowerShellGet -Scope Global -Force
                                           Update-Module -Name PowerShellGet
                                           } until (((Get-Module -ListAvailable).Name) -contains "PowerShellGet")
                                     }

                          } until (((Get-Module -ListAvailable).Name) -contains "AWSPowerShell")
                      }
           }





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
       else {
             Set-content -Path  /var/log/AWSIP/config/MYIP.log -Value $MYIP
            }



#///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



   if (($Firstrun -eq '0') -and ($RDPGROUP -eq '1') -and ($SSHGroup -eq '1'))
    {
      $instances = ((Get-EC2Instance).Instances).InstanceID
write-host Instances enumerated  [<<outer loop>>]


      $RDP = (Get-EC2SecurityGroup -GroupName "RDP").GroupId
      $SSH = (Get-EC2SecurityGroup -GroupName "SSH").GroupId

Write-host "START Instance vs SG Group evaluation"
   Foreach ($instance in $instances)
    {
      IF(((Get-EC2Instance -InstanceId $instance).Instances.securitygroups.GroupName -notcontains "RDP") -or  ((Get-EC2Instance -InstanceId $instance).Instances.securitygroups.GroupName -notcontains "SSH"))

        { write-host instance $instance is missing one or more security groups
          Do
            {


                             if (((Get-EC2Instance -InstanceId $instance).Instances.securitygroups.GroupName -notcontains "SSH") -and ((get-ec2instance $instance).Instances.Platform -notcontains "Windows" ))

								    {write-host NO_SSH_GROUP LINKED TO Linux_INSTANCE $instance

                                      Do{

                                        $instanceGroups = ((Get-EC2InstanceAttribute -InstanceId $instance -Attribute groupSet).Groups).Groupid

                                        $commandstring = ($SSH,$instanceGroups) -split ' '
                                        Edit-EC2InstanceAttribute -InstanceId $instance -Group $commandstring
                                        } until((Get-EC2Instance -InstanceId $instance).Instances.securitygroups.GroupName -contains "SSH")
									} write-host SSH-GROUP linked to $instance
									#if((Get-EC2Instance -InstanceId $instance).Instances.securitygroups.GroupName -contains "SSH") {write-host SSH-GROUP linked to $instance}






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




       #OS Check:
    IF ($IsWindows -Like "True")

       {
         If ($FirstRun -eq '0')
            {$OLDIP = (GET-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -Name "OLDIP").OLDIP}
            IF(($MYIP -ne $OLDIP) -and ($MYIP -ne "0") -and ($OLDIP -ne "0"))

            {write-host IP ADDRESSES out of SYNC!!!!! [outer loop]} elseif
            (($MYIP -eq $OLDIP) -and ($MYIP -ne "0")-and($OLDIP -ne "0"))
            {write-host IP ADDRESSES IN SYNC [<<outer loop>>]}
       }
    Else

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
     else
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
          IF  (($OLDSSHGroup -like "sg-*") -or ($NEWSSHGroup -like "sg-*"))
              {SET-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -Name "SSHGroup" -Value "1"}
          IF  ($NEWSSHGroup -like "sg-*")
              {SET-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -Name "NEWSSHGroup" -Value "1"}


          IF  (($OLDRDPGroup -like "sg-*") -or ($NEWRDPGroup -like "sg-*"))
              {SET-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -Name "RDPGroup" -Value "1"}
              IF  ($NEWRDPGroup -like "sg-*")
              {SET-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -Name "NEWRDPGroup" -Value "1"}
         } else

          #Linux:
          {
            IF ((($OLDSSHGroup -like "sg-*") -or ($NEWSSHGroup -like "sg-*"))-and (Get-EC2SecurityGroup -GroupName "SSH").GroupId -like "sg-*")
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
        } else
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
     If ((($OLDIP -ne $MYIP) -and ($NEWRDPGroup -eq "1")) -or ($FIRSTRUN -eq '1') )
        {
        Write-host NEW Groups Adding Permssions
        $ip1 = @{ IpProtocol="tcp"; FromPort="22"; ToPort="22"; IpRanges="$MYIP"}
        $ip2 = @{ IpProtocol="tcp"; FromPort="3389"; ToPort="3389"; IpRanges="$MYIP"}
        Grant-EC2SecurityGroupIngress -GroupID $SSH -IpPermission @( $ip1 )
        Grant-EC2SecurityGroupIngress -GroupID $RDP -IpPermission @( $ip2 )
        }
        elseif
        (($OLDIP -ne $MYIP) -and ($RDPGROUP -eq "1") -and ($FIRSTRUN -eq '0'))
        {
        Write-host Groups Exist  Removing Old Permissions before Adding Permissions
        $ip1 = @{ IpProtocol="tcp"; FromPort="22"; ToPort="22"; IpRanges="$OLDIP"}
        $ip2 = @{ IpProtocol="tcp"; FromPort="3389"; ToPort="3389"; IpRanges="$OLDIP"}
        REVOKE-EC2SecurityGroupIngress -GroupID $SSH -IpPermission @( $ip1 )
        REVOKE-EC2SecurityGroupIngress -GroupID $RDP -IpPermission @( $ip2 )
        #
        Write-host Adding Permissions After Removal
        $ip1 = @{ IpProtocol="tcp"; FromPort="22"; ToPort="22"; IpRanges="$MYIP"}
        $ip2 = @{ IpProtocol="tcp"; FromPort="3389"; ToPort="3389"; IpRanges="$MYIP"}
        GRANT-EC2SecurityGroupIngress -GroupID $SSH -IpPermission @( $ip1 )
        GRANT-EC2SecurityGroupIngress -GroupID $RDP -IpPermission @( $ip2 )
        }
            IF ($IsWindows -Like "True")
               {

               $OLDIP = (Get-EC2SecurityGroup -Groupname RDP).IpPermissions.ipv4Ranges.cidrip
               SET-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -Name "OLDIP" -Value "$OLDIP"
               }else {
               #Linux
               $OLDIP = (Get-EC2SecurityGroup -Groupname RDP).IpPermissions.ipv4Ranges.cidrip
               set-content -Path  /var/log/AWSIP/config/OLDIP.log -Value $OLDIP
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
    } else

        {
          if($RDPGroup -eq '1' -and $SSHGRoup -eq '1' -and $FirstRun -eq '0')
          {
          set-content -Path  /var/log/AWSIP/config/NEWRDPGroup.log  -Value '0'
          set-content -Path  /var/log/AWSIP/config/NEWSSHGroup.log  -Value '0'
          Set-Variable -name NEWRDPGroup -Value '0'
          Set-Variable -name NEWSSHGroup -Value '0'
          }
        }



} until ($MYIP -like "finish")

#//////////////////////////////////\\\\\\\\\\\\\\\\\\\//////////////////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\////////////////////////////\\\\\\\\\
