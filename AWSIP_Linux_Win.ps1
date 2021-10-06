#Notes:
# This script creates two security groups in your AWS Account namely "RDP" and "SSH" 
# Its implemented as a loop ,which means that the powershell window this script is executed in , should remain open .  
# It also maintains a consistent pemission entry for your public IP address in each of these security groups . 
# This version is region specific , and you are required to manually perform the initial cofiguration for the AWS Powershell tools . 
# https://docs.aws.amazon.com/powershell/latest/userguide/specifying-your-aws-credentials.html#specifying-your-aws-credentials-use.
# The script runs on both Windows and Linux , provided that Powershell is installed in your linux environment . 



Do
{

      #Pre-Flight Checks
#<1>_Outside loop configure logging
      #Get-ScriptAnalyzerRule
       Write-host START LOG
       Get-Date
       #Set-PSDebug -Trace 2
       Start-Sleep -Seconds 120 #Frequency ENTRY!!  (Avoid Rate Limit)

#<2>_Outside loop CREATE/CHECK REG ENTRIES       (PRE-FLIGHT)

       #Check OS Type
      Write-Host "Checking OS Type"

   IF ($IsWindows -Like "True")

       {
                   write-host Inspecting Registry [AWSIP] registry key  [<<outer loop>>]
                   if(Test-Path -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP')
                       {write-host [AWSIP] registry key is present}
                   else #Create Registry Keys
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
                          #Linux:
                          #Create Folders/Files (Mock Registry)
                          New-Item -Path "/var/log" -Name "AWSIP" -ItemType "directory"
                          New-Item -Path "/var/log/AWSIP" -Name "config" -ItemType "directory"

                          #Linux (Set Access)
                          chmod -R +0777 "/var/log/AWSIP"

                          New-Item -Path "/var/log/AWSIP/config" -Name "RDPGroup.log" -ItemType "file"
                          New-Item -Path "/var/log/AWSIP/config" -Name "SSHGroup.log" -ItemType "file"
                          New-Item -Path "/var/log/AWSIP/config" -Name "NEWRDPGroup.log" -ItemType "file"
                          New-Item -Path "/var/log/AWSIP/config" -Name "NEWSSHGroup.log" -ItemType "file"
                          New-Item -Path "/var/log/AWSIP/config" -Name "OLDIP.log" -ItemType "file"
                          New-Item -Path "/var/log/AWSIP/config" -Name "MYIP.log" -ItemType "file"


                          #Linux (Set Access)
                          chmod -R +0777 "/var/log/AWSIP"

                          #Zero Values
                          set-content -Path  /var/log/AWSIP/config/RDPGroup.log  -Value 0
                          set-content -Path  /var/log/AWSIP/config/SSHGroup.log  -Value 0
                          set-content -Path  /var/log/AWSIP/config/NEWRDPGroup.log  -Value 0
                          set-content -Path  /var/log/AWSIP/config/NEWSSHGroup.log  -Value 0
                          set-content -Path  /var/log/AWSIP/config/OLDIP.log -Value 0
                          set-content -Path  /var/log/AWSIP/config/MYIP.log -Value 0
                          #Read Values:
                          $RDPGroup = get-content -Path  /var/log/AWSIP/config/RDPGroup.log
                          $SSHGroup = get-content -Path  /var/log/AWSIP/config/SSHGroup.log
                          $NEWRDPGroup = get-content -Path  /var/log/AWSIP/config/NEWRDPGroup.log
                          $NEWSSHGroup = get-content -Path  /var/log/AWSIP/config/NEWSSHGroup.log
                          $OLDIP = get-content -Path  /var/log/AWSIP/config/OLDIP.log
                          $MYIP = get-content -Path  /var/log/AWSIP/config/MYIP.log
                         }
                   }



#<3>_Outside loop CHECK AWS TOOLS INSTALLATION  (PRE-FLIGHT)
       Write-host AWS Powershell Tools  availability check [<<outer loop>>]
       #Set versions in array
       $versions = {4,5,5.1}
       #\\\\\\\\\\\\\\\\\\\\\\\\\\\\
       #Start Powershell Core Support. Alternative https://docs.microsoft.com/en-us/powershell/scripting/gallery/concepts/script-psedition-support?view=powershell-7.1
       if ((($PSVersionTable).PSEdition -like "core") -and (($PSVersionTable).PSversion.Major -ge "6"))
          {
           try {
                #Attempting to Import AWS AWSPowerShell.NetCore
                 Write-Host attempting initial import AWSPowerShell.NetCore
                  Import-Module -name AWSPowerShell.NetCore -Scope  Global -force
               }
            catch {
                   Do {
                       #Download and install module
                       Write-Host installing AWSPowerShell.NetCore
                       Install-Module -name AWSPowerShell.NetCore -Scope  AllUsers -force
                       } until (((Get-Module -ListAvailable).Name) -contains "AWSPowerShell.NetCore")
                  }
                  if( (( Get-Module -ListAvailable).Name) -contains "AWSPowerShell.NetCore")
                    {write-host AWSPowerShell.NetCore Support Added}
       }

       #Powershell Core Support Powershell Desktop version
       if ((($PSVersionTable).PSEdition -like "desktop") -and (($PSVersionTable).PSversion.Major -in $versions))
          {
           try {
                 #Attempting to Import AWS AWSPowerShell.NetCore
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
       #End Powershell Core Support


       #Start AWSPowerShell Desktop Support
       if ((($PSVersionTable).PSEdition -like "desktop")  -and (($PSVersionTable).PSversion.Major -eq "3"))
          {#OS Check:
           #Attempting to Import AWS AWSPowerShell
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
                                           #PsGet Sub-Routine
                                           Write-Host Getting PS-Get Module
                                           invoke-webrequest -Uri https://psg-prod-eastus.azureedge.net/packages/powershellget.2.2.5.nupkg -OutFile 'c:\temp\AWSPowerShell.zip'  #needs to be converted to linux
                                           Expand-archive "C:\temp\AWSPowerShell.zip" "C:\temp\AWSPowerShell"
                                           Move-item "C:\temp\AWSPowerShell\PowerShellGet.psd1" "C:\Program Files\WindowsPowerShell\Modules"
                                           Import-Module -Name PowerShellGet -Scope Global -Force
                                           Update-Module -Name PowerShellGet
                                           } until (((Get-Module -ListAvailable).Name) -contains "PowerShellGet")
                                     }

                          } until (((Get-Module -ListAvailable).Name) -contains "AWSPowerShell")
                      }
           }
       #END AWSPowerShell Desktop Support



#1st RUN CHECK
       If (($SSHGroup -and $RDPGroup -eq '0') -and ($NEWRDPGroup -and $NEWRDPGROUP-eq '0') -and ($OLDIP-and $MYIP -eq '0'))
       {set-variable -name FIRSTRUN -value "1"} else {set-variable -name FIRSTRUN -value "0"}

#Start DO Loop
#<4>_Outside loop  CHECK CURRENT IP
      write-host checking current public ip      [<<outer loop>>]
      #loop until $webip contains IP address
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

      #continue after IP has been retrieved

      $Sub = "/32"
      $MyIP = $webip.trim()+$sub

       #set registry value
       #OS Check:
    IF ($IsWindows -Like "True")
       {
        SET-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -Name "MYIP" -Value "$MYIP"##Set value for MYIP
       }
       else {
             Set-content -Path  /var/log/AWSIP/config/MYIP.log -Value $MYIP
            }



#///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#(1) _Monitor_<instances>  Outside loop "Security Group VS Instance Monitor"

#Set-PSBreakpoint -script "C:\Users\manuel\Desktop\PowershellScripts\AWS Security Group Access_Complete_Powershell_Core.ps1" -Line 112

   if (($Firstrun -eq '0') -and ($RDPGROUP -eq '1') -and ($SSHGroup -eq '1')) #Condition to Guard Loop to ensure that it only runs if groups exist
    {
      $instances = ((Get-EC2Instance).Instances).InstanceID
write-host Instances enumerated  [<<outer loop>>]

      #Variables are set as place holders for existing Security group ids
      $RDP = (Get-EC2SecurityGroup -GroupName "RDP").GroupId #Retrieve sg- for existing RDP Group and set variable
      $SSH = (Get-EC2SecurityGroup -GroupName "SSH").GroupId #Retrieve sg- for existing SSH Group and set variable

Write-host "START Instance vs SG Group evaluation"
   Foreach ($instance in $instances) #start "Instance vs SG Group evaluation"
    { #Only start evaluation if groups are not linked to instances
      IF(((Get-EC2Instance -InstanceId $instance).Instances.securitygroups.GroupName -notcontains "RDP") -or  ((Get-EC2Instance -InstanceId $instance).Instances.securitygroups.GroupName -notcontains "SSH"))

        { write-host instance $instance is missing one or more security groups
          Do # Start-loop until desired state (RDP and SSH, Linked to each instance in account)
            {    #START SSH GROUP vs instance CHECK

                        #Foreach ($instance in $instances) commented out as part of trouble shooting
                              #{commented out as part of trouble shooting
                                if ((Get-EC2Instance -InstanceId $instance).Instances.securitygroups.GroupName -notcontains "SSH")

								    {write-host NO_SSH_GROUP LINKED TO INSTANCE $instance

                                      Do{# Modify [CmdletBinding()] to [CmdletBinding(SupportsShouldProcess=$true, DefaultParameterSetName='Path')]
                                        #Get Linked Groups
                                        $instanceGroups = ((Get-EC2InstanceAttribute -InstanceId $instance -Attribute groupSet).Groups).Groupid
                                        #rebuild string for next command
                                        $commandstring = ($SSH,$instanceGroups) -split ' ' #See Script notes above
                                        #Modify instance (grant Security Group access)
                                        Edit-EC2InstanceAttribute -InstanceId $instance -Group $commandstring
                                        } until((Get-EC2Instance -InstanceId $instance).Instances.securitygroups.GroupName -contains "SSH")
									}#END SSH GROUP vs instance CHECK
									if((Get-EC2Instance -InstanceId $instance).Instances.securitygroups.GroupName -contains "SSH") {write-host SSH-GROUP linked to $instance}
	                          #}commented out as part of trouble shooting




                 #START RDP GROUP vs instance CHECK

                        #Foreach ($instance in $instances) commented out as part of trouble shooting
                            #{commented out as part of trouble shooting
                               if ((Get-EC2Instance -InstanceId $instance).Instances.securitygroups.GroupName -notcontains "RDP")

		                           {write-host no rdp group linked  to instance $instance      [>>inner loop<<]

                					 Do{
                                        #Get Linked Groups
                                        $instanceGroups = ((Get-EC2InstanceAttribute -InstanceId $instance -Attribute groupSet).Groups).Groupid
                                        #rebuild string for next command
                                        $commandstring = ($RDP,$instanceGroups) -split ' ' #See Script notes above
                                        #Modify instance (grant Security Group access)
                                        Edit-EC2InstanceAttribute -InstanceId $instance -Group $commandstring
										} until((Get-EC2Instance -InstanceId $instance).Instances.securitygroups.GroupName -contains "RDP")
				       			   }#END RDP GROUP vs instance CHECK
								   if((Get-EC2Instance -InstanceId $instance).Instances.securitygroups.GroupName -contains "RDP") {write-host RDP-GROUP linked to $instance}
                              #}commented out as part of trouble shooting

		    } until (((Get-EC2Instance -InstanceId $instance).Instances.securitygroups.GroupName -contains "RDP") -and ((Get-EC2Instance -InstanceId $instance).Instances.securitygroups.GroupName -contains "SSH")) # End-loop until desired state (RDP and SSH, Linked to each instance in account)
write-host "END Instance vs Group remediation"   [>>inner loop<<]
        } write-host "END Instance vs Group evaluation" $instance    [>>inner loop<<]
    }

 }


#(2) _Monitor  Outside loop  "IP Monitor"

       #OS Check:
    IF ($IsWindows -Like "True")
       #Windows:
       {
         If ($FirstRun -eq '0')
            {$OLDIP = (GET-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -Name "OLDIP").OLDIP}##Set value for OLDIP variable Pre-evaluation ,not doing so causes blank value if firstrun is not '1',resulting in continuous ip missmatch  until $oldip is read at end of the script
            IF(($MYIP -ne $OLDIP) -and ($MYIP -ne "0") -and ($OLDIP -ne "0"))#This trigger will still work even if $oldip does not exist ,
            #trigger internal check and Remediation Desired state $myip = $oldip
            {write-host IP ADDRESSES out of SYNC!!!!! [outer loop]} elseif
            (($MYIP -eq $OLDIP) -and ($MYIP -ne "0")-and($OLDIP -ne "0"))
            {write-host IP ADDRESSES IN SYNC [<<outer loop>>]}
       }
    Else
        #Linux:
        {
           $OLDIP = (get-content -Path  /var/log/AWSIP/config/OLDIP.log)
           IF(($MYIP -ne $OLDIP) -and ($MYIP -ne "0")-and($OLDIP -ne "0"))#This trigger will still work even if $oldip does not exist ,
           #trigger internal check and Remediation Desired state $myip = $oldip
           {write-host IP ADDRESSES out of SYNC!!!!! [outer loop]} elseif
           (($MYIP -eq $OLDIP) -and ($MYIP -ne "0")-and($OLDIP -ne "0"))
           {write-host IP ADDRESSES IN SYNC [<<outer loop>>]}
        }

     #<internal Start>

#_Trigger_<2>  Outside loop "Security Group Monitor"

   IF($IsWindows -Like "True")
       {
        #windows:
        #Read Registry Set Variables
        $RDPGROUP = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -name "RDPGroup").RDPGROUP
        $SSHGROUP = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -name "SSHGroup").SSHGROUP
       }
     else
      {
        #Linux:
        #Read Registry Set Variables
        $SSHGroup = (get-content -Path  /var/log/AWSIP/config/SSHGroup.log)
        $RDPGroup = (get-content -Path  /var/log/AWSIP/config/RDPGroup.log)
      }

     #Desired state ($RDPGroup = 1 -and $SSHGroup = 1)
     If ((($RDPGroup -or $SSHGroup -eq '0') -and ($myip -ne $oldip)) -or ($FIRSTRUN -eq '1'))
     {
                                                                                                                                                                            #__Start_Group_Creation
     Do #Create Groups
     {
        Do # RDP Group Creation Loop                                                                                                                                                       #RDP Group Creation Loop
         {
         Try #Non-existing security group throw errors in script so (if condition) cannot be evaluated hence Try Catch
         {
         $OLDRDPGroup = (Get-EC2SecurityGroup -GroupName RDP).GroupId #Get Existing RDP Group If possible
         }
         Catch
         {
         write-host RDP GROUP DOES NOT EXIST,Creating.............[RDP Group Creation loop] [>>Inner loop<<]
         $NEWRDPGroup = New-EC2SecurityGroup -GroupName RDP -Description "Windows remote Access" #Create New RDP Group and set variable
         }
         finally
         {
         if ($NEWRDPGroup -like "sg-*") #Finally Set NEWRDPGroup variable
         {write-host  RDP Group Exists [RDP Group Creation loop]  [>>Inner loop<<]}
          }


         }until (($NEWRDPGroup -like "sg-*") -or ($OLDRDPGroup -like "sg-*")) #Loop until Desired State (until an RDP Security Group Exists)


        Do # SSH Group Creation Loop                                                                                                                                                      SSH Group Creation Loop
         {
          Try
           {
             $OLDSSHGroup = (Get-EC2SecurityGroup -GroupName SSH).GroupId #Get Existing SSH Group If Possible
           }
          Catch
           {
             write-host SSH GROUP DOES NOT EXIST,Creating.............[SSH Group Creation loop] [>>Inner loop<<]
             $NEWSSHGroup = New-EC2SecurityGroup -GroupName SSH -Description "Linux remote Access" #Create New SSH Group and set variable
           }
           finally
           {
             if ($NEWSSHGroup -like "sg-*") #Finally Set NEWSSHGroup variable
                {write-host  SSH Group Exists. [SSH Group Creation loop]  [>>Inner loop<<]}
           }

         }until (($NEWSSHGroup -like "sg-*") -or ($OLDSSHGroup -like "sg-*"))  #Loop until Desired State (until an SSH Security Group Exists)


      } until ((($NEWRDPGroup -like "sg-*") -and ($NEWSSHGroup -like "sg-*")) -or (($OLDRDPGroup -like "sg-*") -and ($OLDSSHGroup -like "sg-*")))

         #Finally Set Registry Value For Group Registry Keys to "1" Before Exiting loop
         #OSCHECK
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
              {SET-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -Name "NEWRDPGroup" -Value "1"} #Loop until Desired State (until both Security Groups Exists)    #__END_Group_Creation
         } else

          #Linux:
          {
            IF  (($OLDSSHGroup -like "sg-*") -or ($NEWSSHGroup -like "sg-*"))
                {$SSHGroup = set-content -Path  /var/log/AWSIP/config/SSHGroup.log  -Value "1"}
            IF  ($NEWSSHGroup -like "sg-*")
                {$NEWSSHGroup = set-content -Path  /var/log/AWSIP/config/NEWSSHGroup.log  -Value "1"}


            IF (($OLDRDPGroup -like "sg-*") -or ($NEWRDPGroup -like "sg-*"))
               {$RDPGroup = set-content -Path  /var/log/AWSIP/config/RDPGroup.log  -Value "1"}
            IF ($NEWRDPGroup -like "sg-*")
               {$NEWRDPGroup = set-content -Path  /var/log/AWSIP/config/NEWRDPGroup.log  -Value "1"}
          }
    }

#///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


#<6>_Outside loop ADD /Revoke Permissions Monitor loop
     #Read Registry Set Variables (Sanity Check)
     #OSCHECK
     If ($IsWindows -Like "True")
        {
         #Windows:
         $RDPGROUP = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -name "RDPGroup").RDPGroup
         $SSHGROUP = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -name "SSHGroup").SSHGroup
         $NEWRDPGROUP = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -name "NEWRDPGroup").NEWRDPGroup
         $NEWSSHGROUP = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -name "NEWSSHGroup").NEWSSHGroup
         $RDP = (Get-EC2SecurityGroup -GroupName "RDP").GroupId #Retrieve sg- for existing RDP Group and set variable
         $SSH = (Get-EC2SecurityGroup -GroupName "SSH").GroupId #Retrieve sg- for existing SSH Group and set variable
         $OLDIP = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -name "OLDIP").OLDIP
        } else
        {
         #Linux:
         $RDPGroup = get-content -Path  /var/log/AWSIP/config/RDPGroup.log
         $SSHGroup = get-content -Path  /var/log/AWSIP/config/SSHGroup.log
         $NEWRDPGroup = get-content -Path  /var/log/AWSIP/config/NEWRDPGroup.log
         $NEWSSHGroup = get-content -Path  /var/log/AWSIP/config/NEWSSHGroup.log
         $RDP = (Get-EC2SecurityGroup -GroupName "RDP").GroupId #Retrieve sg- for existing RDP Group and set variable
         $SSH = (Get-EC2SecurityGroup -GroupName "SSH").GroupId #Retrieve sg- for existing SSH Group and set variable
         $OLDIP = get-content -Path  /var/log/AWSIP/config/OLDIP.log
        }



     #
     If ((($OLDIP -ne $MYIP) -and ($NEWRDPGroup -eq "1")) -or ($FIRSTRUN -eq '1') ) #New Groups Scenario IE Create new Permissions for new Groups
        {
        Write-host NEW Groups Adding Permssions
        $ip1 = @{ IpProtocol="tcp"; FromPort="22"; ToPort="22"; IpRanges="$MYIP"}
        $ip2 = @{ IpProtocol="tcp"; FromPort="3389"; ToPort="3389"; IpRanges="$MYIP"}
        Grant-EC2SecurityGroupIngress -GroupID $SSH -IpPermission @( $ip1 )
        Grant-EC2SecurityGroupIngress -GroupID $RDP -IpPermission @( $ip2 )
        }
        elseif
        (($OLDIP -ne $MYIP) -and ($RDPGROUP -eq "1") -and ($FIRSTRUN -eq '0')) #OLD Groups Scenario IE Update Permissions Existing Groups
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
            IF ($IsWindows -Like "True") #OS CHECK
               {
               #Windows
               #Set OLDIP Variable and registry KEY AFTER Permissions have been SET
               $OLDIP = (Get-EC2SecurityGroup -Groupname RDP).IpPermissions.ipv4Ranges.cidrip
               SET-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -Name "OLDIP" -Value "$OLDIP"##Set value for OLDIP
               }else {
               #Linux
               $OLDIP = (Get-EC2SecurityGroup -Groupname RDP).IpPermissions.ipv4Ranges.cidrip
               set-content -Path  /var/log/AWSIP/config/OLDIP.log -Value $OLDIP
               }

     #
    IF($IsWindows -Like "True")
    {
     #Windows:
     If ($RDPGroup -eq '1' -and $SSHGRoup -eq '1' -and $FirstRun -eq '0')#Cleanup NewSecurity Group Variables and Re-Set Registy to 0
        {
         Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -Name "NEWRDPGroup" -Value "0"
         Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\Config" -Name "NEWSSHGroup" -Value "0"
         Set-Variable -name NEWRDPGroup -Value '0'
         Set-Variable -name NEWSSHGroup -Value '0'
        }
    } else
     #Linux:
        {
          if($RDPGroup -eq '1' -and $SSHGRoup -eq '1' -and $FirstRun -eq '0')
          {
          set-content -Path  /var/log/AWSIP/config/NEWRDPGroup.log  -Value '0'
          set-content -Path  /var/log/AWSIP/config/NEWSSHGroup.log  -Value '0'
          Set-Variable -name NEWRDPGroup -Value '0'
          Set-Variable -name NEWSSHGroup -Value '0'
          }
        }


    #<Internal Stop>

 # Modify [CmdletBinding()] to [CmdletBinding(SupportsShouldProcess=$true, DefaultParameterSetName='Path')]
} until ($MYIP -like "finish")

#//////////////////////////////////\\\\\\\\\\\\\\\\\\\//////////////////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\////////////////////////////\\\\\\\\\
