###########################################################################################################
# Copyright (C) 2018 Flexera Software LLC. All Rights Reserved. See LICENSE.txt for full license details.

#updated 4/4/2022 by D Hoagland
#If OperatingSystem is null, retrieve Operating_System - Get-Computer and Get-OS
###########################################################################################################

# Security Protocol = TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Invoke-JAMFMethod ($uri, $username, $password)
# handles setup and retrieval of webservice
{
    #setup basic authentication
    $pair = $pair = "$($username):$($password)"
    $encodeCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($pair))
    $basicAuthValue = "Basic $encodeCreds"
    $headers = @{ Authorization = $basicAuthValue }

    
    add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
 
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        

    Invoke-RestMethod -Uri $uri -Headers $headers -ContentType "application/json" -Method GET

}

function fixURI ($uri){
# fixes the URI to make sure trailing / is there when appending method

    if ($uri.Substring($uri.length -1) -eq '/')
        {$uri}
    else 
        {$uri+'/'}

}

function truncString ($str, $len) {
# truncates a string when needed to the defined length
    if ($str.Length -gt $len)
        {$str.Substring(0,$len)}
    else 
        {$str}

}

function Get-Version($apiroot, $username, $password)
# Version 1.0, do a small web service retrieval to ensure connectivity
{

	

	$obj = New-Object -TypeName PSObject
	$obj | Add-Member -MemberType NoteProperty -Name Version -Value "1.0"

	$obj
}

function Get-Computers ($apiroot, $hardwareSearch, $username, $password)
# Get Computer List
{
	$apiroot=fixURI($apiroot)

          
    #set webservice URL for call, write info to log
    $uri=$apiroot+"JSSResource/advancedcomputersearches/name/"+$hardwareSearch
        
    $response = Invoke-JAMFMethod -uri $uri -username $username -password $password
    
         
    foreach ($r in $response.advanced_computer_search.computers.computer)
        # Loop through response, this gets some basic info
        {
            # Output Computer objects for retrieval by framework - make sure to truncate strings as needed 
            $r | ForEach-Object { $_ |
		            Select-Object -Property @{N='ExternalID'; E={[long]$_.id}},
									@{N='ComputerName'; E={truncString -str $_.name -len 256 }},
									@{N='MACAddress'; E={truncString -str $_.mac_address -len 256 }},
									@{N='ModelNo'; E={truncString -str $_.model -len 128 }},
									@{N='SerialNo'; E={truncString -str $_.serial_number -len 100 }},
									@{N='InventoryAgent'; E={'JAMF Pro'}},
		           				    @{N='OperatingSystem'; E={(&{
                                            if ($_.OperatingSystem.length -gt 2)
                                                {truncString -str $_.OperatingSystem -len 256 }
                                             Else {truncString -str $_.Operating_System -len 256 }                                           
                                    })}}, 
									@{N='ServicePack'; E={truncString -str $_.os_name+" "+$_.Service_Pack -len 128}},
									@{N='IPAddress'; E={truncString -str $_.ip_address -len 256 }},
									@{N='Manufacturer'; E={truncString -str $_.make -len 128 }},
									@{N='InventoryDate'; E={[datetime]$_.Last_Inventory_Update }}, 
                                    # if model contains MacBook, it's a Laptop, else it's a Desktop
									@{N='ChassisType'; E={(&{If($_.model -like “*MacBook*”) {"Laptop"} Else {"Desktop"}})}}, 
									@{N='ProcessorType'; E={truncString -str $_.processor_type -len 256 }},
									@{N='MaxClockSpeed'; E={[int]$_.processor_speed_mhz}},
									@{N='NumberOfProcessors'; E={[int]$_.Number_of_Processors }},
									@{N='NumberOfCores'; E={[int]$_.Total_Number_of_Cores }},
									@{N='TotalMemory'; E={[long]$_.Total_RAM_MB }},
									@{N='LastLoggedOnUser'; E={truncString -str $_.UserName -len 128}},
									@{N='EmailAddress'; E={truncString -str $_.Email_Address -len 256 }}
		       } 
             
      
        }      
          
 
    
}	




function Get-Apps ($apiroot, $softwareSearch, $username, $password)
# Get Installed Apps List
{
	$apiroot=fixURI($apiroot)
 
    #set webservice URL for call, write info to log
    #$uri=$apiroot+"JSSResource/advancedcomputersearches/id/287"
    $uri=$apiroot+"JSSResource/advancedcomputersearches/name/"+$softwareSearch
        
    $response = Invoke-JAMFMethod -uri $uri -username $username -password $password

 
   
        foreach ($r in $response.advanced_computer_search.computers.computer)
        #loop through devices retrieved
        {    
            $computerId = $r.id  
  
            
           
            foreach ($t in $r.Applications.Application)
            #loop through installed applications retrieved
            {
             
               # Output Installed Apps objects for retrieval by framework
               $t | ForEach-Object { 
                    

                    $_ |
 		            Select-Object -Property @{N='ComputerID'; E={[long]$computerId}},
									# Strip .app from Title if it ends in .App, look for app title first, if not there, use available update
									@{N='DisplayName'; E={(&{
                                            if ($_.Application_Title.length -gt 2)
                                            {
                                                If($_.Application_Title.Substring($_.Application_Title.Length - 4) -eq “.app”) 
                                                    {truncString -str $_.Application_Title.Substring(0,$_.Application_Title.Length - 4) -len 256} 
                                                Else {truncString -str $_.Application_Title -len 256}
                                            } Else {
                                                If($_.Available_Update.Substring($_.Available_Update.Length - 4) -eq “.app”) 
                                                    {truncString -str $_.Available_Update.Substring(0,$_.Available_Update.Length - 4) -len 256} 
                                                Else {truncString -str $_.Available_Update -len 256}
                                            }
                                            

                                       
                                    })}}, 
									@{N='Evidence'; E={'Any'}},
									@{N='DatabaseName'; E={$null}},
									@{N='InstanceName'; E={$null}},
									@{N='Version'; E={truncString -str $_.Application_Version -len 72}},
									@{N='Publisher'; E={$null}},
									@{N='AccessMode'; E={$null}},
									@{N='UserID'; E={$null}}
                
		        }

             }
            
        } 
        
      
 }

 function Get-OS ($apiroot, $hardwareSearch, $username, $password)
# Get Computer List
{
	$apiroot=fixURI($apiroot)

          
    #set webservice URL for call, write info to log
    $uri=$apiroot+"JSSResource/advancedcomputersearches/name/"+$hardwareSearch
        
    $response = Invoke-JAMFMethod -uri $uri -username $username -password $password
    
    #loop through twice, some ARL entries map on Caption, others on name, so set the OS for both
         
    foreach ($r in $response.advanced_computer_search.computers.computer)
        # Loop through response, this gets some basic info
        {
            # Output Computer objects for retrieval by framework
            $r | ForEach-Object { $_ |
		            Select-Object -Property @{N='ComputerID'; E={[long]$_.id}},
									@{N='ClassName'; E={'MGS_OperatingSystem'}},
									@{N='PropertyName'; E={'Caption'}},
									@{N='PropertyValue'; E={(&{
                                            if ($_.OperatingSystem.length -gt 2)
                                                {truncString -str $_.OperatingSystem -len 256 }
                                             Else {truncString -str $_.Operating_System -len 256 }                                           
                                    })}}, 
                                    @{N='InstanceName'; E={$null}}
		       } 
             
      
        }      
 
     foreach ($r in $response.advanced_computer_search.computers.computer)
        # Loop through response, this gets some basic info
        {
            # Output Computer objects for retrieval by framework
            $r | ForEach-Object { $_ |
		            Select-Object -Property @{N='ComputerID'; E={[long]$_.id}},
									@{N='ClassName'; E={'MGS_OperatingSystem'}},
									@{N='PropertyName'; E={'Name'}},
									@{N='PropertyValue'; E={(&{
                                            if ($_.OperatingSystem.length -gt 2)
                                                {truncString -str $_.OperatingSystem -len 256 }
                                             Else {truncString -str $_.Operating_System -len 256 }                                           
                                    })}}, 
                                    @{N='InstanceName'; E={$null}}
		       } 
             
      
        }      
         
 
    
}	


#get-apps 'https://tryitout.jamfcloud.com' 'user' 'pw'
# Get-OS 'https://tryitout.jamfcloud.com/' 'Flexera Hardware Search' 'user' 'pw'

