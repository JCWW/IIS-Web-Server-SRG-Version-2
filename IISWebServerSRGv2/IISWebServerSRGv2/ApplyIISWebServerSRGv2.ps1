#
# ApplyIISWebServerSRGv2.ps1
#

### Web Server Security Requirements Guide (SRG) - Version 2, Release 2 STIGs ###

## Load WebAdministration Module ##
#Import-Module WebAdministration

## Load WebServerSTIGS Module ##
#Write-Output "Importing"
#Import-Module WebServerSTIGS

### IIS 7 Server STIGs ###

Write-Output "`n ----- Applying Web Server Security Requirements Guide: Release 2 Benchmark Date: 23 Oct 2015 -----"

Write-Output "`n ----- Applying V-40791 from Web Server -----"

#Set-V40791

Write-Output "`n ----- Applying V-40792 from Web Server -----"

#Set-V40792

Write-Output "`n ----- Applying V-41600 from Web Server -----"
Write-Output "`n ----- Applying V-41612 from Web Server -----"
Write-Output "`n ----- Applying V-41613 from Web Server -----"
Write-Output "`n ----- Applying V-41614 from Web Server -----"
Write-Output "`n ----- Applying V-41615 from Web Server -----"
Write-Output "`n ----- Applying V-41617 from Web Server -----"
Write-Output "`n ----- Applying V-41620 from Web Server -----"
Write-Output "`n ----- Applying V-56021 from Web Server -----"

#Set-LogDataFields

Write-Output "`n ----- Applying V-41670 from Web Server -----"

#Set-V41670 -Path "D:\inetpub\logs"

Write-Output "`n ----- Applying V-41671 from Web Server -----"
 
#Set-V41671 -Path "D:\inetpub"

Write-Output "`n ----- Applying V-41672 from Web Server -----"

#Set-V41672 -Path "D:\inetpub"
 
Write-Output "`n ----- Applying V-41699 from Web Server -----"

#Set-V41699  

Write-Output "`n ----- Applying V-41701 from Web Server -----"

#Set-V41701  

Write-Output "`n ----- Applying V-41702 from Web Server -----"

#Set-V41702

Write-Output "`n ----- Applying V-41833 from Web Server -----"

#Set-V41833

Write-Output "`n ----- Applying V-41852 from Web Server -----"

#Set-V41852

Write-Output "`n ----- Applying V-41854 from Web Server -----"

#Set-V41854

Write-Output "`n ----- Applying V-41855 from Web Server -----"

#Set-V41855

Write-Output "`n ----- Applying V-55949 from Web Server -----"

#Set-V55949

Write-Output "`n ----- Applying V-55951 from Web Server -----"

#Set-V55951

Write-Output "`n ----- Applying V-55997 from Web Server -----"

#Set-V55997

Write-Output "`n ----- Applying V-56003 from Web Server -----"

#Set-V56003

Write-Output "`n ----- Applying V-56007 from Web Server -----"

#Set-V56007

Write-Output "`n ----- Applying V-56011 from Web Server -----"
Write-Output "`n ----- Resolved by running V-6003 -----"

#Set-V56011

Write-Output "`n ----- Applying V-56015 from Web Server -----"
Write-Output "`n ----- Also Resolved by running V-56003 -----"

#Set-V56015

Write-Output "`n ----- REVIEW -----"
Write-Output "`n ----- Applying V-56017 from Web Server -----"
#Set-V56017

Write-Output "`n ----- Applying V-56023 from Web Server -----"
#Set-V56023

Write-Output "`n ----- Applying V-56035 from Web Server -----"
#Set-V56035