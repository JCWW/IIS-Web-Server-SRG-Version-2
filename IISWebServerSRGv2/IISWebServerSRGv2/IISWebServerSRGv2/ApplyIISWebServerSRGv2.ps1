#
# ApplyIISWebServerSRGv2.ps1
#

### Web Server Security Requirements Guide (SRG) - Version 2, Release 2 STIGs ###

## Load WebAdministration Module ##
Import-Module WebAdministration

## Load WebServerSTIGS Module ##
#Write-Output "Importing"
Import-Module IISWebServerSRGv2

### IIS Backup ###
BackUp-GisaWebConfiguration

### IIS 7 Server STIGs ###

Write-Output "`n ----- Applying Web Server Security Requirements Guide: Release 2 Benchmark Date: 23 Oct 2015 -----"

#Set-GISAV40791

#Set-GISAV40792

#Set-GISALogDataFields

#Set-GISAV41670 -Path "D:\inetpub\logs"

#Set-GISAV41671 -Path "D:\inetpub\logs"

#Set-GISAV41672 -Path "D:\inetpub\logs

#Set-GISAV41672 -Path "D:\inetpub\logs"

#Set-GISAV41695
 
#Set-GISAV41699

#Set-GISAV41701  
 
#Set-GISAV41702
 
#Set-GISAV41833

#Set-GISAV41852

#Set-GISAV41854

#Set-GISAV41855

#Set-GISAV41855

#Set-GISAV55949

#Set-GISAV55951

#Set-GISAV55997

#Set-GISAV56003

#Set-GISAV56007

#Set-GISAV56011

#Set-GISAV56015
 

Write-Output "`n ----- REVIEW -----"
Write-Output "`n ----- Applying V-56017 from Web Server Security Requirements Guide -----"
#Set-V56017

#Set-GISAV56023

#Set-GISAV56035

