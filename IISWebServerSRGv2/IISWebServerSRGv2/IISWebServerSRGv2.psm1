function Set-LogDataFields {
	
	<#
	.SYNOPSIS
	Applies findings V-41600,V-41612, V-41613, V-41614, V-41615,V-41617,V-41620
	 ("Log files must consist of the required data fields") from the Web Server STIG.
	.DESCRIPTION
	Configures IIS log settings in accordance with STIG requirements.
	.EXAMPLE
	Set-LogDataFields
	.COMPONENT
	IIS Web Server
	.LINK
	http://iase.disa.mil/stigs/app-security/web-servers/Pages/index.aspx
	.LINK
	http://iasecontent.disa.mil/stigs/zip/July2015/U_IIS_7-0_V1R8_STIG.zip
	.LINK
	https://www.stigviewer.com/stig/iis_7.0_web_site/2015-06-01/finding/V-41612
	.LINK
	https://www.stigviewer.com/stig/iis_7.0_web_site/2015-06-01/finding/V-41600
	.LINK
	https://www.stigviewer.com/stig/iis_7.0_web_site/2015-06-01/finding/V-41613
	.LINK
	https://www.stigviewer.com/stig/iis_7.0_web_site/2015-06-01/finding/V-41615
	.LINK
	https://www.stigviewer.com/stig/iis_7.0_web_site/2015-06-01/finding/V-41617
	.LINK
	https://www.stigviewer.com/stig/iis_7.0_web_site/2015-06-01/finding/V-41620
	#>
	
	Set-WebConfigurationProperty "/system.applicationHost/sites/siteDefaults" -name logfile.logExtFileFlags -value "Date,Time,ClientIP,UserName,ServerIP,Method,UriStem,UriQuery,HttpStatus,Win32Status,TimeTaken,ServerPort,UserAgent,Referer,HttpSubStatus"
	
	Write-Output "`Configured IIS logs per STIG guidelines"
}

function Set-V40791 {

	<#
	.SYNOPSIS
	Applies finding V-40791 ("The web server must limit the number of allowed simultaneous session requests.") from the WebServer STIG.
	.DESCRIPTION
	For every IIS Site, configures the maximum number of allowed connections
	.PARAMETER Limit
	Optional. Configures the maximum number of connections allowed for all IIS sites. If not specified, the default value is the maximum value of 4,294,967,294.
	.EXAMPLE
	Set-V40791
	.EXAMPLE
	Set-MaxConnections -Limit 4000
	.COMPONENT
	IIS Web Server
	.LINK
	http://iase.disa.mil/stigs/app-security/web-servers/Pages/index.aspx
	.LINK
	http://iasecontent.disa.mil/stigs/zip/Oct2015/U_Web_Server_V2R2_SRG.zip
	.LINK
	https://www.stigviewer.com/stig/web_server_security_requirements_guide/2014-11-17/finding/V-40791
	#>

	[CmdletBinding()]
	param(
		[ValidateRange(0,4294967294)]
		[long]$Limit = 1000
	)

	$serverConfiguration = "/system.applicationHost/sites/*"

	$applicationHosts = Get-WebConfiguration -filter $serverConfiguration

	foreach ($application in $applicationHosts) {
		
		$name = $application.Name
		
		Set-WebConfigurationProperty -Filter $serverConfiguration -name Limits -Value @{MaxConnections=$limit}

	}

}

function Set-V40792 {

	<#
	.SYNOPSIS
	Applies finding V-40792 ("The web server must perform server-side session management.") from the WebServer STIG.
	.DESCRIPTION
	For every IIS Site, configures the maximum number of allowed connections    
	.EXAMPLE
	Set-V40792  
	.COMPONENT
	IIS Web Server
	.LINK
	http://iase.disa.mil/stigs/app-security/web-servers/Pages/index.aspx
	.LINK
	http://iasecontent.disa.mil/stigs/zip/Oct2015/U_Web_Server_V2R2_SRG.zip
	.LINK
	https://www.stigviewer.com/stig/web_server_security_requirements_guide/2015-08-28/finding/V-40792
	#>
 
	$serverConfiguration = "/system.web/sessionState"

	Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT'  -filter $serverConfiguration -name "mode" -value "InProc"
  
 }
 
function Set-V41670 {
 
	<#
	.SYNOPSIS
	Applies finding V-41670 ("Web server log files must only be accessible by privileged users.") from the WebServer STIG.
	.DESCRIPTION
	Configure the web server log files so unauthorized access of log information is not possible.
	.PARAMETER Path
	Optional. Sets the path to apply the STIG configuration too.
	.EXAMPLE
	Set-V41670
	.COMPONENT
	IIS Web Server
	.LINK
	http://iase.disa.mil/stigs/app-security/web-servers/Pages/index.aspx
	.LINK
	http://iasecontent.disa.mil/stigs/zip/Oct2015/U_Web_Server_V2R2_SRG.zip
	.LINK
	https://www.stigviewer.com/stig/web_server_security_requirements_guide/2015-08-28/finding/V-41670
	#>
	 
	[CmdletBinding()]
	param(
		[string]$Path = "D:\inetpub"
	)
	 
	Remove-Inheritance $Path
 
	Remove-NTFSPermissions $Path "Creator owner" "Read,Modify"
 }

function Set-V41671 {
 
	<#
	.SYNOPSIS
	Applies finding V-41671 ("Web server log files must only be accessible by privileged users.") from the WebServer STIG.
	.DESCRIPTION
	Configure the web server log files so unauthorized access of log information is not possible.
	.PARAMETER Path
	Optional. Sets the path to apply the STIG configuration too.
	.EXAMPLE
	Set-V41670
	.COMPONENT
	IIS Web Server
	.LINK
	http://iase.disa.mil/stigs/app-security/web-servers/Pages/index.aspx
	.LINK
	http://iasecontent.disa.mil/stigs/zip/Oct2015/U_Web_Server_V2R2_SRG.zip
	.LINK
	https://www.stigviewer.com/stig/web_server_security_requirements_guide/2015-08-28/finding/V-41671
	#>
	 
	[CmdletBinding()]
	param(
		[string]$Path = "D:\inetpub"
	)
	 
	Remove-Inheritance $Path
 
	Remove-NTFSPermissions $Path "Creator owner" "Read,Modify"
 }

function Set-V41672 {
 
	<#
	.SYNOPSIS
	Applies finding V-41672 ("Web server log files must only be accessible by privileged users.") from the WebServer STIG.
	.DESCRIPTION
	Configure the web server log files so unauthorized access of log information is not possible.
	.PARAMETER Path
	Optional. Sets the path to apply the STIG configuration too.
	.EXAMPLE
	Set-V41672
	.COMPONENT
	IIS Web Server
	.LINK
	http://iase.disa.mil/stigs/app-security/web-servers/Pages/index.aspx
	.LINK
	http://iasecontent.disa.mil/stigs/zip/Oct2015/U_Web_Server_V2R2_SRG.zip
	.LINK
	https://www.stigviewer.com/stig/web_server_security_requirements_guide/2015-08-28/finding/V-41672
	#>
	 
	[CmdletBinding()]
	param(
		[string]$Path = "D:\inetpub"
	)
	 
	Remove-Inheritance $Path
 
	Remove-NTFSPermissions $Path "Creator owner" "Read,Modify"
 }

function Set-V41699 {
	
	<#
	.SYNOPSIS
	Applies finding V-41699 ("The web server must have Multipurpose Internet Mail Extensions (MIME) that invoke OS shell programs disabled.") from the WebServer STIG.
	.DESCRIPTION
	Configure the web server to disable all MIME types that invoke OS shell programs.
	.EXAMPLE
	Set-V41699
	.COMPONENT
	IIS Web Server
	.LINK
	http://iase.disa.mil/stigs/app-security/web-servers/Pages/index.aspx
	.LINK
	http://iasecontent.disa.mil/stigs/zip/Oct2015/U_Web_Server_V2R2_SRG.zip
	.LINK
	https://www.stigviewer.com/stig/web_server_security_requirements_guide/2015-08-28/finding/V-41699
	#>

	Remove-ShellMIMEType
  }
   
function Set-V41701 {

 <#
	.SYNOPSIS
	Applies finding V-V41701 ("The web server must have resource mappings set to disable the serving of certain file types.") from the WebServer STIG.
	.DESCRIPTION
	Configure the web server to only serve file types to the user that are needed by the hosted applications. All other file types must be disabled.
	.EXAMPLE
	Set-V41701
	.COMPONENT
	IIS Web Server
	.LINK
	http://iase.disa.mil/stigs/app-security/web-servers/Pages/index.aspx
	.LINK
	http://iasecontent.disa.mil/stigs/zip/Oct2015/U_Web_Server_V2R2_SRG.zip
	.LINK
	https://www.stigviewer.com/stig/web_server_security_requirements_guide/2015-08-28/finding/V-41701
	#>
	 
   Set-DoubleEscapingURLs

   Set-HighBitCharacters
	
   Add-AllowedFileExtensionsServer -File "C:\WebServerSTIGS\AllowedFileExtensions.csv"
}
 
function Set-V41702 {

 <#
	.SYNOPSIS
	Applies finding V-V41702 ("The web server must have Web Distributed Authoring (WebDAV) disabled.") from the WebServer STIG.
	.DESCRIPTION
	Configure the web server to disable Web Distributed Authoring. 
	.EXAMPLE
	Set-V41702
	.COMPONENT
	IIS Web Server
	.LINK
	http://iase.disa.mil/stigs/app-security/web-servers/Pages/index.aspx
	.LINK
	http://iasecontent.disa.mil/stigs/zip/Oct2015/U_Web_Server_V2R2_SRG.zip
	.LINK
	https://www.stigviewer.com/stig/web_server_security_requirements_guide/2015-08-28/finding/V-41702
	#>
	 
	$feature = get-windowsfeature web-dav-publishing

	if($feature.Installed){
	  
	UnInstall-WindowsFeature -Name Web-Dav-Publishing -whatif

	}
}

function Set-V41833 {

	<#
	.SYNOPSIS
	Applies finding V-41833 ("The web server must restrict the ability of users to launch Denial of Service (DoS) attacks against other information systems or networks.") from the WebServer STIG.
	.DESCRIPTION
	For every IIS Site, configures the maximum number of allowed connections
	.PARAMETER Limit
	Optional. Configures the maximum number of connections allowed for all IIS sites. If not specified, the default value is the maximum value of 4,294,967,294.
	.EXAMPLE
	Set-V41833
	.EXAMPLE
	Set-MaxConnections -Limit 4000
	.COMPONENT
	IIS Web Server
	.LINK
	http://iase.disa.mil/stigs/app-security/web-servers/Pages/index.aspx
	.LINK
	http://iasecontent.disa.mil/stigs/zip/Oct2015/U_Web_Server_V2R2_SRG.zip
	.LINK
	https://www.stigviewer.com/stig/web_server_security_requirements_guide/2014-11-17/finding/V-41833
	#>

	   [CmdletBinding()]
	param(
		[ValidateRange(0,4294967294)]
		[long]$Limit = 1000
	)

	$serverConfiguration = "/system.applicationHost/sites/*"

	$applicationHosts = Get-WebConfiguration -filter $serverConfiguration

	foreach ($application in $applicationHosts) {
		
		$name = $application.Name
		
		Set-WebConfigurationProperty -Filter $serverConfiguration -name Limits -Value @{MaxConnections=$limit}
	}
}

function Set-V41854 {

	<#
	.SYNOPSIS
	Applies finding V-41854 ("Warning and error messages displayed to clients must be modified to minimize the identity of the web server, patches, loaded modules, and directory paths.") from the Web Server STIG.
	.DESCRIPTION
	Configure the web server to minimize the information provided to the client in warning and error messages
	.EXAMPLE
	Set-V41854
	.COMPONENT
	IIS Web Server
	.LINK
	http://iase.disa.mil/stigs/app-security/web-servers/Pages/index.aspx
	.LINK
	  http://iasecontent.disa.mil/stigs/zip/Oct2015/U_Web_Server_V2R2_SRG.zip
	.LINK
	  https://www.stigviewer.com/stig/web_server_security_requirements_guide/2014-11-17/finding/V-41854
	#>

	Set-AlternateHostName
}
  
function Set-V41855 {

   <#
	.SYNOPSIS
	Applies finding V-41855 ("Debugging and trace information used to diagnose the web server must be disabled.") from the Web Server STIG.
	.DESCRIPTION
	Configure the web server to minimize the information given to clients on error conditions by disabling debugging and trace information.
	.EXAMPLE
	Set-V41855
	.COMPONENT
	IIS Web Server
	.LINK
	http://iase.disa.mil/stigs/app-security/web-servers/Pages/index.aspx
	.LINK
	  http://iasecontent.disa.mil/stigs/zip/Oct2015/U_Web_Server_V2R2_SRG.zip
	.LINK
	  https://www.stigviewer.com/stig/web_server_security_requirements_guide/2014-11-17/finding/V-41855
	#>
	  
	#Disable Server Tracing#
	C:\Windows\System32\inetsrv\appcmd.exe configure trace /disable

	$sites = Get-Website

	foreach ($site in $sites){
			
		if($site.traceFailedRequestsLogging.enabled){
			
			#Disable Site Failed Tracing Information 
			C:\Windows\System32\inetsrv\appcmd.exe configure trace $site.name /disablesite
		}
	  
	}
}

function Set-V55949 {

<#
	.SYNOPSIS
	Applies finding V-55949 ("The web server must set an inactive timeout for sessions.") from the Web Server STIG.
	.DESCRIPTION
	Configure the web server to minimize the information given to clients on error conditions by disabling debugging and trace information.
	 .PARAMETER Limit
	Optional. Configures the maximum idle time in minutes. Default is 20. 
	Set-V55949 -Timeout 20
	.COMPONENT
	IIS Web Server
	.LINK
	http://iase.disa.mil/stigs/app-security/web-servers/Pages/index.aspx
	.LINK
	  http://iasecontent.disa.mil/stigs/zip/Oct2015/U_Web_Server_V2R2_SRG.zip
	.LINK
	  https://www.stigviewer.com/stig/web_server_security_requirements_guide/2014-11-17/finding/V-55949
	#>

	
	[CmdletBinding()]
	param(
		[ValidateRange(0,60)]
		[long]$Timeout = 20
	)

   $appPools = Get-ChildItem –Path IIS:\AppPools

   foreach ($app in $appPools){
   
	   $name = $app.name
   
	   Set-ItemProperty  "IIS:\AppPools\$name" -Name processModel.idleTimeout -value ( [TimeSpan]::FromMinutes($Timeout))
   }
}

function Set-V55951 {

<#
	.SYNOPSIS
	Applies finding V-55951 ("The web server must set an absolute timeout for sessions.") from the Web Server STIG.
	.DESCRIPTION
	Configure the web server to close sessions after an absolute period of time.   
	Set-V55951 
	.COMPONENT
	IIS 7.0 Web Site
	.LINK
	http://iase.disa.mil/stigs/app-security/web-servers/Pages/index.aspx
	.LINK
	  http://iasecontent.disa.mil/stigs/zip/Oct2015/U_Web_Server_V2R2_SRG.zip
	.LINK
	  https://www.stigviewer.com/stig/web_server_security_requirements_guide/2014-11-17/finding/V-55951
	#>
   
	Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT' -filter "system.web/sessionState" -name "timeout" -value "00:20:00"
}
 
function Set-V55997 {

<#
	.SYNOPSIS
	Applies finding V-55997 ("The web server must set an absolute timeout for sessions.") from the Web Server STIG.
	.DESCRIPTION
	Configure the web server to close sessions after an absolute period of time.
	Set-V55997
	.COMPONENT
	IIS 7.0 Web Site
	.LINK
	http://iase.disa.mil/stigs/app-security/web-servers/Pages/index.aspx
	.LINK
	  http://iasecontent.disa.mil/stigs/zip/Oct2015/U_Web_Server_V2R2_SRG.zip
	.LINK
	  https://www.stigviewer.com/stig/web_server_security_requirements_guide/2014-11-17/finding/V-55997
	#>
   
	$applicationPoolsPath = "/system.applicationHost/applicationPools"
	$applicationPools = Get-WebConfiguration $applicationPoolsPath

	foreach ($appPool in $applicationPools.Collection)
	{
		$appPoolPath = "$applicationPoolsPath/add[@name='$($appPool.Name)']"
		
		Set-WebConfiguration "$appPoolPath/recycling/periodicRestart/@privateMemory" -Value 4000000
		Set-WebConfiguration "$appPoolPath/recycling/periodicRestart/@requests" -Value 1740
		Set-WebConfiguration "$appPoolPath/recycling/periodicRestart/@memory" -Value 4000000
	}

}   

function Set-V56003 {

<#
	.SYNOPSIS
	Applies finding V-56003 ("The web server must implement required cryptographic protections using cryptographic modules complying with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance when encrypting data that must be compartmentalized.") from the Web Server STIG.
	.DESCRIPTION
	Configure the web server to encrypt the session identifier for transmission to the client. 
	Set-V56003
	.COMPONENT
	IIS Web Server
	.LINK
	http://iase.disa.mil/stigs/app-security/web-servers/Pages/index.aspx
	.LINK
	  http://iasecontent.disa.mil/stigs/zip/Oct2015/U_Web_Server_V2R2_SRG.zip
	.LINK
	  https://www.stigviewer.com/stig/web_server_security_requirements_guide/2014-11-17/finding/V-56003
	#>
	
	Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/security/access" -name "sslFlags" -value "Ssl128"

}

function Set-V56007 {

<#
	.SYNOPSIS
	Applies finding V-56007 ("Cookies exchanged between the web server and the client, such as session cookies, must have cookie properties set to prohibit client-side scripts from reading the cookie data.") from the Web Server STIG.
	.DESCRIPTION
	Configure the web server to disallow client-side scripts the capability of reading cookie information.
	 .PARAMETER Limit
	Optional. Configures the maximum idle time in minutes. Default is 20. 
	Set-V56007
	.COMPONENT
	IIS Web Server
	.LINK
	http://iase.disa.mil/stigs/app-security/web-servers/Pages/index.aspx
	.LINK
	  http://iasecontent.disa.mil/stigs/zip/Oct2015/U_Web_Server_V2R2_SRG.zip
	.LINK
	  https://www.stigviewer.com/stig/web_server_security_requirements_guide/2014-11-17/finding/V-56007
	#>
	
   Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT'  -filter "system.web/sessionState" -name "cookieName" -value "ASP.NET_SessionID"
	
}

function Set-V56009 {

<#
	.SYNOPSIS
	Applies finding V-56009 ("Cookies exchanged between the web server and the client, such as session cookies, must have cookie properties set to force the encryption of cookies.") from the Web Server STIG.
	.DESCRIPTION
	Cookies exchanged between the web server and the client, such as session cookies, must have cookie properties set to force the encryption of cookies.
	 .PARAMETER Limit
	Optional. Configures the maximum idle time in minutes. Default is 20. 
	Set-V56009
	.COMPONENT
	IIS Web Server
	.LINK
	http://iase.disa.mil/stigs/app-security/web-servers/Pages/index.aspx
	.LINK
	  http://iasecontent.disa.mil/stigs/zip/Oct2015/U_Web_Server_V2R2_SRG.zip
	.LINK
	  https://www.stigviewer.com/stig/web_server_security_requirements_guide/2014-11-17/finding/V-56009
	#>
	
  Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT'  -filter "system.web/httpCookies" -name "requireSSL" -value "True"
	
}
 
function Set-V56011 {

<#
	.SYNOPSIS
	Applies finding V-56011 ("A web server must maintain the confidentiality of controlled information during transmission through the use of an approved TLS version.") from the Web Server STIG.
	.DESCRIPTION
	A web server must maintain the confidentiality of controlled information during transmission through the use of an approved TLS version.
	Set-V56011
	.COMPONENT	
	IIS Web Server
	.LINK
	http://iase.disa.mil/stigs/app-security/web-servers/Pages/index.aspx
	.LINK
	http://iasecontent.disa.mil/stigs/zip/Oct2015/U_Web_Server_V2R2_SRG.zip
	.LINK
	https://www.stigviewer.com/stig/web_server_security_requirements_guide/2014-11-17/finding/V-56011
	.NOTES
	SAME AS Set-V56003
	#>
	
	 Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/security/access" -name "sslFlags" -value "Ssl128"
	
}

function Set-V56015 {

<#
	.SYNOPSIS
	Applies finding V-56015 ("The web server must maintain the confidentiality and integrity of information during reception.") from the Web Server STIG.
	.DESCRIPTION
	Configure the web server to utilize a transmission method that maintains the confidentiality and integrity of information during reception.
	Set-V56015
	.COMPONENT
	IIS Web Server
	.LINK
	http://iase.disa.mil/stigs/app-security/web-servers/Pages/index.aspx
	.LINK
	http://iasecontent.disa.mil/stigs/zip/Oct2015/U_Web_Server_V2R2_SRG.zip
	.LINK
	https://www.stigviewer.com/stig/web_server_security_requirements_guide/2014-11-17/finding/V-56015
	#>
	
	 Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/security/access" -name "sslFlags" -value "Ssl128"
}

function Set-V56017 {

<#
	.SYNOPSIS
	Applies findingV-56017 ("The web server must maintain the confidentiality and integrity of information during reception.") from the Web Server STIG.
	.DESCRIPTION
	Configure the web server to utilize cryptography when protecting compartmentalized data.
	Set-V56017
	.COMPONENT
	IIS Web Server
	.LINK
	http://iase.disa.mil/stigs/app-security/web-servers/Pages/index.aspx
	.LINK
	http://iasecontent.disa.mil/stigs/zip/Oct2015/U_Web_Server_V2R2_SRG.zip
	.LINK
	https://www.stigviewer.com/stig/web_server_security_requirements_guide/2014-11-17/finding/V-56017
	#>
	
	# Add and Enable TLS 1.2 for client and server SCHANNEL communications
	New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force | Out-Null
	New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
	New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
	New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force | Out-Null
	New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
	New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
	Write-Host 'TLS 1.2 has been enabled.'

}

function Set-V56023 {

	<#
	.SYNOPSIS
	Applies findingV-56023 ("The web server must generate a unique session identifier for each session using a FIPS 140-2 approved random number generator.") from the Web Server STIG.
	.DESCRIPTION
	Configure the web server to generate unique session identifiers using a FIPS 140-2 random number generator.
	Set-V56023
	.COMPONENT
	IIS Web Server
	.LINK
	http://iase.disa.mil/stigs/app-security/web-servers/Pages/index.aspx
	.LINK
	http://iasecontent.disa.mil/stigs/zip/Oct2015/U_Web_Server_V2R2_SRG.zip
	.LINK
	https://www.stigviewer.com/stig/web_server_security_requirements_guide/2014-11-17/finding/V-56023
	#>
	
	Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT'  -filter "system.web/machineKey" -name "validation" -value "SHA1"
}

function Set-V56025 {

<#
	.SYNOPSIS
	Applies findingV-56025 ("Cookies exchanged between the web server and client, such as session cookies, must have security settings that disallow cookie access outside the originating web server and hosted application.") from the Web Server STIG.
	.DESCRIPTION
	Configure the web server to generate unique session identifiers using a FIPS 140-2 random number generator.
	Set-V56025
	.COMPONENT
	IIS Web Server
	.LINK
	http://iase.disa.mil/stigs/app-security/web-servers/Pages/index.aspx
	.LINK
	http://iasecontent.disa.mil/stigs/zip/Oct2015/U_Web_Server_V2R2_SRG.zip
	.LINK
	https://www.stigviewer.com/stig/web_server_security_requirements_guide/2014-11-17/finding/V-56025
	#>
	
	Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT'  -filter "system.web/machineKey" -name "decryptionKey" -value "AutoGenerate,IsolateApps"
	Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT'  -filter "system.web/machineKey" -name "validationKey" -value "AutoGenerate,IsolateApps"
}

function Set-V56035 {

	<#
	.SYNOPSIS
	Applies findingV-56035 ("The web server must display a default hosted application web page, not a directory listing, when a requested web page cannot be found.") from the Web Server STIG.
	.DESCRIPTION
	Place a default web page in every web document directory.
	Set-V56035
	.COMPONENT
	IIS Web Server
	.LINK
	http://iase.disa.mil/stigs/app-security/web-servers/Pages/index.aspx
	.LINK
	http://iasecontent.disa.mil/stigs/zip/Oct2015/U_Web_Server_V2R2_SRG.zip
	.LINK
	https://www.stigviewer.com/stig/web_server_security_requirements_guide/2014-11-17/finding/V-56035
	#>

	Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/directoryBrowse" -name "enabled" -value "False"
}
 
function Add-FileExtensionServer ($extension,$allowed) {
	
	C:\Windows\System32\inetsrv\appcmd.exe set config -section:system.webServer/security/requestFiltering /+"fileExtensions.[fileExtension='$extension',allowed='$allowed']"
	
}

function Add-FileExtensionSite ($extension,$allowed,$website) {

	C:\Windows\System32\inetsrv\appcmd.exe set config $website -section:system.webServer/security/requestFiltering /+"fileExtensions.[fileExtension='$extension',allowed='$allowed']"

}

function Add-AllowedFileExtensionsServer {
	
	[CmdletBinding()]
	param(
		[string]$File
	)

	$allowedExtensions = Import-CSV -Path $file

	  foreach ($extension in $allowedExtensions) {
		
		Write-Output "Setting $($extension.fileExtension) to allowed in Request Filtering"
		
		Add-FileExtensionServer $extension.fileExtension $extension.Allowed
	
	}
}

function Set-AlternateHostName {

	$fqdn = "$env:computername.$env:userdnsdomain"

	$runtimeConfig = Get-WebConfiguration -filter "/system.webServer/serverRuntime"

	if (!$runtimeConfig.alternateHostName){

		Write-Output "Server is not STIG compliant - alternateHostName is blank"
		   
		Set-WebConfigurationProperty -Filter "/system.webServer/serverRuntime" -name alternateHostName -Value $fqdn

	}

	else {

		Write-Output "Server is STIG Compliant - alternateHostName is $runtimeConfig.alternateHostName"
	
	}

}
 
function Set-DoubleEscapingURLs {

	$serverConfig = "/system.webServer/security/requestFiltering"
	$requestFiltering = Get-WebConfiguration -filter $serverConfig

	# Apply configuration at the server level first #

	if ($requestFiltering.allowDoubleEscaping -eq $true){
		
		Write-Output "Server configuration is not STIG compliant - setting double escaping to false"
		
		$requestFiltering.allowDoubleEscaping = $false
		$requestFiltering | Set-WebConfiguration -filter $serverConfig -PSPath IIS:\
	}
	else {
		
		Write-Output "Server configuration is STIG compliant - allow double escaping already set to false"
	}


	# Apply configuration to each IIS site via a loop #

	$websites = Get-WebSite

	foreach ($website in $websites) {

		$siteName = $website.Name

		if ($iisVersion -le 7) {

				C:\Windows\System32\inetsrv\appcmd.exe set config $siteName -section:system.webServer/security/requestFiltering /allowdoubleescaping:false

		} 
			
		else {

			$requestFiltering = Get-WebConfiguration -filter $serverConfig -Location $siteName
		
			if ($requestFiltering.allowDoubleEscaping -eq $true){
		
				Write-Output "$siteName is not STIG compliant - setting allow double escaping to false"
		   
				Set-WebConfigurationProperty -Filter $serverConfig -name allowDoubleEscaping -Value False -PSPath IIS:\sites\$siteName
		
			} else {
		
				Write-Output "$siteName is STIG Compliant - allow double escaping is already set to false"
		
			}
		}
	   
	}

}

function Set-HighBitCharacters {

	<#
	.SYNOPSIS
	Applies finding V-26044 ("The web-site must not allow non-ASCII characters in URLs.") from the IIS 7 Web Site STIG.
	.DESCRIPTION
	Disables high bit non-ASCII characters in IIS request filtering
	.EXAMPLE
	Set-HighBitCharacters
	.COMPONENT
	IIS 7.0 Web Site
	.LINK
	http://iase.disa.mil/stigs/app-security/web-servers/Pages/index.aspx
	.LINK
	http://iasecontent.disa.mil/stigs/zip/July2015/U_IIS_7-0_V1R8_STIG.zip
	.LINK
	https://www.stigviewer.com/stig/iis_7.0_web_site/2015-06-01/finding/V-26044
	#>

	$serverConfig = "/system.webServer/security/requestFiltering"
	$requestFiltering = Get-WebConfiguration -filter $serverConfig

	# Apply configuration at the server level first #

	if ($requestFiltering.allowHighBitCharacters -eq $true){
		
		Write-Output "Server configuration is not STIG compliant - setting allow high bit characters to false"
		
		$requestFiltering.allowHighBitCharacters = $false
		$requestFiltering | Set-WebConfiguration -filter $serverConfig -PSPath IIS:\
	}
	else {
		
		Write-Output "Server configuration is STIG compliant - allow high bit characters already set to false"
	}

	# Apply configuration to each IIS site via a loop #

	$websites = Get-WebSite

	foreach ($website in $websites) {
			
		$siteName = $website.Name

		if ($iisVersion -le 7) {

				C:\Windows\System32\inetsrv\appcmd.exe set config $siteName -section:system.webServer/security/requestFiltering /allowHighBitCharacters:false

		} 

		else {
		
			$requestFiltering = Get-WebConfiguration -filter $serverConfig -Location $siteName
		
			if ($requestFiltering.allowHighBitCharacters -eq $true) {
		
				Write-Output "$siteName is not STIG compliant - setting allow high bit characters to false"
				Set-WebConfigurationProperty -Filter $serverConfig -name allowHighBitCharacters -Value False -PSPath IIS:\sites\$siteName
		
			}
		
			else {
		   
				Write-Output "$siteName - STIG Compliant - Allow high bit characters is set to false"
		
			}
		}
	}

}
 
function Remove-NTFSPermissions {


  <#
	.SYNOPSIS
	 Removes the security inheritance from from the Path
	.DESCRIPTION
	Configure the web server log files so unauthorized access of log information is not possible.
	.PARAMETER FolderPath
	Sets the path to break inheritance.
	.PARAMETER AccountToRemove
	Sets the path to break inheritance.
	.PARAMETER PermissionToRemove
	Sets the path to break inheritance.
	.EXAMPLE
	Remove-Inheritance -Path "D:\Inetpub" -AccountToRemove "Creator owner" -PermissionToRemove "Read,Modify"
	#>
	  
	[CmdletBinding()]
	param(
		[string]$Path = "D:\inetpub",
		[string]$AccountToRemove,
		[string]$PermissionToRemove
	)

	$fileSystemRights = [System.Security.AccessControl.FileSystemRights]$permissionToRemove

	$inheritanceFlag = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"

	$propagationFlag = [System.Security.AccessControl.PropagationFlags]"None"

	$accessControlType =[System.Security.AccessControl.AccessControlType]::Allow
  
	$ntAccount = New-Object System.Security.Principal.NTAccount($accountToRemove)

	if($ntAccount.IsValidTargetType([Security.Principal.SecurityIdentifier])) {

		$FileSystemAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($ntAccount, $fileSystemRights, $inheritanceFlag, $propagationFlag, $accessControlType)

		
		$oFS = New-Object IO.DirectoryInfo($Path)

		$DirectorySecurity = $oFS.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access)

		

		$DirectorySecurity.RemoveAccessRuleAll($FileSystemAccessRule)
		 
		$oFS.SetAccessControl($DirectorySecurity)
				

		return "Permissions " + $permissionToRemove + " Removed on " + $Path + " folder"

	}

	return 0

}
  
function Remove-Inheritance {

   <#
	.SYNOPSIS
	 Removes the security inheritance from from the Path
	.DESCRIPTION
	Configure the web server log files so unauthorized access of log information is not possible.
	.PARAMETER Path
	Optional. Sets the path to break inheritance.
	.EXAMPLE
	Remove-Inheritance -Path "D:\Inetpub"
	#>
	
	[CmdletBinding()]
	param(
		[string]$Path = "D:\inetpub"
	)
	 
	#$isProtected = $True
	#$preserveInheritance = $True       

	#$acl = Get-Acl -Path $Path

	#$acl.SetAccessRuleProtection($isProtected,$preserveInheritance);
 
	#Set-Acl -Path $Path -AclObject $acl
	
	$isProtected = $true

	$preserveInheritance = $true
		

	$oFS = New-Object IO.DirectoryInfo($Path)

	$DirectorySecurity = $oFS.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access)

	
	$DirectorySecurity.SetAccessRuleProtection($isProtected, $preserveInheritance)
		

	$oFS.SetAccessControl($DirectorySecurity)
}
 
function Remove-ShellMIMEType {
 
	$serverConfiguration = "/system.webServer/staticContent/*"

	$hosts = Get-WebConfiguration -Filter $serverConfiguration

	foreach($host in $hosts){
	
	if($host.mimeType -like 'shell/*')
	{
		$fileExtension = $host.fileExtension
		$mimeType = $host.mimeType

		C:\Windows\System32\inetsrv\appcmd.exe set config /section:staticContent /-"[fileExtension='$fileExtension',mimeType='$mimeType']"
	  
	}      
} 

}