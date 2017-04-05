# IIS Web Server SRG Version: 2
Powershell scripts that handle the ISA Web Server STIG Requirements for IIS


## SharePoint 2013 STIGs Installation and Configuration

### Installation

1. Download or clone this repository: `git clone https://github.com/JCWW/IIS-Web-Server-SRG-Version-2`
2. Update the `$downloadFolder` variable in `InstallIISWebServerSRGv2Module.ps1'  with the path to the directory in the cloned repository. 
3. Run `InstallIISWebServerSRGv2Module.ps1`
4. The module files will be copied to the modules folder for your user account. This is typically `C:\Users\username\Documents\WindowsPowerShell\Modules\`. If the folder does not exist already it will be created as part of the installation script.
