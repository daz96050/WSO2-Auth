<#
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2020 v5.7.182
	 Created on:   	12/21/2020 10:49 AM
	 Created by:   	Dakota Zinn
	 Organization:
	 Filename:     	WSO2-Auth.psd1
	 -------------------------------------------------------------------------
	 Module Manifest
	-------------------------------------------------------------------------
	 Module Name: WSO2-Auth
	===========================================================================
#>


@{

	# Script module or binary module file associated with this manifest
	RootModule = 'WSO2-Auth.psm1'

	# Version number of this module.
	ModuleVersion = '1.0.0.0'

	# ID used to uniquely identify this module
	GUID = 'a9c0aa3b-6ca9-45f6-a8c0-8b5ee4b111e5'

	# Author of this module
	Author = 'Dakota Zinn'

	# Company or vendor of this module
	CompanyName = ''

	# Copyright statement for this module
	Copyright = '(c) 2020. All rights reserved.'

	# Description of the functionality provided by this module
	Description = 'Module for Authentication with WSO2 APIM and Identity Server'

	# Minimum version of the Windows PowerShell engine required by this module
	PowerShellVersion = '5.0'

	# Name of the Windows PowerShell host required by this module
	PowerShellHostName = ''

	# Minimum version of the Windows PowerShell host required by this module
	PowerShellHostVersion = ''

	# Minimum version of the .NET Framework required by this module
	DotNetFrameworkVersion = '2.0'

	# Minimum version of the common language runtime (CLR) required by this module
	CLRVersion = '2.0.50727'

	# Processor architecture (None, X86, Amd64, IA64) required by this module
	ProcessorArchitecture = 'None'

	# Modules that must be imported into the global environment prior to importing
	# this module
	RequiredModules	       = @(
		"MSAL.PS"
	)

	# Assemblies that must be loaded prior to importing this module
	RequiredAssemblies = @()

	# Script files (.ps1) that are run in the caller's environment prior to
	# importing this module
	ScriptsToProcess = @()

	# Type files (.ps1xml) to be loaded when importing this module
	TypesToProcess = @()

	# Format files (.ps1xml) to be loaded when importing this module
	FormatsToProcess = @()

	# Modules to import as nested modules of the module specified in
	# ModuleToProcess
	NestedModules = @()

	# Functions to export from this module
	FunctionsToExport = @(
		'Connect-WSO2'
		'Disconnect-WSO2'
		'Get-WSO2Token'
		'Get-AzureJWT'
	) #For performance, list functions explicitly

	# Cmdlets to export from this module
	CmdletsToExport = '*'

	# Variables to export from this module
	VariablesToExport	   = @(

	)

	# Aliases to export from this module
	AliasesToExport = '*' #For performance, list alias explicitly

	# DSC class resources to export from this module.
	#DSCResourcesToExport = ''

	# List of all modules packaged with this module
	ModuleList = @()

	# List of all files packaged with this module
	FileList = @()

	# Private data to pass to the module specified in ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
	PrivateData = @{

		#Support for PowerShellGet galleries.
		PSData = @{

			# Tags applied to this module. These help with module discovery in online galleries.
			Tags = @(
				'WSO2'
				'Authentication'
			)

			# A URL to the license for this module.
			# LicenseUri = ''

			# A URL to the main website for this project.
			ProjectUri = 'https://github.com/daz96050/WSO2-Auth'

			# A URL to an icon representing this module.
			IconUri = 'https://wso2.cachefly.net/wso2/sites/all/2020-theme/images/wso2-logo.svg'

			# ReleaseNotes of this module
			# ReleaseNotes = ''

		} # End of PSData hashtable

	} # End of PrivateData hashtable
}








