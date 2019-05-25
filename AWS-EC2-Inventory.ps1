[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)][object]$ExportDirectory="C:\Temp\AWS-Export"
)
#TODO#################################"
#   * Security Groups
######################################"

#Create Export Directory
if (-NOT (test-path $ExportDirectory)) {
    New-Item -Path $ExportDirectory -ItemType Directory | Out-Null
}

#Get AWS Region
$aws_region = Get-AWSRegion
$Regions = ($aws_region).Region


#region functions
    function Export-Region {
        $Data = Get-AWSRegion
        return $Data
    }

    function Export-EC2AvailabilityZone {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)][object]$Region
        )

        $Object = @(
            "RegionName"
            "State"
            "ZoneId"
            "ZoneName" 
        )
        $Data = Get-EC2AvailabilityZone -Region $Region | Select-Object -Property $Object
        return $Data
    }

    function Export-EC2Tag {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)][object]$Region
        )
        $Data = Get-EC2Tag -Region $Region
        $Data | Add-Member -MemberType NoteProperty "RegionName" -Value "$Region"
        return $Data
    }

    function Export-EC2Instance {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)][object]$EC2Instances,
            [Parameter(Mandatory = $true)][string]$Region
        )

        $Object = @(
            "Architecture"
            "EbsOptimized"
            "EnaSupport"
            "Hypervisor"
            "InstanceId"
            "InstanceType"
            "ImageId"
            "KeyName"
            "LaunchTime"
            "Platform"
            "PrivateDnsName"
            "PrivateIpAddress"
            "PublicDnsName"
            "PublicIpAddress"
            "RamdiskId"
            "RootDeviceName"
            "RootDeviceType"
            "SourceDestCheck"
            "SpotInstanceRequestId"
            "VirtualizationType"
            "VpcId"
        )
        $Data = $EC2Instances | Select-Object -Property $Object
        $Data | Add-Member -MemberType NoteProperty "RegionName" -Value "$Region"
        return $Data
    }
#end region


#region main
    $Count = 0
    $aws_region | Export-Csv -Path "$ExportDirectory\Export-Aws-Region.csv" -NoTypeInformation
    ForEach ($Region in $Regions) {
    
        $EC2Instances = (Get-EC2Instance -Region "$Region").Instances
        if($EC2Instances){
            $Export_Aws_Instances = Export-EC2Instance -EC2Instances  $EC2Instances -Region $Region
        }
        $Export_Aws_AvailabilityZone = Export-EC2AvailabilityZone -Region $Region
        $Export_Aws_EC2Tag = Export-EC2Tag -Region $Region
        
        $FileName = Get-Variable -Name "Export_Aws_*" -Scope Local

        $FileName | ForEach-Object {
            $FilePath =  "$ExportDirectory\$($_.Name).csv"
            $Data = $($_.Value)
            if($Count -eq 0){
                if(Test-Path $FilePath){
                    Write-Host "Cleaning file $FilePath" -ForegroundColor Yellow
                    Remove-Item -Path $FilePath -Force | Out-Null
                }
            }
            $Data | Format-Table
            if($Data){
                Write-Host "addded $FilePath" -ForegroundColor Green
                $Data| Export-Csv -Path "$FilePath" -NoTypeInformation -Append
            }
        }
        $Count++
    }
#end region
