$ErrorActionPreference = "Stop"

function Clean-HashTable {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [pscustomobject]$Hashtable
    )

    $params = New-Object PSobject -property $Hashtable
    $NewHashTable = $params.psobject.properties | Where-Object { $_.value -ne "" } | Select-Object Name,Value
    return $NewHashTable
}




function New-PSEC2Instance {

    param (
        [Parameter(Mandatory = $true)][string]$serverName,
        [Parameter(Mandatory = $false)][string]$Region = "eu-west-3",
        [Parameter(Mandatory = $true)][string]$amiId,
        [Parameter(Mandatory = $true)][string]$instanceType,
        [Parameter(Mandatory = $true)][string]$securityGroups,
        [Parameter(Mandatory = $true)][string]$KeyPairName,
        [Parameter(Mandatory = $false)][string]$PemFile,
        [Parameter(Mandatory = $false)][switch]$NoNewKeyPair
    )

    #
    # ─── TODO ───────────────────────────────────────────────────────────────────────
    # Adding New Volume Creation
 
    try {
        
        #
        # ─── INITIALISE THE AWS SDK AND IMPORT THE HELPERS ───────────────
        # Download: https://aws.amazon.com/powershell/
        # Docs: http://docs.aws.amazon.com/powershell/latest/reference/Index.html
        # ─────────────────────────────────────────────────────────────────

        & Initialize-AWSDefaults

        #
        # ─── LOGIN ───────────────────────────────────────────────────────
        #

        $sessionCreds = Get-AWSCredentials;

        if (!$sessionCreds) {
            $awsKey = Read-Host "Enter the AWS access key"
            $awsSecretKey = Read-Host "Enter the AWS secret key"
        }
        else {
            $awsKey = $sessionCreds.GetCredentials().AccessKey
            $awsSecretKey = $sessionCreds.GetCredentials().SecretKey
        }

        Set-AWSCredentials -AccessKey $awsKey -SecretKey $awsSecretKey
        Set-DefaultAWSRegion -Region $Region

        #
        # ─── CREATE A KEY PAIR FOR DECRYPTING THE WINDOWS PASSWORD ───────
        #

        if($NoNewKeyPair){
            
            Write-Host "=> Checking AWS Key Pair $KeyPairName..." -NoNewline
            # FIXME Compare key pair with PemFile before to continue
            $GetKeyPair = (Get-EC2KeyPair -KeyName "$KeyPairName").KeyMaterial
            Write-Host "OK" -ForegroundColor Green
            
            Write-Host "=> Test-Path keyPair path $PemFile..." -NoNewline
            if(-NOT (Test-path $PemFile)){
                Write-Error -Message "Not found"
            }
            Write-Host "OK" -ForegroundColor Green

        }else{
           
            Write-Host "=> Creating KeyPair '$KeyPairName' and save key to '$PemFile'..." -NoNewline
            # FIXME Adding Force Mode (Otherwrite file)
            if(Test-path $PemFile){
                Write-Error -Message "This $PemFile file already exist"
            }

            $GetKeyPair = (New-EC2KeyPair -KeyName "$KeyPairName").KeyMaterial
            $GetKeyPair | Out-File "$PemFile"
            Write-Host "OK" -ForegroundColor Green
        }


        # Write-Host "=> Compare keyPair and Pem File..." -NoNewline
        # $pemContent = Get-Content -Path $PemFile
        # if($GetKeyPair -eq $pemContent){
        
        #     Write-Host "OK" -ForegroundColor Green
        
        # }else{
        #     Write-Error "KeyPair doesn't match between aws key and pem file"
        # }
     

        #
        # ─── CREATE THE AWS INSTANCE FROM AN AMI ─────────────────────────
        #

        Write-Host "=> Creating '$instanceType' instance from ami '$amiId' in subnet '$subnetId'..." -NoNewline

        $securityGroups = $securityGroups.Replace(' ', '')
        $securityGroupId = $securityGroups.Split(',')

        $parameters = @{
            AssociatePublicIp = $false
            ImageId           = $amiId
            InstanceType      = $instanceType
            KeyName           = $KeyPairName
            SecurityGroupId   = $securityGroupId
            Region            = $Region
            #SubnetId          = $subnetId
        }

        $data = New-EC2Instance @parameters
        Write-Host "OK" -ForegroundColor Green

        if (!$data -or $data.Instances.Length -ne 1) {
            Write-Warning "No instance data was returned from AWS"
            exit 1;
        }

        #
        # ─── ADDING AWS TAGS ─────────────────────────────────────────────
        #

        $instance = $data.Instances[0]
        $script:instanceId = $instance.InstanceId

        Write-Host "=> Adding tags to '[$instanceType][$instanceId]'..." -NoNewline
        $Tags = @( 
            @{key="Name";value="James"},
            @{key="CreatedBy";value="James"},
            @{key="Department";value="Solutions Architecture"} 
        )
        New-EC2Tag -Tag $tags -Resource $instanceId
        Write-Host "OK" -ForegroundColor Green


        #
        # ─── WAIT FOR THE INSTANCE TO BE RUNNING ─────────────────────────
        #
        #   Docs: http://docs.aws.amazon.com/sdkfornet1/latest/apidocs/html/P_Amazon_EC2_Model_InstanceState_Name.htm
        #   - valid values are: pending | running | shutting-down | terminated | stopping | stopped
        #
        # ─────────────────────────────────────────────────────────────────

        $data = Get-EC2Instance -InstanceId $instanceId -Region $Region
        $currentState = $data.Instances[0].State.Name;

        while ($currentState -ne "running") {
            Write-Debug "Waiting 60 seconds for instance '$instanceId' to be in a 'running' state (currently '$currentState')..."
            Start-Sleep 60

            $data = Get-EC2Instance -InstanceId $instanceId -Region $Region
            $currentState = $data.Instances[0].State.Name;
        }

        Write-Debug "instance '$instanceId' is now state '$currentState'"

        $data = Get-EC2Instance -InstanceId $instanceId -Region $Region
        $ip = $data.Instances[0].PrivateIpAddress

        if (!$ip) {
            Write-Warning "No ip found for instance $instanceId, aborting."
            Write-Warning "Terminating $instanceId"
            Stop-EC2Instance -Instance $instanceId -Terminate -Force -Confirm:$false
            exit;
        }

        #
        # ─── DECRYPT AND GET THE ADMINISTRATOR PASSWORD ──────────────────
        #

        Write-Host "=> Retrieving the encrypted administrator password..." 

        $tries = 10;
        $tryCount = 0;

        while ($tryCount -lt $tries) {
            try {
                $adminPassword = Get-EC2PasswordData -InstanceId $instanceId -PemFile "$PemFile"
            }
            catch {
                $adminPassword = ""
            }

            if ($adminPassword) {
                break;
            }

            $tryCount += 1;
            Write-Debug "Waiting 60 seconds for administrator password (attempt $tryCount of $tries)..."
            Start-Sleep 60
        }


        if (!$adminPassword) {
            Write-Warning "No admin password retrieved for instance $instanceId, aborting."
            Write-Warning "Terminating instance id '$instanceId'"
            Stop-EC2Instance -Instance $instanceId -Terminate -Force -Confirm:$false
            exit;
        }

        Write-Host "The IP of instance '$instanceId' is '$ip'"
        Write-Host "The administrator password is '$adminPassword'"
    
    }catch{
        Write-Host "KO" -ForegroundColor Red
        Write-Host $PSItem -ForegroundColor Red
    }
}

$Region = "eu-west-3"
Set-DefaultAWSRegion -Region $Region
$sessionCreds = Get-AWSCredentials;
$awsKey = $sessionCreds.GetCredentials().AccessKey
$awsSecretKey = $sessionCreds.GetCredentials().SecretKey
Set-AWSCredentials -AccessKey $awsKey -SecretKey $awsSecretKey

$parameters = @{

    serverName     = "PSGUI"
    amiId          = "ami-0a3421f99d36f7006"
    instanceType   = "t2.micro" 
    securityGroups = "sg-04b97f6d024193934"
    KeyPairName    = "Administrators10"
    PemFile        = "C:\Temp\Administrators10.pem"
    NoNewKeyPair   = $false
    Region         = "eu-west-3"
}

New-PSEC2Instance @parameters


#
# ─── VOLUMES ────────────────────────────────────────────────────────────────────
#

$HardDisks = @(
    @{SnapshotId = "";Size = 80;AvailabilityZone = "eu-west-3c";VolumeType = "gp2";Encrypted = $false;Iops = "";KmsKeyId = "";TagSpecification = "";Force=$false}
    @{SnapshotId = "";Size = 90;AvailabilityZone = "eu-west-3c";VolumeType = "gp2";Encrypted = $false;Iops = "";KmsKeyId = "";TagSpecification = "";Force=$false}
)

try{
    $Count=1
    $AZ = [char[]](65..90)
    $HardDisks | ForEach-Object {
        Write-Host "=> Create New Volume..." -NoNewline
        
        $Volume = New-EC2Volume -Size $($_.Size) -AvailabilityZone "$($_.AvailabilityZone)" -VolumeType "$($_.VolumeType)"
        $VolumeId = $Volume.VolumeId
        #$Volume = New-EC2Volume -Size 50 -AvailabilityZone "eu-west-3c" -VolumeType gp2 -Region eu-west-3
        Write-Host "OK" -ForegroundColor Green

        Do{
            Sleep -Seconds 2
            $VolumeState = (Get-EC2Volume -VolumeId $VolumeId).State
            #FIXME  Timeout to add

        }while($VolumeState -ne "available")
        
        
        Write-Host "=> Attach volume [$volumeId] to [$instanceId]..." -NoNewline
        $DeviceName = ("xvd$($AZ[$Count])").ToLower()  
        Add-EC2Volume -InstanceId $instanceId -VolumeId $VolumeId -Device "$DeviceName" -Force
        Write-Host "OK" -ForegroundColor Green
        $Count++
    }
}catch{

    Write-Host $PSItem -ForegroundColor Red
}
