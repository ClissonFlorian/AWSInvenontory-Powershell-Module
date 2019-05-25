function New-PSEC2Instance {

    param (
        [Parameter(Mandatory = $true)][string]$serverName,
        [Parameter(Mandatory = $false)][string]$Region="eu-west-3",
        [Parameter(Mandatory = $true)][string]$amiId,
        [Parameter(Mandatory = $true)][string]$instanceType,
        [Parameter(Mandatory = $true)][string]$keyName,
        [Parameter(Mandatory = $true)][string]$securityGroups
        #[Parameter(Mandatory = $true)][string]$subnetId
    )

    #=====================================================================================
    # Initialise the AWS SDK and import the helpers
    #
    # Download: https://aws.amazon.com/powershell/
    # Docs: http://docs.aws.amazon.com/powershell/latest/reference/Index.html
    #
    #=====================================================================================
    & Initialize-AWSDefaults

    #=====================================================================================
    # Login
    #=====================================================================================
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
    #=====================================================================================
    # Create a key pair for decrypting the Windows password
    #=====================================================================================
    $pemFullPath = "$pwd\$keyName.pem"

    #=====================================================================================
    # Create the AWS instance from an AMI
    #=====================================================================================
    Write-Host "=> Creating '$instanceType' instance from ami '$amiId' in subnet '$subnetId'..." -ForegroundColor Magenta

    $securityGroups = $securityGroups.Replace(' ', '')
    $securityGroupId = $securityGroups.Split(',')

    $parameters = @{
        AssociatePublicIp = $false
        ImageId           = $amiId
        InstanceType      = $instanceType
        KeyName           = $keyName
        SecurityGroupId   = $securityGroupId
        Region            = $Region
        #SubnetId          = $subnetId
    }

    $data = New-EC2Instance @parameters

    if (!$data -or $data.Instances.Length -ne 1) {
        Write-Warning "No instance data was returned from AWS"
        exit 1;
    }

    $instance = $data.Instances[0]
    $instanceId = $instance.InstanceId

    # Name it
    $tag = New-Object Amazon.EC2.Model.Tag
    $tag.Key = "Name"
    $tag.Value = "$serverName"
    New-EC2Tag -Tag $tag -Resource $instanceId

    $tag = New-Object Amazon.EC2.Model.Tag
    $tag.Key = "AddedBy"
    $tag.Value = $env:USERNAME
    New-EC2Tag -Tag $tag -Resource $instanceId

    #=====================================================================================
    # Wait for the instance to be running
    #
    # Docs: http://docs.aws.amazon.com/sdkfornet1/latest/apidocs/html/P_Amazon_EC2_Model_InstanceState_Name.htm
    # - valid values are: pending | running | shutting-down | terminated | stopping | stopped
    #
    #=====================================================================================
    $data = Get-EC2Instance -InstanceId $instanceId -Region $Region
    $currentState = $data.Instances[0].State.Name;

    while ($currentState -ne "running") {
        Write-Debug "Waiting 60 seconds for instance '$instanceId' to be in a 'running' state (currently '$currentState')..."
        Sleep 60

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

    Write-Debug "The IP of instance '$instanceId' is '$ip'"

    #=====================================================================================
    # Decrypt and get the administrator password
    #=====================================================================================
    Write-Host "=> Retrieving the encrypted administrator password..." -ForegroundColor Magenta

    $tries = 10;
    $tryCount = 0;

    while ($tryCount -lt $tries) {
        try {
            $adminPassword = Get-EC2PasswordData -InstanceId $instanceId -PemFile $pemFullPath
        }
        catch {
            $adminPassword = ""
        }

        if ($adminPassword) {
            break;
        }

        $tryCount += 1;
        Write-Debug "Waiting 60 seconds for administrator password (attempt $tryCount of $tries)..."
        Sleep 60
    }


    if (!$adminPassword) {
        Write-Warning "No admin password retrieved for instance $instanceId, aborting."
        Write-Warning "Terminating instance id '$instanceId'"
        Stop-EC2Instance -Instance $instanceId -Terminate -Force -Confirm:$false
        exit;
    }

    Write-Debug "The administrator password is '$adminPassword'"

    $Error.Clear();

    #=====================================================================================
    # Open up WinRM on the machine, lock it down later
    #=====================================================================================
    Write-Host "=> Configuring WinRM client to connect to AWS..." -ForegroundColor Magenta

    winrm quickconfig
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
    Set-Item WSMan:\localhost\Client\AllowUnencrypted -Value $true -Force

    #=====================================================================================
    # Wait for WinRM to appear
    #=====================================================================================
    Write-Host "=> Waiting for WinRM to be enabled on the server..." -ForegroundColor Magenta

    Test-WinRMConnection $adminPassword $ip $instanceId

    #=====================================================================================
    # Set Region and Language Settings (Windows 2012)
    #=====================================================================================
    Write-Host "=> Configuring region and language settings..." -ForegroundColor Magenta

    # GetNewRemoteSession is a helper for new-pssession
    $session = GetNewRemoteSession $ip $adminPassword

    # For the system locale (requires restart)
    Invoke-Command -Session $session -ScriptBlock { Set-WinSystemLocale en-GB }

    # For the current user account
    Invoke-Command -Session $session -ScriptBlock { Set-Culture en-GB }
    Invoke-Command -Session $session -ScriptBlock { Set-WinHomeLocation -GeoId 242 }
    Invoke-Command -Session $session -ScriptBlock { Set-WinUserLanguageList en-GB -Force }

    #=====================================================================================
    # Terminate the instance if there were errors
    #=====================================================================================
    if ($Error.Count -eq 0) {
        Write-Information "`nFinished. '$instanceId' is alive!"
    }
    else {
        Write-Warning "`nErrors occurred (use `$Error to view them)"
        Write-Host ""
        $terminate = Read-Host "Do you want to terminate the instance? ([Y/N])"

        if ($terminate.ToLower() -eq "y") {
            Write-Debug "Terminating instance id '$instanceId'"
            $state = Stop-EC2Instance -Instance $instanceId -Terminate -Force -Confirm:$false
            Write-Debug "Instance id '$instanceId' new state is $($state.CurrentState)"
        }
    }
}


$parameters = @{

    serverName     = "PSGUI"
    amiId          = "ami-0a3421f99d36f7006"
    instanceType   = "t2.micro" 
    KeyName        = "Administrators"
    securityGroups = "sg-04b97f6d024193934"
}

New-PSEC2Instance @parameters