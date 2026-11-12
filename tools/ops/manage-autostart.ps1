[CmdletBinding()]
param(
    [ValidateSet("Install", "Remove", "Status", "Restart", "Stop")]
    [string]$Action = "Status",
    [string]$Root = "",
    [string]$TaskName = "ReverseResearch Server"
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($Root)) {
    $Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
} else {
    $Root = (Resolve-Path $Root).Path
}

Import-Module (Join-Path $PSScriptRoot "runtime-artifact.psm1") -Force
$exe = Resolve-RRInstalledArtifact -Root $Root
$account = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$listenPort = 19100
$healthUrl = "http://127.0.0.1:$listenPort/healthz"
$shutdownUrl = "http://127.0.0.1:$listenPort/control/shutdown"
$tokenPath = Join-Path $Root "state\auth\local-mcp.token"

function Resolve-Sid {
    param([string]$Identity)
    if ([string]::IsNullOrWhiteSpace($Identity)) {
        return ""
    }
    try {
        return (New-Object System.Security.Principal.NTAccount($Identity)).Translate([System.Security.Principal.SecurityIdentifier]).Value
    } catch {
        return $Identity
    }
}

function Get-TaskStatus {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $task) {
        return [ordered]@{
            installed = $false
            exact_definition = $false
            task_name = $TaskName
            expected_executable = $exe
            expected_arguments = "serve --tunnel"
            expected_working_directory = $Root
        }
    }

    $actions = @($task.Actions)
    $triggers = @($task.Triggers)
    $actionInfo = $actions | Select-Object -First 1
    $triggerInfo = $triggers | Select-Object -First 1

    $actionExact = (
        $actions.Count -eq 1 -and
        $actionInfo.Execute -eq $exe -and
        $actionInfo.Arguments -eq "serve --tunnel" -and
        $actionInfo.WorkingDirectory -eq $Root
    )
    $triggerExact = (
        $triggers.Count -eq 1 -and
        $triggerInfo.CimClass.CimClassName -eq "MSFT_TaskLogonTrigger" -and
        ((Resolve-Sid $triggerInfo.UserId) -eq $currentSid)
    )
    $principalExact = (
        (Resolve-Sid $task.Principal.UserId) -eq $currentSid -and
        [string]$task.Principal.LogonType -eq "Interactive" -and
        [string]$task.Principal.RunLevel -eq "Limited"
    )
    $settingsExact = (
        [int]$task.Settings.RestartCount -eq 3 -and
        [string]$task.Settings.RestartInterval -eq "PT1M" -and
        [bool]$task.Settings.StartWhenAvailable
    )
    $exact = ($actionExact -and $triggerExact -and $principalExact -and $settingsExact)

    return [ordered]@{
        installed = $true
        exact_definition = $exact
        task_name = $task.TaskName
        state = [string]$task.State
        executable = $actionInfo.Execute
        arguments = $actionInfo.Arguments
        working_directory = $actionInfo.WorkingDirectory
        trigger_type = $triggerInfo.CimClass.CimClassName
        trigger_user = $triggerInfo.UserId
        account = $task.Principal.UserId
        logon_type = [string]$task.Principal.LogonType
        run_level = [string]$task.Principal.RunLevel
        restart_count = [int]$task.Settings.RestartCount
        restart_interval = [string]$task.Settings.RestartInterval
        start_when_available = [bool]$task.Settings.StartWhenAvailable
    }
}

function Test-Listener {
    return [bool](Get-NetTCPConnection -State Listen -LocalPort $listenPort -ErrorAction SilentlyContinue)
}

function Wait-Listener {
    param(
        [bool]$Present,
        [int]$TimeoutSeconds
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $current = Test-Listener
        if ($current -eq $Present) {
            return
        }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)
    throw "listener state did not become Present=$Present on port $listenPort"
}

function Wait-Healthy {
    param([int]$TimeoutSeconds)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        try {
            $health = Invoke-RestMethod -Uri $healthUrl -Method Get -TimeoutSec 2
            if ($health.ok) {
                return $health
            }
        } catch {
        }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)
    throw "ReverseResearch did not become healthy within $TimeoutSeconds seconds"
}

function Request-GracefulShutdown {
    if (-not (Test-Listener)) {
        return $false
    }
    if (-not (Test-Path -LiteralPath $tokenPath -PathType Leaf)) {
        throw "local MCP bearer token not found at $tokenPath"
    }
    $token = (Get-Content -Raw -LiteralPath $tokenPath).Trim()
    if ($token.Length -ne 64) {
        throw "invalid local MCP bearer token length"
    }
    $headers = @{ Authorization = "Bearer $token" }
    $response = Invoke-WebRequest -Uri $shutdownUrl -Method Post -Headers $headers -UseBasicParsing -TimeoutSec 5
    if ([int]$response.StatusCode -ne 202) {
        throw "graceful shutdown returned HTTP $($response.StatusCode)"
    }
    return $true
}

function Assert-ExactTask {
    $status = Get-TaskStatus
    if (-not $status.installed) {
        throw "scheduled task '$TaskName' is not installed"
    }
    if (-not $status.exact_definition) {
        throw "scheduled task '$TaskName' does not match the canonical definition"
    }
    return $status
}

switch ($Action) {
    "Install" {
        if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
            throw "ReverseResearch MCP executable not found at $exe; run the MCP build BAT first"
        }
        $taskAction = New-ScheduledTaskAction -Execute $exe -Argument "serve --tunnel" -WorkingDirectory $Root
        $trigger = New-ScheduledTaskTrigger -AtLogOn -User $account
        $principal = New-ScheduledTaskPrincipal -UserId $account -LogonType Interactive -RunLevel Limited
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
        $task = New-ScheduledTask -Action $taskAction -Trigger $trigger -Principal $principal -Settings $settings -Description "Start the local ReverseResearch MCP server and Secure MCP Tunnel at user logon."
        Register-ScheduledTask -TaskName $TaskName -InputObject $task -Force | Out-Null
        $status = Get-TaskStatus
        $status | ConvertTo-Json -Depth 4
        if (-not $status.exact_definition) {
            exit 3
        }
    }
    "Remove" {
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($task) {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        }
        (Get-TaskStatus) | ConvertTo-Json -Depth 4
    }
    "Status" {
        $status = Get-TaskStatus
        $status | ConvertTo-Json -Depth 4
        if ($status.installed -and -not $status.exact_definition) {
            exit 3
        }
    }
    "Stop" {
        [void](Assert-ExactTask)
        $requested = Request-GracefulShutdown
        if ($requested) {
            Wait-Listener -Present $false -TimeoutSeconds 40
        }
        [ordered]@{
            stopped = (-not (Test-Listener))
            graceful_request_sent = $requested
            task = Get-TaskStatus
        } | ConvertTo-Json -Depth 5
    }
    "Restart" {
        [void](Assert-ExactTask)
        $requested = Request-GracefulShutdown
        if ($requested) {
            Wait-Listener -Present $false -TimeoutSeconds 40
        }

        # Runtime/backend drain budget is 30s; give Task Scheduler state
        # propagation another 10s instead of declaring a healthy drain hung.
        $deadline = (Get-Date).AddSeconds(40)
        do {
            $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
            if ([string]$task.State -ne "Running") {
                break
            }
            Start-Sleep -Milliseconds 250
        } while ((Get-Date) -lt $deadline)
        if ([string]$task.State -eq "Running") {
            throw "scheduled task remained Running after graceful shutdown"
        }

        Start-ScheduledTask -TaskName $TaskName
        Wait-Listener -Present $true -TimeoutSeconds 90
        $health = Wait-Healthy -TimeoutSeconds 60
        [ordered]@{
            restarted = $true
            graceful_request_sent = $requested
            health_ok = [bool]$health.ok
            task = Get-TaskStatus
        } | ConvertTo-Json -Depth 5
    }
}

