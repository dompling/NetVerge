param(
    [Parameter(Mandatory)][string]$App,
    [Parameter(Mandatory)][ValidateSet('Open', 'EnableService', 'DisableService', 'Restart', 'Healthy', 'FillRule', 'ToggleRule', 'DeleteRule', 'RuleHits', 'RuleHitsZero', 'Inspect')][string]$Action
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
$process = Get-Process -Name 'NetVerge-MITM' -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -eq $App -and $_.MainWindowHandle -ne 0 } | Select-Object -First 1
if (!$process) { exit 0 }

$root = [Windows.Automation.AutomationElement]::FromHandle($process.MainWindowHandle)
$scope = [Windows.Automation.TreeScope]::Descendants
$nameProperty = [Windows.Automation.AutomationElement]::NameProperty
$invoke = [Windows.Automation.InvokePattern]::Pattern

function Find-Element([string]$Name, [Windows.Automation.ControlType]$Type) {
    $condition = [Windows.Automation.PropertyCondition]::new($nameProperty, $Name, [Windows.Automation.PropertyConditionFlags]::IgnoreCase)
    if ($Type) {
        $kind = [Windows.Automation.PropertyCondition]::new([Windows.Automation.AutomationElement]::ControlTypeProperty, $Type)
        $condition = [Windows.Automation.AndCondition]::new($condition, $kind)
    }
    return $root.FindFirst($scope, $condition)
}

# These are public synthetic fixture inputs, never credentials.
function Read-EditValue([string]$Label) {
    $field = Find-Element $Label ([Windows.Automation.ControlType]::Edit)
    if (!$field) { return $null }
    $pattern = $null
    if (!$field.TryGetCurrentPattern([Windows.Automation.ValuePattern]::Pattern, [ref]$pattern)) { return $null }
    return $pattern.Current.Value
}

switch ($Action) {
    'Open' {
        if (Find-Element 'Windows MITM service mode') { 'OK'; break }
        $continue = Find-Element 'CONTINUE WITH SIDECAR'
        if ($continue -and $continue.Current.IsEnabled) {
            $continue.GetCurrentPattern($invoke).Invoke()
            'CONTINUED'
            break
        }
        $button = Find-Element 'MITM' ([Windows.Automation.ControlType]::Button)
        if ($button -and $button.Current.IsEnabled) {
            $button.GetCurrentPattern($invoke).Invoke()
            'OK'
        }
    }
    { $_ -in 'EnableService', 'DisableService' } {
        $element = Find-Element 'Windows MITM service mode' ([Windows.Automation.ControlType]::Button)
        if ($element -and $element.Current.IsEnabled) {
            # Each transition starts from a persisted, verified state. WebView2 exposes
            # this switch as a button, so activate it once and verify the saved result.
            if ($Action -eq 'DisableService') {
                $keys = New-Object -ComObject WScript.Shell
                if (!$keys.AppActivate($process.Id)) { break }
                $element.SetFocus()
                if (!$element.Current.HasKeyboardFocus) { break }
                $keys.SendKeys(' ')
                'OK'
                break
            }
            $toggle = $null
            if ($element.TryGetCurrentPattern([Windows.Automation.TogglePattern]::Pattern, [ref]$toggle)) {
                $toggle.Toggle()
            } else {
                $element.GetCurrentPattern($invoke).Invoke()
            }
            'OK'
        }
    }
    'Restart' {
        $button = Find-Element 'Restart'
        if ($button -and $button.Current.IsEnabled) {
            try { $button.GetCurrentPattern($invoke).Invoke() }
            catch [Windows.Automation.ElementNotAvailableException] { }
            'OK'
        }
    }
    'FillRule' {
        $add = Find-Element 'Add rule' ([Windows.Automation.ControlType]::Button)
        if ($add) { $add.GetCurrentPattern($invoke).Invoke(); break }
        $keys = New-Object -ComObject WScript.Shell
        if (!$keys.AppActivate($process.Id)) { break }
        $fields = [ordered]@{'MITM hostname'='api.example.test'; 'Exact path'='/demo'; 'X- header name'='X-NetVerge-Test'; 'Header value'='1'}
        foreach ($label in $fields.Keys) {
            $field = Find-Element $label ([Windows.Automation.ControlType]::Edit)
            if (!$field -or !$field.Current.IsEnabled) { return }
            $field.SetFocus()
            Start-Sleep -Milliseconds 150
            if (!$field.Current.HasKeyboardFocus) { return }
            # Keyboard injection is asynchronous in WebView2. Confirm the
            # actual edit value before moving focus, instead of assuming that
            # SendKeys delivered its entire sequence.
            if ((Read-EditValue $label) -cne $fields[$label]) {
                $keys.SendKeys('^a')
                Start-Sleep -Milliseconds 100
                $keys.SendKeys($fields[$label])
                $deadline = [DateTime]::UtcNow.AddSeconds(2)
                while ((Read-EditValue $label) -cne $fields[$label] -and [DateTime]::UtcNow -lt $deadline) {
                    Start-Sleep -Milliseconds 100
                }
                if ((Read-EditValue $label) -cne $fields[$label]) { return }
            }
            $keys.SendKeys('{TAB}')
            Start-Sleep -Milliseconds 150
            $field = Find-Element $label ([Windows.Automation.ControlType]::Edit)
            if (!$field -or $field.Current.HasKeyboardFocus) { return }
        }
        foreach ($label in $fields.Keys) {
            if ((Read-EditValue $label) -cne $fields[$label]) { return }
        }
        'OK'
    }
    'ToggleRule' {
        $button = Find-Element 'Enable rule' ([Windows.Automation.ControlType]::Button)
        if (!$button -or !$button.Current.IsEnabled) { break }
        $keys = New-Object -ComObject WScript.Shell
        if (!$keys.AppActivate($process.Id)) { break }
        $button.SetFocus()
        Start-Sleep -Milliseconds 150
        if (!$button.Current.HasKeyboardFocus) { break }
        $keys.SendKeys(' ')
        'OK'
    }
    'DeleteRule' {
        $button = Find-Element 'Delete' ([Windows.Automation.ControlType]::Button)
        if ($button) { $button.GetCurrentPattern($invoke).Invoke(); 'OK' }
    }
    { $_ -in 'RuleHits', 'RuleHitsZero' } {
        # WebView2 may expose an accessible live status as a group rather than
        # Text. Match its entire localized (English fixture) label and count.
        # Never match unrelated digits such as a fingerprint or traffic rate.
        $elements = $root.FindAll($scope, [Windows.Automation.Condition]::TrueCondition)
        foreach ($element in $elements) {
            if ($element.Current.IsOffscreen) { continue }
            if ($element.Current.Name -match '^Hits this worker session\s*\u00b7\s*(0|[1-9][0-9]*)$') {
                $count = [uint32]$Matches[1]
                if (($Action -eq 'RuleHits' -and $count -gt 0) -or
                    ($Action -eq 'RuleHitsZero' -and $count -eq 0)) {
                    'OK'
                    break
                }
            }
        }
    }
    'Healthy' {
        if (Find-Element 'Local link healthy') { 'OK'; break }
        # The icon contributes a zero-width character to WebView2's accessible name.
        $buttons = $root.FindAll($scope, [Windows.Automation.PropertyCondition]::new(
            [Windows.Automation.AutomationElement]::ControlTypeProperty, [Windows.Automation.ControlType]::Button))
        $refresh = $buttons | Where-Object { ($_.Current.Name -replace '[\p{Cf}\s]', '') -eq 'Refresh' } | Select-Object -First 1
        if ($refresh -and $refresh.Current.IsEnabled) { $refresh.GetCurrentPattern($invoke).Invoke() }
    }
    'Inspect' {
        $elements = $root.FindAll($scope, [Windows.Automation.Condition]::TrueCondition)
        $elements | Where-Object { $_.Current.Name } | Select-Object -First 70 |
            ForEach-Object { $_.Current.ControlType.ProgrammaticName + ' ' + $_.Current.Name }
        foreach ($label in @('MITM hostname', 'Exact path', 'X- header name', 'Header value')) {
            $value = Read-EditValue $label
            if ($null -ne $value) { 'Fixture field ' + $label + ' = ' + $value }
        }
    }
}
