param(
    [Parameter(Mandatory)][string]$App,
    [Parameter(Mandatory)][ValidateSet('Open', 'EnableService', 'DisableService', 'ServicePending', 'Restart', 'Healthy', 'FillRule', 'AddSecondRule', 'ConflictSecondRule', 'ToggleSecondRule', 'MoveUpSecondRule', 'DeleteSecondRule', 'OpenRequestRule', 'FillRequestRule', 'OpenPathRule', 'FillPathRule', 'OpenBodyRule', 'FillBodyRule', 'ToggleRule', 'DeleteRule', 'RuleHits', 'RuleHitsZero', 'RecentRequests', 'FilterRecent', 'InspectRecent', 'ClearRecent', 'RecentEmpty', 'PauseRecent', 'ResumeRecent', 'RecentPathVisible', 'Inspect')][string]$Action
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
        if (!$element -or !$element.Current.IsEnabled) { break }

        # Use a real pointer activation of the visible WebView control, not an
        # InvokePattern/SendKeys result that may never reach the DOM. Foreground
        # and clickable point must both belong to the current desktop window.
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class NetVergeServiceSwitchInput {
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetCursorPos(int x, int y);
    [DllImport("user32.dll")] public static extern void mouse_event(uint flags, uint dx, uint dy, uint data, UIntPtr extraInfo);
}
'@
        $keys = New-Object -ComObject WScript.Shell
        if (!$keys.AppActivate($process.Id)) { break }
        $element.SetFocus()
        Start-Sleep -Milliseconds 150
        if ([NetVergeServiceSwitchInput]::GetForegroundWindow() -ne $process.MainWindowHandle) { break }
        $element = Find-Element 'Windows MITM service mode' ([Windows.Automation.ControlType]::Button)
        if (!$element -or !$element.Current.IsEnabled -or $element.Current.IsOffscreen) { break }

        $point = New-Object System.Windows.Point
        if (!$element.TryGetClickablePoint([ref]$point)) { break }
        $bounds = $element.Current.BoundingRectangle
        if (!$bounds.Contains($point)) { break }
        $hit = [Windows.Automation.AutomationElement]::FromPoint($point)
        # Accept the element itself or a descendant exposed by WebView2.
        $walker = [Windows.Automation.TreeWalker]::RawViewWalker
        $owned = $false
        for ($i = 0; $hit -and $i -lt 12; $i++) {
            if ([Windows.Automation.Automation]::Compare($hit, $element)) { $owned = $true; break }
            $hit = $walker.GetParent($hit)
        }
        if (!$owned) { break }
        if (![NetVergeServiceSwitchInput]::SetCursorPos([int][Math]::Round($point.X), [int][Math]::Round($point.Y))) { break }
        if ([NetVergeServiceSwitchInput]::GetForegroundWindow() -ne $process.MainWindowHandle) { break }
        [NetVergeServiceSwitchInput]::mouse_event(2, 0, 0, 0, [UIntPtr]::Zero)
        [NetVergeServiceSwitchInput]::mouse_event(4, 0, 0, 0, [UIntPtr]::Zero)
        # This means input was dispatched, NOT that the preference was saved.
        'DISPATCHED mouse'
    }
    'ServicePending' {
        $button = Find-Element 'Restart' ([Windows.Automation.ControlType]::Button)
        if ($button -and $button.Current.IsEnabled) { 'OK' }
    }
    'Restart' {
        $button = Find-Element 'Restart'
        if ($button -and $button.Current.IsEnabled) {
            try { $button.GetCurrentPattern($invoke).Invoke() }
            catch [Windows.Automation.ElementNotAvailableException] { }
            'OK'
        }
    }
    { $_ -in 'OpenRequestRule', 'OpenPathRule', 'OpenBodyRule' } {
        $label = switch ($Action) {
            'OpenPathRule' { 'URL path rewrite' }
            'OpenBodyRule' { 'Response body rewrite' }
            default { 'Request header rewrite' }
        }
        $button = Find-Element $label ([Windows.Automation.ControlType]::Button)
        if ($button -and $button.Current.IsEnabled) {
            $toggle = $null
            if ($button.TryGetCurrentPattern([Windows.Automation.TogglePattern]::Pattern, [ref]$toggle)) {
                if ($toggle.Current.ToggleState -eq [Windows.Automation.ToggleState]::On) { 'OK'; break }
                $toggle.Toggle()
                Start-Sleep -Milliseconds 200
                if ($toggle.Current.ToggleState -eq [Windows.Automation.ToggleState]::On) { 'OK'; break }
            }
            $keys = New-Object -ComObject WScript.Shell
            if (!$keys.AppActivate($process.Id)) { break }
            $button.SetFocus()
            Start-Sleep -Milliseconds 150
            if (!$button.Current.HasKeyboardFocus) { break }
            $keys.SendKeys(' ')
            Start-Sleep -Milliseconds 200
            'OK'
        }
    }
    { $_ -in 'FillRule', 'FillRequestRule', 'FillPathRule', 'FillBodyRule' } {
        $add = Find-Element 'Add rule' ([Windows.Automation.ControlType]::Button)
        if ($add) { $add.GetCurrentPattern($invoke).Invoke(); break }
        $keys = New-Object -ComObject WScript.Shell
        if (!$keys.AppActivate($process.Id)) { break }
        $fields = [ordered]@{'MITM hostname'='api.example.test'; 'Exact path'='/demo'; 'X- header name'='X-NetVerge-Test'; 'Header value'='1'}
        if ($Action -eq 'FillRequestRule') {
            $fields = [ordered]@{'MITM hostname'='api.example.test'; 'Exact path'='/demo'; 'X-Custom- header name'='X-Custom-NetVerge-Test'; 'Header value'='rewritten'}
        }
        if ($Action -eq 'FillPathRule') {
            $fields = [ordered]@{'MITM hostname'='api.example.test'; 'Exact path'='/demo'; 'Target path'='/changed'}
        }
        if ($Action -eq 'FillBodyRule') {
            $fields = [ordered]@{'MITM hostname'='api.example.test'; 'Exact path'='/demo'; 'Search text'='netverge-windows-tun-origin'; 'Replacement text'='netverge-body-rewritten'}
        }
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
    { $_ -in 'AddSecondRule', 'ConflictSecondRule' } {
        if (!(Find-Element 'MITM hostname #2' ([Windows.Automation.ControlType]::Edit))) {
            $add = Find-Element 'Add another rule' ([Windows.Automation.ControlType]::Button)
            if ($add -and $add.Current.IsEnabled) { $add.GetCurrentPattern($invoke).Invoke() }
            break
        }
        $keys = New-Object -ComObject WScript.Shell
        if (!$keys.AppActivate($process.Id)) { break }
        $fields = [ordered]@{'MITM hostname #2'='api.example.test'; 'Exact path #2'='/demo'; 'X- header name #2'='X-NetVerge-Extra'; 'Header value #2'='second'}
        if ($Action -eq 'ConflictSecondRule') {
            $fields = [ordered]@{'X- header name #2'='X-NetVerge-Test'; 'Header value #2'='override'}
        }
        foreach ($label in $fields.Keys) {
            $field = Find-Element $label ([Windows.Automation.ControlType]::Edit)
            if (!$field -or !$field.Current.IsEnabled) { return }
            $field.SetFocus()
            Start-Sleep -Milliseconds 150
            if (!$field.Current.HasKeyboardFocus) { return }
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
    { $_ -in 'ToggleRule', 'ToggleSecondRule', 'MoveUpSecondRule', 'DeleteSecondRule' } {
        $label = switch ($Action) {
            'ToggleRule' { 'Enable rule' }
            'ToggleSecondRule' { 'Enable rule #2' }
            'MoveUpSecondRule' { 'Move up #2' }
            'DeleteSecondRule' { 'Delete #2' }
        }
        $button = Find-Element $label ([Windows.Automation.ControlType]::Button)
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
    'RecentRequests' {
        $row = Find-Element ("GET api.example.test/demo " + [char]0xb7 + " 200 " + [char]0xb7 + " URL path rewrite")
        if ($row) { 'OK'; break }
        $button = Find-Element 'Recent requests' ([Windows.Automation.ControlType]::Button)
        if ($button -and !(Find-Element ("GET api.example.test/demo " + [char]0xb7 + " 200"))) {
            $keys = New-Object -ComObject WScript.Shell
            if (!$keys.AppActivate($process.Id)) { break }
            $button.SetFocus()
            if ($button.Current.HasKeyboardFocus) { $keys.SendKeys(' '); Start-Sleep -Milliseconds 500 }
        }
    }
    'FilterRecent' {
        $search = Find-Element 'Search hostname or path' ([Windows.Automation.ControlType]::Edit)
        $select = Find-Element 'Matched rules' ([Windows.Automation.ControlType]::ComboBox)
        if (!$search -or !$select) { break }
        $keys = New-Object -ComObject WScript.Shell
        if (!$keys.AppActivate($process.Id)) { break }
        $search.SetFocus()
        $keys.SendKeys('^a')
        $keys.SendKeys('/demo/other')
        Start-Sleep -Milliseconds 200
        $select.SetFocus()
        # The last option shows requests with no matched rule.
        $keys.SendKeys('{END}')
        Start-Sleep -Milliseconds 200
        $row = Find-Element ("GET api.example.test/demo/other " + [char]0xb7 + " 200 " + [char]0xb7 + " No match")
        if (!$row) { break }
        # Move up to URL path rewrite: /demo/other must now disappear.
        $keys.SendKeys('{UP}')
        Start-Sleep -Milliseconds 200
        if (!(Find-Element 'No requests match these filters.')) { break }
        $search.SetFocus()
        $keys.SendKeys('^a')
        $keys.SendKeys('{BACKSPACE}')
        Start-Sleep -Milliseconds 200
        if (Find-Element ("GET api.example.test/demo " + [char]0xb7 + " 200 " + [char]0xb7 + " URL path rewrite")) { 'OK' }
    }
    'InspectRecent' {
        $limit = Find-Element 'Up to 20 completed requests (12 KB memory cap); sensitive headers redacted.'
        $reqRedacted = Find-Element 'authorization: [redacted]'
        $resRedacted = Find-Element 'set-cookie: [redacted]'
        $resPath = Find-Element 'x-observed-path: /changed?id=7&id=8&raw=a%2Fb'
        if ($limit -and $reqRedacted -and $resRedacted -and $resPath) {
            $elements = $root.FindAll($scope, [Windows.Automation.Condition]::TrueCondition)
            $leaked = $false
            $timed = $false
            $hasHost = $false
            foreach ($element in $elements) {
                $name = $element.Current.Name
                if ($name -match 'client-sensitive-secret|origin-sensitive-secret') { $leaked = $true }
                if ($name -match '^host: api\.example\.test(?::443)?$') { $hasHost = $true }
                if ($name -match '^Completed\s*\u00b7\s*\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\s*\u00b7\s*(0|[1-9][0-9]*) ms$') { $timed = $true }
            }
            if (!$leaked -and $hasHost -and $timed) { 'OK'; break }
        }
        $details = Find-Element ("Details GET api.example.test/demo " + [char]0xb7 + " 200") ([Windows.Automation.ControlType]::Button)
        if ($details -and !$reqRedacted) {
            $keys = New-Object -ComObject WScript.Shell
            if (!$keys.AppActivate($process.Id)) { break }
            $details.SetFocus()
            if ($details.Current.HasKeyboardFocus) { $keys.SendKeys(' '); Start-Sleep -Milliseconds 400 }
        }
    }
    'ClearRecent' {
        if (Find-Element 'No completed requests in this worker session.') { 'OK'; break }
        $button = Find-Element 'Clear requests' ([Windows.Automation.ControlType]::Button)
        if ($button -and $button.Current.IsEnabled) {
            $keys = New-Object -ComObject WScript.Shell
            if (!$keys.AppActivate($process.Id)) { break }
            $button.SetFocus()
            if ($button.Current.HasKeyboardFocus) { $keys.SendKeys(' '); Start-Sleep -Milliseconds 400 }
        }
    }
    { $_ -in 'PauseRecent', 'ResumeRecent' } {
        $source, $target = if ($Action -eq 'PauseRecent') { 'Pause updates', 'Resume updates' } else { 'Resume updates', 'Pause updates' }
        if (Find-Element $target ([Windows.Automation.ControlType]::Button)) { 'OK'; break }
        $button = Find-Element $source ([Windows.Automation.ControlType]::Button)
        if ($button -and $button.Current.IsEnabled) { $button.GetCurrentPattern($invoke).Invoke() }
    }
    'RecentPathVisible' {
        if (Find-Element ("GET api.example.test/demo " + [char]0xb7 + " 200 " + [char]0xb7 + " URL path rewrite")) { 'OK' }
    }
    'RecentEmpty' {
        if (Find-Element 'No completed requests in this worker session.') { 'OK' }
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
