param(
    [Parameter(Mandatory)][string]$App,
    [Parameter(Mandatory)][ValidateSet('Open', 'EnableService', 'DisableService', 'Restart', 'Healthy', 'Inspect')][string]$Action
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
    }
}
