param(
    [Parameter(Mandatory)][string]$App,
    [Parameter(Mandatory)][ValidateSet('Open', 'Switch', 'Restart', 'Healthy', 'Inspect')][string]$Action
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

function Find-Element([string]$Name) {
    return $root.FindFirst($scope, [Windows.Automation.PropertyCondition]::new($nameProperty, $Name))
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
        $links = $root.FindAll($scope, [Windows.Automation.PropertyCondition]::new(
            [Windows.Automation.AutomationElement]::ControlTypeProperty, [Windows.Automation.ControlType]::Hyperlink))
        foreach ($link in $links) {
            if ($link.Current.Name -eq 'MITM' -and $link.Current.IsEnabled) {
                $link.GetCurrentPattern($invoke).Invoke()
                'OK'
                break
            }
        }
    }
    'Switch' {
        $element = Find-Element 'Windows MITM service mode'
        if ($element -and $element.Current.IsEnabled) {
            $toggle = $element.GetCurrentPattern([Windows.Automation.TogglePattern]::Pattern)
            if ($toggle.Current.ToggleState -eq [Windows.Automation.ToggleState]::Off) { $toggle.Toggle() }
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
        $refresh = Find-Element 'Refresh'
        if ($refresh -and $refresh.Current.IsEnabled) { $refresh.GetCurrentPattern($invoke).Invoke() }
    }
    'Inspect' {
        $elements = $root.FindAll($scope, [Windows.Automation.Condition]::TrueCondition)
        $elements | Where-Object { $_.Current.Name } | Select-Object -First 70 |
            ForEach-Object { $_.Current.ControlType.ProgrammaticName + ' ' + $_.Current.Name }
    }
}
