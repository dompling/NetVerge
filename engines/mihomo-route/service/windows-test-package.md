# NetVerge MITM Windows x64 test package

Extract the ZIP to a fixed folder. Use PowerShell 7 and keep this folder separate from your normal NetVerge installation. The test client uses the Windows development service `clash_verge_service_dev`.

```powershell
./NetVerge-MITM.ps1 -Action Install
./NetVerge-MITM.ps1 -Action Run
```

Enable TUN and select Rule mode. Close the app, then run the command below from an elevated PowerShell session. The first run creates the local bootstrap with an empty hostname list.

```powershell
./NetVerge-MITM.ps1 -Action Run -Bootstrap ./mitm-bootstrap.yaml
```

In the MITM page, save an explicit hostname selection. Toggle Windows MITM service mode and restart the app from the page. The test does not install a trusted certificate. Use the existing certificate controls only when you want to trust the test CA.

Close the app before changing the installed version. To upgrade, extract the new ZIP into the same test folder and run `-Action Install` again. Keep the prior ZIP so you can re-extract it in the same folder and reinstall it for rollback. If the MITM switch was enabled, re-save the service-mode selection with the intended version after replacing the approved core. The switch binds the expected core digest.

Run `./NetVerge-MITM.ps1 -Action Uninstall` to remove the development service and approved test cores. The app files and your local development profile are kept.
