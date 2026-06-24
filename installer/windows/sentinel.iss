; Sentinel SIEM — Inno Setup Script
; Builds: dist\SentinelSetup.exe
;
; Requirements:
;   - Inno Setup 6.x  (https://jrsoftware.org/isdl.php)
;   - dist\sentinel\  produced by PyInstaller (run build.py first)
;
; Build:
;   iscc installer\windows\sentinel.iss

#define MyAppName      "Sentinel SIEM"
#define MyAppVersion   "1.0.0"
#define MyAppPublisher "Nebula Networking"
#define MyAppURL       "https://github.com/ThatAIGuyDFW/NebuLog"
#define MyAppExeName   "sentinel.exe"
#define MyBundleDir    "..\..\dist\sentinel"
#define MyOutputDir    "..\..\dist"

[Setup]
AppId={{A3B1C2D4-E5F6-7890-ABCD-EF1234567890}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}

; Install to Program Files
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes

; Output
OutputDir={#MyOutputDir}
OutputBaseFilename=SentinelSetup
SetupIconFile=..\assets\icon.ico
Compression=lzma2/ultra64
SolidCompression=yes

; Require admin rights (needed to install as a Windows Service and bind port 514)
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=

; Minimum Windows version: Windows 10 (10.0)
MinVersion=10.0

; Uninstall
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName}

; Wizard appearance
WizardStyle=modern
WizardImageFile=..\assets\wizard-banner.bmp
WizardSmallImageFile=..\assets\wizard-small.bmp

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon";   Description: "Create a &desktop shortcut";       GroupDescription: "Additional icons:"; Flags: unchecked
Name: "startupitem";  Description: "Start Sentinel automatically at &login"; GroupDescription: "Startup:"
Name: "windowsservice"; Description: "Install as a &Windows Service (recommended for servers)"; GroupDescription: "Service:"

[Files]
; Main bundle — everything PyInstaller produced
Source: "{#MyBundleDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
; Start Menu
Name: "{group}\{#MyAppName}";        Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"

; Desktop shortcut (optional)
Name: "{autodesktop}\{#MyAppName}";  Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

; Startup folder (login launch)
Name: "{userstartup}\{#MyAppName}";  Filename: "{app}\{#MyAppExeName}"; Tasks: startupitem

[Run]
; Run setup wizard on first install
Filename: "{app}\{#MyAppExeName}"; Parameters: "--setup"; \
    Description: "Configure Sentinel SIEM"; \
    Flags: nowait postinstall skipifsilent; \
    Check: IsFirstInstall

; Install Windows Service (optional task)
Filename: "{app}\{#MyAppExeName}"; Parameters: "--install-service"; \
    Flags: runhidden waituntilterminated; \
    Tasks: windowsservice

[UninstallRun]
; Stop and remove the Windows Service on uninstall
Filename: "{app}\{#MyAppExeName}"; Parameters: "--uninstall-service"; \
    Flags: runhidden waituntilterminated; \
    RunOnceId: "StopService"

[Code]
function IsFirstInstall(): Boolean;
begin
  Result := not RegKeyExists(HKLM, 'SOFTWARE\Nebula Networking\Sentinel');
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    RegWriteStringValue(HKLM, 'SOFTWARE\Nebula Networking\Sentinel', 'InstallPath', ExpandConstant('{app}'));
    RegWriteStringValue(HKLM, 'SOFTWARE\Nebula Networking\Sentinel', 'Version', '{#MyAppVersion}');
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    RegDeleteKeyIncludingSubkeys(HKLM, 'SOFTWARE\Nebula Networking\Sentinel');
end;
