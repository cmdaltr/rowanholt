; Rivendell's Windows installer (Inno Setup 6), for the current user (no admin). Either
; Rivendell runs on this PC: the source tree, an optional evidence folder mounted through
; docker-compose.local.yml, and a pointer to Docker Desktop when it isn't installed. Or
; it connects to a team's Rivendell server: just the launcher and the server's address.
; Both get Start menu and desktop shortcuts to Rivendell.ps1. The release workflow
; compiles it:
;   ISCC /DAppVersion=1.4.0 /DSourceDir=<unpacked source> /DOutputDir=<dir> rivendell.iss

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\.."
#endif
#ifndef OutputDir
  #define OutputDir "dist"
#endif
#define PowerShell "{sys}\WindowsPowerShell\v1.0\powershell.exe"
; Quotes doubled: it goes inside the quoted Parameters values below
#define Launcher '-NoProfile -ExecutionPolicy Bypass -File ""{app}\app\windows\Rivendell.ps1""'

[Setup]
AppId={{9AA724CE-3AC2-45C6-9E9E-4C2A5DC33BD1}
AppName=Rivendell
AppVersion={#AppVersion}
AppVerName=Rivendell {#AppVersion}
AppPublisher=cmdaltr
AppPublisherURL=https://github.com/cmdaltr/rivendell
AppSupportURL=https://github.com/cmdaltr/rivendell/issues
DefaultDirName={%USERPROFILE}\Rivendell
DisableDirPage=no
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64 arm64
ArchitecturesInstallIn64BitMode=x64 arm64
LicenseFile={#SourceDir}\LICENSE
SetupIconFile={#SourceDir}\app\icons\rivendell.ico
UninstallDisplayIcon={app}\app\icons\rivendell.ico
UninstallDisplayName=Rivendell
OutputDir={#OutputDir}
OutputBaseFilename=Rivendell-Setup-{#AppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Excludes: "\app\windows\*,\app\icons\*"; Flags: ignoreversion recursesubdirs createallsubdirs; Check: RunsHere
Source: "{#SourceDir}\app\windows\*"; DestDir: "{app}\app\windows"; Flags: ignoreversion recursesubdirs
Source: "{#SourceDir}\app\icons\*"; DestDir: "{app}\app\icons"; Flags: ignoreversion recursesubdirs

[Icons]
Name: "{autoprograms}\Rivendell"; Filename: "{#PowerShell}"; Parameters: "{#Launcher}"; WorkingDir: "{app}"; IconFilename: "{app}\app\icons\rivendell.ico"; Comment: "Rivendell DFIR platform"
Name: "{autoprograms}\Stop Rivendell"; Filename: "{#PowerShell}"; Parameters: "{#Launcher} -Stop"; WorkingDir: "{app}"; IconFilename: "{app}\app\icons\rivendell.ico"; Comment: "Stop Rivendell's containers"; Flags: runminimized; Check: RunsHere
Name: "{autodesktop}\Rivendell"; Filename: "{#PowerShell}"; Parameters: "{#Launcher}"; WorkingDir: "{app}"; IconFilename: "{app}\app\icons\rivendell.ico"; Comment: "Rivendell DFIR platform"; Tasks: desktopicon

[Run]
Filename: "https://www.docker.com/products/docker-desktop/"; Description: "Open the Docker Desktop download page (Rivendell needs it)"; Flags: postinstall shellexec skipifsilent; Check: NeedsDocker
Filename: "{#PowerShell}"; Parameters: "{#Launcher}"; WorkingDir: "{app}"; Description: "Open Rivendell"; Flags: postinstall nowait skipifsilent; Check: CanLaunch

[UninstallDelete]
Type: files; Name: "{app}\.rivendell-version"
Type: files; Name: "{app}\.rivendell-built"
Type: files; Name: "{app}\.rivendell-server"

[Code]
const
  LocalHeader = '# Written by Rivendell''s Windows installer';

var
  ModePage: TInputOptionWizardPage;
  ServerPage: TInputQueryWizardPage;
  DockerPage: TOutputMsgWizardPage;
  EvidencePage: TInputDirWizardPage;

function DockerInstalled: Boolean;
begin
  Result := FileExists(ExpandConstant('{commonpf64}\Docker\Docker\Docker Desktop.exe'))
    or (FileSearch('docker.exe', GetEnv('PATH')) <> '');
end;

// Rivendell runs on this PC (rather than connecting to a server)
function RunsHere: Boolean;
begin
  Result := ModePage.SelectedValueIndex = 0;
end;

function NeedsDocker: Boolean;
begin
  Result := RunsHere and not DockerInstalled;
end;

function CanLaunch: Boolean;
begin
  Result := not RunsHere or DockerInstalled;
end;

// A typed server address as https://host[:port]; '' if it isn't one (http for localhost only)
function NormaliseServer(Text: String): String;
var
  Scheme, Rest: String;
  P: Integer;
begin
  Result := '';
  Text := Trim(Text);
  P := Pos('://', Text);
  if P = 0 then
  begin
    Scheme := 'https';
    Rest := Text;
  end else begin
    Scheme := Lowercase(Copy(Text, 1, P - 1));
    Rest := Copy(Text, P + 3, Length(Text));
  end;
  P := Pos('/', Rest);
  if P > 0 then
    Rest := Copy(Rest, 1, P - 1);
  if (Rest = '') or (Pos(' ', Rest) > 0) then
    Exit;
  if (Scheme = 'https') or ((Scheme = 'http') and ((Pos('localhost', Rest) = 1) or (Pos('127.0.0.1', Rest) = 1))) then
    Result := Scheme + '://' + Rest;
end;

procedure InitializeWizard;
begin
  ModePage := CreateInputOptionPage(wpWelcome, 'Where Rivendell runs',
    'Run Rivendell on this PC, or use your team''s Rivendell server?',
    'A server needs nothing here but a window onto it: no Docker, no evidence, no 70 MB of files.',
    True, False);
  ModePage.Add('Run Rivendell on this PC (needs Docker Desktop)');
  ModePage.Add('Connect to my team''s Rivendell server');
  ModePage.SelectedValueIndex := StrToIntDef(GetPreviousData('Mode', '0'), 0);

  ServerPage := CreateInputQueryPage(ModePage.ID, 'Rivendell server',
    'Your team''s Rivendell server.',
    'Its address, e.g. rivendell.example.org. If Edge warns about its certificate, ask the server''s admin for its root certificate.');
  ServerPage.Add('Server address:', False);
  ServerPage.Values[0] := GetPreviousData('Server', '');

  DockerPage := CreateOutputMsgPage(ServerPage.ID, 'Docker Desktop',
    'Rivendell runs as a set of Docker containers.',
    'Docker Desktop isn''t installed. Setup carries on without it, and offers its download page at the end.' + #13#10#13#10 +
    'Install Docker Desktop (it needs WSL 2), start it once, then open Rivendell from the Start menu.' + #13#10#13#10 +
    'Docker Desktop is free for personal use and small businesses; larger organisations need a paid subscription.');

  EvidencePage := CreateInputDirPage(wpSelectDir, 'Evidence folder',
    'Optional: a folder of disk images, memory dumps or Gandalf archives.',
    'Rivendell sees it inside its containers under /mnt/<drive>/..., so D:\Cases becomes /mnt/d/Cases. ' +
    'External drives aren''t visible otherwise. Leave it blank to skip; run setup again to change it.',
    False, '');
  EvidencePage.Add('');
  EvidencePage.Values[0] := GetPreviousData('EvidenceDir', '');
end;

procedure RegisterPreviousData(PreviousDataKey: Integer);
begin
  SetPreviousData(PreviousDataKey, 'EvidenceDir', EvidencePage.Values[0]);
  SetPreviousData(PreviousDataKey, 'Mode', IntToStr(ModePage.SelectedValueIndex));
  SetPreviousData(PreviousDataKey, 'Server', ServerPage.Values[0]);
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := ((PageID = DockerPage.ID) and (DockerInstalled or not RunsHere))
    or ((PageID = EvidencePage.ID) and not RunsHere)
    or ((PageID = ServerPage.ID) and RunsHere);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  Dir: String;
begin
  Result := True;
  if (CurPageID = ServerPage.ID) and (NormaliseServer(ServerPage.Values[0]) = '') then
  begin
    MsgBox('Enter the server''s address, e.g. rivendell.example.org (https only).', mbError, MB_OK);
    Result := False;
  end;
  if CurPageID = EvidencePage.ID then
  begin
    Dir := Trim(EvidencePage.Values[0]);
    if (Dir <> '') and ((Length(Dir) < 3) or (Dir[2] <> ':') or not DirExists(Dir)) then
    begin
      MsgBox('Choose an existing folder on a lettered drive (C:\..., D:\...), or leave it blank.', mbError, MB_OK);
      Result := False;
    end;
  end;
end;

function ToContainerPath(Dir: String): String;
var
  Rest: String;
begin
  Rest := Copy(Dir, 3, Length(Dir));
  StringChangeEx(Rest, '\', '/', True);
  if (Length(Rest) > 1) and (Rest[Length(Rest)] = '/') then
    Rest := Copy(Rest, 1, Length(Rest) - 1);
  Result := '/mnt/' + Lowercase(Copy(Dir, 1, 1)) + Rest;
end;

procedure WriteEvidenceCompose;
var
  Dir, Source, Target, LocalFile, Yaml: String;
  Existing: AnsiString;
begin
  LocalFile := ExpandConstant('{app}\docker-compose.local.yml');
  // A hand-written file is left alone
  if FileExists(LocalFile) and LoadStringFromFile(LocalFile, Existing) and (Pos(LocalHeader, String(Existing)) <> 1) then
    Exit;
  Dir := Trim(EvidencePage.Values[0]);
  if Dir = '' then
  begin
    DeleteFile(LocalFile);
    Exit;
  end;
  Source := Dir;
  StringChangeEx(Source, '\', '/', True);
  Target := ToContainerPath(Dir);
  Yaml := LocalHeader + ': the evidence folder, read-only in the backend.' + #10 +
    'services:' + #10 +
    '  backend:' + #10 +
    '    volumes:' + #10 +
    '      - type: bind' + #10 +
    '        source: "' + Source + '"' + #10 +
    '        target: "' + Target + '"' + #10 +
    '        read_only: true' + #10 +
    '  celery-worker:' + #10 +
    '    volumes:' + #10 +
    '      - type: bind' + #10 +
    '        source: "' + Source + '"' + #10 +
    '        target: "' + Target + '"' + #10;
  SaveStringToFile(LocalFile, Yaml, False);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    if RunsHere then
    begin
      SaveStringToFile(ExpandConstant('{app}\.rivendell-version'), '{#AppVersion}', False);
      DeleteFile(ExpandConstant('{app}\.rivendell-server'));
      WriteEvidenceCompose;
    end else
      SaveStringToFile(ExpandConstant('{app}\.rivendell-server'), NormaliseServer(ServerPage.Values[0]), False);
  end;
end;
