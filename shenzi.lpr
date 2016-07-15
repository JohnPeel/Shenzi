program Shenzi;

{$mode objfpc}{$H+}
{$I Simba.inc}

uses
  {$IFDEF UNIX}cmem, cthreads, {$ENDIF} Interfaces,
  Classes, lazmouseandkeyinput, mmlpsthread, simbaunit, newsimbasettings,
  MufasaTypes, ocr, files, FileUtil, sysutils, Forms
  {$IFDEF WINDOWS}, windows, shellapi{$ENDIF};

{$IFDEF WINDOWS}
function CheckTokenMembership(TokenHandle: THandle; SidToCheck: PSID; var IsMember: BOOL): BOOL; stdcall; external advapi32;
{$ENDIF}

type
  TConfig = set of (hasScriptFile, hasDefault, isQuiet, doRun);

var
  AppPath, DocPath, DataPath: string;
  Thread: TLPThread;
  OCR_Fonts: TMOCR;
  ErrorData: TErrorData;
  loadFontsOnScriptStart: boolean;
  Config: TConfig = [];
  ScriptFile, Script: string;

procedure _writeLn(s: string);
begin
  if (not (isQuiet in Config)) then
    WriteLn(s);
end;

function GetDocPath(): string;
begin
{$IFDEF NOTPORTABLE}
  {$IFDEF WINDOWS}
    Result := IncludeTrailingPathDelimiter(GetUserDir()) + 'My Documents' + DS + 'Simba' + DS;
  {$ELSE}
    Result := IncludeTrailingPathDelimiter(GetEnvironmentVariable('XDG_DATA_HOME'));
    if (Result = '') then
      Result := IncludeTrailingPathDelimiter(GetEnvironmentVariable('HOME')) + '.local' + DS + 'share' + DS;
    Result := Result + 'Simba' + DS;
  {$ENDIF}
  if (not (DirectoryExists(Result))) then
    if (not (CreateDir(Result))) then
      Result := IncludeTrailingPathDelimiter(AppPath);
{$ELSE}
  Result := IncludeTrailingPathDelimiter(AppPath);
{$ENDIF}
end;

function GetDataPath(): string;
begin
{$IFDEF NOTPORTABLE}
  Result := IncludeTrailingPathDelimiter(GetAppConfigDir(False));
  if (not (DirectoryExists(Result))) then
    if (not (CreateDir(Result))) then
      Result := GetDocPath();
{$ELSE}
  Result := IncludeTrailingPathDelimiter(AppPath);
{$ENDIF}
end;

procedure ExitCodeExceptHandler(Obj: TObject; Addr: Pointer; FrameCount: Longint; Frame: PPointer);
begin
  ShowException(Obj, Addr);
  if ExitCode = 0 then
    ExitCode := 1;
  Halt(ExitCode);
end;

{$IFDEF WINDOWS}
const
  SECURITY_NT_AUTHORITY: TSIDIdentifierAuthority = (Value: (0, 0, 0, 0, 0, 5));
  SECURITY_BUILTIN_DOMAIN_RID = $00000020;
  DOMAIN_ALIAS_RID_ADMINS     = $00000220;

function UserInGroup(Group: DWORD): Boolean;
var
  pIdentifierAuthority: TSIDIdentifierAuthority;
  pSid: Windows.PSID;
  IsMember: BOOL;
begin
  pIdentifierAuthority := SECURITY_NT_AUTHORITY;
  Result := AllocateAndInitializeSid(pIdentifierAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, Group, 0, 0, 0, 0, 0, 0, pSid);
  try
    if ((Result) and (CheckTokenMembership(0, pSid, IsMember))) then
      Result := IsMember;
  finally
    FreeSid(pSid);
  end;
end;
{$ENDIF}

procedure OnError(Self: TObject);
var
  RetStr: string;
begin
  RetStr := '';
  if (Pos('error', Lowercase(ErrorData.Error)) = 0) then
    RetStr += 'Error: ';

  RetStr += ErrorData.Error;

  if (ErrorData.Row > 0) then
    RetStr += ' at line ' + IntToStr(ErrorData.Row);

  if (ErrorData.Module <> '') then
    RetStr += ' in ' + ExtractRelativepath(AppPath, ErrorData.Module);

  WriteLn(RetStr);
end;

procedure HandleParameters();
var
  ErrorMsg: string;
begin
  ErrorMsg := Application.CheckOptions('hrqdf:', ['help', 'run', 'quiet', 'default', 'file:']);
  if (ErrorMsg = '') then
  begin
    if Application.HasOption('h', 'help') then
    begin
      //TODO: Write help... soon...
      Halt(0);
    end;

    if Application.HasOption('r', 'run') then
      Include(Config, doRun);

    if Application.HasOption('q', 'quiet') then
      Include(Config, isQuiet);

    if Application.HasOption('d', 'default') then
      Include(Config, hasDefault);

    if Application.HasOption('f', 'file') then
    begin
      Include(Config, hasScriptFile); Exclude(Config, hasDefault);
      ScriptFile := Application.GetOptionValue('f', 'file');
    end;
  end else
    WriteLn(ErrorMsg);
end;

function LoadFile(const Filename: string): string;
var
  Strings: TStringList;
begin
  Strings := TStringList.Create();
  Strings.LoadFromFile(Filename);
  Result := Strings.Text;
  Strings.Free();
end;

{$IFDEF WINDOWS}
var
  isElevated, isWritable: Boolean;
  Params: string;
  I: LongInt;
  sei: TShellExecuteInfoA;
{$ENDIF}

begin
  {$IFDEF DEBUG}
  if FileExists('Shenzi.trc') then
    DeleteFile('Shenzi.trc');
  SetHeapTraceOutput('Shenzi.trc');
  {$ENDIF DEBUG}

  Application.Initialize;

  ExceptProc := @ExitCodeExceptHandler;

  {$IFDEF WINDOWS}
  isElevated := UserInGroup(DOMAIN_ALIAS_RID_ADMINS);
  isWritable := DirectoryIsWritable(Application.Location);

  {$IFDEF SIMBA_VERBOSE}
  _WriteLn('Elevated: ' + BoolToStr(isElevated, True));
  _WriteLn('Writable: ' + BoolToStr(isWritable, True));
  {$ENDIF}

  if (not isWritable) and (not isElevated) then
  begin
    _WriteLn('No write access, going to try elevating!');

    FillChar(sei, SizeOf(sei), 0);
    sei.cbSize := SizeOf(sei);
    sei.Wnd := 0;
    sei.fMask := SEE_MASK_ASYNCOK or SEE_MASK_FLAG_NO_UI or SEE_MASK_NO_CONSOLE or SEE_MASK_UNICODE;
    sei.lpVerb := 'runas';
    sei.lpFile := PAnsiChar(Application.ExeName);

    Params := '';
    for I := 0 to Paramcount - 1 do
      Params += ' ' + ParamStrUTF8(I + 1);

    sei.lpParameters := PAnsiChar(Params);
    sei.nShow := SW_SHOWNORMAL;

    WriteLn(sei.lpVerb, ' ', sei.lpFile, ' ', sei.lpParameters);

    if (ShellExecuteExA(@sei)) then
    begin
      _WriteLn('Elevated Simba started properly... Halting this one.');
      Halt;
    end;

    _WriteLn('You have no write access to this directory, and elevation failed!');
  end;
  {$ENDIF}

  Randomize;

  AppPath := IncludeTrailingPathDelimiter(Application.Location);
  DocPath := GetDocPath();
  DataPath := {$IFDEF LINUX}DocPath{$ELSE}GetDataPath(){$ENDIF};
  SimbaSettingsFile := {$IFDEF LINUX}GetDataPath(){$ELSE}DataPath{$ENDIF} + 'settings.xml';

  CreateSimbaSettings(SimbaSettingsFile);

  if not DirectoryExists(SimbaSettings.Includes.Path.Value) then
    CreateDir(SimbaSettings.Includes.Path.Value);
  if not DirectoryExists(SimbaSettings.Fonts.Path.Value) then
    CreateDir(SimbaSettings.Fonts.Path.Value);
  if not DirectoryExists(SimbaSettings.Plugins.Path.Value) then
    CreateDir(SimbaSettings.Plugins.Path.Value);

  HandleParameters();
  if (hasDefault in Config) then
    ScriptFile := SimbaSettings.SourceEditor.DefScriptPath.Value;

  if (hasScriptFile in Config) or (hasDefault in Config) then
    Script := LoadFile(ScriptFile)
  else
    Script := 'program new; begin WriteLn(''Testing''); end;';

  if SimbaSettings.Oops then
    _Writeln('WARNING: No permissions to write to ' + SimbaSettingsFile);

  try
    Thread := TLPThread.Create(True, @CurrentSyncInfo, SimbaSettings.Plugins.Path.Value);
  except
    on e: Exception do
    begin
      Thread := nil;
      Halt(1);
    end;
  end;

  Thread.FreeOnTerminate := True;
  Thread.SetDebug(@_writeLn);
  Thread.SetScript(Script);
  Thread.SetPath(ExtractFilePath(ScriptFile));
  Thread.ErrorData := @ErrorData;
  with TMethod(Thread.OnError) do
  begin
    Data := nil;
    Code := @OnError;
  end;

  if DirectoryExists(SimbaSettings.Plugins.Path.Value) then
     PluginsGlob.AddPath(SimbaSettings.Plugins.Path.Value);

  if (not (Assigned(OCR_Fonts))) then
  begin
    OCR_Fonts := TMOCR.Create(Thread.Client);
    if (DirectoryExists(SimbaSettings.Fonts.Path.Value)) then
      OCR_Fonts.Fonts.Path := SimbaSettings.Fonts.Path.Value;
  end;

  loadFontsOnScriptStart := True;//SimbaSettings.Fonts.LoadOnScriptStart.GetDefValue(True);
  if ((loadFontsOnScriptStart) and (DirectoryExists(SimbaSettings.Fonts.Path.Value))) then
    OCR_Fonts.InitTOCR(SimbaSettings.Fonts.Path.Value);

  Thread.SetFonts(OCR_Fonts.Fonts);
  Thread.SetSettings(SimbaSettings.MMLSettings, SimbaSettingsFile);

  Thread.FreeOnTerminate := False;
  Thread.CompileOnly := not (doRun in Config);
  Thread.Start();
  Thread.WaitFor();

  //if (Thread.Failed) then
    //ExitCode := 1;

  Thread.Free;

  if (Assigned(OCR_Fonts)) then
    FreeAndNil(OCR_Fonts);
  if (Assigned(PluginsGlob)) then
    FreeAndNil(PluginsGlob);
  FreeSimbaSettings(False, SimbaSettingsFile);

  Application.Free;
  Halt(ExitCode);
end.

