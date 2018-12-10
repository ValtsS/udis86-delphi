unit udis86d;

// with adapted verison of UDIS86 1.7.2
//
// 2006/12/20 fixed bugs record definition in udis86.pas
// 2007/04/04 renewal with udis86 1.4
// 2007/08/29 renewal with udis86 1.5
// 2018/12/10 using adjusted version of udis86 1.7.2
//

interface

uses classes, udis86, contnrs;

type

  TDisInstruction = class
    address:cardinal;
    instr_len:integer;
    hex:packed array of byte;
    mnemonic:integer;
    mnemonic_str:string;
    asmstr:string;

    operands:array [0..3] of ud_operand;

    procedure ResetOperands;

    Function getCalltarget:cardinal;
    procedure setcalltarget(target:cardinal);

    Function opr_is_gpr(i:integer):boolean;

    Function Op_count:integer;

  end;


  ud_user_data = class
   CallBackLen : integer;
   CallBackPos : int64;
   CallBackBuff : Pointer;
   CallBackStream : Pointer;
  end;


  TDecodeHook = procedure (instr:TDisInstruction;var abort:boolean; userdata:pointer) of object;


  TUDIS86SyntaxMode = (UDIS86SynMASM,UDIS86SynATT); // disassemble syntax
  // udis86 1.4
  TUDIS86Vendor = (UDIS86VendorAMD,UDIS86VendorIntel); // disassemble hardware vendor 1.4
  //
  TUDIS86 = class
      FUdis : ptr_ud;
      FIsStream : boolean;
      FDecMode : byte;        // 16, 32, 64
      FSyntaxMode : TUDIS86SyntaxMode;  // AT&T or MASM
      FVendor : TUDIS86Vendor; // udis86 1.4
      FRemoveOffset : boolean;
      FRemoveHexCode : boolean;
      FTextInput : boolean;
      FResultBuff : TStringList;
      FFault : Int64;
      FFtext : string;
      LineInfo: TStringList;
    private
      procedure DoDisassemble(skip: Integer);
    protected
      Function GetLineInfo(lineoffset:Int64):string;


    public
      constructor Create;
      destructor Destroy; override;
      procedure DecodeBuffer(buf : pointer; skip, len : integer);
      Function  XDecodeBuffer(buf : pointer; skip, len : integer):TObjectList;
      Function  XDecodeBuffer2(buf : pointer; skip, len : integer; hook:TDecodeHook; userdata:pointer):TObjectList;
      procedure DecodeStream(Stream : TStream; skip, len : integer);
      procedure SetDecodeMode(bits : integer);      // 16, 32, 64
      procedure SetRemoveOffset(Value : boolean);   // remove offset
      procedure SetRemoveHexCode(Value : boolean);  // remove byte code
      procedure SetTextModeInput(Value : boolean);  // Value = false(binary) True(00-2byte hex string)
      procedure SetPC(Value : int64);               // set program counter
      procedure SetSyntaxMode(Value : TUDIS86SyntaxMode); // syntax mode
      procedure SetVendor(Value : TUDIS86Vendor);   // udis86 1.4
      procedure Reset;

      Procedure ClearLineInfo;
      Procedure AddLineInfo(LinePointAddr:Cardinal; Text:String);

      property ResultText : TStringList read FResultBuff;
      property FaultPoint : Int64 read FFault write FFault;
      property FaultText : string read FFText write FFtext;
  end;


function UDIS_SimpleDisasm(mem:pointer;address,len:cardinal):string;

implementation

uses sysutils;


type pcardinal = ^cardinal;

Function TDisInstruction.getCalltarget:cardinal;
var pc:pcardinal;
begin
  Assert(instr_len=5);
  Assert(UpperCase(mnemonic_str)='CALL');
  pc:=@hex[1];
  result:=pc^+5+address;
end;

procedure TDisInstruction.setcalltarget(target:cardinal);
var pc:pcardinal;
begin
  Assert(instr_len=5);
  Assert(UpperCase(mnemonic_str)='CALL');
  pc:=@hex[1];
  pc^:=address+5;
  pc^:=cardinal(target)-pc^;
end;

Function TDisInstruction.opr_is_gpr(i:integer):boolean;
begin
 if (i>=length(operands)) or (i<0) then raise Exception.Create('out of range operand requested');
 result:=ud_opr_is_gpr(@Self.operands[i]);
end;


Function TDisInstruction.Op_count:integer;
var i:integer;
begin
 result:=0;
 for i:=0 to length(operands)-1 do
  if operands[i].optype=UD_NONE then begin
   result:=i;
   break;
  end;

end;

procedure TDisInstruction.ResetOperands;
var i:integer;
begin
 for i:=0 to length(operands)-1 do
  operands[i].optype:=UD_NONE;

end;

function UDIS_SimpleDisasm(mem:pointer;address,len:cardinal):string;
var bl:TUDIS86;
begin
 bl:=TUDIS86.Create;
  try
    bl.SetDecodeMode(32);
     bl.SetPC(address);
     bl.setSyntaxMode(UDIS86SynMASM);
     bl.DecodeBuffer(mem,0, len);
      result:=bl.ResultText.Text;
  except
   result:='';
  end;
   bl.Free;

end;



Function getUserData(ud:ptr_ud):ud_user_data;
begin
 result:=ud_user_data(ud_get_userdata(ud));

end;




{ TUDIS86 }

function HookFuncBuff(ud : ptr_ud):integer; cdecl;
var udd:ud_user_data;
begin
 udd:=getUserData(ud);
  Result := UD_EOI;
  if udd.CallBackLen=0 then exit;
  Result := integer(pchar(udd.CallBackBuff)[udd.CallBackPos]);
  inc(udd.CallBackPos); dec(udd.CallBackLen);
end;

function HookFuncStream(ud : ptr_ud):integer; cdecl;
var
  ReadValue : byte;
  udd:ud_user_data;
begin
 udd:=getUserData(ud);
  Result := UD_EOI;
  if udd.CallBackLen=0 then exit;
  if 1=TStream(udd.CallBackStream).Read(ReadValue,1) then begin
    Result := ReadValue;
    dec(udd.CallBackLen);
  end;
end;

function HookFuncBuffHex(ud : ptr_ud):integer; cdecl;
var
  bufhex : string;
  udd:ud_user_data;
begin
 udd:=getUserData(ud);
  Result := UD_EOI;
  if udd.CallBackLen=0 then exit;
  bufHex := '$00';
  bufHex[2] := pchar(udd.CallBackBuff)[udd.CallBackPos];
  dec(udd.CallBackLen); inc(udd.CallBackPos);
  if udd.CallBackLen=0 then exit;
  bufHex[3] := pchar(udd.CallBackBuff)[udd.callBackPos];
  dec(udd.CallBackLen); inc(udd.CallBackPos);
  result := strtointdef(bufhex,UD_EOI);
end;

function HookFuncStreamHex(ud : ptr_ud):integer; cdecl;
var
  bufhex : string;
  udd:ud_user_data;
begin
 udd:=getUserData(ud);
  Result := UD_EOI;
  if udd.CallBackLen=0 then exit;
  bufhex := '$00';
  if 2=TStream(udd.CallBackStream).Read(bufHex[2],2) then begin
    Result := strtointdef(bufhex,UD_EOI);
    dec(udd.CallBackLen,2);
  end;
end;


constructor TUDIS86.Create;
begin
  inherited;
  LineInfo:=TStringList.Create;
  FIsStream := false;
  FDecMode := 32;
  FSyntaxMode := UDIS86SynMASM;
  FVendor := UDIS86VendorAMD;
  FRemoveOffset := false;
  FRemoveHexCode := false;
  FTextInput := false;

  getmem(FUdis, ud_get_size_required);
  // init udis
  ud_init(FUdis);

  ud_set_userdata(FUDis, Int64(ud_user_data.Create));

  // Create output buff
  FResultBuff := TStringList.Create;
  SetDecodeMode(FDecMode);
  SetSyntaxMode(FSyntaxMode);
  SetVendor(FVendor);
end;

procedure TUDIS86.DecodeBuffer(buf: pointer; skip, len: integer);
var udd:ud_user_data;
begin
 udd:=getUserData(Fudis);
  udd.CallBackLen := Len;
  udd.CallBackBuff := buf;
  FIsStream := false;
  DoDisassemble(skip);
end;

procedure TUDIS86.DecodeStream(Stream: TStream; skip, len: integer);
var  udd:ud_user_data;
begin
 udd:=getUserData(FUdis);
  udd.CallBackLen := Len;
  udd.CallBackStream := pointer(Stream);
  FIsStream := true;
  DoDisassemble(skip);
end;

destructor TUDIS86.Destroy;
begin
  getUserData(FUDis).Free;
  FreeMem(FUdis);
  FResultBuff.Free;
  FreeAndNil(lineinfo);
  inherited;
end;

procedure TUDIS86.SetDecodeMode(bits: integer);
begin
  ud_set_mode(FUdis,bits);
end;

procedure TUDIS86.SetPC(Value: int64);
begin
  ud_set_pc(FUdis,Value);
end;

procedure TUDIS86.SetRemoveHexCode(Value: boolean);
begin
  FRemoveHexCode := Value;
end;

procedure TUDIS86.SetRemoveOffset(Value: boolean);
begin
  FRemoveOffset := Value;
end;

procedure TUDIS86.SetSyntaxMode(Value: TUDIS86SyntaxMode);
begin
  case Value of
  UDIS86SynATT : ud_set_syntaxATT(FUdis);
  UDIS86SynMASM: ud_set_syntaxINTEL(FUdis);
  end;
end;

Function TUDIS86.XDecodeBuffer2(buf : pointer; skip, len : integer; hook:TDecodeHook; userdata:pointer):TObjectList;
var
  ins:TDisInstruction;
  abrt:Boolean;
  i:integer;
  operand:ptr_ud_operand;
  udd:ud_user_data;
begin
 udd:=getUserData(FUDis);
 result:=TObjectList.Create(true);
  udd.CallBackLen := Len;
  udd.CallBackBuff := buf;
  FIsStream := false;
  FResultBuff.Clear;
  udd.CallBackPos := 0;
  SetTextModeInput(FTextInput);
  ud_input_skip(FUdis,skip);
  while ud_disassemble(FUdis)>0 do begin

    ins:=TDisInstruction.Create;

    ins.address:=ud_insn_off(FUdis);
    ins.instr_len:=ud_insn_len(FUdis);
    setlength(ins.hex,ins.instr_len);
    Move(ud_insn_ptr(FUdis)^ , (@ins.hex[0])^, ins.instr_len);

    ins.mnemonic:=ud_insn_mnemonic(FUDis);
    ins.mnemonic_str:=ud_lookup_mnemonic(ins.mnemonic);
    ins.asmstr:=ud_insn_asm(FUdis);

    ins.ResetOperands;

    for i:=0 to length(ins.operands)-1 do
    begin
     operand:=ud_insn_opr(FUDis, i);
     if operand<>nil then
      ins.operands[i]:=operand^
     else
      ins.operands[i].optype:=UD_NONE;
    end;


    result.Add(ins);

    abrt:=false;

    if Assigned(hook) then begin
     hook(ins, abrt, userdata);
     if abrt then
        break;
    end;


  end;
end;

Function TUDIS86.XDecodeBuffer(buf : pointer; skip, len : integer):TObjectList;
begin
 result:=XDecodeBuffer2(buf, skip, len, nil, nil);
end;

procedure TUDIS86.DoDisassemble(skip: Integer);
var
  adrfmt, resultbuf: string;
  hex1: PAnsiChar;
  hex2: PAnsiChar;
  tempc: Char;
  LInfo:string;
  mnen: enum_t;
  udd:ud_user_data;
begin
 udd:=getUserData(FUDis);
 if FDecMode=64 then adrfmt:='%.16x : ' else adrfmt:='%.8x : ';
  FResultBuff.Clear;
  udd.CallBackPos := 0;
  SetTextModeInput(FTextInput);
  ud_input_skip(FUdis,skip);
  while ud_disassemble(FUdis)>0 do begin

    LInfo:=GetLineInfo(ud_insn_off(FUdis));

     if (LInfo<>'') then begin
       resultbuf:='; ' + LInfo + ' :';
       FResultBuff.Add(resultbuf);
     end;

    resultbuf:='';

    if not FRemoveOffset then Resultbuf := format(adrfmt,[ud_insn_off(FUdis)]);
    if not FRemoveHexCode then begin
      hex1 := ud_insn_hex(FUdis);
      hex2 := hex1;
      inc(hex2,16);
      tempc := hex1[16];
      hex1[16] := #0;
      Resultbuf := Resultbuf + format('%-16s %-24s',[strpas(hex1),ud_insn_asm(FUdis)]);

      mnen:=ud_insn_mnemonic(FUDis);

      resultbuf:=resultbuf+#13#10+      ud_lookup_mnemonic(mnen);

      hex1[16] := tempc;
      if strlen(hex1)>16 then begin
        FResultBuff.Add(Resultbuf);
        Resultbuf := '';
        if not FRemoveOffset then
          Resultbuf := format('%19s',[' ']);
        Resultbuf := Resultbuf + format('%-16s',[strpas(hex2)]);
      end;
    end else Resultbuf := Resultbuf + format('%-24s',[ud_insn_asm(FUdis)]);


    if (FFtext<>'') then begin
      if ( (FFault >= ud_insn_off(FUdis)) and
           (FFault < (ud_insn_off(FUdis)+ud_insn_len(FUDis)))) then
         begin
           resultbuf:=resultbuf + '  ; <- ' + FFtext;
         end;
    end;
    FResultBuff.Add(resultbuf);
  end;
end;

procedure TUDIS86.Reset;
begin
  ud_init(FUdis);
  FIsStream := false;
  SetDecodeMode(FDecMode);
  SetSyntaxMode(FSyntaxMode);
  FResultBuff.Clear;
  ClearLineInfo;
end;

Function TUDIS86.GetLineInfo(lineoffset:Int64):string;
var i:integer;
begin
 result:='';

   for i:=0 to LineInfo.Count-1 do begin
     if Cardinal(LineInfo.Objects[i])=cardinal(lineoffset) then begin
      result:=LineInfo[i];
      break;
     end;
   end;

end;

Procedure TUDIS86.ClearLineInfo;
begin
 LineInfo.Clear;
end;

Procedure TUDIS86.AddLineInfo(LinePointAddr:Cardinal; Text:String);
begin
 LineInfo.AddObject(Text, pointer(LinePointAddr));
end;

procedure TUDIS86.SetTextModeInput(Value: boolean);
var
  inputhook : TUDInputHookProc;
begin
  FTextInput := Value;
  if Value then begin
    if not FIsStream then inputhook := HookFuncBuffHex
      else inputhook := HookFuncStreamHex;
  end else begin
    if not FIsStream then inputhook := HookFuncBuff
      else inputhook := HookFuncStream;
  end;
  ud_set_input_hook(FUdis,inputhook);
end;

procedure TUDIS86.SetVendor(Value: TUDIS86Vendor);
begin
  case Value of
  UDIS86VendorINTEL : ud_set_vendor(FUdis,UD_VENDOR_INTEL);
  else ud_set_vendor(FUdis,UD_VENDOR_AMD);
  end;
end;

end.
