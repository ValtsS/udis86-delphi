unit udis86;

(* udis86.pas
   2006/10/17 by Do-wan Kim

   2006/12/20 : fix bugs at record definition
*)

// don't change list order below linkage
// bcc32 -c -u- -vu -O -D_MSC_VER -D__UD_STANDALONE__
{$L udis86.obj}
{$L decode.obj}
{$L itab.obj}
{$L syn-att.obj}
{$L syn-intel.obj}
{$L syn.obj}

interface

{$MINENUMSIZE 4}

const
  UD_EOI			  = -1; // for ud_disassemble
  UD_VENDOR_AMD   = 0;
  UD_VENDOR_INTEL =	1;
  // UD_INP_CACHE_SZ	=	32;


type
  uint8_t   =   byte;
  uint8_tp  =   ^uint8_t;
  uint16_t  =   word;
  uint32_t  =   longword;
  uint64_t  =   int64;  // it's singed in delphi :/
  int8_t    =   shortint;
  int16_t   =   smallint;
  int32_t   =   longint;
  int64_t   =   int64;
  enum_t    =   longint; // enum = longint;
  size_t    =   integer;


ud_type = (

  UD_NONE,

  (* 8 bit GPRs *)
  UD_R_AL,  UD_R_CL,  UD_R_DL,  UD_R_BL,
  UD_R_AH,  UD_R_CH,  UD_R_DH,  UD_R_BH,
  UD_R_SPL, UD_R_BPL, UD_R_SIL, UD_R_DIL,
  UD_R_R8B, UD_R_R9B, UD_R_R10B,  UD_R_R11B,
  UD_R_R12B,  UD_R_R13B,  UD_R_R14B,  UD_R_R15B,

  (* 16 bit GPRs *)
  UD_R_AX,  UD_R_CX,  UD_R_DX,  UD_R_BX,
  UD_R_SP,  UD_R_BP,  UD_R_SI,  UD_R_DI,
  UD_R_R8W, UD_R_R9W, UD_R_R10W,  UD_R_R11W,
  UD_R_R12W,  UD_R_R13W,  UD_R_R14W,  UD_R_R15W,

  (* 32 bit GPRs *)
  UD_R_EAX, UD_R_ECX, UD_R_EDX, UD_R_EBX,
  UD_R_ESP, UD_R_EBP, UD_R_ESI, UD_R_EDI,
  UD_R_R8D, UD_R_R9D, UD_R_R10D,  UD_R_R11D,
  UD_R_R12D,  UD_R_R13D,  UD_R_R14D,  UD_R_R15D,

  (* 64 bit GPRs *)
  UD_R_RAX, UD_R_RCX, UD_R_RDX, UD_R_RBX,
  UD_R_RSP, UD_R_RBP, UD_R_RSI, UD_R_RDI,
  UD_R_R8,  UD_R_R9,  UD_R_R10, UD_R_R11,
  UD_R_R12, UD_R_R13, UD_R_R14, UD_R_R15,

  (* segment registers *)
  UD_R_ES,  UD_R_CS,  UD_R_SS,  UD_R_DS,
  UD_R_FS,  UD_R_GS,

  (* control registers*)
  UD_R_CR0, UD_R_CR1, UD_R_CR2, UD_R_CR3,
  UD_R_CR4, UD_R_CR5, UD_R_CR6, UD_R_CR7,
  UD_R_CR8, UD_R_CR9, UD_R_CR10,  UD_R_CR11,
  UD_R_CR12,  UD_R_CR13,  UD_R_CR14,  UD_R_CR15,

  (* debug registers *)
  UD_R_DR0, UD_R_DR1, UD_R_DR2, UD_R_DR3,
  UD_R_DR4, UD_R_DR5, UD_R_DR6, UD_R_DR7,
  UD_R_DR8, UD_R_DR9, UD_R_DR10,  UD_R_DR11,
  UD_R_DR12,  UD_R_DR13,  UD_R_DR14,  UD_R_DR15,

  (* mmx registers *)
  UD_R_MM0, UD_R_MM1, UD_R_MM2, UD_R_MM3,
  UD_R_MM4, UD_R_MM5, UD_R_MM6, UD_R_MM7,

  (* x87 registers *)
  UD_R_ST0, UD_R_ST1, UD_R_ST2, UD_R_ST3,
  UD_R_ST4, UD_R_ST5, UD_R_ST6, UD_R_ST7,

  (* extended multimedia registers *)
  UD_R_XMM0,  UD_R_XMM1,  UD_R_XMM2,  UD_R_XMM3,
  UD_R_XMM4,  UD_R_XMM5,  UD_R_XMM6,  UD_R_XMM7,
  UD_R_XMM8,  UD_R_XMM9,  UD_R_XMM10, UD_R_XMM11,
  UD_R_XMM12, UD_R_XMM13, UD_R_XMM14, UD_R_XMM15,

  (* 256B multimedia registers *)
  UD_R_YMM0,  UD_R_YMM1,  UD_R_YMM2,  UD_R_YMM3,
  UD_R_YMM4,  UD_R_YMM5,  UD_R_YMM6,  UD_R_YMM7,
  UD_R_YMM8,  UD_R_YMM9,  UD_R_YMM10, UD_R_YMM11,
  UD_R_YMM12, UD_R_YMM13, UD_R_YMM14, UD_R_YMM15,

  UD_R_RIP,

  (* Operand Types *) // Starts with $9C
  UD_OP_REG,  UD_OP_MEM,  UD_OP_PTR,  UD_OP_IMM,
  UD_OP_JIMM, UD_OP_CONST
);

  ud_operand = packed record

  optype:ud_type;
  size:uint16_t;
  base:ud_type;
  index:ud_type;
  scale:uint8_t;

  lval : packed record
          case offset:uint8_t of
          0 : ( sbyte : int8_t);
          1 : ( ubyte : uint8_t);
          2 : ( sword : int16_t);
          3 : ( uword : uint16_t);
          4 : ( sdword : int32_t);
          5 : ( udword : uint32_t);
          6 : ( sqword : int64_t);
          7 : ( uqword : uint64_t);
          8 : ( ptr   : record
                        seg : uint16_t;
                        off : uint32_t;
                        end; )
         end;

  end;

  ptr_ud_operand = ^ud_operand;

  ptr_ud = pointer;
  TUDInputHookProc = function(ud : ptr_ud):integer; cdecl;
  TUDSyntaxProc = procedure(ud : ptr_ud); cdecl;
  TUDTranFunctionProc = procedure(ud : ptr_ud); cdecl;

// =====================
// function definition
// =====================


function ud_get_size_required:cardinal; cdecl;

//extern void ud_init(struct ud*);
procedure ud_init(ud : ptr_ud); cdecl;


procedure ud_set_userdata(ud : ptr_ud; userdata:Int64); cdecl;


Function ud_get_userdata(ud : ptr_ud):Int64; cdecl;

//extern void ud_set_mode(struct ud*, uint8_t);
procedure ud_set_mode(ud : ptr_ud; mode : uint8_t); cdecl;

//extern void ud_set_pc(struct ud*, uint64_t);
procedure ud_set_pc(ud : ptr_ud; pc : uint64_t); cdecl;

//extern void ud_set_input_hook(struct ud*, int (*)(struct ud*));
procedure ud_set_input_hook(ud : ptr_ud; hookproc : TUDInputHookProc); cdecl;

//extern void ud_set_input_buffer(struct ud*, uint8_t*, size_t);
procedure ud_set_input_buffer(ud : ptr_ud; buf : uint8_tp; len : size_t); cdecl;

// --- extern void ud_set_input_file(struct ud*, FILE*);

// udis86 1.4
procedure ud_set_vendor(ud : ptr_ud; vender : byte); cdecl;

//extern void ud_set_syntax(struct ud*, void (*)(struct ud*));
procedure ud_set_syntax(ud : ptr_ud; syntaxproc : TUDSyntaxProc); cdecl;

//DW
procedure ud_set_syntaxINTEL(ud : ptr_ud); cdecl;
procedure ud_set_syntaxATT(ud : ptr_ud); cdecl;

//extern void ud_input_skip(struct ud*, size_t);
procedure ud_input_skip(ud : ptr_ud; len : size_t); cdecl;

//extern int ud_input_end(struct ud*);
function ud_input_end(ud : ptr_ud):integer; cdecl;

//extern unsigned int ud_decode(struct ud*);
function ud_decode(ud : ptr_ud): longword; cdecl;

//extern unsigned int ud_disassemble(struct ud*);
function ud_disassemble(ud : ptr_ud): longword; cdecl;

//extern void ud_translate_intel(struct ud*);
procedure ud_translate_intel(ud : ptr_ud); cdecl;

//extern void ud_translate_att(struct ud*);
procedure ud_translate_att(ud : ptr_ud); cdecl;

//extern char* ud_insn_asm(struct ud* u);
function ud_insn_asm(ud : ptr_ud):pchar; cdecl;

//extern uint8_t* ud_insn_ptr(struct ud* u);
function ud_insn_ptr(ud : ptr_ud):uint8_tp; cdecl;

//extern uint64_t ud_insn_off(struct ud*);
function ud_insn_off(ud : ptr_ud):uint64_t; cdecl;

//extern char* ud_insn_hex(struct ud*);
function ud_insn_hex(ud : ptr_ud):pchar; cdecl;

//extern unsigned int ud_insn_len(struct ud* u);
function ud_insn_len(ud : ptr_ud):longword; cdecl;

//extern const char* ud_lookup_mnemonic(enum ud_mnemonic_code c);
function ud_lookup_mnemonic(c : enum_t):pchar; cdecl;

function ud_insn_mnemonic(ud : ptr_ud):enum_t; cdecl;

//extern const struct ud_operand* ud_insn_opr(const struct ud *u, unsigned int n);
//function ud_insn_opr(ud : ptr_ud; n:cardinal):ud_operand_t; cdecl;
function ud_insn_opr(ud : ptr_ud; n:cardinal):ptr_ud_operand; cdecl;

Function ud_opr_is_gpr(opr:ptr_ud_operand):boolean;


implementation

uses windows, sysutils;

function ud_get_size_required:cardinal; cdecl; external;

//extern void ud_init(struct ud*);
procedure ud_init(ud : ptr_ud); cdecl; external;


procedure ud_set_userdata(ud : ptr_ud; userdata:Int64); cdecl; external;


Function ud_get_userdata(ud : ptr_ud):Int64; cdecl; external;


//extern void ud_set_mode(struct ud*, uint8_t);
procedure ud_set_mode(ud : ptr_ud; mode : uint8_t); cdecl; external;

//extern void ud_set_pc(struct ud*, uint64_t);
procedure ud_set_pc(ud : ptr_ud; pc : uint64_t); cdecl; external;

//extern void ud_set_input_hook(struct ud*, int (*)(struct ud*));
procedure ud_set_input_hook(ud : ptr_ud; hookproc : TUDInputHookProc); cdecl; external;

//extern void ud_set_input_buffer(struct ud*, uint8_t*, size_t);
procedure ud_set_input_buffer(ud : ptr_ud; buf : uint8_tp; len : size_t); cdecl; external;

// --- extern void ud_set_input_file(struct ud*, FILE*);

// udis86 1.4
procedure ud_set_vendor(ud : ptr_ud; vender : byte); cdecl; external;

//extern void ud_set_syntax(struct ud*, void (*)(struct ud*));
procedure ud_set_syntax(ud : ptr_ud; syntaxproc : TUDSyntaxProc); cdecl; external;

//extern void ud_input_skip(struct ud*, size_t);
procedure ud_input_skip(ud : ptr_ud; len : size_t); cdecl; external;

//extern int ud_input_end(struct ud*);
function ud_input_end(ud : ptr_ud):integer; cdecl; external;

//extern unsigned int ud_decode(struct ud*);
function ud_decode(ud : ptr_ud): longword; cdecl; external;

//extern unsigned int ud_disassemble(struct ud*);
function ud_disassemble(ud : ptr_ud): longword; cdecl; external;

//extern void ud_translate_intel(struct ud*);
procedure ud_translate_intel(ud : ptr_ud); cdecl; external;

//extern void ud_translate_att(struct ud*);
procedure ud_translate_att(ud : ptr_ud); cdecl; external;

//extern char* ud_insn_asm(struct ud* u);
function ud_insn_asm(ud : ptr_ud):pchar; cdecl; external;

//extern uint8_t* ud_insn_ptr(struct ud* u);
function ud_insn_ptr(ud : ptr_ud):uint8_tp; cdecl; external;

//extern uint64_t ud_insn_off(struct ud*);
function ud_insn_off(ud : ptr_ud):uint64_t; cdecl; external;

//extern char* ud_insn_hex(struct ud*);
function ud_insn_hex(ud : ptr_ud):pchar; cdecl; external;

//extern unsigned int ud_insn_len(struct ud* u);
function ud_insn_len(ud : ptr_ud):longword; cdecl; external;

//extern const char* ud_lookup_mnemonic(enum ud_mnemonic_code c);
function ud_lookup_mnemonic(c : enum_t):pchar; cdecl; external;

function ud_insn_mnemonic(ud : ptr_ud):enum_t; cdecl; external;

function ud_insn_opr(ud : ptr_ud; n:cardinal):ptr_ud_operand; cdecl; external;

//DW
procedure ud_set_syntaxINTEL(ud : ptr_ud); cdecl;
begin
  ud_set_syntax(ud,ud_translate_intel);
end;

procedure ud_set_syntaxATT(ud : ptr_ud); cdecl;
begin
  ud_set_syntax(ud,ud_translate_att);
end;

// functions for c obj
procedure memset(P: Pointer; B: Integer; count: Integer); cdecl;
begin
  FillChar(P^, count, B);
end;


function __wvnsprintf(Output: PChar; cchDest:integer; FormatStr: PChar; const arglist: va_list): Integer; stdcall; external 'Shlwapi.dll' name 'wvnsprintfA';


function vsprintf(Buffer, Format: PChar; Arguments: {array of const}va_list):integer; cdecl;
begin
  result := wvsprintf(Buffer, Format, Arguments);
end;

function vsnprintf(Buffer:PChar; cchDest:integer; Format: PChar; Arguments: {array of const}va_list):integer; cdecl;
begin
  result := __wvnsprintf(Buffer, ccHdest, Format, Arguments);
end;


procedure _llushr;assembler;
asm
		cmp		cl, 32
		jl		@__llushr@below32

		cmp		cl, 64
		jl		@__llushr@below64

		xor		edx, edx
		xor		eax, eax
		ret

@__llushr@below64:

		mov		eax, edx
		xor		edx, edx
		shr		eax, cl
		ret

@__llushr@below32:

		shrd	eax, edx, cl
		shr		edx, cl
		ret

end;


Function ud_opr_is_gpr(opr:ptr_ud_operand):boolean;
begin

  result:= (opr^.optype = UD_OP_REG) and
         (cardinal(opr^.base) >= cardinal(UD_R_AL))   and
         (cardinal(opr^.base) <= cardinal(UD_R_R15));
end;


begin
end.

