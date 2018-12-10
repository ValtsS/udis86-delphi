program udistest;

{$APPTYPE CONSOLE}

uses sysutils, classes, udis86d, udis86;


const
  buffx : array[0..5] of byte = ($00,$db,$44,$24,$18,$d9);

var
    ax : ud_operand;
    bl : TUDIS86;
    buff : TFileStream;

begin
  bl := TUDIS86.Create;
  try
   buff := TFileStream.Create('testdata.bin',fmOpenRead);
   try
     bl.SetPC($400000);
     bl.SetDecodeMode(32);
     bl.SetRemoveOffset(false);
     bl.SetRemoveHexCode(false);
     //bl.DecodeStream(buff,0,buff.Size);
     try
     bl.DecodeBuffer(@buffx[0],0,6);
     except
     end;
     writeln(bl.ResultText.Text);
     bl.Reset;
     buff.Position := 0;
     try
     bl.DecodeStream(buff,0,buff.Size);
     except
     end;
     writeln(bl.ResultText.Text);
   finally
     buff.Free;
   end;
  finally
    bl.Free;
  end;
end.

