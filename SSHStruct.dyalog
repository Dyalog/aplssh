⍝∇:require =/CInterop.dyalog

:Namespace SSHStruct
  
    ∇ r←ScriptPath
        ⍝r←SALT_Data.SourceFile
     
        ⍝ Adám's SourceFile function
      r←{ ⍝ Get pathname to sourcefile for item ⍵
          c←⎕NC⊂,⍕⍵
          c=2.1:(SALT_Var_Data.VD[;1]⍳⊂⍵(⊢,~)'#.')⊃SALT_Var_Data.VD[;2],⊂''
          c∊3.1 3.2 4.1 4.2:1↓⊃('§'∘=⊂⊢)∊¯2↑⎕NR ⍵
          (r←326=⎕DR ⍵)∨c∊9+0.1×⍳8:{6::'' ⋄ ''≡f←⊃(4∘⊃¨(/⍨)(⍵≡⊃)¨)5177⌶⍬:⍵.SALT_Data.SourceFile ⋄ f}⍎⍣(~r)⊢⍵
          ''
      }⎕THIS
    ∇
    
    isOS←{⍵≡(≢⍵)↑⊃#.⎕WG'APLVersion'}
    
    init←0
    
    ⍝ initialize
    ∇ Init;name;path;⍙T
      →init/0
     
        ⍝ We expect the DLL to be in the script directory, failing that we want it on the path.
      path←{(~∨\'SSHStruct'⍷⍵)/⍵}ScriptPath
      name←'aplhelpers.',⊃'so' 'dll'[1+isOS'Windows']
     
        ⍝ try loading it from the script directory
      path←path,name
      :Trap 0
          '⍙T'⎕NA'I1 ',path,'|test'
          {}42≡⍙T
      :Else
            ⍝ try loading it from the path
          path←name
          '⍙T'⎕NA'I1 ',path,'|test'
          {}42≡⍙T
      :EndTrap
     
        ⍝ still here?
     
        ⍝⍝⍝ stat
      ⎕NA'U8 ',path,'|stat_size P'
      ⎕NA'I4 ',path,'|stat_mode P'
      ⎕NA'I8 ',path,'|stat_atime P'
      ⎕NA'I8 ',path,'|stat_mtime P'
     
      init←1
    ∇
    
    ⍝ Decode a 'stat' structure
    ⍝ giving (size, mode, atime, mtime)
    ∇ (size mode atime mtime)←stat statblk
      size←stat_size statblk.Ref
      mode←stat_mode statblk.Ref
      atime←stat_atime statblk.Ref
      mtime←stat_mtime statblk.Ref
    ∇
    
:EndNamespace
