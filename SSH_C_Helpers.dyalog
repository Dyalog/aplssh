⍝∇:require =/CInterop.dyalog

:Namespace SSH_C_Helpers

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
        path←{(~∨\'SSH_C_Helpers'⍷⍵)/⍵}ScriptPath
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
        
        ⍝⍝⍝ knownhosts
        ⎕NA'U4 ',path,'|knownhost_magic P'
        ⎕NA'P  ',path,'|knownhost_node P'
        ⎕NA'P  ',path,'|knownhost_name P'
        ⎕NA'P  ',path,'|knownhost_key P'
        ⎕NA'I4 ',path,'|knownhost_typemask P'
        

        ⍝⍝ deal with getaddrinfo with wrappers
        ⎕NA'I4 ',path,'|apl_getaddrinfo I4 <0C <0C U1 >P'
        ⎕NA'I4 ',path,'|apl_freeaddrinfo P'
        ⎕NA'I4 ',path,'|apl_addr_family P'
        ⎕NA'I4 ',path,'|apl_addr_socktype P'
        ⎕NA'P  ',path,'|apl_addr_addrlen P'
        ⎕NA'P  ',path,'|apl_addr_canonname P'
        ⎕NA'P  ',path,'|apl_addr_sockaddr P'
        ⎕NA'P  ',path,'|apl_addr_next P'

        init←1
    ∇

    ⍝ Read a C string at a given address, but give the empty string if
    ⍝ a null pointer is given.
    ∇ r←str ptr
        r←'' ⋄ →(ptr=0)/0
        r←#.CInterop.ReadCStr ptr
    ∇
    
    ⍝ Decode a 'stat' structure
    ⍝ giving (size, mode, atime, mtime)
    ∇ (size mode atime mtime)←stat statblk
        size←stat_size statblk.Ref
        mode←stat_mode statblk.Ref
        atime←stat_atime statblk.Ref
        mtime←stat_mtime statblk.Ref
    ∇
    
    ⍝ knownhosts
    ∇ (magic node name key typemask)←knownhost ref;sptr
        magic←knownhost_magic ref
        node←knownhost_node ref
        name←str knownhost_name ref
        key←str knownhost_key ref
        typemask←knownhost_typemask ref
    ∇
        

    ⍝⍝ Decode an 'apl_addr' structure
    ∇ (fam type len name sa next)←apl_addr ref
        fam←apl_addr_family ref
        type←apl_addr_socktype ref 
        len←apl_addr_addrlen ref
        name←str apl_addr_canonname ref
        sa←apl_addr_sockaddr ref
        next←apl_addr_next ref
    ∇



:EndNamespace
