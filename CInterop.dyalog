:Namespace CInterop
    ⍝ Low-level C interoperation 

    init←0

    ∇ Init
        :If ∨/'Windows'⍷⊃#.⎕WG'APLVersion'
            InitWindows
        :Else
            InitUnix
        :EndIf
        init←1
    ∇       

    ∇ InitWindows
        ⎕NA'P msvcrt|malloc P'
        ⎕NA'  msvcrt|free   P'
        
        'mread'⎕NA' msvcrt|memcpy =U1[] P P'
        'mwrite'⎕NA'msvcrt|memcpy P <U1[] P'
    ∇

    ∇ InitUnix;l


        'NonWindows'#.⎕CY'quadna.dws'
        #.NonWindows.Setup

        ⍝ quadna.dws doens't know about the C library on the Mac
        :If 'Mac'≡3↑⊃#.⎕WG'APLVersion'
            l←'/usr/lib/system/libsystem_c.dylib'
        :Else
            l←#.NonWindows.libc ⍬
        :EndIf
        
        ⎕NA'P ',l,'|malloc P'
        ⎕NA'  ',l,'|free P'

        'mread'⎕NA l,' |memcpy =U1[] P P'
        'mwrite'⎕NA l,'|memcpy P <U1[] P'
    ∇

    ∇ ptr←AllocMem bytes
        :If ~init ⋄ Init ⋄ :EndIf
        ptr←malloc bytes
    ∇

    ∇ FreeMem ptr
        :If ~init ⋄ Init ⋄ :EndIf
        {}free ptr
    ∇

    ∇ out←ptr ReadBytes size
        :If ~init ⋄ Init ⋄ :EndIf
        :If size=0 ⋄ out←⍬ ⋄ :Return ⋄ :EndIf
        out←mread (size/0) ptr size
    ∇

    ∇ s←ReadCStr ptr;byte
        s←''
        :Repeat
            byte←⊃ptr ReadBytes 1
            →(byte=0)/0
            s,←⎕UCS byte
            ptr+←1
        :EndRepeat
    ∇

    ∇ ptr WriteBytes data
        :If ~init ⋄ Init ⋄ :EndIf
        {}mwrite ptr data(≢data)
    ∇

    ⍝ This class loads some data into memory (as a byte array) 
    ⍝ and gives you a pointer to it. The memory will be freed 
    ⍝ automatically when the object goes out of scope.
    :Class DataBlock
        when←/⍨

        :Field Private ptr←0
        :Field Private size←0
        ∇init data
            :Access Public
            :Implements Constructor

            ⍝ automatically convert strings to UTF-8 bytes
            :If ''≡0↑data
                data←'UTF-8'⎕UCS data
            :EndIf

            ptr←#.CInterop.AllocMem (size←≢data)
            'Memory allocation failed.' ⎕SIGNAL 999 when ptr=0

            ptr #.CInterop.WriteBytes data
        ∇

        ∇destroy
            :Implements Destructor
            →(ptr=0)/0
            #.CInterop.FreeMem ptr
        ∇

        ∇r←Ref
            :Access Public
            r←ptr
        ∇

        ∇s←Size
            :Access Public
            s←size
        ∇ 

        ∇d←Data
            :Access Public
            d←ptr #.CInterop.ReadBytes size
        ∇
    :EndClass

:EndNamespace
