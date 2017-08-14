:Namespace CInterop
    ⍝ Low-level C interoperation 

    init←0
    libc←⍬ ⍝ will be filled in by Init

    ⍝ What kind of architecture do we have? (32/64 bits)
    ∇ n←Bits
        n←{⊃⊃(//)⎕VFI(⍵∊⎕D)/⍵}⊃#.⎕WG'APLVersion'
    ∇
    
    ∇ Init
        :If ∨/'Windows'⍷⊃#.⎕WG'APLVersion'
            InitWindows
        :Else
            InitUnix
        :EndIf
        init←1
    ∇       

    ∇ InitWindows
        libc←'msvcrt'

        ⎕NA'P msvcrt|malloc P'
        ⎕NA'  msvcrt|free   P'

        'mread'⎕NA' msvcrt|memcpy =U1[] P P'
        'mwrite'⎕NA'msvcrt|memcpy P <U1[] P'


        ⎕NA'msvcrt|memcpy P P P'

        init←1
    ∇

    ⍝ Return the 'libc' variable, initializing it first if necessary
    ∇ l←LibC
        :If ~init ⋄ Init ⋄ :EndIf
        l←libc
    ∇

    ∇ InitUnix


        'NonWindows'#.⎕CY'quadna.dws'
        #.NonWindows.Setup

        ⍝ quadna.dws doens't know about the C library on the Mac
        :If 'Mac'≡3↑⊃#.⎕WG'APLVersion'
            libc←'/usr/lib/system/libsystem_c.dylib'
        :Else
            libc←#.NonWindows.libc ⍬
        :EndIf

        ⎕NA'P ',libc,'|malloc P'
        ⎕NA'  ',libc,'|free P'

        'mread'⎕NA libc,' |memcpy =U1[] P P'
        'mwrite'⎕NA libc,'|memcpy P <U1[] P'

        ⎕NA libc,'|memcpy P P P'

        init←1
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

    ⍝ Read and write structs
    ⍝ 'struct' must be an argument in the ⎕NA style
    ⍝ (something that would fit between {...}).
    ⍝ Note that (just like ⎕NA itself, according to the docs),
    ⍝ no memory alignment is done.
    :Class Struct
        when←/⍨

        :Field Private struct←⍬
        :Field Private memrw←⍬
        :Field Private size←¯1
        :Field Private ptr←⍬
        :Field Private proto←⍬
        :Field Private owned←0 ⍝ if 1, memory will be freed.

        ⍝ Initialize a struct and some memory for it. The memory will be freed
        ⍝ once the object goes out of scope.
        ∇init _struct
            :Access Public
            :Implements Constructor

            :If ~#.CInterop.init ⋄ #.CInterop.Init ⋄ :EndIf

            struct←_struct

            ⍝ make appropriate ⎕NA calls
            memrw←⎕NS''
            'read'  memrw.⎕NA #.CInterop.libc,'|memcpy ={',struct,'} P P'
            'write' memrw.⎕NA #.CInterop.libc,'|memcpy P <{',struct,'} P'

            ⍝ allocate memory
            ptr←#.CInterop.AllocMem size←StructSize
            owned←1

            ⍝ make a prototype object
            mkproto
        ∇

        ⍝ Use the memory pointed to as a struct. Memory will _not_ be freed.
        ∇initmem (_struct _ref)
            :Access Public
            :Implements Constructor

            ⍝ We don't own this memory
            owned←0
            ptr←_ref

            struct←_struct

            ⍝ make appropriate ⎕NA calls
            memrw←⎕NS''
            'read'  memrw.⎕NA #.CInterop.libc,'|memcpy ={',struct,'} P P'
            'write' memrw.⎕NA #.CInterop.libc,'|memcpy P <{',struct,'} P'

            size←StructSize

            ⍝ make a prototype object
            mkproto
        ∇


        ⍝ Read random memory _as if_ it were this struct. 
        ⍝ If there is not enough memory, it will syserror.
        ∇out←Cast ptr
            :Access Public
            out←memrw.read proto ptr size
        ∇

        ∇out←Read
            :Access Public
            ⍝ read the struct
            →(ptr=0)/0

            out←memrw.read proto ptr size
        ∇

        ∇Write in
            :Access Public
            ⍝ write the struct
            →(ptr=0)/0
            {}memrw.write ptr in size
        ∇

        ∇destroy;localptr
            :Access Private
            :Implements Destructor
            →(ptr=0)/0

            →(~owned)/0 ⍝ we don't own the memory, leave it alone

            ⍝ free the memory
            localptr←ptr
            ptr←0
            #.CInterop.FreeMem localptr
        ∇

        ⍝ get the size
        ∇sz←Size
            :Access Public
            sz←size
        ∇

        ⍝ get the pointer
        ∇p←Ref
            :Access Public
            p←ptr
        ∇

        ⍝ make a prototype object for the struct
        ∇mkproto;mkpfield

            ⍝ make a prototype object for a field
            mkpfield←{
                ⍝ is this an array? 
                arrsz←1⌈⊃⊃(//)⎕VFI 1↓(+\+⌿1 ¯1×[1]'[]'∘.=⍵)/⍵
                field←(∧\⍵≠'[')/⍵

                ⍝ array - make N items and enclose them
                ⍵≢field: ⊂arrsz/∇field

                ⍝ is it C or T? then we need a character
                (⍵~⎕D)∊'CT': ' '

                ⍝ otherwise, we need a number
                0
            }

            proto←mkpfield¨(struct≠' ')⊆struct
        ∇

        ⍝ calculate the size of the struct
        ∇sz←StructSize;dsz;td;pd;field;sz;fsz;fpos;arrsz
            :Access Public

            ⍝ luckily, <>=0#[]{} aren't allowed within structs

            ⍝ Default size of 'T': 2 on Windows and 4 on Unix
            td←2+2×'Windows'≢7↑⊃#.⎕WG'APLVersion'
            ⍝ Default size of 'P': (N/8), on an N-bit APL interpreter
            pd←{(⊃⊃(//)⎕VFI(⍵∊⎕D)/⍵)÷8}⊃#.⎕WG'APLVersion'

            dsz←('I'4)('U'4)('C'1)('T'td)('F'8)('D'16)('J'16)('P'pd)

            ⍝ process each field of the struct
            sz←0
            :For field :In (struct≠' ')⊆struct
                ⍝ do we have an array size? if not, use 1
                arrsz←1⌈⊃⊃(//)⎕VFI 1↓(+\+⌿1 ¯1×[1]'[]'∘.=field)/field

                ⍝ remove array from field if it's there
                field←(∧\field≠'[')/field

                ⍝ is there a size specified for the type?
                :If 0≠fsz←⊃⊃(//)⎕VFI(field∊⎕D)/field
                    ⍝ Yes: use it
                    sz+←fsz×arrsz
                :ElseIf ∨/fpos←field=⊃¨dsz
                    ⍝ We have a standard size for it, use that
                    sz+←arrsz×2⊃⊃fpos/dsz
                :Else
                    ⍝ Invalid field specification
                    ⎕SIGNAL⊂('EN'11)('Message' ('Invalid field specification: ',field))
                :EndIf
            :EndFor
        ∇
    :EndClass

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

        ⍝ Copy data in here from a given memory address
        ∇Load (inptr sz)
            :Access Public
            'Size too big' ⎕SIGNAL (sz>size)/11

            {}#.CInterop.memcpy ptr inptr sz
        ∇

        ∇d←Data
            :Access Public
            d←ptr #.CInterop.ReadBytes size
        ∇
    :EndClass

:EndNamespace
