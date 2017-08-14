⍝∇:require =/CInterop.dyalog
:Namespace Sock
    ⍝⍝ Low-level wrapper around Berkeley sockets (on Unix) or Winsock (on Windows)
    ⍝⍝ Supports TCP/UDP only for now (as this is enough for the SSH library)

    ⍝ convert binary functions to bitwise ones
    bin←{2⊥⍺⍺/2⊥⍣¯1⊢(⍺⍺/⍬),⍵}

    ⍝ error
    SOCK_ERR←701

    :Namespace UnixErrors
        EPERM←1
        EINTR←4
        EBADF←9
        EAGAIN←11
        EACCESS←13
        EFAULT←14
        ENOTSOCK←88
        EPROTOTYPE←91
        EAFNOSUPPORT←97
        EADDRINUSE←98
        EADDRNOTAVAIL←99
        ENETUNREACH←101
        EISCONN←106
        ETIMEDOUT←110
        ECONNREFUSED←111
        EALREADY←114
        EINPROGRESS←115
        
        EAI_NONAME←¯2
        EAI_ADDRFAMILY←¯9
        EAI_AGAIN←¯3
        EAI_BADFLAGS←¯1
        EAI_FAIL←¯4
        EAI_FAMILY←¯6
        EAI_MEMORY←¯10
        EAI_NODATA←¯5
        EAI_SERVICE←¯8
        EAI_SOCKTYPE←¯7
        EAI_SYSTEM←¯11
        
    :EndNamespace

    :Namespace UnixConstants
        AF_UNSPEC←0
        AF_INET←2
        AF_INET6←10

        AI_ADDRCONFIG←32
        AI_V4MAPPED←8
        AI_CANONNAME←2
        AI_PASSIVE←1

        SOCK_STREAM←1
        SOCK_DGRAM←2
        SOCK_RAW←3
        SOCK_SEQPACKET←5
    :EndNamespace

    ∇ Init
        ⍝ Make sure the C interop code is initialized
        #.CInterop.Init

        ⍝ Run OS-specific initialization
        :If 'Windows'≡7↑⊃#.⎕WG'APLVersion'
            InitWindows
        :Else
            InitUnix
        :EndIf

        ⎕NA'I ',socklib,'|socket I I I'
        ⎕NA'I ',socklib,'|bind I P P'
        ⎕NA'I ',socklib,'|listen I I'
        ⎕NA'I ',socklib,'|connect I P P'
        ⎕NA'I ',socklib,'|accept I P =P'
        ⎕NA'I ',socklib,'|send I <U1[] P I'
        ⎕NA'I ',socklib,'|recv I =U1[] P I'
        ⍝⍝⍝ close is OS-specific ⍝⍝⍝

        ⎕NA'I ',socklib,'|poll ={I U2 U2} I I'
        ⎕NA'I ',socklib,'|getsockopt I I I P =U'
        ⎕NA'I ',socklib,'|setsockopt I I I P U'

        ⍝ convenience functions
        'getsockopt_int'⎕NA'I ',socklib,'|getsockopt I I I >I =U'
        'setsockopt_int'⎕NA'I ',socklib,'|setsockopt I I I <I U'

        ⍝ getaddrinfo
        ⎕NA'I ',socklib,'|getaddrinfo <0C <0C P >P'
        ⎕NA'  ',socklib,'|freeaddrinfo P'
        'getaddrinfo_p'⎕NA'I ',socklib,'|getaddrinfo P <0C P >P'

    ∇

    ∇ InitUnix
        ⍝ on Unix, the socket functions are in libc
        socklib←#.CInterop.LibC

        ⍝ closing a socket is done using 'close'
        ⎕NA'I ',socklib,'|close I'

        ⍝ geterrno is supplied by dyalib
        ⎕NA'I ',#.NonWindows.dyalib,'geterrno'

        Err←UnixErrors
        Cnst←UnixConstants
    ∇

    ∇ InitWindows
        ⍝ on Windows, the socket functions are in Ws2_32.dll
        socklib←'Ws2_32.dll'

        ⍝ closing a socket is done using 'closesocket', but we'll rename it
        'close'⎕NA'I ',socklib,'|closesocket P'

        ⍝ geterrno is supplied (as WSAGetLastError) by the socket library
        'geterrno'⎕NA'I ',socklib,'|WSAGetLastError'
        
        Err←UnixErrors
    ∇

    ⍝ Get address info
    ⍝ Arguments: <family> GetAddrInfo host port 
    
    ∇ r←{family} GetAddrInfo (host port);hints;rt;ptr;ai;numf;sz;blk;sptr;canon

        ⍝ if no family is given, use all
        :If 0=⎕NC'family' ⋄ family←#.Sock.Cnst.AF_UNSPEC ⋄ :EndIf

        ⍝ if the port is numeric, pass it in as a string
        :If 0=⍬⍴0⍴port ⋄ port←⍕port ⋄ :EndIf
        
        hints←⎕NEW #.Sock.addrinfo
        hints.ai_family←family
        hints.ai_flags←∨bin #.Sock.Cnst.(AI_V4MAPPED AI_CANONNAME AI_ADDRCONFIG)
        hints.ai_flags←∨bin hints.ai_flags, (0=≢host)/#.Sock.Cnst.AI_PASSIVE
        
        
        :If 0=≢host
            ⍝ pass in NULL to show that no host is meant
            rt sptr←getaddrinfo_p 0 port (hints.Ref) 0
        :Else
            rt sptr←getaddrinfo host port (hints.Ref) 0
        :EndIf
        
        ⍝ if EAI_NONAME, we've found nothing, which is technically not an error state,
        ⍝ so just return an empty list ("everything we found")
        :If rt=#.Sock.Err.EAI_NONAME
            r←⍬
            :Return
        :EndIf
        
        ⎕SIGNAL (rt≠0)/⊂('EN'#.Sock.SOCK_ERR)('Message' (⍕rt))

        r←⍬

        ptr←sptr
        :While ptr≠0
            ⍝ Walk through the linked list and grab all the entries
            ai←⎕NEW #.Sock.addrinfo ptr

            ⍝ numeric fields
            numf←ai.(ai_family ai_socktype ai_protocol)

            ⍝ copy the actual socket into a DataBlock so it can be used
            sz←ai.ai_addrlen
            blk←⎕NEW #.CInterop.DataBlock (sz/0)
            blk.Load ai.ai_addr sz

            ⍝ load the canon name if it's there
            canon←''
            :If 0≠ai.ai_canonname
                canon←#.CInterop.ReadCStr ai.ai_canonname
            :EndIf

            ⍝ add it to the return value
            r,←⊂numf,blk,⊂canon
            
            ⍝ look at the next field
            ptr←ai.ai_next
        :EndWhile

        ⍝ If the starting pointer wasn't zero, we should now free everything
        ⍝ (the relevant data has been copied)
        :If 0≠sptr
            freeaddrinfo sptr
        :EndIf

    ∇

    ⍝ IPV4 socket.
    :Class Socket
        :Field Private fd←¯1
        :Field Private fam
        :Field Private type
        :Field Private shouldClose←0
        
        bin←{2⊥⍺⍺/2⊥⍣¯1⊢(⍺⍺/⍬),⍵}
        
        ⍝ Make an IPV4 socket
        ∇init type_
            :Access Public
            :Implements Constructor
            
            fam←#.Sock.Cnst.AF_INET
            type←type_
            
            fd←#.Sock.socket fam type 0
            :If fd=¯1
                ⎕SIGNAL ⊂('EN' #.Sock.SOCK_ERR)('Message' (⍕geterrno))
            :EndIf
        ∇
        
        ∇destroy
            :Access Private
            :Implements Destructor
            
            →(fd=¯1)/0
            →(~shouldClose)/0
            Close
        ∇
        
        ⍝ Close the socket
        ∇Close;lfd
            :Access Public
            →(fd=¯1)/0
            lfd←fd
            shouldClose←0
            fd←¯1
            {}#.Sock.close lfd
        ∇
        
        ⍝ Get the file descriptor
        ∇n←FD
            :Access Public
            n←fd
        ∇
        
        ⍝ Connect it
        ∇Connect (host port);addrs;addr;rt;blk
            :Access Public
            ⍝ find the data for the host and port
            addrs←fam #.Sock.GetAddrInfo (host port)
            ⎕SIGNAL(0=≢addrs)/⊂('EN'11)('Message' 'Address not found.')
            
            ⍝ find one that matches our type
            addrs←(type=2⊃¨addrs)/addrs
            ⎕SIGNAL(0=≢addrs)/⊂('EN'11)('Message' ('No connection to address found using type ',⍕type))
            
            ⍝ use the first one, if there is more than one left, they all must point to the same place
            addr←⊃addrs
            
            ⍝ the parsed address is contained in the 4th element
            blk←4⊃addr
            
            rt←#.Sock.connect fd blk.Ref blk.Size
            
            :If rt≠0
                ⎕SIGNAL ⊂('EN' #.Sock.SOCK_ERR)('Message' (⍕geterrno))
            :EndIf
            
            shouldClose←1
        ∇
        
        ⍝ Send some data via the socket (bytes, numeric)
        ∇{flags} Send data;r
            :Access Public
            ⍝ no flags → 0
            :If 0=⎕NC'flags' ⋄ flags←0 ⋄ :EndIf
            
            ⍝ list of flags → or them together
            flags←∨bin flags
            
            r←#.Sock.send fd data (≢data) flags
            
            :If r≠≢data
                ⎕SIGNAL ⊂('EN' #.Sock.SOCK_ERR)('Message' (⍕geterrno))                
            :EndIf
        ∇
        
        ⍝ Receive data from the socket (bytes, numeric)
        ∇data←{flags} Recv size;r
            :Access Public
            ⍝ no flags → 0
            :If 0=⎕NC'flags' ⋄ flags←0 ⋄ :EndIf
            ⍝ list of flags → or them together
            flags←∨bin flags
            
            ⍝ receive some data
            r data←#.Sock.recv fd (size/0) size flags
            
            :If r=¯1
                ⎕SIGNAL ⊂('EN' #.Sock.SOCK_ERR)('Message' (⍕geterrno))                  
            :EndIf
            data←r↑data
        ∇
        
    :EndClass
    
    :Class addrinfo :#.CInterop.Struct
        ⍝  this field is only there for alignment on 64-bit
        ⍝                                     \
        :Field Private STRUCT←'I4 I4 I4 I4 U4 U4 P P P'
        :Field Private STRUCT_32←'I4 I4 I4 I4 U4 P P P'
        
        :Field Private state ←(0  0  0  0  0   0 0 0 0)

        ∇init;struct
            :Access Public
            struct←(1+#.CInterop.Bits=32)⊃STRUCT STRUCT_32
            state↓⍨←#.CInterop.Bits=32
            :Implements Constructor :Base struct
            Write state ⍝ zero it all out
        ∇

        ∇init_mem addr;struct
            :Access Public
            struct←(1+#.CInterop.Bits=32)⊃STRUCT STRUCT_32
            state↓⍨←#.CInterop.Bits=32
            :Implements Constructor :Base (struct addr)
            state←Read ⍝ read the current state
        ∇

        :Section Fields
            :Property ai_flags
                :Access Public
                ∇r←get
                    state←Read ⋄ r←state[1]
                ∇
                ∇set v
                    state[1]←v.NewValue ⋄ Write state
                ∇
            :EndProperty

            :Property ai_family
                :Access Public
                ∇r←get
                    state←Read ⋄ r←state[2]
                ∇
                ∇set v
                    state[2]←v.NewValue ⋄ Write state
                ∇
            :EndProperty

            :Property ai_socktype
                :Access Public
                ∇r←get
                    state←Read ⋄ r←state[3]
                ∇
                ∇set v
                    state[3]←v.NewValue ⋄ Write state
                ∇
            :EndProperty

            :Property ai_protocol
                :Access Public
                ∇r←get
                    state←Read ⋄ r←state[4]
                ∇
                ∇set v
                    state[4]←v.NewValue ⋄ Write state
                ∇
            :EndProperty

            :Property ai_addrlen
                :Access Public
                ∇r←get
                    state←Read ⋄ r←state[5]
                ∇
                ∇set v
                    state[5]←v.NewValue ⋄ Write state
                ∇
            :EndProperty

            :Property ai_addr
                :Access Public
                ∇r←get
                    state←Read ⋄ r←state[7-#.CInterop.Bits=32]
                ∇
                ∇set v
                    state[7-#.CInterop.Bits=32]←v.NewValue ⋄ Write state
                ∇
            :EndProperty

            :Property ai_canonname
                :Access Public
                ∇r←get
                    state←Read ⋄ r←state[8-#.CInterop.Bits=32]
                ∇
                ∇set v
                    state[8-#.CInterop.Bits=32]←v.NewValue ⋄ Write state
                ∇
            :EndProperty

            :Property ai_next
                :Access Public
                ∇r←get
                    state←Read ⋄ r←state[9-#.CInterop.Bits=32]
                ∇
                ∇set v
                    state[9-#.CInterop.Bits=32]←v.NewValue ⋄ Write state
                ∇
            :EndProperty      
        :EndSection

    :EndClass

:EndNamespace
