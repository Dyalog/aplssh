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
        
        NI_NUMERICSERV←2

        SOCK_STREAM←1
        SOCK_DGRAM←2
        SOCK_RAW←3
        SOCK_SEQPACKET←5

        SOL_SOCKET←1
        SO_REUSEADDR←2
        
        POLLIN←1
    :EndNamespace

    init←0
    ∇ Init
        ⍝ don't initialize twice
        →init/0

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
        
        ⍝ gethostinfo
        ⎕NA'I ',socklib,'|getnameinfo P U =0C U =0C U I'
        

        init←1
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

    ∇ InitWindows;wsaversion;wsadata;r
        ⍝ on Windows, the socket functions are in Ws2_32.dll
        socklib←'Ws2_32.dll'

        ⍝ closing a socket is done using 'closesocket', but we'll rename it
        'close'⎕NA'I ',socklib,'|closesocket P'

        ⍝ geterrno is supplied (as WSAGetLastError) by the socket library
        'geterrno'⎕NA'I ',socklib,'|WSAGetLastError'

        ⍝ furthermore, we need to call WSAStartup to get the sockets to work
        ⍝ we don't really need anything from wsadata.
        ⍝ we _should_ call WSACleanup at some point as well. 

        ⎕NA'I ',socklib,'|WSAStartup U2 P'
        wsaversion←256⊥2 2 ⍝ version 2.2
        wsadata←⎕NEW #.CInterop.DataBlock (32/0) ⍝ 32 bytes is more than enough for anyone
        r←WSAStartup wsaversion wsadata.Ref
        :If r≠0
            ⎕SIGNAL ⊂('EN'SOCK_ERR)('Message' ('Winsock initialization failed: ',⍕r))
        :EndIf


        Err←UnixErrors
    ∇

    ⍝ Get host and port, given sockaddr
    ∇ (host port)←GetNameInfo addrblk;p;psz;r;host;port
        p←(psz←255)/' '
        r host port←#.Sock.getnameinfo addrblk.Ref addrblk.Size p psz p psz #.Sock.Cnst.NI_NUMERICSERV
        :If r≠0
            ⎕SIGNAL('EN'SOCK_ERR)('Message' ('getnameinfo: ',⍕r))
        :EndIf
    ∇
        
        
    
    ⍝ Get address info
    ⍝ Arguments: <family> GetAddrInfo host port 
    ∇ r←{family} GetAddrInfo args;host;port;pasv;hints;rt;ptr;ai;numf;sz;blk;sptr;canon
        host port←args[1 2]
        pasv←0
        :If 3=≢args ⋄ pasv←args[3] ⋄ :EndIf

        ⍝ if no family is given, use all
        :If 0=⎕NC'family' ⋄ family←#.Sock.Cnst.AF_UNSPEC ⋄ :EndIf

        ⍝ if the port is numeric, pass it in as a string
        :If 0=⍬⍴0⍴port ⋄ port←⍕port ⋄ :EndIf

        ⍝ if no host is given, that means passive must be on
        pasv∨←0=≢host

        hints←⎕NEW #.Sock.addrinfo
        hints.ai_family←family
        hints.ai_flags←∨bin #.Sock.Cnst.(AI_V4MAPPED AI_CANONNAME AI_ADDRCONFIG)
        hints.ai_flags←∨bin hints.ai_flags, pasv/#.Sock.Cnst.AI_PASSIVE


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

    ⍝ Wrapper around 'poll'.
    :Class Poller
        :Field Private socks←⍬
        :Field Private evts←⍬
        :Field Private revts←⍬
        
        ∇init
            :Access Public
            :Implements Constructor
        ∇
        
        ⍝ register a socket to poll for events
        ∇sevts Register sock
            :Access Public
            :If sock∊socks
                ⍝ already have it
                'Socket already registered.'⎕SIGNAL 11
                →0
            :EndIf
            socks ,← sock
            evts ,← sevts
            revts ,← 0
        ∇
        
        ⍝ deregister a socket
        ∇Unregister sock;keep
            :Access Public
            :If ~sock∊socks
                ⍝ don't have it
                'Socket not registered.'⎕SIGNAL 11
                →0
            :EndIf
            keep←socks≠sock
            socks/⍨←keep
            evts/⍨←keep
            revts/⍨←keep
        ∇
        
        ⍝ Poll, return sockets for which events have occurred
        ∇s←Poll timeout;fds;r;rstruct;rfds;r_evts;r_revts
            :Access Public
            ⍝ make polling datastructure
            fds←↓⍉↑(socks.FD) evts revts
            r rstruct←#.Sock.poll fds (≢fds) timeout
            :If r=¯1
                ⎕SIGNAL⊂('EN'#.Sock.SOCK_ERR)('Message' (⍕#.Sock.geterrno))
            :EndIf
            
            rfds r_evts r_revts←↓⍉↑rstruct
            revts←r_revts
            
            ⍝ select those sockets that had events
            s←(revts≠0)/socks
        ∇   
    :EndClass
    
    ⍝ IPV4 socket.
    :Class Socket
        :Field Private fd←¯1
        :Field Private fam
        :Field Private type
        :Field Private shouldClose←0
        :Field Private origAddr←⍬

        bin←{2⊥⍺⍺/2⊥⍣¯1⊢(⍺⍺/⍬),⍵}

        ⍝ Make an IPV4 socket
        ∇init type_
            :Access Public
            :Implements Constructor

            fam←#.Sock.Cnst.AF_INET
            type←type_

            fd←#.Sock.socket fam type 0
            :If fd=¯1
                ⎕SIGNAL ⊂('EN' #.Sock.SOCK_ERR)('Message' (⍕#.Sock.geterrno))
            :EndIf
        ∇


        ⍝ Initializer to pass a socket FD into
        ∇init_sock (addrblk fd_)
            :Access Public
            :Implements Constructor
            fd←fd_
            shouldClose←1
            origAddr←addrblk
        ∇
        
        ⍝ Return the originating host and port if this socket came from 'listen'
        ∇(host port)←ListenConnection;h;p;sin_addr
            :Access Public
            :If origAddr≡⍬
                host port←'' 0
                :Return
            :EndIf
            
            host port←#.Sock.GetNameInfo origAddr
            
        ∇

        ∇destroy
            :Access Private
            :Implements Destructor

            →(fd=¯1)/0
            →(~shouldClose)/0
            Close
        ∇

        ⍝ Set an integer socket option
        ∇setsockopt_int (level option value)
            :Access Public
            {}#.Sock.setsockopt_int fd level option value 4
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

        ⍝ Opening a connection and binding are basically the same thing, so
        ⍝ here's an operator that abstracts over everything
        ∇(fn InitSock pasv) (host port);addrs;addr;rt;blk
            ⍝ find the data for the host and port
            addrs←fam #.Sock.GetAddrInfo (host port pasv)
            ⎕SIGNAL(0=≢addrs)/⊂('EN'11)('Message' 'Address not found.')

            ⍝ find one that matches our type
            addrs←(type=2⊃¨addrs)/addrs
            ⎕SIGNAL(0=≢addrs)/⊂('EN'11)('Message' ('No connection to address found using type ',⍕type))

            ⍝ use the first one, if there is more than one left, they all must point to the same place
            addr←⊃addrs

            ⍝ the parsed address is contained in the 4th element
            blk←4⊃addr

            ⍝ either bind or connect the socket
            rt←fn fd blk.Ref blk.Size

            :If rt≠0
                ⎕SIGNAL ⊂('EN' #.Sock.SOCK_ERR)('Message' (⍕#.Sock.geterrno))
            :EndIf

            shouldClose←1           
        ∇

        ⍝ Bind a socket
        ⍝ 'Host' may be "" in order not to filter
        ∇Bind (host port)
            :Access Public
            (#.Sock.bind InitSock 1) (host port)
        ∇

        ⍝ Listen on the socket once it is bound
        ∇Listen backlog;r
            :Access Public
            r←#.Sock.listen fd backlog
            :If r=¯1
                ⎕SIGNAL ⊂('EN' #.Sock.SOCK_ERR)('Message' (⍕#.Sock.geterrno))
            :EndIf
        ∇

        ⍝ Accept a connection from the socket once it is listening
        ⍝ Will return a new socket object 
        ∇sck←Accept;addrblk;rt;sz
            :Access Public 
            addrblk←⎕NEW #.CInterop.DataBlock (256/0) ⍝ 256 bytes ought to be enough for anyone
            rt sz←#.Sock.accept fd addrblk.Ref 256
            :If rt=¯1
                ⎕SIGNAL ⊂('EN' #.Sock.SOCK_ERR)('Message' (⍕#.Sock.geterrno))
            :EndIf 

            ⍝ we're still here, so I guess we can make a new socket
            sck←⎕NEW Socket (addrblk rt)
        ∇

        ⍝ Connect it
        ∇Connect (host port)
            :Access Public
            (#.Sock.connect InitSock 0) (host port)
        ∇

        ⍝ Send some data via the socket (bytes, numeric)
        ∇r←{flags} Send data;r
            :Access Public
            ⍝ no flags → 0
            :If 0=⎕NC'flags' ⋄ flags←0 ⋄ :EndIf

            ⍝ list of flags → or them together
            flags←∨bin flags

            r←#.Sock.send fd data (≢data) flags

            :If r<0
                ⎕SIGNAL ⊂('EN' #.Sock.SOCK_ERR)('Message' (⍕#.Sock.geterrno))                
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
                ⎕SIGNAL ⊂('EN' #.Sock.SOCK_ERR)('Message' (⍕#.Sock.geterrno))                  
            :EndIf
            data←r↑data
        ∇

    :EndClass

    :Class sockaddr_in :#.CInterop.Struct
        :Field Private STRUCT←'I2 U2 U4 U8'
        :Field Private state←(0 0 0 0)
        ∇init;struct
            :Access Public
            :Implements Constructor :Base STRUCT
        ∇
        
        ∇init_mem addr;struct
            :Access Public
            :Implements Constructor :Base (STRUCT addr)
        ∇
        
        :Section Fields
            :Property sin_family
                ∇r←get
                    state←Read ⋄ r←state[1]
                ∇
                ∇set v
                    state[1]←v.NewValue ⋄ Write state
                ∇
            :EndProperty
            :Property sin_port
                ∇r←get
                    state←Read ⋄ r←state[2]
                ∇
                ∇set v
                    state[2]←v.NewValue ⋄ Write state
                ∇
            :EndProperty
            :Property sin_addr
                ∇r←get
                    state←Read ⋄ r←state[3]
                ∇
                ∇set v
                    state[3]←v.NewValue ⋄ Write state
                ∇
            :EndProperty
        :EndSection
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
