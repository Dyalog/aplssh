⍝∇:require =/CInterop.dyalog
⍝∇:require =/SSH_C_Helpers.dyalog
⍝∇:require =/Sock.dyalog

:Namespace SSH
    ⍝ APL bindings for the libssh2 library

    SSH_ERR←801 ⍝ signaled when there's something wrong with the SSH library

    ⍝ convert binary functions to bitwise ones
    bin←{2⊥⍺⍺/2⊥⍣¯1⊢(⍺⍺/⍬),⍵}
 
    ∇ r←ScriptPath
        ⍝ Adám's SourceFile function
        r←{ ⍝ Get pathname to sourcefile for item ⍵
            c←⎕NC⊂,⍕⍵
            c=2.1:(SALT_Var_Data.VD[;1]⍳⊂⍵(⊢,~)'#.')⊃SALT_Var_Data.VD[;2],⊂''
            c∊3.1 3.2 4.1 4.2:1↓⊃('§'∘=⊂⊢)∊¯2↑⎕NR ⍵
            (r←326=⎕DR ⍵)∨c∊9+0.1×⍳8:{6::'' ⋄ ''≡f←⊃(4∘⊃¨(/⍨)(⍵≡⊃)¨)5177⌶⍬:⍵.SALT_Data.SourceFile ⋄ f}⍎⍣(~r)⊢⍵
            ''
        }⎕THIS
    ∇

    ⍝ base64 encode/decode
    base64enc←{
        vals←⎕A,819⌶⎕A,⎕D,'+/'
        bits←,⍉(8/2)⊤,⍵
        base64←2⊥⍉↑(⎕IO=6|⍳⍴bits)⊂bits
        vals[⎕IO+base64],((××4-⊢)4|⍴base64)/'='
    }

    base64dec←{
        vals←⎕A,819⌶⎕A,⎕D,'+/'
        bits←,⍉(6/2)⊤(vals⍳⍵~'=')-⎕IO
        bits←(⊢↑⍨⍴-8|⍴)bits
        2⊥⍉↑(⎕IO=8|⍳⍴bits)⊂bits
    }

    init←0
    ∇ Init;r
        →init/0 ⍝ don't initialize twice

        ⍝ Make sure the C helper is initialized
        #.SSH_C_Helpers.Init

        ⍝ Make sure the socket library is initialized
        #.Sock.Init

        ⍝ load the library functions
        C.LoadLib

        ⍝ run the libssh2 initialization
        r←C.libssh2_init 0

        ⍝ signal an error if it did not work
        ⎕SIGNAL(r≠0)⊂('EN'SSH_ERR)('Message' (⍕r))

        init←1 
    ∇

    ⍝ An SSH session
    :Class Session
        :Field Private Shared S ⍝ shorthand for the namespace
        :Field Private Shared C ⍝ shorthand for all the C functions
        :Field Private session←0
        :Field Private socket←⍬ ⍝ socket associated with the session, if there is one

        ⍝ Fill in arguments with default values.
        defaults←{
            (≢⍺)↑⍵,(≢⍵)↓⍺
        }

        ⍝ Make an error message
        ∇r←EMSG
            r←⍕LastError
        ∇

        ∇r←Ref
            :Access Public
            r←session
        ∇

        ∇destroy
            :Implements Destructor
            →(session=0)/0
            Disconnect S.SSH_DISCONNECT_BY_APPLICATION 'Session destructor called'
        ∇

        ∇Disconnect args;reas;desc;lang;localsess
            :Access Public
            →(session=0)/0
            reas desc lang←(S.SSH_DISCONNECT_BY_APPLICATION '' '')defaults args
            localsess←session
            session←0
            {}C.libssh2_session_disconnect_ex localsess reas desc lang
            {}C.libssh2_session_free localsess
        ∇

        ⍝ common initialization routine
        ∇_init_common
            ⍝ put the namespaces in the shorthand fields
            S ← #.SSH
            C ← #.SSH.C

            ⍝ is the SSH lib initialized yet?
            :If ~#.SSH.init ⋄ #.SSH.Init ⋄ :EndIf

            ⍝ make a session
            ⍝ we don't do callbacks into APL, because APL doesn't do callbacks into APL...
            session←C.libssh2_session_init_ex 0 0 0 0
            ⎕SIGNAL(session=0)/⊂('EN'S.SSH_ERR)('Message' EMSG)
        ∇

        ⍝ Initialize the session
        ∇init
            :Implements Constructor
            :Access Public
            _init_common
        ∇

        ⍝ Utility initializer, which does socket creation, connection, and handshake
        ⍝ all at once (if you don't need anything special)
        ∇init_connect (host port);sock;addr;fam
            :Implements Constructor
            :Access Public
            _init_common ⍝ initialization

            ⍝ find whether to use IPV6 or IPV4
            addr←#.Sock.GetAddrInfo (host (⍕port))

            :If 0=≢addr
                ⍝ None found
                ⎕SIGNAL⊂('EN'6)('Message' 'No such host.')
            :EndIf

            ⍝ find family of first type of addr (= what to use)
            fam←⊃⊃addr

            sock←⎕NEW #.Sock.Socket (#.Sock.Cnst.SOCK_STREAM fam 0)

            sock.Connect (host port)
            Handshake sock
        ∇

        ⍝ Handshake. 'sock' should be a socket object
        ∇Handshake sock;r
            :Access Public
            r←C.libssh2_session_handshake session sock.FD
            ⎕SIGNAL(r≠0)/⊂('EN'S.SSH_ERR)('Message' EMSG)
            socket←sock
        ∇

        ⍝ Get the current host key
        ∇(key type)←Hostkey;len;p;blk
            :Access Public
            p len type←C.libssh2_session_hostkey session 0 0
            ⎕SIGNAL(p=0)/⊂('EN'S.SSH_ERR)('Message' EMSG)
            ⍝ I'm assuming "len" is given for a reason, so let's make sure not to read past it
            blk←⎕NEW #.CInterop.DataBlock (len/0)
            blk.Load p len
            ⍝ Return the key base64-encoded
            key←S.base64enc blk.Data
        ∇

        ⍝ Get the hostkey hash, as a byte vector
        ⍝ Type may be 'MD5' or 'SHA1' (or, of course, LIBSSH2_HOSTKEY_HASH_...)
        ∇hash←HostkeyHash type;blk;sz;ptr
            :Access Public
            sz←0

            ⍝ support string input
            :If     'md5'≡819⌶type  ⋄ type←S.HOSTKEY_HASH_MD5 
            :ElseIf 'sha1'≡819⌶type ⋄ type←S.HOSTKEY_HASH_SHA1 
            :EndIf

            ⍝ get the size (as defined in the documentation)
            :If type≡S.HOSTKEY_HASH_MD5  ⋄ sz←16 ⋄ :EndIf
            :If type≡S.HOSTKEY_HASH_SHA1 ⋄ sz←20 ⋄ :EndIf

            ⍝ if the size is still unknown, then the hash type was invalid
            ⎕SIGNAL(sz=0)/⊂('EN'11)('Message' ('Invalid hash type: ',∊⍕type))

            ⍝ ask for the hash type
            ptr←C.libssh2_hostkey_hash session type
            ⎕SIGNAL(ptr=0)/⊂('EN'S.SSH_ERR)('Message' EMSG)

            ⍝ reserve some memory to store the hash type
            blk←⎕NEW #.CInterop.DataBlock (sz/0)
            blk.Load ptr sz
            hash←blk.Data
        ∇

        ⍝ Get a list of supported authentication methods.
        ⍝ libssh2 returns this as a comma-delineated string, this being APL
        ⍝ we can return a string vector instead.
        ⍝ Internally, this works by trying to authenticate with SSH_USERAUTH_NONE,
        ⍝ might you find a server that supports this, we won't get a list back.
        ⍝
        ⍝ This function will check if that authentication succeeded, and will then
        ⍝ return the empty vector. If the lack of result was due to an error, an error
        ⍝ will be signaled.
        ∇list←UserauthList username;ptr;str
            :Access Public

            ptr←C.libssh2_userauth_list session username (≢username)

            :If ptr=0
                ⍝ did the "authentication" succeed?
                :If Authenticated
                    ⍝ such security
                    list←⍬
                :Else
                    ⍝ this really is an error
                    ⎕SIGNAL⊂('EN'S.SSH_ERR)('Message' EMSG)
                :EndIf
            :Else
                ⍝ we have a pointer to a comma-delimited string
                str←#.CInterop.ReadCStr ptr
                list←(str≠',')⊆str
            :EndIf
        ∇

        ⍝Try to authenticate by password
        ∇Userauth_Password (name password);r
            :Access Public
            r←C.libssh2_userauth_password_ex session name (≢name) password (≢password) 0
            ⎕SIGNAL (r≠0)/⊂('EN'S.SSH_ERR)('Message' EMSG)
        ∇

        ⍝ Try to authenticate by public key
        ∇Userauth_Publickey (name pubkey privkey pass);r;pkblk;pkptr
            :Access Public

            ⍝ 'pubkey' may be zero, and must therefore be passed in as a pointer
            pkptr←0
            :If 0≠≢pubkey
                ⍝ a public key is given, so we need to turn it into a C string
                pkblk←⎕NEW #.CInterop.DataBlock pubkey
                pkptr←pkblk.Ref
            :EndIf

            r←C.libssh2_userauth_publickey_fromfile_ex session name (≢name) pkptr privkey pass
            ⎕SIGNAL (r≠0)/⊂('EN'S.SSH_ERR)('Message' EMSG)
        ∇              

        ⍝ Return the last error, as a string.
        ∇(num msg)←LastError;msgp;msgl
            :Access Public
            num msgp msgl←C.libssh2_session_last_error session 0 0 0
            msg←#.CInterop.ReadCStr msgp
        ∇

        ⍝ See if this session is authenticated. Returns a boolean.
        ∇r←Authenticated
            :Access Public
            r←C.libssh2_userauth_authenticated session
        ∇

        ∇r←GetBlocking
            :Access Public
            r←C.libssh2_session_get_blocking session
        ∇

        ∇SetBlocking b
            :Access Public
            {}C.libssh2_session_set_blocking session b
        ∇

        ⍝ Make a new session channel
        ∇ch←Channel_Open_Session;lch
            :Access Public
            lch←⎕NEW S.⍙Channel ⎕THIS
            lch._start_open_session
            ch←lch
        ∇

        ⍝ Make a new channel 
        ∇ch←Channel_Direct_TCPIP (desthost destport shost sport);lch
            :Access Public
            lch←⎕NEW S.⍙Channel ⎕THIS
            lch._start_Direct_TCPIP (desthost destport shost sport)
            ch←lch
        ∇

        ⍝ Start an SCP transfer
        ∇(ch stat)←SCP_Recv path;lch;sb
            :Access Public
            lch←⎕NEW S.⍙Channel ⎕THIS
            sb←lch._start_scp_recv path
            stat←#.SSH_C_Helpers.stat sb
            ch←lch
        ∇

        ⍝ Start an SCP upload
        ∇ch←SCP_Send args;path;mode;size;mtime;atime;lch
            :Access Public
            'Path, mode, size are mandatory.'⎕SIGNAL(3>≢args)/6
            path mode size←args[⍳3]
            mtime atime←3↓5↑args,0,0
            lch←⎕NEW S.⍙Channel ⎕THIS
            lch._start_scp_send (path mode size mtime atime)
            ch←lch
        ∇

        :Section Convenience
            ⍝ Read a file over SCP, in one go.
            ∇(stat data)←ReadFile path;chan;size;amt;agn;d
                :Access Public
                :If ~Authenticated ⋄ 'Not authenticated' ⎕SIGNAL 11 ⋄ :EndIf

                chan stat←SCP_Recv path
                data←⍬
                size←⊃stat
                :While 0<amt←size-≢data
                    ⍝ If the channel is non-blocking we might need to do this several times.
                    agn d←chan.Read amt
                    :If agn ⋄ :Continue ⋄ :EndIf
                    data,←d
                :EndWhile
            ∇

            ⍝ Write data into an SCP file, in one go.
            ⍝ Right arg: path and data
            ⍝ Optional left arg: mode, mtime, atime
            ∇{opts} WriteFile (path data);mode;size;mtime;atime;chan;agn;wr
                :Access Public
                :If ~Authenticated ⋄ 'Not authenticated' ⎕SIGNAL 11 ⋄ :EndIf

                :If 0=⎕NC'opts' ⋄ opts←⍬ ⋄ :EndIf

                mode mtime atime←((8⊥6 4 4)0 0)defaults opts
                size←≢data

                ⍝ send the file
                chan←SCP_Send (path mode (≢data) mtime atime)
                :While 0<≢data
                    agn wr←chan.Write data
                    :If agn ⋄ :Continue ⋄ :EndIf
                    data↓⍨←wr
                :EndWhile

                ⍝ send an EOF and wait for the other side to acknowledge it
                chan.SendEOF
                chan.WaitEOF
                chan.WaitClosed
            ∇

            ⍝ Run a command, wait for it to finish.
            ∇{rslt}←Exec cmd;chan;stdout;agn;status
                :Access Public
                :If ~Authenticated ⋄ 'Not authenticated' ⎕SIGNAL 11 ⋄ :EndIf

                ⍝ start a new channel to run our command on
                chan←Channel_Open_Session
                chan.Exec cmd

                ⍝ blocking read
                stdout←chan.ReadAll

                ⍝ we should now be done, so close the channel and retrieve the exit status
                :Repeat
                    agn←chan.Close
                :Until ~agn

                status←chan.ExitStatus

                rslt←status stdout
            ∇
        :EndSection

    :EndClass

    ⍝ these are instantiated by the Session class
    :Class ⍙Channel
        :Field Private ptr←0
        :Field Private S
        :Field Private C
        :Field Private session

        :Section Convenience
            ⍝ read the whole channel, up to the end
            ∇data←ReadAll;agn;d;BLOCKSZ
                :Access Public
                BLOCKSZ←8192

                data←⍬

                :Repeat
                    agn d←Read BLOCKSZ
                    :If agn ⋄ :Continue ⋄ :EndIf
                    data,←d
                :Until 0=≢d
            ∇

        :EndSection

        ⍝ Make an error message to throw
        ∇r←EMSG
            r←⍕session.LastError
        ∇

        ∇r←Ref
            :Access Public
            r←ptr
        ∇

        ∇init sess
            :Access Public
            :Implements Constructor

            S←#.SSH
            C←#.SSH.C
            session←sess
        ∇

        ⍝ Execute a command on this channel
        ∇{agn}←Exec cmdline;r
            :Access Public
            Check
            agn←0
            r←C.libssh2_channel_process_startup ptr 'exec' 4 cmdline (≢cmdline)

            :If r<0
                :If r=S.ERROR_EAGAIN
                    agn←1
                :Else
                    ⎕SIGNAL⊂('EN'S.SSH_ERR)('Message' EMSG)
                :EndIf
            :EndIf 
        ∇

        ⍝ get the exit status
        ∇status←ExitStatus
            :Access Public
            Check

            status←C.libssh2_channel_get_exit_status ptr
        ∇

        ⍝ channel_open_session
        ∇_start_open_session 
            :Access Public

            ptr←C.libssh2_channel_open_ex session.Ref 'session' 7 S.CHANNEL_WINDOW_DEFAULT S.CHANNEL_PACKET_DEFAULT '' 0

            :If ptr=0
                'Cannot initialize channel' ⎕SIGNAL S.SSH_ERR
            :EndIf
        ∇

        ⍝ start a direct TCPIP channel
        ∇_start_Direct_TCPIP (desthost destport shost sport)
            :Access Public

            ptr←C.libssh2_channel_direct_tcpip_ex session.Ref desthost destport shost sport
            :If ptr=0
                'Cannot initialize channel' ⎕SIGNAL S.SSH_ERR
            :EndIf
        ∇

        ⍝ start a channel to receive a file via SCP
        ∇statblk←_start_scp_recv path
            :Access Public
            statblk←⎕NEW #.CInterop.DataBlock (256/0)
            ptr←C.libssh2_scp_recv2 session.Ref path statblk.Ref
            :If ptr=0
                'Cannot initialize channel' ⎕SIGNAL S.SSH_ERR
            :EndIf
        ∇

        ⍝ start a channel to send a file via SCP
        ∇_start_scp_send (path mode size mtime atime)
            :Access Public
            ptr←C.libssh2_scp_send64 session.Ref path mode size mtime atime
            :If ptr=0
                'Cannot initialize channel' ⎕SIGNAL S.SSH_ERR
            :EndIf
        ∇

        ∇destroy
            :Access Private
            :Implements Destructor
            Free
        ∇

        ∇Free;localptr
            :Access Public
            →(ptr=0)/0
            localptr←ptr
            ptr←0
            {}C.libssh2_channel_free ptr
        ∇

        ⍝ Close the channel
        ∇{agn}←Close;r
            :Access Public

            agn←0
            r←C.libssh2_channel_close ptr
            :If r=S.ERROR_EAGAIN
                agn←1
            :ElseIf r<0
                ⎕SIGNAL ⊂('EN'S.SSH_ERR)('Message' EMSG)
            :EndIf
        ∇

        ⍝ this is ugly, but I can't guarantee it's initialized otherwise
        ⍝ (no abstract classes apparently)
        ∇Check
            ⎕SIGNAL(ptr=0)/⊂('EN'16)('Message' 'Channel not initialized.')
        ∇

        ⍝ ERROR_EAGAIN sets 'again', anything else is considered an error
        ∇(again r)←{stream} Write data;rr
            :Access Public
            Check
            :If 0=⎕NC'stream' ⋄ stream←0 ⋄ :EndIf
            rr←C.libssh2_channel_write_ex ptr stream data (≢data)
            :If (rr<0)∧rr≠S.ERROR_EAGAIN
                ⎕SIGNAL⊂('EN'S.SSH_ERR)('Message' EMSG)
            :EndIf
            (again r)←(rr=S.ERROR_EAGAIN) rr
        ∇

        ∇(again data)←{stream} Read len;rr;d
            :Access Public
            Check
            :If 0=⎕NC'stream' ⋄ stream←0 ⋄ :EndIf
            rr d←C.libssh2_channel_read_ex ptr stream (len/0) len
            :If (rr<0)∧rr≠S.ERROR_EAGAIN
                ⎕SIGNAL⊂('EN'S.SSH_ERR)('Message' EMSG)
            :EndIf
            (again data)←(rr=S.ERROR_EAGAIN)((0⌈rr)↑d)
        ∇

        ⍝ See if the channel is out of data
        ∇r←EOF
            :Access Public
            Check
            r←C.libssh2_channel_eof ptr
            ⎕SIGNAL(r<0)/⊂('EN'S.SSH_ERR)('Message' EMSG)
        ∇

        ⍝ Send EOF. 
        ∇{agn}←SendEOF;r
            :Access Public
            Check
            agn←0
            r←C.libssh2_channel_send_eof ptr
            :If r<0
                :If r=S.ERROR_EAGAIN
                    agn←1
                :Else
                    ⎕SIGNAL⊂('EN'S.SSH_ERR)('Message' EMSG)
                :EndIf
            :EndIf
        ∇

        ⍝ Wait for EOF.
        ∇{agn}←WaitEOF;r
            :Access Public
            Check
            agn←0
            r←C.libssh2_channel_wait_eof ptr
            :If r<0
                :If r=S.ERROR_EAGAIN
                    agn←1
                :Else
                    ⎕SIGNAL⊂('EN'S.SSH_ERR)('Message' EMSG)
                :EndIf
            :EndIf
        ∇

        ⍝ Wait for the remote side to close the channel
        ∇{agn}←WaitClosed;r
            :Access Public
            Check
            agn←0
            r←C.libssh2_channel_wait_closed ptr
            :If r<0
                :If r=S.ERROR_EAGAIN
                    agn←1
                :Else
                    ⎕SIGNAL⊂('EN'S.SSH_ERR)('Message' EMSG)
                :EndIf
            :EndIf
        ∇


    :EndClass

    ⍝ read and write a known hosts file
    :Class KnownHosts
        :Field Private session
        :Field Private S
        :Field Private C

        :Field Private ptr

        ⍝ Make an error message to throw
        ∇r←EMSG
            r←⍕session.LastError
        ∇

        ⍝ initialize 
        ∇init sess
            :Access Public
            :Implements Constructor
            session←sess

            ⍝ shortcuts
            S←#.SSH
            C←#.SSH.C

            ptr←C.libssh2_knownhost_init session.Ref
            ⎕SIGNAL(ptr=0)/⊂('EN'S.SSH_ERR)('Message' EMSG)
        ∇

        ⍝ free
        ∇destroy;localptr
            :Access Private
            :Implements Destructor
            localptr←ptr
            ptr←0
            {}C.libssh2_knownhost_free localptr
        ∇

        ⍝ load entries from a file
        ⍝ shy result is amount of entries read 
        ∇{n}←ReadFile filename
            :Access Public
            ⍝ type is 1 (LIBSSH2_KNOWNHOST_FILE_OPENSSH), the only supported format

            n←C.libssh2_knownhost_readfile ptr filename 1
            ⎕SIGNAL(n<0)/⊂('EN'S.SSH_ERR)('Message' EMSG)
        ∇

        ⍝ write entries to a file
        ∇WriteFile filename;r
            :Access Public
            ⍝ type is 1 (LIBSSH2_KNOWNHOST_FILE_OPENSSH), the only supported format
            r←C.libssh2_knownhost_writefile ptr filename 1
            ⎕SIGNAL(r<0)/⊂('EN'S.SSH_ERR)('Message' EMSG)
        ∇

        ⍝ check if a host+key is in the collection
        ∇(ok status)←Check (host key typemask);r
            :Access Public
            typemask←S.bin∨typemask
            status←C.libssh2_knownhost_check ptr host key (≢key) typemask 0
            ok←status=0
        ∇

        ⍝ add a host to the store
        ∇Add (host salt key comment typemask);r
            :Access Public
            typemask←S.bin∨typemask
            r←C.libssh2_knownhost_addc ptr host salt key (≢key) comment (≢comment) typemask 0
            ⎕SIGNAL(r<0)/⊂('EN'S.SSH_ERR)('Message' EMSG)
        ∇


        ⍝ retrieve all known hosts
        ∇hosts←Hosts;r;prev;blk
            :Access Public
            hosts←⍬

            prev←0
            r←0
            :Repeat
                r prev←C.libssh2_knownhost_get ptr 0 prev
                :If r<0 ⋄ ⎕SIGNAL⊂('EN'S.SSH_ERR)('Message' EMSG) ⋄ :EndIf
                :If r=1 ⋄ :Leave ⋄ :EndIf
                hosts,←⊂#.SSH_C_Helpers.knownhost prev
            :EndRepeat
        ∇

        ⍝ delete a host with a given key
        ∇Delete delkey;r;prev;key
            :Access Public
            r←0
            prev←0
            :Repeat
                r prev←C.libssh2_knownhost_get ptr 0 prev
                :If r<0 ⋄ ⎕SIGNAL⊂('EN'S.SSH_ERR)('Message' EMSG) ⋄ :EndIf
                :If r=1 ⋄ :Leave ⋄ :EndIf
                key←4⊃#.SSH_C_Helpers.knownhost prev
                :If key≡delkey
                    ⍝ delete this one
                    r←C.libssh2_knownhost_del ptr prev
                    ⎕SIGNAL(r<0)/⊂('EN'S.SSH_ERR)('Message' EMSG)
                    :Leave
                :EndIf
            :EndRepeat
        ∇
    :EndClass

    :Section Constants
        ⍝ The constants are named as in the C include files, but without the LIBSSH2_ prefix.

        HOSTKEY_HASH_MD5  ← 1
        HOSTKEY_HASH_SHA1 ← 2

        KNOWNHOST_TYPE_PLAIN  ← 1
        KNOWNHOST_TYPE_SHA1   ← 2
        KNOWNHOST_TYPE_CUSTOM ← 3

        KNOWNHOST_KEYENC_RAW    ← 0 65535⊥1
        KNOWNHOST_KEYENC_BASE64 ← 0 65535⊥2

        KNOWNHOST_CHECK_MATCH    ← 0
        KNOWNHOST_CHECK_MISMATCH ← 1
        KNOWNHOST_CHECK_NOTFOUND ← 2
        KNOWNHOST_CHECK_FAILURE  ← 3

        ERROR_SOCKET_NONE            ← ¯1
        ERROR_BANNER_RECV            ← ¯2
        ERROR_BANNER_SEND            ← ¯3
        ERROR_INVALID_MAC            ← ¯4
        ERROR_KEX_FAILURE            ← ¯5
        ERROR_ALLOC                  ← ¯6
        ERROR_SOCKET_SEND            ← ¯7
        ERROR_KEY_EXCHANGE_FAILURE   ← ¯8
        ERROR_TIMEOUT                ← ¯9
        ERROR_HOSTKEY_INIT           ← ¯10
        ERROR_HOSTKEY_SIGN           ← ¯11
        ERROR_DECRYPT                ← ¯12
        ERROR_SOCKET_DISCONNECT      ← ¯13
        ERROR_PROTO                  ← ¯14
        ERROR_PASSWORD_EXPIRED       ← ¯15
        ERROR_FILE                   ← ¯16
        ERROR_METHOD_NONE            ← ¯17
        ERROR_AUTHENTICATION_FAILED  ← ¯18
        ERROR_PUBLICKEY_UNRECOGNIZED ← ¯18 ⍝ yes this is correct
        ERROR_PUBLICKEY_UNVERIFIED   ← ¯19 
        ERROR_CHANNEL_OUTOFORDER     ← ¯20
        ERROR_CHANNEL_FAILURE        ← ¯21
        ERROR_CHANNEL_REQUEST_DENIED ← ¯22
        ERROR_CHANNEL_UNKNOWN        ← ¯23
        ERROR_CHANNEL_WINDOW_EXCEEDED← ¯24
        ERROR_CHANNEL_PACKET_EXCEEDED← ¯25
        ERROR_CHANNEL_CLOSED         ← ¯26
        ERROR_CHANNEL_EOF_SENT       ← ¯27
        ERROR_SCP_PROTOCOL           ← ¯28
        ERROR_ZLIB                   ← ¯29
        ERROR_SOCKET_TIMEOUT         ← ¯30
        ERROR_SFTP_PROTOCOL          ← ¯31
        ERROR_REQUEST_DENIED         ← ¯32
        ERROR_METHOD_NOT_SUPPORTED   ← ¯33
        ERROR_INVAL                  ← ¯34
        ERROR_INVALID_POLL_TYPE      ← ¯35
        ERROR_PUBLICKEY_PROTOCOL     ← ¯36
        ERROR_EAGAIN                 ← ¯37
        ERROR_BUFFER_TOO_SMALL       ← ¯38
        ERROR_BAD_USE                ← ¯39
        ERROR_COMPRESS               ← ¯40
        ERROR_OUT_OF_BOUNDARY        ← ¯41
        ERROR_AGENT_PROTOCOL         ← ¯42 
        ERROR_SOCKET_RECV            ← ¯43
        ERROR_ENCRYPT                ← ¯44
        ERROR_BAD_SOCKET             ← ¯45
        ERROR_KNOWN_HOSTS            ← ¯46


        SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT   ← 1
        SSH_DISCONNECT_PROTOCOL_ERROR                ← 2
        SSH_DISCONNECT_KEY_EXCHANGE_FAILED           ← 3
        SSH_DISCONNECT_RESERVED                      ← 4
        SSH_DISCONNECT_MAC_ERROR                     ← 5
        SSH_DISCONNECT_COMPRESSION_ERROR             ← 6
        SSH_DISCONNECT_SERVICE_NOT_AVAILABLE         ← 7
        SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED← 8
        SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE       ← 9
        SSH_DISCONNECT_CONNECTION_LOST               ← 10
        SSH_DISCONNECT_BY_APPLICATION                ← 11
        SSH_DISCONNECT_TOO_MANY_CONNECTIONS          ← 12
        SSH_DISCONNECT_AUTH_CANCELLED_BY_USER        ← 13
        SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE← 14
        SSH_DISCONNECT_ILLEGAL_USER_NAME             ← 15


        CHANNEL_WINDOW_DEFAULT ← 2*21
        CHANNEL_PACKET_DEFAULT ← 32768

    :EndSection
    ⍝ Low-level C functions
    :Namespace C
        ∇ l←lib;isOS

            ⍝ Return the right library for our OS
            isOS←{⍵≡(≢⍵)↑⊃#.⎕WG'APLVersion'}

            :If isOS'Windows'
                l←'libssh2.dll'
            :ElseIf isOS'Linux'
            :OrIf isOS'Mac'
                l←'libssh2.so'
            :EndIf
        ∇


        ⍝ load the library functions
        ∇ LoadLib;l
            l←lib    
            :Trap 102 ⍝ if it's not on the path, try script directory        
                ⎕NA'P  ',l,'|libssh2_version                         I'
            :Else
                l,⍨←{(~∨\'SSH.dyalog'⍷⍵)/⍵}#.SSH.ScriptPath 
            :EndTrap

            ⎕NA'I  ',l,'|libssh2_agent_connect&                  P'
            ⎕NA'I  ',l,'|libssh2_agent_disconnect&               P'
            ⎕NA'I  ',l,'|libssh2_agent_free                      P'
            ⎕NA'I  ',l,'|libssh2_agent_get_identity              P P P'
            ⎕NA'P  ',l,'|libssh2_agent_init                      P'
            ⎕NA'I  ',l,'|libssh2_agent_list_identities           P'
            ⎕NA'I  ',l,'|libssh2_agent_userauth                  P <0C P'
            ⎕NA'I  ',l,'|libssh2_channel_close                   P'
            ⎕NA'P  ',l,'|libssh2_channel_direct_tcpip_ex&        P <0C I <0C I'
            ⎕NA'I  ',l,'|libssh2_channel_eof                     P'
            ⎕NA'I  ',l,'|libssh2_channel_flush_ex&               P I'
            ⎕NA'P  ',l,'|libssh2_channel_forward_accept&         P'
            ⎕NA'I  ',l,'|libssh2_channel_forward_cancel&         P'
            ⎕NA'P  ',l,'|libssh2_channel_forward_listen_ex&      P <0C I >I I'
            ⎕NA'I  ',l,'|libssh2_channel_free&                   P'
            ⎕NA'I  ',l,'|libssh2_channel_get_exit_signal         P >P >P >P >P >P >P'
            ⎕NA'I  ',l,'|libssh2_channel_get_exit_status         P'
            ⎕NA'I  ',l,'|libssh2_channel_handle_extended_data2   P I'
            ⎕NA'P  ',l,'|libssh2_channel_open_ex&                P <0C U U U <0C U'
            ⎕NA'I  ',l,'|libssh2_channel_process_startup&        P <0C U <0C U'
            ⎕NA'I  ',l,'|libssh2_channel_read_ex&                P I =U1[] P'
            ⎕NA'I  ',l,'|libssh2_channel_receive_window_adjust2& P U8 U1 >U'
            ⎕NA'I  ',l,'|libssh2_channel_request_pty_ex&         P <0C U <0C U I I I I'
            ⎕NA'I  ',l,'|libssh2_channel_send_eof&               P'
            ⎕NA'   ',l,'|libssh2_channel_set_blocking&           P I'
            ⎕NA'I  ',l,'|libssh2_channel_setenv_ex&              P <0C U <0C U'
            ⎕NA'I  ',l,'|libssh2_channel_wait_closed&            P'
            ⎕NA'I  ',l,'|libssh2_channel_wait_eof&               P'
            ⎕NA'U8 ',l,'|libssh2_channel_window_read_ex&         P >U8 >U8'
            ⎕NA'U8 ',l,'|libssh2_channel_window_write_ex&        P >U8'
            ⎕NA'I  ',l,'|libssh2_channel_write_ex&               P I <U1[] P'
            ⎕NA'   ',l,'|libssh2_exit'
            ⎕NA'   ',l,'|libssh2_free                            P P'
            ⎕NA'P  ',l,'|libssh2_hostkey_hash                    P I'
            ⎕NA'I  ',l,'|libssh2_init                            I'
            ⎕NA'   ',l,'|libssh2_keepalive_config                P I U'
            ⎕NA'   ',l,'|libssh2_keepalive_send                  P >I'
            ⎕NA'I  ',l,'|libssh2_knownhost_addc                  P <0C <0C <0C P <0C P I P'
            ⎕NA'I  ',l,'|libssh2_knownhost_check                 P <0C <0C P I P'
            ⎕NA'I  ',l,'|libssh2_knownhost_del                   P P'
            ⎕NA'   ',l,'|libssh2_knownhost_free                  P'
            ⎕NA'I  ',l,'|libssh2_knownhost_get                   P >P P'
            ⎕NA'I  ',l,'|libssh2_knownhost_init                  P'
            ⎕NA'I  ',l,'|libssh2_knownhost_readfile              P <0C I'
            ⎕NA'I  ',l,'|libssh2_knownhost_readline              P <0C P I'
            ⎕NA'I  ',l,'|libssh2_knownhost_writefile             P <0C I'
            ⎕NA'I  ',l,'|libssh2_knownhost_writeline             P P =U1[] P >P I'
            ⎕NA'I  ',l,'|libssh2_poll                            ={U1 P U8 U8}[] U U8'
            ⎕NA'I  ',l,'|libssh2_publickey_add_ex                P <0C U8 <U1[] U8 I1 U8 <{P U8 P U8 I1}[]'

            ⎕NA'P  ',l,'|libssh2_scp_recv2&                      P <0C P'
            ⎕NA'P  ',l,'|libssh2_scp_send64&                     P <0C I U8 P P'
            ⎕NA'P  ',l,'|libssh2_session_abstract                P'

            ⎕NA'P  ',l,'|libssh2_session_banner_get              P'
            ⎕NA'I  ',l,'|libssh2_session_banner_set              P <0C'
            ⎕NA'I  ',l,'|libssh2_session_block_directions        P'
            ⎕NA'I  ',l,'|libssh2_session_disconnect_ex&          P I <0C <0C'
            ⎕NA'I  ',l,'|libssh2_session_flag                    P I I'
            ⎕NA'I  ',l,'|libssh2_session_free                    P'
            ⎕NA'I  ',l,'|libssh2_session_get_blocking            P'
            ⎕NA'U8 ',l,'|libssh2_session_get_timeout             P'
            ⎕NA'I  ',l,'|libssh2_session_handshake&              P I'
            ⎕NA'P  ',l,'|libssh2_session_hostkey                 P >P >I'
            ⎕NA'P  ',l,'|libssh2_session_init_ex                 P P P P'
            ⎕NA'I  ',l,'|libssh2_session_last_errno              P'
            ⎕NA'I  ',l,'|libssh2_session_last_error              P >P >I I'
            ⎕NA'I  ',l,'|libssh2_session_method_pref             P I <0C'
            ⎕NA'P  ',l,'|libssh2_session_methods                 P I'
            ⎕NA'   ',l,'|libssh2_session_set_blocking            P I'
            ⎕NA'I  ',l,'|libssh2_session_set_last_error          P I <0C'
            ⎕NA'   ',l,'|libssh2_session_set_timeout             P I8'
            ⎕NA'I  ',l,'|libssh2_session_supported_algs          P I >P'

            ⎕NA'I  ',l,'|libssh2_sftp_close_handle               P'
            ⎕NA'I  ',l,'|libssh2_sftp_fstat_ex                   P P I'
            ⎕NA'I  ',l,'|libssh2_sftp_fstatvfs                   P       >{U8 U8 U8 U8 U8 U8 U8 U8 U8 U8 U8}'
            ⎕NA'I  ',l,'|libssh2_sftp_fsync                      P'
            ⎕NA'I  ',l,'|libssh2_sftp_init                       P'
            ⎕NA'U8 ',l,'|libssh2_sftp_last_error                 P'
            ⎕NA'I  ',l,'|libssh2_sftp_mkdir_ex                   P <0C U U8'
            ⎕NA'P  ',l,'|libssh2_sftp_open_ex                    P <0C U U8 I8 I'
            ⎕NA'I  ',l,'|libssh2_sftp_read&                      P =U1[] P'
            ⎕NA'I  ',l,'|libssh2_sftp_readdir_ex                 P =U1[] P =U1[] P >{U8 U8 U8 U8 U8 U8 U8}'
            ⎕NA'I  ',l,'|libssh2_sftp_rename_ex                  P <0C U <0C U U8'
            ⎕NA'I  ',l,'|libssh2_sftp_rmdir_ex                   P <0C U'
            ⎕NA'   ',l,'|libssh2_sftp_seek64                     P U8'
            ⎕NA'I  ',l,'|libssh2_sftp_shutdown                   P'
            ⎕NA'I  ',l,'|libssh2_sftp_stat_ex                    P <0C U I >{U8 U8 U8 U8 U8 U8 U8}'
            ⎕NA'I  ',l,'|libssh2_sftp_statvfs                    P <0C P >{U8 U8 U8 U8 U8 U8 U8 U8 U8 U8 U8}'
            ⎕NA'I  ',l,'|libssh2_sftp_symlink_ex                 P <0C U <0C U I'
            ⎕NA'U8 ',l,'|libssh2_sftp_tell64                     P'
            ⎕NA'I  ',l,'|libssh2_sftp_unlink_ex                  P <0C U'
            ⎕NA'I  ',l,'|libssh2_sftp_write&                     P <0C P'

            ⎕NA'I  ',l,'|libssh2_userauth_authenticated          P'
            ⎕NA'P  ',l,'|libssh2_userauth_list                   P <0C U'
            ⎕NA'I  ',l,'|libssh2_userauth_password_ex            P <0C U <0C U P'
            ⎕NA'I  ',l,'|libssh2_userauth_publickey_fromfile_ex  P <0C U P <0C <0C'
            ⎕NA'I  ',l,'|libssh2_userauth_publickey_frommemory   P <0C U <0C U <0C U <0C'

            ⎕NA'P  ',l,'|libssh2_version                         I'


        ∇
    :EndNamespace

:EndNamespace
