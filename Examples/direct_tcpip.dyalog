⍝∇:require =/../SSH.dyalog

:Namespace direct_tcpip
    keyfile1←'/home/marinus/apl_sshid/id_rsa.pub'
    keyfile2←'/home/marinus/apl_sshid/id_rsa'

    username←'marinus'
    password←''

    server_ip←'127.0.0.1'
    local_listenip←'127.0.0.1'
    local_listenport←2222

    remote_desthost←'localhost'
    remote_destport←22

    ∇ direct_tcpip methods;sock;session;auth_list;listensock;forwardsock;fhost;fport;meth;channel;poller;ps;buf;r;again
        ⍝ initialize SSH library
        #.SSH.Init

        ⍝ set up an SSH connection and do a handshake
        session←⎕NEW #.SSH.Session(server_ip 22)

        ⍝ show the hostkey hash
        ⍝ (authentication has not yet been done)
        ⎕←session.HostkeyHash'SHA1'

        ⍝ check what authentication methods are available
        auth_list←session.UserauthList username
        ⎕←'Authentication methods:',auth_list

        ⍝ use only the methods that are available
        methods∩←auth_list
        :For meth :In methods
            ⎕←'Trying ',meth
            :Trap #.SSH.SSH_ERR
                :Select meth
                :Case 'password'
                    session.Userauth_Password username password
                    ⎕←meth,' succeeded'
                    →success
                :Case 'publickey'
                    session.Userauth_Publickey username keyfile1 keyfile2 password
                    ⎕←meth,' succeeded'
                    →success
                :Else
                    ⎕←'Unknown method.'
                :EndSelect
            :Else
                ⎕←'Failed.'
                ⎕←⎕DMX
            :EndTrap
            ⎕←''
        :EndFor
        ⎕←'No supported authentication methods found.'
        →shutdown

        success:

        listensock←⎕NEW #.Sock.Socket #.Sock.Cnst.SOCK_STREAM
        listensock.setsockopt_int #.Sock.Cnst.SOL_SOCKET #.Sock.Cnst.SO_REUSEADDR 1

        listensock.Bind(local_listenip local_listenport)

        listensock.Listen 2

        ⎕←'Waiting for TCP connection on ',local_listenport,':',local_listenip

        forwardsock←listensock.Accept
        fhost fport←forwardsock.ListenConnection
        fport←⍎fport ⍝ convert to number 

        ⎕←'Forwarding connection from here to remote ',remote_desthost,':',remote_destport

        channel←session.Channel_Direct_TCPIP remote_desthost remote_destport fhost fport

        ⍝ non-blocking IO
        session.SetBlocking 0

        ⍝ poll
        poller←⎕NEW #.Sock.Poller
        #.Sock.Cnst.POLLIN poller.Register forwardsock

        :Trap ⍬
            :Repeat
                ⍞←'Po'
                ps←poller.Poll 10
                ⍞←'ll'
                ⎕←''
                
                :If forwardsock∊ps
                    ⍞←'Reading from socket... '
                    ⍝ read data from the socket
                    buf←forwardsock.Recv 1024
                    :If 0=≢buf
                        ⎕←'Client disconnected'
                        →shutdown
                    :EndIf

                    ⍝ write the whole buffer into the channel as needed

                    ⍞←'Writing to channel...'
                    :While 0<≢buf
                        ⍞←'.' 
                        ⍝ try to write the buffer
                        again r←channel.Write buf
                        :If again ⋄ :Continue ⋄ :EndIf

                        ⍝ remove the data that's actually been written from the buffer
                        buf↓⍨←r
                    :EndWhile
                    ⎕←'Done'
                :EndIf

                :Repeat
                    ⍞←'Reading from channel... '
                    ⍝ try to read some data from the channel
                    again buf←channel.Read 1024
                    :If again ⋄ :Leave ⋄ :EndIf

                    ⍝ write the whole buffer to the socket as needed
                    ⍞←'Writing to socket...'
                    :While 0<≢buf
                        ⍞←'.'
                        r←forwardsock.Send buf
                        buf↓⍨←r
                    :EndWhile

                    :If channel.EOF
                        ⎕←'The server at ',remote_desthost,':',remote_destport,' disconnected!'
                        →shutdown
                    :EndIf
                    ⎕←'Done'
                :EndRepeat
            :EndRepeat



        :EndTrap

        shutdown:

    ∇
:EndNamespace
