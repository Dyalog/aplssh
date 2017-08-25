⍝∇:require =/SSH.dyalog

:Class APLProcess
    ⍝ Start (and eventually dispose of) a Process

    (⎕IO ⎕ML)←1 1

    :Field Public Args←''
    :Field Public Ws←''
    :Field Public Exe←''
    :Field Public Proc←⎕NS ''
    :Field Public onExit←''
    :Field Public RunTime←0    ⍝ Boolean or name of runtime executable 
    :Field Public IsWin←0
    :Field Public IsSsh←0

    endswith←{w←,⍵ ⋄ a←,⍺ ⋄ w≡(-(⍴a)⌊⍴w)↑a}
    tonum←{⊃⊃(//)⎕VFI ⍵}
    eis←{2>|≡⍵:,⊂⍵ ⋄ ⍵} ⍝ enclose if simple

    ∇ path←SourcePath;source
        ⍝ Determine the source path of the class

        :Trap 6
            source←⍎'(⊃⊃⎕CLASS ⎕THIS).SALT_Data.SourceFile' ⍝ ⍎ works around a bug
        :Else
            :If 0=⍴source←{((⊃¨⍵)⍳⊃⊃⎕CLASS ⎕THIS)⊃⍵,⊂''}5177⌶⍬
                source←⎕WSID
            :Else ⋄ source←4⊃source
            :EndIf
        :EndTrap
        path←{(-⌊/(⌽⍵)⍳'\/')↓⍵}source
    ∇

    ∇ make1 args;rt;cmd;ws
        :Access Public Instance
        :Implements Constructor
        ⍝ args is:
        ⍝  [1]  the workspace to load
        ⍝  [2]  any command line arguments
        ⍝ {[3]} if present, a Boolean indicating whether to use the runtime version, OR a character vector of the executable name to run 
        ⍝ {[4]} if present, the RIDE_INIT parameters to use
        ⍝ {[5]} if present, a log-file prefix for process output

        args←{2>|≡⍵:,⊂⍵ ⋄ ⍵}args
        args←5↑args,(⍴args)↓'' '' 0 '' ''
        (ws cmd rt RIDE_INIT OUT_FILE)←args   
        IsWin←IsWindows
        IsMac←IsMacOS
        PATH←SourcePath
        Start(ws cmd rt)  
    ∇

    ∇ Run
        :Access Public Instance
        Start(Ws Args RunTime)
    ∇

    ∇ Start(ws args rt);psi;pid;cmd;host;port;pubkey;keyfile;exe;z;output
        (Ws Args)←ws args
        args,←' RIDE_INIT="',RIDE_INIT,'"', (0≠≢RIDE_INIT)/' RIDE_SPAWNED=1' 
        ⍝ NB Always set RIDE_INIT to override current process setting

        :If ~0 2 6∊⍨10|⎕DR rt ⍝ if rt is character or nested, it defines what to start
            Exe←(RunTimeName⍣rt) GetCurrentExecutable ⍝ else, deduce it 
        :Else
            Exe←rt
            rt←0
        :EndIf

        :If IsWin∧~IsSsh←326=⎕DR Exe
            ⎕USING←'System,System.dll'
            psi←⎕NEW Diagnostics.ProcessStartInfo,⊂Exe(ws,' ',args)
            psi.WindowStyle←Diagnostics.ProcessWindowStyle.Minimized
            Proc←Diagnostics.Process.Start psi
        :Else ⍝ Unix         
            :If ~∨/'LOG_FILE'⍷args            ⍝ By default
                args,←' LOG_FILE=/dev/nul '   ⍝    no log file
            :EndIf

            :If IsSsh                             
                (host port pubkey keyfile exe)←Exe  
                cmd←args,' ',exe,' +s -q ',ws          
                IsWin←0
                Proc←SshProc host port pubkey keyfile cmd
            :Else
                z←⍕GetCurrentProcessId                                                   
                output←(1+×≢OUT_FILE)⊃'/dev/null' OUT_FILE
                pid←_SH'{ ',args,' ',Exe,' +s -q ',ws,' -c APLppid=',z,' </dev/null >',output,' 2>&1 & } ; echo $!'
                Proc.Id←pid
                Proc.HasExited←HasExited
            :EndIf
            Proc.StartTime←⎕NEW Time ⎕TS
        :EndIf
    ∇

    ∇ Close;count;limit
        :Implements Destructor
        WaitForKill&200 0.1 ⍝ Start a new thread to do the dirty work
    ∇

    ∇ WaitForKill(limit interval);count
        :If (0≠⍴onExit)∧~HasExited ⍝ If the process is still alive
            :Trap 0 ⋄ ⍎onExit ⋄ :EndTrap ⍝ Try this

            count←0
            :While ~HasExited
                {}⎕DL interval
                count←count+1
            :Until count>limit
        :EndIf ⍝ OK, have it your own way

        {}Kill Proc
    ∇

    ∇ r←IsWindows
        :Access Public Shared
        r←'Win'≡3↑platform←⊃#.⎕WG'APLVersion'
    ∇

    ∇ r←IsMacOS
        :Access Public Shared
        r←'Mac'≡3↑platform←⊃#.⎕WG'APLVersion'
    ∇

    ∇ r←GetCurrentProcessId;t
        :Access Public Shared
        :If IsWin
            r←⍎'t'⎕NA'U4 kernel32|GetCurrentProcessId'
        :ElseIf IsSsh
            r←Proc.Pid
        :Else
            r←tonum⊃_SH'echo $PPID'
        :EndIf
    ∇

    ∇ r←GetCurrentExecutable;⎕USING;t;gmfn
        :Access Public Shared
        :If IsWin
            r←''
            :Trap 0
                'gmfn'⎕NA'U4 kernel32|GetModuleFileName* P =T[] U4'
                r←⊃⍴/gmfn 0(1024⍴' ')1024
            :EndTrap
            :If 0∊⍴r
                ⎕USING←'System,system.dll'
                r←2 ⎕NQ'.' 'GetEnvironment' 'DYALOG'
                r←r,(~(¯1↑r)∊'\/')/'/' ⍝ Add separator if necessary
                r←r,(Diagnostics.Process.GetCurrentProcess.ProcessName),'.exe'
            :EndIf 
        ⍝:ElseIf IsSsh
        ⍝    ∘∘∘ ⍝ Not supported
        :Else ⍝ SSH just uses UNIX commands
            t←⊃_PS'-o args -p ',⍕GetCurrentProcessId ⍝ AWS
            :If '"'''∊⍨⊃t  ⍝ if command begins with ' or "
                r←{⍵/⍨{∧\⍵∨≠\⍵}⍵=⊃⍵}t
            :Else
                r←{⍵↑⍨¯1+1⍳⍨(¯1↓0,⍵='\')<⍵=' '}t ⍝ otherwise find first non-escaped space (this will fail on files that end with '\\')
            :EndIf
        :EndIf
    ∇

    ∇ r←RunTimeName exe
        ⍝ Assumes that:
        ⍝ Windows runtime ends in "rt.exe"
        ⍝ *NIX runtime ends in ".rt"
        r←exe
        :If IsWin
            :If 'rt.exe'≢¯6↑{('rt.ex',⍵)[⍵⍳⍨'RT.EX',⍵]}exe ⍝ deal with case insensitivity
                r←'rt.exe',⍨{(~∨\⌽<\⌽'.'=⍵)/⍵}exe
            :EndIf
        :Else
            r←exe,('.rt'≢¯3↑exe)/'.rt'
        :EndIf
    ∇


    ∇ r←KillChildren Exe;kids;⎕USING;p;m;i;mask
        :Access Public Shared
        ⍝ returns [;1] pid [;2] process name of any processes that were not killed
        r←0 2⍴0 ''
        :If ~0∊⍴kids←ListProcesses Exe ⍝ All child processes using the exe
            :If IsWin
                ⎕USING←'System,system.dll'
                p←Diagnostics.Process.GetProcessById¨kids[;1]
                p.Kill
                ⎕DL 1
                :If 0≠⍴p←(~p.HasExited)/p
                    ⎕DL 1
                    p.Kill
                    ⎕DL 1
                    :If ∨/m←~p.HasExited
                        r←(kids[;1]∊m/p.Id)⌿kids
                    :EndIf
                :EndIf
            ⍝:ElseIf IsSsh
            ⍝    ∘∘∘ 'Shoot' works for SSH as well
            :Else
                mask←(⍬⍴⍴kids)⍴0
                :For i :In ⍳⍴mask
                    mask[i]←Shoot kids[i;1]
                :EndFor
                r←(~mask)⌿kids
            :EndIf
        :EndIf
    ∇

    ∇ r←{all}ListProcesses procName;me;⎕USING;procs;unames;names;name;i;pn;kid;parent;mask;n
        :Access Public
        ⍝ returns either my child processes or all processes
        ⍝ procName is either '' for all children, or the name of a process
        ⍝ r[;1] - child process number (Id)
        ⍝ r[;2] - child process name
        me←GetCurrentProcessId
        r←0 2⍴0 ''
        procName←,procName
        all←{6::⍵ ⋄ all}0 ⍝ default to just my childen

        :If IsWin
            ⎕USING←'System,system.dll'

            :If 0∊⍴procName ⋄ procs←Diagnostics.Process.GetProcesses''
            :Else ⋄ procs←Diagnostics.Process.GetProcessesByName⊂procName ⋄ :EndIf
            :If all
                r←↑procs.(Id ProcessName)
                r⌿⍨←r[;1]≠me
            :Else
                :If 0<⍴procs
                    unames←∪names←procs.ProcessName
                    :For name :In unames
                        :For i :In ⍳n←1+.=(,⊂name)⍳names
                            pn←name,(n≠1)/'#',⍕i
                            :Trap 0 ⍝ trap here just in case a process disappeared before we get to it
                                parent←⎕NEW Diagnostics.PerformanceCounter('Process' 'Creating Process Id'pn)
                                :If me=parent.NextValue
                                    kid←⎕NEW Diagnostics.PerformanceCounter('Process' 'Id Process'pn)
                                    r⍪←(kid.NextValue)name
                                :EndIf
                            :EndTrap
                        :EndFor
                    :EndFor
                :EndIf
            :EndIf 
        ⍝:ElseIf IsSsh
        ⍝    ∘∘∘
        :Else ⍝ Linux / SSH (_PS takes care of sending the command over SSH if necessary)
            ⍝ unfortunately, Ubuntu (and perhaps others) report the PPID of tasks started via ⎕SH as 1
            ⍝ so, the best we can do at this point is identify processes that we tagged with ppid=
            mask←' '∧.=procs←' ',↑_PS'-eo pid,cmd',((~all)/' | grep APLppid=',(⍕GetCurrentProcessId)),(0<⍴procName)/' | grep ',procName,' | grep -v grep' ⍝ AWS
            mask∧←2≥+\mask
            procs←↓¨mask⊂procs
            mask←me≠tonum¨1⊃procs ⍝ remove my task
            procs←mask∘/¨procs[1 2]
            mask←1
            :If 0<⍴procName
                mask←∨/¨(procName,' ')∘⍷¨(2⊃procs),¨' '
            :EndIf
            mask>←∨/¨'grep '∘⍷¨2⊃procs ⍝ remove procs that are for the searches
            procs←mask∘/¨procs
            r←↑[0.1]procs
        :EndIf
    ∇

    ∇ r←Kill;delay
        :Access Public Instance
        r←0 ⋄ delay←0.1
        :Trap 0
            :If IsWin
                Proc.Kill
                :Repeat
                    ⎕DL delay
                    delay+←delay
                :Until (delay>10)∨Proc.HasExited
            :ElseIf IsSsh
                {}UNIXIssueKill 3 Proc.Id ⍝ issue strong interrupt (UNIXIssueKill handles SSH)
                {}⎕DL 2 ⍝ wait a couple seconds for it to react
                :If ~Proc.HasExited ⍝ a separate thread will do this once the SSH'ed process gets killed
                    {}UNIXIssueKill 9 Proc.Id ⍝ briong out the big guns
                    {}⎕DL 2
                :AndIf ~Proc.HasExited
                    :Repeat
                        ⎕DL delay
                        delay+←delay
                    :Until (delay>10)∨Proc.HasExited
                :EndIf
            :Else ⍝ Local UNIX
                {}UNIXIssueKill 3 Proc.Id ⍝ issue strong interrupt
                {}⎕DL 2 ⍝ wait a couple seconds for it to react
                :If ~Proc.HasExited←~UNIXIsRunning Proc.Id
                    {}UNIXIssueKill 9 Proc.Id ⍝ issue strong interrupt
                    {}⎕DL 2 ⍝ wait a couple seconds for it to react
                :AndIf ~Proc.HasExited←~UNIXIsRunning Proc.Id
                    :Repeat
                        ⎕DL delay
                        delay+←delay
                    :Until (delay>10)∨Proc.HasExited~UNIXIsRunning Proc.Id
                :EndIf
            :EndIf
            r←Proc.HasExited
        :EndTrap
    ∇

    ∇ r←Shoot Proc;MAX;res
        MAX←100
        r←0
        :If 0≠⎕NC⊂'Proc.HasExited'
            :Repeat
                :If ~Proc.HasExited
                    :If IsWin
                        Proc.Kill
                        ⎕DL 0.2
                    :ElseIf IsSsh
                        {}UNIXIssueKill 3 Proc.Id
                        {}⎕DL 2 ⍝ wait a couple seconds for it to react
                        ⍝ Proc.HasExited will be set by a different thread 
                    :Else
                        {}UNIXIssueKill 3 Proc.Id ⍝ issue strong interrupt AWS
                        {}⎕DL 2 ⍝ wait a couple seconds for it to react
                        :If ~Proc.HasExited←0∊⍴res←UNIXGetShortCmd Proc.Id       ⍝ AWS
                            Proc.HasExited∨←∨/'<defunct>'⍷⊃,/res
                        :EndIf
                    :EndIf
                :EndIf
                MAX-←1
            :Until Proc.HasExited∨MAX≤0
            r←Proc.HasExited
        :ElseIf 2=⎕NC'Proc' ⍝ just a process id?
            {}UNIXIssueKill 9 Proc.Id
            {}⎕DL 2
            r←~UNIXIsRunning Proc.Id  ⍝ AWS
        :EndIf
    ∇

    ∇ r←HasExited
        :Access public instance
        :If IsWin∨IsSsh
            r←{0::⍵ ⋄ Proc.HasExited}1 
        :Else
            r←~UNIXIsRunning Proc.Id ⍝ AWS
        :EndIf
    ∇

    ∇ r←IsRunning args;⎕USING;start;exe;pid;proc;diff;res
        :Access public shared
        ⍝ args - pid {exe} {startTS}
        r←0
        args←eis args
        (pid exe start)←3↑args,(⍴args)↓0 ''⍬
        :If IsWin
            ⎕USING←'System,system.dll'
            :Trap 0
                proc←Diagnostics.Process.GetProcessById pid
                r←1
            :Else
                :Return
            :EndTrap
            :If ''≢exe
                r∧←exe≡proc.ProcessName
            :EndIf
            :If ⍬≢start
                :Trap 90
                    diff←|-/#.DFSUtils.DateToIDN¨start(proc.StartTime.(Year Month Day Hour Minute Second Millisecond))
                    r∧←diff≤24 60 60 1000⊥0 1 0 0÷×/24 60 60 1000 ⍝ consider it a match within a 1 minute window
                :Else
                    r←0
                :EndTrap
            :EndIf
        :ElseIf IsSsh
            r←UNIXIsRunning pid
        :Else
            r←UNIXIsRunning pid
        :EndIf
    ∇

    ∇ r←SSHIsRunning pid;pids
        pids←(∊⎕VFI¨SSHRunCmd 'ps -o pid -x')~0 1
        r←pid∊pids
    ∇
        
    ∇ r←Stop pid;proc
        :Access public
        ⍝ attempts to stop the process with processID pid
        :If IsWin
            ⎕USING←'System,system.dll'
            :Trap 0
                proc←Diagnostics.Process.GetProcessById pid
            :Else
                r←1
                :Return
            :EndTrap
            proc.Kill
            {}⎕DL 0.5
            r←~##.APLProcess.IsRunning pid
        :ElseIf IsSsh
            {}UNIXIssueKill 3 pid ⍝ sends the same command, but over SSH 
        :ElseIf
            {}UNIXIssueKill 3 pid ⍝ issue strong interrupt
        :EndIf
    ∇

    ∇ r←UNIXIsRunning pid;txt
        ⍝ Return 1 if the process is in the process table and is not a defunct
        r←0
        →(r←' '∨.≠txt←UNIXGetShortCmd pid)↓0
        r←~∨/'<defunct>'⍷txt
    ∇

    ∇ {r}←UNIXIssueKill(signal pid)
        signal pid←⍕¨signal pid
        cmd←'kill -',signal,' ',pid,' >/dev/null 2>&1 ; echo $?'
        :If IsSsh
            r←SshRunCmd cmd
        :Else
            r←⎕SH cmd
        :EndIf
    ∇

    ∇ r←UNIXGetShortCmd pid;cmd
        ⍝ Retrieve sort form of cmd used to start process <pid> 
        cmd←(1+IsMac)⊃'cmd' 'command'
        cmd←'ps -o ',cmd,' -p ',(⍕pid),' 2>/dev/null ; exit 0'        
        :If IsSsh
            r←⊃1↓SshRunCmd cmd
        :Else
            r←⊃1↓⎕SH cmd
        :EndIf
    ∇

    ∇ r←_PS cmd;ps;fn
        ps←'ps ',⍨('AIX'≡3↑⊃'.'⎕WG'APLVersion')/'/usr/sysv/bin/'    ⍝ Must use this ps on AIX
        :If IsSsh
            fn←SshRunCmd
        :Else
            fn←⎕SH
        :EndIf
        r←1↓fn ps,cmd,' 2>/dev/null; exit 0'                  ⍝ Remove header line
    ∇

    ∇ r←{quietly}_SH cmd
        :Access public shared
        quietly←{6::⍵ ⋄ quietly}0
        :If quietly
            cmd←cmd,' </dev/null 2>&1'
        :EndIf
        r←{0::'' ⋄ ⎕SH ⍵}cmd
    ∇

    :Class Time
        :Field Public Year
        :Field Public Month
        :Field Public Day
        :Field Public Hour
        :Field Public Minute
        :Field Public Second
        :Field Public Millisecond

        ∇ make ts
            :Implements Constructor
            :Access Public
            (Year Month Day Hour Minute Second Millisecond)←7↑ts
            ⎕DF(⍕¯2↑'00',⍕Day),'-',((12 3⍴'JanFebMarAprMayJunJulAugSepOctNovDec')[⍬⍴Month;]),'-',(⍕100|Year),' ',1↓⊃,/{':',¯2↑'00',⍕⍵}¨Hour Minute Second
        ∇

    :EndClass

    ∇ r←ProcessUsingPort port;t
        ⍝ return the process ID of the process (if any) using a port
        :Access public shared
        r←⍬
        :If IsWin
            :If ~0∊⍴t←_SH'netstat -a -n -o'
            :AndIf ~0∊⍴t/⍨←∨/¨'LISTENING'∘⍷¨t
            :AndIf ~0∊⍴t/⍨←∨/¨((':',⍕port),' ')∘⍷¨t
                r←∪∊¯1↑¨(//)∘⎕VFI¨t
            :EndIf
        :Else
            :If ~0∊⍴t←_SH'netstat -l -n -p 2>/dev/null | grep '':',(⍕port),' '''
                r←∪∊{⊃(//)⎕VFI{(∧\⍵∊⎕D)/⍵}⊃¯1↑{⎕ML←3 ⋄ (' '≠⍵)⊂⍵}⍵}¨t
            :EndIf
        :EndIf
    ∇

    ∇ r←MyDNSName;GCN
        :Access Public Shared

        :If IsWin
            'GCN'⎕NA'I4 Kernel32|GetComputerNameEx* U4 >0T =U4'
            r←2⊃GCN 7 255 255
            :Return
            ⍝ ComputerNameNetBIOS = 0
            ⍝ ComputerNameDnsHostname = 1
            ⍝ ComputerNameDnsDomain = 2
            ⍝ ComputerNameDnsFullyQualified = 3
            ⍝ ComputerNamePhysicalNetBIOS = 4
            ⍝ ComputerNamePhysicalDnsHostname = 5
            ⍝ ComputerNamePhysicalDnsDomain = 6
            ⍝ ComputerNamePhysicalDnsFullyQualified = 7 <<<
            ⍝ ComputerNameMax = 8
        :ElseIf IsSsh
            r←⊃SshRunCmd'hostname'
        :ElseIf
            r←⊃_SH'hostname'
        :EndIf
    ∇

    ∇ x←{raw} SshRunCmd cmd;sess;host;user;privkey;pubkey
        :If 0=⎕NC'raw' ⋄ raw←0 ⋄ :EndIf
        
        :If ~IsSsh
        :OrIf 0=⎕NC⊂'Proc.SSHInfo'
            ⎕SIGNAL⊂('EN'11)('Message' 'Not a SSH process instance.')
        :EndIf
        
        :Trap #.SSH.SSH_ERR
            host user pubkey privkey←Proc.SSHInfo
            sess←⎕NEW #.SSH.Session (host 22)
            sess.Userauth_Publickey user pubkey privkey ''
            x←(⎕UCS¨{⎕ML←3 ⋄ ⍵⊂⍨⍵≠10})⍣(~raw)⊢2⊃sess.Exec cmd
        :Else
            ⎕SIGNAL⊂('EN'11)('Message' ('SSH error:', ⎕DMX.Message))
        :EndTrap
    ∇

    ∇ Proc←SshProc(host user pubkey privkey cmd);sess;runcmd;pids;listpids;pid
        ⍝ run a command and split the output on newlines
        runcmd←{
            rv dat←⍺.Exec ⍵
            rv≠0:⎕SIGNAL('EN'11)('Command failed with error ',(⍕rv),': ',⍕⍵)
            ⎕UCS¨{⎕ML←3 ⋄ ⍵⊂⍨⍵≠10}dat
        } 

        :Trap #.SSH.SSH_ERR
            sess←⎕NEW #.SSH.Session (host 22)
            sess.Userauth_Publickey user pubkey privkey ''

            ⍝ list the PIDs of currently running Dyalog instances
            listpids←{
                pids←sess runcmd'ps -o pid,command -u ',user,' |grep dyalog|grep -v grep|grep -v sh\  |awk ''{print $1}'''
                (∊⎕VFI¨pids)~0 1
            }

            pids←listpids⍬

            Proc←⎕NS''
            Proc.HasExited←0
            Proc.SSHInfo←host user pubkey privkey
            Proc.tid←{SshRun ⍵ Proc}&cmd

            ⎕DL 1 ⍝ wait for process to start

            :If 1≤≢pid←(listpids⍬)~pids
                Proc.Id←Proc.Pid←⊃pid
            :Else
                ⍝ No new Dyalog process was started
                ⎕SIGNAL('EN'11)('Message' ('Process did not start.'))
            :EndIf

        :Else
            ⎕SIGNAL⊂('EN'11)('Message' ('SSH error: ',⎕DMX.Message))
        :EndTrap
    ∇    

    ∇ SshRun (cmd proc);host;user;pubkey;privkey;sess
        host user pubkey privkey←proc.SSHInfo
        sess←⎕NEW #.SSH.Session (host 22)
        sess.Userauth_Publickey user pubkey privkey ''
        {}sess.Exec cmd
        proc.HasExited ← 1
    ∇


:EndClass
