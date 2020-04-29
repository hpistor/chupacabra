%vuln( Description, [prereqs], [result], [Role-[key-(pred, [val]),...,key-(pred,[val])]] )
%note, result cannot be empty
%note, config values must be strings or predicates


% == REVERSE SHELL == %
% situation(name, input, output, Vuln, Config, MachineCount)

% build_situation(Description, Input, Output, MachineCount)
build_situation('reverse_shell', [shell], [root_shell], 2).

% vuln(Description, Input, Output, Config, SrcMachine, DstMachine)
vuln('listening-shell', [shell], [reverse_shell], [], 1, 1).
vuln('reverse-shell', [reverse_shell], [root_shell, shell], [lamp-[], nossh-[]], 1, 2).

% == FTP ==

% GOal output [vsftpd-[version-(only,["2.3.4"])]]

vuln('scan-ftp', [], [ftp, vsftpd234],
        [vsftpd-[version-(only, ["2.3.4"])]], 1, 1).
vuln('scan-ftp', [], [ftp, vsftpd303],
        [vsftpd-[version-(only, ["3.0.3"])]], 1, 1).

vuln('vsftpd-backdoor', [vsftpd234], [root_shell, shell],
        [vsftpd-[version-(only, ["2.3.4"])]], 1, 1).

% == SSH ==

vuln('scan-ssh', [], [ssh, openssh76p1],
        [openssh-[version-(only, ["7.6p1"])]], 1, 1).

%vuln('ssh-login-root(brute-force)', [ssh], [root_shell],
%        [openssh-[allowrootlogin-(only, ["Yes"])],
%        users-[root-(only, [generatePassword])]], 1, 1).

vuln('ssh-login-root', [ssh, passwords], [root_shell, shell],
        [openssh-[allowrootlogin-(only, ["Yes"])],
        users-[root-(only, [generatePassword])]], 1, 1).

%vuln('ssh-login(brute-force)', [ssh, user_list], [user_shell],
%        [users-[logins-(exists, [generateUsername]),
%                passwords-(exists, [generatePassword])]], 1, 1).

vuln('ssh-login-user', [ssh, user_list, passwords], [user_shell, shell],
        [users-[logins-(exists, [generateUsername]),
                passwords-(exists, [generatePassword])]], 1, 1).

vuln('enumerate-users', [openssh76p1], [user_list], [], 1, 1).

% == Web ==

vuln('scan-http', [], [http],
        [apache-[]], 1, 1).

% vuln('find-login-page', [http], [php_webapp, login_page],
%         [apache-[modules-(exists, ["libapache2-mod-php"])],
%         php-[deployments-(exists, ["loginpage1"])],
%         mysql-[db-(exists, ["logindb1"]),
%                root-(only, [generatePassword])]], 1, 1).

vuln('find-login-page', [http], [php_webapp, login_page, bad_sql],
       [apache-[modules-(exists, ["libapache2-mod-php"])],
        php-[deployments-(exists, ["loginpage1-badsql"])],
        mysql-[db-(exists, ["logindb1"]),
               root-(only, [generatePassword])]], 1, 1).

%vuln('web-login-admin(brute-force)', [login_page, web_user_list], [web_admin_access, web_passwords], [], 1, 1).

vuln('web-login-admin', [login_page, web_user_list, web_passwords], [web_admin_access], [], 1, 1).

vuln('sql-injection', [login_page, bad_sql], [db_access], [], 1, 1).

vuln('exec-custom-php', [php_webapp, web_admin_access], [user_shell, shell], [], 1, 1).

% == Database ==

vuln('db-query-users', [db_access], [web_user_list, hashed_web_passwords],
        [mysql-[db-(exists, ["logindb1"])]], 1, 1).

% == Java ==

%vuln('scan-jboss', [http], [jboss],
%        [jboss-[]], 1, 1).

% CVE-2017-12149
%vuln('deserialization-attack', [jboss], [user_shell],
%        [jboss-[version-(only, ["5.2.2"]),
%                deployments-(exists, ["jbossdemo1.war"])]], 1, 1).

% == Password cracking ==

vuln('exposed-shadow-file', [user_shell], [hashed_passwords], [], 1, 1).
vuln('exposed-shadow-file', [ftp], [hashed_passwords], [], 1, 1).

vuln('crack-hashes', [hashed_passwords], [passwords], [], 1, 1).
vuln('crack-hashes', [hashed_web_passwords], [web_passwords], [], 1, 1).

% == User shell to root shell (privilege escalation) ==

vuln('scan-for-setuid-binary', [user_shell], [setuid_binary], [], 1, 1).

vuln('examine-setuid-binary', [setuid_binary], [assumed_PATH_var], [], 1, 1).

vuln('custom-PATH-setuid', [user_shell, setuid_binary, assumed_PATH_var], [root_shell, shell], [], 1, 1).

%vuln('scan-for-root-cronjobs', [user_shell], [root_cronjob], [], 1, 1).

%vuln('hijack-root-cronjob', [root_cronjob], [root_shell], [], 1, 1).


