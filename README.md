# ansi-playbooks
playbooks

		                                            Ansible 


cat hosts 
[Server_Checklist_Installation]
ip

---------------------------------------------------------------------------------------------------

cat site.yml 
---

- hosts: Server_Checklist_Installation
  remote_user: user
  sudo: true

  roles:

      - checklist

--------------------------------------------

---

# tasks file for common
#
- name: Copying resolv.conf file to remote
  copy: 
    src: /etc/ansible/server_checklist/checklist/files/resolv.conf
    dest: /etc/

- name: Installing epel-release-latest
  yum:
    name: epel-release
    state: latest

- name: Installing Basic Requires packages
  yum:
    name: ['perl-String-Random.noarch','perl-MIME-Lite.noarch','httpd','ntpdate','psmisc','lsof','net-tools','wget','vim','bind-utils','nmap','bind','net-snmp','lynx','tcpdump','perl-MIME-Lite','telnet','mlocate','sysstat','traceroute','smartmontools.x86_64','rsync','atop','nrpe']
    state: latest

- name: Restarting named service
  service:
    name: named
    state: restarted
    enabled: yes


- name: starting rc-local.service service
  service:
    name: rc-local.service
    state: started
    enabled: yes

- name: Starting nrpe service
  service:
    name: nrpe
    state: started
    enabled: yes

- name: Stopping NetworkManager service
  service:
    name: NetworkManager
    state: stopped
    enabled: no

- name: Adding user web with passsord
  user:
   name: web
   shell: /bin/bash
   password: $1$$password hash

- name: Changing password for root user
  become: true # do this as root
  user:
   name: root
   password: $1$$password hash

- name: Stopping firewalld service
  service:
    name: firewalld
    state: stopped
    enabled: no

- name: Replace SElinux configuration
  replace:
     dest: /etc/selinux/config
     regexp: 'SELINUX=enforcing'
     replace: 'SELINUX=disabled'
     backup: yes

- name: Changing current date format to IST.
  shell: /bin/rm -rf /etc/localtime

- name: Changing current date format to IST via symlink
  file:
    src: /usr/share/zoneinfo/Asia/Kolkata
    dest: /etc/localtime
    state: link
     
- name: Adding server tag to hosts
  shell: /bin/sed -i "1 s/$/ `hostname`/;2d" /etc/hosts

- name: Enabling /etc/yum.repos.d/CentOS-Base.repo 
  shell: /bin/sed -i '/[centosplus]/ s/enabled=0/enabled=1/' /etc/yum.repos.d/CentOS-Base.repo

#- name: Installing kernel-plus.x86_64
#  yum: 
#    name: ['kernel-plus.x86_64']
#    state: latest

- name: Copying kernel kernel-plus-3.10.0-514.6.1.el7.centos.plus.x86_64.rpm to remote
  copy:
    src: /etc/ansible/server_checklist/checklist/files/kernel-plus-3.10.0-514.6.1.el7.centos.plus.x86_64.rpm
    dest: /tmp/

- name: Installing kernel-plus-3.10.0-514.6.1.el7.centos.plus.x86_64...
  yum:
    name: /tmp/kernel-plus-3.10.0-514.6.1.el7.centos.plus.x86_64.rpm
    state: present

- name: Changing default grub value in grub configuration
  replace:
     dest: /etc/default/grub
     regexp: 'GRUB_DEFAULT=saved'
     replace: 'GRUB_DEFAULT=0'
     backup: yes

- name: Initialization grub config
  shell: /usr/sbin/grub2-set-default 0

- name: Initialization grub2-mkconfig  /boot/grub2/grub.cfg
  shell: /usr/sbin/grub2-mkconfig -o /boot/grub2/grub.cfg

- name: Disable ipv6 in the /etc/sysctl.conf
  blockinfile:
    path: /etc/sysctl.conf
    block: |
      net.ipv6.conf.all.disable_ipv6 = 1
      net.ipv6.conf.default.disable_ipv6 = 1
      net.ipv4.conf.lo.arp_ignore = 1
      net.ipv4.conf.lo.arp_announce = 2
      net.ipv4.conf.all.arp_ignore = 1
      net.ipv4.conf.all.arp_announce = 2
      net.ipv4.tcp_keepalive_intvl = 30
      net.ipv4.tcp_keepalive_time = 120
      net.ipv4.tcp_fin_timeout = 30
      net.core.somaxconn = 4096
      net.ipv4.tcp_max_syn_backlog = 4096
    insertafter: For more information


- name: initialization sysctl -p 
  shell: /usr/sbin/sysctl -p

- name: Copying rsyncd.conf file to remote
  copy:
    src: /etc/ansible/server_checklist/checklist/files/rsyncd.conf
    dest: /etc/

- name: Restarting rsyncd service
  service:
    name: rsyncd
    state: restarted
    enabled: yes


- name: Copying hosts.allow file to remote
  copy:
    src: /etc/ansible/server_checklist/checklist/files/hosts.allow
    dest: /etc/

- name: Copying hosts.deny file to remote
  copy:
    src: /etc/ansible/server_checklist/checklist/files/hosts.deny
    dest: /etc/

- name: Disabling root login to remote host
  replace:
      dest: /etc/ssh/sshd_config
      regexp: '#PermitRootLogin yes'
      replace: 'PermitRootLogin no'
      backup: yes

- name: Restarting crond service
  service:
    name: crond
    state: restarted

- name: Creating a directory /net/lib
  file:
    path: /net/lib
    state: directory
    mode: 0755

- name: Rsync basis data to remote hosts
  synchronize:
     src: /backup/perl
     dest: /net/lib/

- synchronize:
     src: /backup/bashrc
     dest: /etc/

- synchronize:
     src: /backup/bin
     dest: /usr/local/

- synchronize:
     src: /backup/root
     dest: /var/spool/cron/

- name: Creating a directory /var/log/rotated
  file:
    path: /var/log/rotated
    state: directory
    mode: 0755

- name: Creating a directory /var/log/systems
  file:
    path: /var/log/systems
    state: directory
    mode: 0755

- name: Create file monitor_dmesg 
  file:
    path: /var/log/systems/monitor_dmesg
    state: touch

- name: Rsync basic data file to remote host using synchronize
  synchronize:
     src: /backup/secure_logrotate.conf
     dest: /etc/

- synchronize:
     src: /backup/rh-cve-2016-5195_5.sh
     dest: /root/

- synchronize:
     src: /backup/snmpd.conf
     dest: /etc/snmp/ 

- name: Executing bash commands
  shell: |
    /bin/sed -i "$ a\/usr/local/bin/smtp.start" /etc/rc.d/rc.local
    /usr/bin/chmod +x /etc/rc.d/rc.local
    /usr/bin/chmod +x /etc/rc.local
    /usr/bin/chmod +x /root/monitor_dmesg.sh
    /usr/bin/chmod +x /root/monitor.sh
    /usr/bin/chmod +x /root/rh-cve-2016-5195_5.sh
    source /etc/bashrc 
  
- name: Create empty file /etc/security/limits.d/nofile.conf
  file:
    path: /etc/security/limits.d/nofile.conf
    state: touch

- name: Adding security soft limits in /etc/security/limits.d/nofile.conf
  blockinfile:
    path: /etc/security/limits.d/nofile.conf
    block: |
      *    soft    nofile 1000000
      *    hard    nofile 1000000
      postfix   soft    nproc     10240

- name: Changing LANG by using localectl
  shell: /usr/bin/localectl set-locale LANG=C

- name : Installing & create Ldap configuration
  yum:
    name: ['openldap-clients','nss-pam-ldapd']
    state: latest

- name: Adding PAM ssh config to /etc/pam.d/sshd
  shell: /bin/sed -i "$ a\session    optional     pam_mkhomedir.so skel=/etc/skel umask=077" /etc/pam.d/sshd

- name: moving original ldap file /etc/openldap/ldap.conf to /etc/openldap/ldap.conf.org
  command: /usr/bin/mv /etc/openldap/ldap.conf /etc/openldap/ldap.conf.org
 

- synchronize:
     src: /backup/ldap.conf
     dest: /etc/openldap/ 

- name:  Configuring Authconfig for LDAP 
  shell: |
    /sbin/authconfig --enableldap --update
    /sbin/authconfig --enableldapauth --update
    /sbin/authconfig --ldapserver=ldap://URL --update
    /sbin/authconfig --ldapbasedn=dc=domain,dc=co,dc=in --update

- name : Restarting & Enabling nscd service
  service:
    name: nscd
    state: restarted
    enabled: yes 

- name : Restarting & Enabling nslcd service
  service:
    name: nslcd
    state: restarted
    enabled: yes

- name: Adding sudo access to infra group
  shell: /bin/echo "%infra  ALL=(ALL)     NOPASSWD:ALL" >>/etc/sudoers
  
- name: Rsyslog configuration
  shell: /bin/sed -i "/\/var\/log\/maillog/d" /etc/logrotate.d/syslog

- name: Adding RateLimitInterval configuration in /etc/rsyslog.conf 
  blockinfile:
    path: /etc/rsyslog.conf
    backup: yes
    block: |
      $IMUXSockRateLimitInterval 0
      $IMJournalRatelimitInterval 0

- name: Restart rsyslog
  service:
    name: rsyslog
    state: restarted
    enabled: yes

- name: Adding journald configuration to /etc/systemd/journald.conf
  blockinfile:
    path: /etc/systemd/journald.conf
    backup: yes
    block: |
      RateLimitInterval=0
      MaxRetentionSec=5s 


- name: Restart journald service
  service:
    name: systemd-journald
    state: restarted
    enabled: yes

- name: stopping abrtd
  service:
    name: abrtd
    state: stopped
    enabled: no
  ignore_errors: yes 

- name: starting snmpd
  service:
    name: snmpd
    state: started
    enabled: yes
  ignore_errors: yes

- name: starting httpd
  service:
    name: httpd
    state: started
    enabled: yes
  ignore_errors: yes

- name: stopping chronyd
  service: 
    name: chronyd
    state: stopped
    enabled: no
  ignore_errors: yes

- name: disable polkit
  service:
    name: polkit
    state: stopped
    enabled: no
  ignore_errors: yes

- name: Comment lines in autoindex.conf file
  replace:
    path: /etc/httpd/conf.d/autoindex.conf
    regexp: 'Alias /icons/ "/usr/share/httpd/icons/"'
    replace: '#Alias /icons/ "/usr/share/httpd/icons/"'
    backup: yes

- name: Comment lines in autoindex.conf file
  replace:
    path: /etc/httpd/conf.d/autoindex.conf
    regexp: '<Directory "/usr/share/httpd/icons">'
    replace: '#<Directory "/usr/share/httpd/icons">'

- name: Comment lines in autoindex.conf file
  replace:
    path: /etc/httpd/conf.d/autoindex.conf
    regexp: 'Options Indexes MultiViews FollowSymlinks'
    replace: '#Options Indexes MultiViews FollowSymlinks)'

- name: Comment lines in autoindex.conf file
  replace:
    path: /etc/httpd/conf.d/autoindex.conf
    regexp: 'AllowOverride None'
    replace: '#AllowOverride None'

- name: Comment lines in autoindex.conf file
  replace:
    path: /etc/httpd/conf.d/autoindex.conf
    regexp: 'Require all granted'
    replace: '#Require all granted'

- name: Comment lines in autoindex.conf file
  replace:
    path: /etc/httpd/conf.d/autoindex.conf
    regexp: '</Directory>'
    replace: '#</Directory>'

- name: Copying main resolv.conf file to /etc/resolv.conf
  copy:
    src: /etc/ansible/server_checklist/checklist/files/resolv.conf.j1
    dest: /etc/resolv.conf

- name: Checking our kernel which is vulnerable or NOT.
  shell: /root/rh-cve-2016-5195_5.sh
  register: result
  ignore_errors: yes

- name: Task Acknowledgement By Telegram
  telegram:
    token: 'xxxxxxxx:xxxxxxxxxxxxxxxxxxxxxxxxxxx'
    chat_id: '-xxxxxxx'
    msg: Ansible -- Server Installation Task Finished.
  ignore_errors: yes


-------------------------------------------------

 cat  server_config.yml
---
 - hosts: web-servers
   user: systems

   tasks:
    - name: install httpd
      yum:
        name: httpd

    - name: install php and maria db
      yum: name={{item}} state=installed
      with_items:  
      - php
      - php-mysql
      - php-pdo
      - php-gd
      - php-mbstring
      - mariadb-server
      - mariadb
      - ntpd



    - name: copy file
      shell: echo "<?php phpinfo (); ?>" > /var/www/html/info.php

    - name: install mariadb
      yum: name={{item}} state=installed
      with_items:
      - mariadb-server
      - mariadb

    
    - name: restart httpd
      service:
        name: httpd
        state: restarted


---------------------------------------------------------------------------------------------------------------------

cat mongo.yml
---
- hosts: hosts
  remote_user: username 
  sudo: true
  tasks:
        - name: ensure a list of packages installed
          yum:
            name: "{{ packages }}"
          vars:
            packages:
            - opensips-snmpstats
            - perl-DBD-MySQL
            state: latest

----------------------------------------------------------------------------------------------------------------------

cat mongodb_ssh.yml
---
- name: Copy mongdb sshd file
  copy:
    src: /backup/mongodb_sshd_config 
    dest: /etc/sshd/sshd_config
    owner: root
    group: root
    mode: 0644
    backup: yes
----------------------------------------------------------------------------------------------------------------------

cat useradd1.yml
---
- hosts: mobility_hosts
  remote_user: p9uHmgts
  sudo: true
  vars:
    users:
    - username: "username"
    - username: "username"
    - username: "username"
    - username: "username"

  
  tasks:
        - name: Changing Accounts Passwords
          user: 
            name: "{{ item.username }}"
            comment: "Changing Accounts Passwords"
            password: $1$password hash
          with_items: "{{ users }}"



cat nrpe.yml
---
- name: Ansible nrpe configuration playbook.
  hosts: hosts
  remote_user: user
  sudo: true

  tasks:
    - name: Checking NRPE Installed Or Not.
      yum:
        list=nrpe
      register: pkg

    - name: Installing NRPE.
      package:
        name=nrpe
        state=latest
      when: ansible_os_family == 'RedHat' and
            pkg.results[0].yumstate != 'installed'

    - name: Checking NRPE plugins Installed Or Not.
      yum:
        list=nagios-plugins-all.x86_64
      register: pkg

    - name: Installing NRPE Plugins.
      package:
        name=nagios-plugins-all.x86_64
        state=latest
      when: ansible_os_family == 'RedHat' and
            pkg.results[0].yumstate != 'installed'

    - name: Copying file to Remote.
      copy:
        src: /backup/shellscript.sh
        dest: /usr/lib64/nagios/plugins/ 
        owner: root
        group: root
        mode: '0755'
--------------------------------------------------------------------------------------------------------------------


 sudoadd1.yml
---
- hosts: hosts
  remote_user: user
  sudo: true
  vars:
    users:
    - username: "username"
    - username: "username"
    
  tasks:
        
  - name: Sudoers | update sudoers file and validate
    lineinfile: "dest=/home/mangeshs/sudoers
      insertafter='^# %wheel'
      line='{{ item.username }} ALL=(ALL) NOPASSWD: ALL'
      regexp='^{{ item.username }} .*'
      state=present
      backup=yes"
    with_items: '{{ users }}'


cat userdel_allserver.yml

---
- hosts: hosts
  remote_user: username
  sudo: true
  vars:
    users:
    - username: "username"
    - username: "username"
    
  tasks:
        - name: Removing username's with home directory.
          user: 
            name: "{{ item.username }}"
            state: absent
            remove: yes
          with_items: "{{ users }}"

----------------------------------------------------------------------------------------------------------------------

cat ping.yml
---
- hosts: hosts
  remote_user: user
  gather_facts: false
  sudo: true
  
  tasks:
- ping:
----------------------------------------------------------------------------------------------------------------------

cat useradd_.yml

---
- hosts: hosts
  remote_user: user
  sudo: true
  vars:
    users:
    - username: "username"
  
  tasks:
        - name: Creating user account with password
          user: 
            name: "{{ item.username }}"
            shell: /bin/bash
            comment: "Testing Accounts"
            password: $5$Opassword hash
          with_items: "{{ users }}"

-----------------------------------------------------------------------------------------------------------------

cat sudoadd.yml
---
- hosts: hosts
  debugger: on_failed
  remote_user: user
  sudo: true
  vars:
    users:
    - username: "username"

  tasks:
        
  - name: Update sudoers file and validate
    lineinfile: 
      insertafter: '^# %wheel'
      path: /etc/sudoers
      state: present
      regexp: '^{{ item.username }} .*'
      line: '{{ item.username }} ALL=(ALL) NOPASSWD: ALL'
      backup: yes
      validate: /usr/sbin/visudo -cf %s 
    with_items: '{{ users }}'






				
