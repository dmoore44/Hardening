#!/bin/bash

echo "CentOS 6.x Hardening Script"
echo " "
sleep 2

echo "1. Checking for packages to remove:"
echo "inetd, xinetd, ypserv, tftp-server, telnet-server, and rsh-serve"
for package in inetd xinetd ypserv tftp-server telnet-server rsh-serve
do
      if ! rpm -qa | grep $package >& /etc/null;
      then
      echo "package $package is not installed"
      else
      echo "The $package is installed. Removing it now."
      yum erase $package
      fi
done
sleep 2
echo " "

echo "2. SElinux is a pain in the ass, lets disable it:"
x=`cat /etc/sysconfig/selinux | grep ^SELINUX | head -n 1 | awk -F= '{print $2}'`
if [ $x != disabled ]
  then
    echo "SElinux is not disabled"
    echo "Changing it to enforcing"
    sed -i 's/^SELINUX=disabled/SELINUX=disabled/' /etc/sysconfig/selinux
  else
    echo "SElinux has already been disabled"
fi
sleep 2
echo " "

echo "3. Changing parameters for password aging"
sed -i '/^PASS_MAX_DAYS/c\PASS_MAX_DAYS  60' /etc/login.defs
sed -i '/^PASS_MIN_DAYS/c\PASS_MIN_DAYS  1' /etc/login.defs
sed -i '/^PASS_MIN_LEN/c\PASS_MIN_LEN   8' /etc/login.defs
sed -i '/^PASS_WARN_AGE/c\PASS_WARN_AGE   15' /etc/login.defs
echo "Changes in /etc/login.defs file are done"
sleep 2
echo " "

#echo "Restricting use of previously used passwords:"
#echo "N/A"
#sleep 2

echo "4. Checking for accounts with empty passwords:"
x=`awk -F: '($2 == "") {print}' /etc/shadow | wc -l`
if [ $x -lt 1 ]
  then
    echo "All accounts have passwords"
  else
    echo "There exists an account without a password, check account configs"
fi
sleep 2
echo " "

echo "5. Checking for non-root accounts with UID equal to 0:"
x=`awk -F: '($3 == "0") {print}' /etc/passwd | awk -F: '{print $1}'`
if [ $x == root ]
  then
    echo "No account other than root has a UID of 0"
  else 
    echo "***** Check your account configs, a non-root account has a UID of 0"
fi
sleep 2
echo " "

#echo "6. Disabling remote login for the root account"
#sed -i '/^#PermitRootLogin/a PermitRootLogin no' /etc/ssh/sshd_config
#sed -i 's/^#Port 22/Port 2222/' /etc/ssh/sshd_config
#sleep 2

echo "7. Linux kernel hardening:"
cp /etc/sysctl.conf /etc/sysctl.conf.backup
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.forwarding = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.mc_forwarding = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 4096" >> /etc/sysctl.conf
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
sleep 2
echo " "

echo "8. Restricting access to commonly used commands"
chmod 100 /bin/rpm
chmod 100 /bin/tar
chmod 100 /bin/gzip
chmod 100 /bin/ping
chmod 100 /bin/gunzip
chmod 100 /bin/mount
chmod 100 /bin/umount
chmod 100 /usr/bin/gzip
chmod 100 /usr/bin/gunzip
chmod 100 /usr/bin/who
chmod 100 /usr/bin/lastb
chmod 100 /usr/bin/last
chmod 100 /usr/bin/lastlog
chmod 100 /sbin/arping
#chmod 100 /usr/sbin/traceroute

#chmod 400 /etc/syslog-ng/syslog-ng.conf
chmod 400 /etc/hosts.allow
chmod 400 /etc/hosts.deny
#chmod 400 /etc/sysconfig/syslog
chmod 644 /var/log/wtmp
echo "commands permissions changed"
sleep 1
echo " "

#echo "Disk partitions:"
#echo "***None applied yet***"
#sleep 2

#echo "disabling IPv6:"
#echo "None applied"
#sleep 2

echo "9. Disabling silly user accounts:"
sed -i 's/^lp/#lp/' /etc/passwd
sed -i 's/^games/#games/' /etc/passwd

sed -i 's/^lp/#lp/' /etc/group
sed -i 's/^games/#games/' /etc/group
sleep 2
echo " "

#echo "creating GRUB password:"

#echo "use of gconftool"

#echo "write verify script"

echo "10. Setting Banne and MOTD messages"
echo "*****************************************************************************" > /etc/motd
echo -e "!!!WARNING!!!\n" >> /etc/motd
echo " Please don't abuse you priviliges..." >> /etc/motd
echo "*****************************************************************************" >> /etc/motd
cp /etc/issue /etc/issue.net
#cp /etc/issue /etc/motd
sleep 1
echo " "
