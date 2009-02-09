%define odist	%{?dist}%{!?dist:.el4}
%define	release	00vit%{odist}

%define pam_ver 0.90
%define ssl_ver 0.9.2
%define mysql_ver 3.23
%define openvpn_ver 2.0

%define ofedora	 %{?fedora}%{!?fedora:0}

%define o1redhat %(cat /etc/redhat-release 2>/dev/null | sed -e 's/^.*release/x/' | awk '{print $2}')
%define o2redhat %(grep -q 'Red Hat' /etc/redhat-release 2>/dev/null && echo %{o1redhat} || echo 0)
%define oredhat  %{?redhat}%{!?redhat:%{o2redhat}}

%define fedora7plus %(test %{ofedora} -ge 7 && echo 1 || echo 0)
%define redhat4plus %(test %{oredhat} -ge 4 && echo 1 || echo 0)

%ifarch x86_64
%define libsubdir lib64
%else
%define libsubdir lib
%endif

Summary:	Let users roam from machine to machine and still be accountable
Name:		userwatch
Version:	0.0.1
Release:	%{release}
License:	GPL
Group:		System
URL:		http://vitki.net/v/projects/userwatch
Source0:	%{name}-%{version}.tar.gz

Requires: openssl >= %{ssl_ver}
Requires: pam >= %{pam_ver}

BuildRequires: pam-devel >= %{pam_ver}
BuildRequires: openssl-devel >= %{ssl_ver}
BuildRequires: mysql-devel >= %{mysql_ver}

BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-buildroot

%package server
Summary:  Server that accounts for roaming users
Group:    System
Requires: openssl >= %{ssl_ver}
Requires: openvpn >= %{openvpn_ver}
Requires: mysql >= %{mysql_ver}

%prep

%setup -q

%build

%configure --with-pamdir=/%{libsubdir}/security

make %{?_smp_mflags}

%{__make}

%install
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}

%{__make} DESTDIR=%{buildroot} install

%define httpd_confd %{_sysconfdir}/httpd/conf.d
%define httpd_modd /usr/lib/httpd/modules
%define etc_initd %{_sysconfdir}/rc.d/init.d

install -d %{buildroot}%{httpd_confd}
cat << FOO > %{buildroot}%{httpd_confd}/mod_uwatch.conf
LoadModule uwatch_module modules/mod_uwatch.so
<IfModule mod_uwatch.c>
  UserWatchEnable On
</IfModule>
FOO

install -Dm0755 userwatch-rc.d.sh %{buildroot}%{etc_initd}/userwatch

mv %{buildroot}%{httpd_modd}/libmod_uwatch.so \
   %{buildroot}%{httpd_modd}/mod_uwatch.so

rm %{buildroot}/lib/security/pam_uwatch.a
rm %{buildroot}/lib/security/pam_uwatch.la

%clean
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}

%files
%defattr(0644,root,root,0755)
/lib/security/pam_uwatch.so
/lib/security/pam_uwatch_auth.so
/lib/security/pam_uwatch_session.so
%attr(0755,root,root) /usr/sbin/uwcli

%files server
%defattr(0644,root,root,0755)
%{httpd_confd}/mod_uwatch.conf
/usr/lib/httpd/modules/mod_uwatch.so
%attr(0755,root,root) %{etc_initd}/userwatch
%attr(0755,root,root) /usr/sbin/uwatchd

%description
Let users roam from machine to machine and still be accountable.
Interacts with pam, openvpn, radius, mysql and netams.
This subpackage contains client-only files

%description server
Let users roam from machine to machine and still be accountable.
Interacts with pam, openvpn, radius, mysql and netams.
This subpackage contains server-only files

%changelog
* Wed Oct 15 2008 Victor Semizarov <vsemizarov$gmail,com> 0.0.1
- Initial package

