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
Name:		netusher
Version:	0.0.1
Release:	%{release}
License:	GPL
Group:		System
URL:		http://vitki.net/v/projects/netusher
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

install -Dm0755 netusher-rc.d.sh %{buildroot}%{etc_initd}/netusher

rm %{buildroot}/lib/security/pam_netusher.a
rm %{buildroot}/lib/security/pam_netusher.la

%clean
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}

%files
%defattr(0644,root,root,0755)
/lib/security/pam_netusher.so
%attr(0755,root,root) /usr/sbin/uwcli

%files server
%defattr(0644,root,root,0755)
%attr(0755,root,root) %{etc_initd}/netusher

%description
Let users roam from machine to machine and still be accountable.
Interacts with pam, openvpn, radius, mysql and netams.
This subpackage contains client-only files

%description server
Let users roam from machine to machine and still be accountable.
Interacts with pam, openvpn, radius, mysql and netams.
This subpackage contains server-only files

%changelog
* Tue Jan 15 2011 Vitki <vitkinet@gmail.com> 0.1
- Initial release

