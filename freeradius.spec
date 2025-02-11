%global docdir %{?_pkgdocdir}%{!?_pkgdocdir:%{_docdir}/%{name}-%{version}}
%define openssl_version %(rpm -q --queryformat '%%{EPOCH}:%%{VERSION}' openssl)
%define perl_version %(eval "`%{__perl} -V:version`"; echo $version)

Name:           freeradius
Version:        3.0.26
Release:        1
Summary:        Remote Authentication Dial-In User Service

License:        GPLv2+ and LGPLv2+
URL:            http://www.freeradius.org/
Source0:        https://freeradius.org/ftp/pub/radius/freeradius-server-%{version}.tar.gz
Source1:        radiusd.service
Source2:        freeradius-logrotate
Source3:        freeradius-pam-conf
Source4:        freeradius-tmpfiles.conf

BuildRequires:  autoconf gdbm-devel openssl openssl-devel pam-devel zlib-devel net-snmp-devel
BuildRequires:  net-snmp-utils readline-devel libpcap-devel systemd-units libtalloc-devel
BuildRequires:  pcre-devel unixODBC-devel json-c-devel libcurl-devel gcc chrpath

Requires:       openssl >= %{openssl_version}
Requires(pre):  shadow-utils glibc-common
Requires(post): systemd-sysv systemd-units
Requires(preun): systemd-units
Requires(postun): systemd-units

Provides:       %{name}-unixODBC = %{version}-%{release} %{name}-rest = %{version}-%{release}
Obsoletes:      %{name}-unixODBC < %{version}-%{release} %{name}-rest < %{version}-%{release}

%description
Remote Authentication Dial-In User Service (RADIUS) is a networking
protocol that provides centralized Authentication, Authorization, and
Accounting (AAA or Triple A) management for users who connect and
use a network service.

%package utils
Summary:        Clients utilities of the FreeRADIUS package
Requires:       %{name} = %{version}-%{release} libpcap >= 0.9.4

%description utils
Collection of FreeRADIUS utilities,additional features not found in any other server.

%package devel
Summary:        Development files of the FreeRADIUS package
Requires:       %{name} = %{version}-%{release}

%description devel
FreeRADIUS header files for development.

%package ldap
Summary:        LDAP support of the FreeRADIUS package
BuildRequires:  openldap-devel
Requires:       %{name} = %{version}-%{release}

%description ldap
FreeRADIUS plugin providing LDAP support.

%package krb5
Summary:        Kerberos 5 support of the FreeRADIUS package
BuildRequires:  krb5-devel
Requires:       %{name} = %{version}-%{release}

%description krb5
FreeRADIUS plugin providing Kerberos 5 authentication support.

%package perl
Summary:        Perl support of the FreeRADIUS package
Requires:       %{name} = %{version}-%{release} perl(:MODULE_COMPAT_%{perl_version})
BuildRequires:  perl-devel perl-generators perl(ExtUtils::Embed)

%description perl
FreeRADIUS plugin providing Perl support.

%package -n python3-freeradius
Summary:        Python 3 support of the FreeRADIUS package
BuildRequires:  python3-devel
Requires:       %{name} = %{version}-%{release}
%{?python_provide:%python_provide python3-freeradius}

%description -n python3-freeradius
FreeRADIUS plugin providing Python 3 support.

%package mysql
Summary:        MySQL support of the FreeRADIUS package
BuildRequires:  mariadb-connector-c-devel
Requires:       %{name} = %{version}-%{release}

%description mysql
FreeRADIUS plugin providing MySQL support.

%package postgresql
Summary:        Postgresql support of the FreeRADIUS package
BuildRequires:  postgresql-devel
Requires:       %{name} = %{version}-%{release}

%description postgresql
FreeRADIUS plugin providing PostgreSQL support.

%package sqlite
Summary:        SQLite support of the FreeRADIUS package
BuildRequires:  sqlite-devel
Requires:       %{name} = %{version}-%{release}

%description sqlite
FreeRADIUS plugin providing SQLite support.

%package help
Summary:        Help document file of the FreeRADIUS package
Requires:       %{name} = %{version}-%{release}
Provides:       %{name}-doc = %{version}-%{release}
Obsoletes:      %{name}-doc < %{version}-%{release}

%description help
Help document of the FreeRADIUS package.

%prep
%autosetup -n freeradius-server-%{version} -p1

%build
echo rlm_python3 >> src/modules/stable

export PY3_LIB_DIR=%{_libdir}/"$(python3-config --configdir |sed 's#/usr/lib/##g')"
export PY3_INC_DIR="$(python3 -c 'import sysconfig; print(sysconfig.get_config_var("INCLUDEPY"))')"

%configure \
        --libdir=%{_libdir}/freeradius --disable-openssl-version-check \
        --with-docdir=%{docdir} --with-rlm-sql_postgresql-include-dir=/usr/include/pgsql \
        --with-rlm-sql-postgresql-lib-dir=%{_libdir} \
        --with-rlm-sql_mysql-include-dir=/usr/include/mysql \
        --with-mysql-lib-dir=%{_libdir}/mariadb \
        --with-unixodbc-lib-dir=%{_libdir} --with-rlm-dbm-lib-dir=%{_libdir} \
        --with-rlm-krb5-include-dir=/usr/kerberos/include \
        --without-rlm_eap_ikev2 --without-rlm_eap_tnc --without-rlm_sql_iodbc \
        --without-rlm_sql_firebird --without-rlm_sql_db2 --without-rlm_sql_oracle \
        --without-rlm_unbound --without-rlm_redis --without-rlm_rediswho \
        --without-rlm_cache_memcached \
        --with-rlm_python3 --with-rlm-python3-lib-dir=$PY3_LIB_DIR \
        --with-rlm-python3-include-dir=$PY3_INC_DIR

%make_build

%install
install -d $RPM_BUILD_ROOT/%{_localstatedir}/lib/radiusd
make install R=$RPM_BUILD_ROOT

install -d $RPM_BUILD_ROOT/var/log/radius/radacct
touch $RPM_BUILD_ROOT/var/log/radius/radutmp
touch $RPM_BUILD_ROOT/var/log/radius/radius.log


install -D -m 644 %{SOURCE1} $RPM_BUILD_ROOT/%{_unitdir}/radiusd.service
install -D -m 644 %{SOURCE2} $RPM_BUILD_ROOT/%{_sysconfdir}/logrotate.d/radiusd
install -D -m 644 %{SOURCE3} $RPM_BUILD_ROOT/%{_sysconfdir}/pam.d/radiusd

install -d %{buildroot}%{_tmpfilesdir}
install -d %{buildroot}%{_localstatedir}/run/
install -d -m 0710 %{buildroot}%{_localstatedir}/run/radiusd/
install -d -m 0700 %{buildroot}%{_localstatedir}/run/radiusd/tmp
install -m 0644 %{SOURCE4} %{buildroot}%{_tmpfilesdir}/radiusd.conf

install -d $RPM_BUILD_ROOT%{_datadir}/snmp/mibs/
install -m 644 mibs/*RADIUS*.mib $RPM_BUILD_ROOT%{_datadir}/snmp/mibs/

rm -f $RPM_BUILD_ROOT/%{_sysconfdir}/raddb/mods-config/sql/ippool/mongo/queries.conf
rm -f $RPM_BUILD_ROOT/%{_sysconfdir}/raddb/mods-config/sql/main/mongo/queries.conf
rm -rf $RPM_BUILD_ROOT/etc/raddb/mods-config/sql/ippool/mssql

install -D LICENSE $RPM_BUILD_ROOT/%{docdir}/LICENSE.gpl
install -D src/lib/LICENSE $RPM_BUILD_ROOT/%{docdir}/LICENSE.lgpl
install -D src/LICENSE.openssl $RPM_BUILD_ROOT/%{docdir}/LICENSE.openssl

for f in COPYRIGHT CREDITS INSTALL.rst README.rst VERSION; do
    cp $f $RPM_BUILD_ROOT/%{docdir}
done

cd  $RPM_BUILD_ROOT/usr
file `find -type f`| grep -w ELF | awk -F":" '{print $1}' | for i in `xargs`
do
  chrpath -d $i
done
cd -
mkdir -p  $RPM_BUILD_ROOT/etc/ld.so.conf.d
echo "%{_bindir}/%{name}" > $RPM_BUILD_ROOT/etc/ld.so.conf.d/%{name}-%{_arch}.conf
echo "%{_libdir}/%{name}" >> $RPM_BUILD_ROOT/etc/ld.so.conf.d/%{name}-%{_arch}.conf

%pre
getent group  radiusd >/dev/null || /usr/sbin/groupadd -r -g 95 radiusd > /dev/null 2>&1
getent passwd radiusd >/dev/null || /usr/sbin/useradd  -r -g radiusd -u 95 -c "radiusd user" \
    -d %{_localstatedir}/lib/radiusd -s /sbin/nologin radiusd > /dev/null 2>&1

%post
/sbin/ldconfig
%systemd_post radiusd.service
if [ $1 -eq 1 ]; then
  if [ ! -e /etc/raddb/certs/server.pem ]; then
    /sbin/runuser -g radiusd -c 'umask 007; /etc/raddb/certs/bootstrap' > /dev/null 2>&1
  fi
fi
exit 0

%preun
%systemd_preun radiusd.service

%postun
/sbin/ldconfig
%systemd_postun_with_restart radiusd.service
if [ $1 -eq 0 ]; then
  getent passwd radiusd >/dev/null && /usr/sbin/userdel  radiusd > /dev/null 2>&1
  getent group  radiusd >/dev/null && /usr/sbin/groupdel radiusd > /dev/null 2>&1
fi
exit 0

/bin/systemctl try-restart radiusd.service >/dev/null 2>&1 || :

%files
%license %{docdir}/{LICENSE.gpl,LICENSE.lgpl,LICENSE.openssl}

%config(noreplace) %{_sysconfdir}/pam.d/radiusd
%config(noreplace) %{_sysconfdir}/logrotate.d/radiusd
%{_unitdir}/radiusd.service
%{_tmpfilesdir}/radiusd.conf
%dir %attr(710,radiusd,radiusd) %{_localstatedir}/run/radiusd
%dir %attr(700,radiusd,radiusd) %{_localstatedir}/run/radiusd/tmp
%dir %attr(755,radiusd,radiusd) %{_localstatedir}/lib/radiusd

# /etc/raddb dir
%dir %attr(755,root,radiusd) /etc/raddb
%defattr(-,root,radiusd)
/etc/raddb/README.rst
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/{panic.gdb,clients.conf,templates.conf,trigger.conf}
%attr(644,root,radiusd) %config(noreplace) /etc/raddb/dictionary
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/{proxy.conf,radiusd.conf}

%config /etc/raddb/hints
%config /etc/raddb/huntgroups
%config(noreplace) /etc/raddb/users
%exclude /etc/raddb/experimental.conf

# /etc/raddb/certs dir
%dir %attr(770,root,radiusd) /etc/raddb/certs
%config(noreplace) /etc/raddb/certs/{Makefile,passwords.mk,xpextensions}
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/certs/*.cnf
%attr(750,root,radiusd) /etc/raddb/certs/{bootstrap}
/etc/raddb/certs/README.md
%exclude /etc/raddb/certs/{*.crt,*.crl,*.csr,*.der,*.key,*.pem,*.p12}
%exclude /etc/raddb/certs/{index.*,serial*,dh,random}

# /etc/raddb/mods-config dir
%dir %attr(750,root,radiusd) /etc/raddb/mods-config
/etc/raddb/mods-config/README.rst
%dir %attr(750,root,radiusd) /etc/raddb/mods-config/attr_filter
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-config/attr_filter/*
%dir %attr(750,root,radiusd) /etc/raddb/mods-config/files
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-config/files/*
%dir %attr(750,root,radiusd) /etc/raddb/mods-config/preprocess
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-config/preprocess/*

%dir %attr(750,root,radiusd) /etc/raddb/mods-config/sql
%dir %attr(750,root,radiusd) /etc/raddb/mods-config/sql/{counter,cui,ippool,ippool-dhcp,main}
%exclude /etc/raddb/mods-config/sql/main/mssql
%exclude /etc/raddb/mods-config/sql/ippool/oracle
%exclude /etc/raddb/mods-config/sql/ippool-dhcp/oracle
%exclude /etc/raddb/mods-config/sql/main/oracle
%exclude /etc/raddb/mods-config/sql/moonshot-targeted-ids
%exclude /etc/raddb/mods-config/unbound/default.conf

# /etc/raddb/sites-available dir
%dir %attr(750,root,radiusd) /etc/raddb/sites-available
/etc/raddb/sites-available/README
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/sites-available/{control-socket,decoupled-accounting}
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/sites-available/{robust-proxy-accounting,soh,coa,coa-relay,example}
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/sites-available/{inner-tunnel,dhcp,check-eap-tls,status}
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/sites-available/{dhcp.relay,virtual.example.com}
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/sites-available/google-ldap-auth
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/sites-available/{originate-coa,vmps,default}
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/sites-available/{proxy-inner-tunnel,dynamic-clients}
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/sites-available/{copy-acct-to-home-server,buffered-sql}
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/sites-available/{tls,channel_bindings,challenge}
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/sites-available/{resource-check,totp} 
%exclude /etc/raddb/sites-available/abfab*

# /etc/raddb/sites-enabled dir
%dir %attr(750,root,radiusd) /etc/raddb/sites-enabled
%config(missingok) /etc/raddb/sites-enabled/{inner-tunnel,default}

# /etc/raddb/mods-available/ dir
%dir %attr(750,root,radiusd) /etc/raddb/mods-available
/etc/raddb/mods-available/README.rst
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-available/{always,attr_filter,cache,cache_auth}
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-available/{cache_eap,chap,counter,cui,date}
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-available/{detail,detail.example.com,detail.log}
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-available/{dhcp,dhcp_sqlippool,digest}
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-available/{dynamic_clients,eap,echo,etc_group}
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-available/{exec,expiration,expr,files,idn}
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-available/{inner-eap,ippool,linelog,logintime}
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-available/ldap_google
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-available/{mac2ip,mac2vlan,mschap,ntlm_auth}
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-available/{opendirectory,otp,pam,pap,passwd}
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-available/{preprocess,python3,python,radutmp,realm}
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-available/{redis,rediswho,replicate,smbpasswd}
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-available/{smsotp,soh,sometimes,sql,sqlcounter}
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-available/{sqlippool,sradutmp,unix,unpack}
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-available/{utf8,wimax,yubikey}
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-available/{dhcp_files,dhcp_passwd,dhcp_sql,sql_map,totp} 
%exclude /etc/raddb/mods-available/{unbound,couchbase,abfab*,moonshot-targeted-ids}

# /etc/raddb/mods-enabled dir
%dir %attr(750,root,radiusd) /etc/raddb/mods-enabled
%config(missingok) /etc/raddb/mods-enabled/{always,attr_filter,cache_eap,chap,date,detail,detail.log}
%config(missingok) /etc/raddb/mods-enabled/{dhcp,digest,dynamic_clients,eap,echo,exec,expiration,expr}
%config(missingok) /etc/raddb/mods-enabled/{files,linelog,logintime,mschap,ntlm_auth,pap,passwd,preprocess}
%config(missingok) /etc/raddb/mods-enabled/{radutmp,realm,replicate,soh,sradutmp,unix,unpack,utf8,totp}

# /etc/raddb/policy.d dir
%dir %attr(750,root,radiusd) /etc/raddb/policy.d
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/policy.d/{accounting,canonicalization,control,cui}
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/policy.d/{debug,dhcp,eap,filter,operator-name,rfc7542}
%exclude /etc/raddb/policy.d/{abfab*,moonshot-targeted-ids}

# /usr/sbin/binaries
%defattr(-,root,root)
/usr/sbin/{checkrad,raddebug,radiusd,radmin}
%exclude /usr/sbin/rc.radiusd

# dictionaries
%dir %attr(755,root,root) /usr/share/freeradius
/usr/share/freeradius/*

# logs
%dir %attr(700,radiusd,radiusd) /var/log/radius/
%dir %attr(700,radiusd,radiusd) /var/log/radius/radacct/
%ghost %attr(644,radiusd,radiusd) /var/log/radius/radutmp
%ghost %attr(600,radiusd,radiusd) /var/log/radius/radius.log

# libs
%attr(755,root,root) %{_libdir}/freeradius/lib*.so*
%dir %attr(755,root,root) %{_libdir}/freeradius
%{_libdir}/freeradius/{proto_dhcp.so,proto_vmps.so,rlm_always.so,rlm_attr_filter.so,rlm_cache.so}
%{_libdir}/freeradius/{rlm_cache_rbtree.so,rlm_chap.so,rlm_counter.so,rlm_cram.so,rlm_date.so}
%{_libdir}/freeradius/{rlm_detail.so,rlm_dhcp.so,rlm_digest.so,rlm_dynamic_clients.so,rlm_eap.so}
%{_libdir}/freeradius/{rlm_eap_fast.so,rlm_eap_gtc.so,rlm_eap_leap.so,rlm_eap_md5.so,rlm_eap_mschapv2.so}
%{_libdir}/freeradius/{rlm_eap_peap.so,rlm_eap_pwd.so,rlm_eap_sim.so,rlm_eap_tls.so,rlm_eap_ttls.so}
%{_libdir}/freeradius/{rlm_exec.so,rlm_expiration.so,rlm_expr.so,rlm_files.so,rlm_ippool.so,rlm_linelog.so}
%{_libdir}/freeradius/{rlm_logintime.so,rlm_mschap.so,rlm_otp.so,rlm_pam.so,rlm_pap.so,rlm_passwd.so}
%{_libdir}/freeradius/{rlm_preprocess.so,rlm_radutmp.so,rlm_realm.so,rlm_replicate.so,rlm_soh.so}
%{_libdir}/freeradius/{rlm_sometimes.so,rlm_sql.so,rlm_sqlcounter.so,rlm_sqlippool.so,rlm_sql_null.so}
%{_libdir}/freeradius/{rlm_unix.so,rlm_unpack.so,rlm_utf8.so,rlm_wimax.so,rlm_yubikey.so}
%{_libdir}/freeradius/{rlm_sql_map.so,rlm_totp.so}
%exclude %{_libdir}/freeradius/{*.a,*.la,rlm_test.so}

# MIB files
%{_datadir}/snmp/mibs/*RADIUS*.mib

# unixODBC
%{_libdir}/freeradius/rlm_sql_unixodbc.so

# rest
%{_libdir}/freeradius/rlm_rest.so
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-available/rest

%config(noreplace) /etc/ld.so.conf.d/*

%files help
%doc %{docdir}/
# utils man pages
%doc %{_mandir}/man1/*
# main man pages
%doc %{_mandir}/man5/*
%doc %{_mandir}/man8/*

%files utils
/usr/bin/*

%files devel
/usr/include/freeradius

%files krb5
%{_libdir}/freeradius/rlm_krb5.so
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-available/krb5

%files perl
%{_libdir}/freeradius/rlm_perl.so
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-available/perl
%dir %attr(750,root,radiusd) /etc/raddb/mods-config/perl
%attr(640,root,radiusd) /etc/raddb/mods-config/perl/example.pl

%files -n python3-freeradius
%dir %attr(750,root,radiusd) /etc/raddb/mods-config/python3
%{_libdir}/freeradius/rlm_python3.so
/etc/raddb/mods-config/python3/{example.py*,radiusd.py*}

%files mysql
%{_libdir}/freeradius/rlm_sql_mysql.so
/etc/raddb/mods-config/sql/main/ndb/README

%dir %attr(750,root,radiusd) /etc/raddb/mods-config/sql/counter/mysql
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-config/sql/counter/mysql/*

%dir %attr(750,root,radiusd) /etc/raddb/mods-config/sql/cui/mysql
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-config/sql/cui/mysql/* 
	
%dir %attr(750,root,radiusd) /etc/raddb/mods-config/sql/dhcp/mssql	
%attr(640,root,radiusd) /etc/raddb/mods-config/sql/dhcp/mssql/queries.conf	
%attr(640,root,radiusd) /etc/raddb/mods-config/sql/dhcp/mssql/schema.sql
		
%dir %attr(750,root,radiusd) /etc/raddb/mods-config/sql/dhcp/mysql	
%attr(640,root,radiusd) /etc/raddb/mods-config/sql/dhcp/mysql/queries.conf	
%attr(640,root,radiusd) /etc/raddb/mods-config/sql/dhcp/mysql/schema.sql	
%attr(640,root,radiusd) /etc/raddb/mods-config/sql/dhcp/mysql/setup.sql	 
	
%dir %attr(750,root,radiusd) /etc/raddb/mods-config/sql/dhcp/oracle	
%attr(640,root,radiusd) /etc/raddb/mods-config/sql/dhcp/oracle/queries.conf	
%attr(640,root,radiusd) /etc/raddb/mods-config/sql/dhcp/oracle/schema.sql 
	
%dir %attr(750,root,radiusd) /etc/raddb/mods-config/sql/dhcp/postgresql	
%attr(640,root,radiusd) /etc/raddb/mods-config/sql/dhcp/postgresql/queries.conf	
%attr(640,root,radiusd) /etc/raddb/mods-config/sql/dhcp/postgresql/schema.sql	
%attr(640,root,radiusd) /etc/raddb/mods-config/sql/dhcp/postgresql/setup.sql	
 
	
%dir %attr(750,root,radiusd) /etc/raddb/mods-config/sql/dhcp/sqlite
	
%attr(640,root,radiusd) /etc/raddb/mods-config/sql/dhcp/sqlite/queries.conf
	
%attr(640,root,radiusd) /etc/raddb/mods-config/sql/dhcp/sqlite/schema.sql

%dir %attr(750,root,radiusd) /etc/raddb/mods-config/sql/ippool/mysql
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-config/sql/ippool/mysql/*

%dir %attr(750,root,radiusd) /etc/raddb/mods-config/sql/ippool-dhcp/mysql
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-config/sql/ippool-dhcp/mysql/*

%dir %attr(750,root,radiusd) /etc/raddb/mods-config/sql/ippool-dhcp/mssql	
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-config/sql/ippool-dhcp/mssql/procedure.sql	
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-config/sql/ippool-dhcp/mssql/queries.conf	
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-config/sql/ippool-dhcp/mssql/schema.sql 
	
%dir %attr(750,root,radiusd) /etc/raddb/mods-config/sql/ippool-dhcp/postgresql	
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-config/sql/ippool-dhcp/postgresql/procedure.sql	
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-config/sql/ippool-dhcp/postgresql/queries.conf	
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-config/sql/ippool-dhcp/postgresql/schema.sql

%dir %attr(750,root,radiusd) /etc/raddb/mods-config/sql/main/mysql
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-config/sql/main/mysql/*

%dir %attr(750,root,radiusd) /etc/raddb/mods-config/sql/main/mysql/extras	
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-config/sql/main/mysql/extras/wimax/*

%dir %attr(750,root,radiusd) /etc/raddb/mods-config/sql/main/ndb
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-config/sql/main/ndb/{setup.sql,schema.sql}

%files postgresql
%{_libdir}/freeradius/rlm_sql_postgresql.so
%dir %attr(750,root,radiusd) /etc/raddb/mods-config/sql/counter/postgresql
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-config/sql/counter/postgresql/*

%dir %attr(750,root,radiusd) /etc/raddb/mods-config/sql/cui/postgresql
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-config/sql/cui/postgresql/*

%dir %attr(750,root,radiusd) /etc/raddb/mods-config/sql/ippool/postgresql
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-config/sql/ippool/postgresql/*

%dir %attr(750,root,radiusd) /etc/raddb/mods-config/sql/main/postgresql
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-config/sql/main/postgresql/*

	
%dir %attr(750,root,radiusd) /etc/raddb/mods-config/sql/main/postgresql/extras	
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-config/sql/main/postgresql/extras/*
%{_libdir}/freeradius/rlm_sql_postgresql.so 

%files sqlite
%{_libdir}/freeradius/rlm_sql_sqlite.so
%dir %attr(750,root,radiusd) /etc/raddb/mods-config/sql/counter/sqlite
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-config/sql/counter/sqlite/*

%dir %attr(750,root,radiusd) /etc/raddb/mods-config/sql/cui/sqlite
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-config/sql/cui/sqlite/*

%dir %attr(750,root,radiusd) /etc/raddb/mods-config/sql/ippool/sqlite
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-config/sql/ippool/sqlite/*

%dir %attr(750,root,radiusd) /etc/raddb/mods-config/sql/ippool-dhcp/sqlite
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-config/sql/ippool-dhcp/sqlite/*

%dir %attr(750,root,radiusd) /etc/raddb/mods-config/sql/main/sqlite
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-config/sql/main/sqlite/*

%files ldap
%{_libdir}/freeradius/rlm_ldap.so
%attr(640,root,radiusd) %config(noreplace) /etc/raddb/mods-available/ldap

%changelog
* Thu Feb 2 2023 liyanan <liyanan32@h-partners.com> - 3.0.26-1
- Update to 3.0.26

* Wed Dec 21 2022 jiangpeng <jiangpeng01@ncti-gba.cn> - 3.0.25-2
- Fix CVE-2022-41859 and CVE-2022-41860 and CVE-2022-41861

* Thu Dec 30 2021 baizhonggui <baizhonggui@huawei.com> - 3.0.25-1
- update to 3.0.25

* Wed Sep 08 2021 chenchen <chen_aka_jan@163.com> - 3.0.21-8
- del rpath from some binaries and bin

* Wed Jun 2 2021 baizhonggui <baizhonggui@huawei.com> - 3.0.21-7
- Fix building error: configure: error: no acceptable C compiler found in $PATH
- Add gcc in BuildRequires

* Mon Apr 26 2021 lingsheng <lingsheng@huawei.com> - 3.0.21-6
- Add missing backslash that precluded server from starting

* Thu Mar 11 2021 lingsheng <lingsheng@huawei.com> - 3.0.21-5
* Fix radeapclient option -q

* Thu Feb 25 2021 lingsheng <lingsheng@huawei.com> - 3.0.21-4
- Fix file conflicts in freeradius-mysql and freeradius-postgresql

* Fri Dec 25 2020 sunguoshuai <sunguoshuai@huawei.com> - 3.0.21-3
- Remove unused arguement

* Wed Nov 11 2020 zhangtao <zhangtao221@huawei.com> - 3.0.21-2
- delete the unused file

* Fri Oct 23 2020 huanghaitao <huanghaitao8@huawei.com> - 3.0.21-1
- Update to 3.0.21 and switch python3 module support

* Mon Aug 31 2020 lingsheng <lingsheng@huawei.com> - 3.0.15-18
- Fix tmpfile path to /run

* Fri Feb 14 2020 yanzhihua <yanzhihua4@huawei.com> - 3.0.15-16
- Package init


