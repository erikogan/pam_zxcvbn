Summary: A PAM module for password entropy checking
Name: pam_zxcvbn
Version: 0.1
Release: 1%{?dist}
License: MIT
Source0: https://github.com/erikogan/pam_zxcvbn/archive/v%{version}.tar.gz#/%{name}-%{version}.tar.gz

%global _moduledir %{_libdir}/security

Requires: libzxcvbn >= 2.4
Requires: pam%{?_isa}
BuildRequires: libzxcvbn-devel
BuildRequires: gettext
BuildRequires: pam-devel

URL: https://github.com/erikogan/pam_zxcvbn

%description
PAM integration of the library for password entropy checks based on common
names, words and patterns in US English.

%prep
%setup -q -n %{name}

%build
make %{?_smp_mflags}

%install
make install DESTDIR=$RPM_BUILD_ROOT LIBDIR=%{_libdir}

%check
# Nothing yet

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-,root,root,-)
%doc README.md LICENSE
%{_moduledir}/pam_zxcvbn.so

%changelog
* Sat Sep 28 2019 Erik Ogan <erik@stealthymonkeys.com> 0.1-1
- Initial Spec
