contrail-delegated-usercert-client
==================================

This is an example of usage of the delegated user certificate client.

First, put 

```bash
<IP access point> contrail.federation.ca under 
```
under ```/etc/hosts```

```bash
$ svn co svn://svn.forge.objectweb.org/svnroot/contrail/trunk/common/contrail-parent
$ mvn clean install
$ svn co svn://svn.forge.objectweb.org/svnroot/contrail/trunk/common/security-commons
$ mvn clean compile
```
Now, change ```DelegatedUserCertClientTest.java``` with the one provided in this repo.

It should work with certificates presented within certs directory.
