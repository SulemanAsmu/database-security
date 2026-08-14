# 🛡️ Database Security Checklist

## 🔑 Principle of Least Privilege
- [ ] Users only have permissions they need
- [ ] No user has DBA privilege unless required
- [ ] Application users cannot access DBA views
- [ ] Separate accounts for each application
- [ ] No shared accounts between users

## 👤 User Account Management
- [ ] Default accounts are locked or removed
- [ ] Passwords meet complexity requirements
- [ ] Password expiry is configured
- [ ] Failed login lockout is configured
- [ ] Inactive accounts are disabled
- [ ] Service accounts have minimal privileges

## 📋 Auditing
- [ ] Failed login attempts are audited
- [ ] Privileged user actions are audited
- [ ] DML on sensitive tables is audited
- [ ] DDL changes are audited
- [ ] Audit logs are stored securely
- [ ] Audit logs are reviewed regularly

## 🔐 Encryption
- [ ] Data at rest is encrypted (TDE)
- [ ] Network connections use SSL/TLS
- [ ] Sensitive columns are encrypted
- [ ] Backup files are encrypted
- [ ] Connection passwords are not in plain text

## 🛡️ Network Security
- [ ] Database port is not exposed to internet
- [ ] Firewall rules restrict DB access
- [ ] Only app servers can connect to DB
- [ ] Remote DBA access uses VPN
- [ ] Listener is password protected

## 🔍 Regular Security Reviews
- [ ] Monthly review of user privileges
- [ ] Quarterly password rotation
- [ ] Review audit logs weekly
- [ ] Annual penetration testing
- [ ] Regular vulnerability scanning

## ⚠️ Common Security Mistakes
1. Using SYS or SYSTEM for application connections
2. Storing passwords in plain text config files
3. Giving DBA role to developers
4. Not auditing privileged user activity
5. Using default passwords on service accounts
6. Not encrypting sensitive data columns
7. Ignoring failed login alerts
8. Not removing terminated employee accounts
