-- =============================================
-- Database:    PostgreSQL 15
-- Author:      Suleman
-- Description: PostgreSQL Users, Roles Security
-- =============================================

\c companydb;

-- -----------------------------------------------
-- STEP 1: Create Roles
-- -----------------------------------------------

-- Read Only Role
CREATE ROLE app_read_only;
GRANT CONNECT  ON DATABASE companydb TO app_read_only;
GRANT USAGE    ON SCHEMA public       TO app_read_only;
GRANT SELECT   ON ALL TABLES IN SCHEMA public TO app_read_only;

-- Read Write Role
CREATE ROLE app_read_write;
GRANT CONNECT  ON DATABASE companydb TO app_read_write;
GRANT USAGE    ON SCHEMA public       TO app_read_write;
GRANT SELECT, INSERT, UPDATE, DELETE
    ON ALL TABLES IN SCHEMA public TO app_read_write;
GRANT USAGE, SELECT
    ON ALL SEQUENCES IN SCHEMA public TO app_read_write;

-- Developer Role
CREATE ROLE app_developer;
GRANT app_read_write TO app_developer;
GRANT CREATE ON SCHEMA public TO app_developer;

-- -----------------------------------------------
-- STEP 2: Create Users
-- -----------------------------------------------

-- Application Service Account
CREATE USER app_service
    WITH PASSWORD 'AppService#2024!'
    CONNECTION LIMIT 20
    VALID UNTIL '2025-12-31';

GRANT app_read_write TO app_service;

-- Report User
CREATE USER report_svc
    WITH PASSWORD 'ReportSvc#2024!'
    CONNECTION LIMIT 5
    VALID UNTIL '2025-06-30';

GRANT app_read_only TO report_svc;

-- DBA User
CREATE USER dba_john
    WITH PASSWORD    'DbaJohn#2024!'
    CREATEROLE
    CREATEDB
    CONNECTION LIMIT 3;

-- -----------------------------------------------
-- STEP 3: Row Level Security (RLS)
-- -----------------------------------------------

-- Enable RLS on Employees table
ALTER TABLE Employees ENABLE ROW LEVEL SECURITY;

-- Policy: Users see only their department
CREATE POLICY dept_isolation_policy
    ON Employees
    USING (
        DepartmentID = (
            SELECT DepartmentID
            FROM Employees
            WHERE LOWER(Email) = LOWER(CURRENT_USER || '@company.com')
        )
        OR
        pg_has_role(CURRENT_USER, 'app_developer', 'MEMBER')
    );

-- DBA bypasses RLS
ALTER TABLE Employees FORCE ROW LEVEL SECURITY;

-- -----------------------------------------------
-- STEP 4: Password Configuration (pg_hba.conf)
-- -----------------------------------------------
/*
Add to pg_hba.conf:
# TYPE  DATABASE    USER         ADDRESS          METHOD
local   all         postgres                      peer
local   all         all                           md5
host    companydb   app_service  192.168.1.0/24   scram-sha-256
host    companydb   report_svc   192.168.1.0/24   scram-sha-256
host    companydb   dba_john     192.168.1.50/32  scram-sha-256
host    all         all          0.0.0.0/0        reject
*/

-- -----------------------------------------------
-- STEP 5: Verify Security
-- -----------------------------------------------

-- Show all users and their attributes
SELECT
    rolname         AS username,
    rolsuper        AS superuser,
    rolcreaterole   AS can_create_role,
    rolcreatedb     AS can_create_db,
    rolcanlogin     AS can_login,
    rolconnlimit    AS conn_limit,
    rolvaliduntil   AS valid_until
FROM pg_roles
WHERE rolcanlogin = TRUE
ORDER BY rolname;

-- Show role memberships
SELECT
    r.rolname   AS role,
    m.rolname   AS member
FROM pg_roles r
JOIN pg_auth_members am ON r.oid = am.roleid
JOIN pg_roles m         ON m.oid = am.member
ORDER BY r.rolname, m.rolname;
