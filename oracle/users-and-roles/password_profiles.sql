-- =============================================
-- Database:    Oracle 19c/21c
-- Author:      Suleman
-- Description: Password Security Profiles
--              Different profiles for different
--              types of users
-- =============================================

-- -----------------------------------------------
-- PROFILE 1: Application Service Accounts
--            Service accounts - no expiry
--            but strict lockout policy
-- -----------------------------------------------
CREATE PROFILE app_profile LIMIT
    -- Password Complexity
    PASSWORD_VERIFY_FUNCTION    ora12c_strong_verify_function,
    PASSWORD_LENGTH             12,

    -- Password Lifetime
    PASSWORD_LIFE_TIME          365,        -- Expire after 1 year
    PASSWORD_GRACE_TIME         7,          -- 7 day grace period
    PASSWORD_REUSE_TIME         365,        -- Cannot reuse for 1 year
    PASSWORD_REUSE_MAX          10,         -- Cannot reuse last 10 passwords

    -- Login Security
    FAILED_LOGIN_ATTEMPTS       5,          -- Lock after 5 failures
    PASSWORD_LOCK_TIME          1/24,       -- Lock for 1 hour (1/24 day)

    -- Session Limits
    SESSIONS_PER_USER           10,         -- Max 10 sessions per user
    IDLE_TIME                   30,         -- Disconnect after 30 min idle
    CONNECT_TIME                480;        -- Max 8 hour session

-- -----------------------------------------------
-- PROFILE 2: DBA Users
--            Higher security, shorter expiry
-- -----------------------------------------------
CREATE PROFILE dba_profile LIMIT
    PASSWORD_VERIFY_FUNCTION    ora12c_strong_verify_function,
    PASSWORD_LENGTH             14,         -- Longer password for DBAs

    PASSWORD_LIFE_TIME          90,         -- Expire every 90 days
    PASSWORD_GRACE_TIME         5,
    PASSWORD_REUSE_TIME         365,
    PASSWORD_REUSE_MAX          12,

    FAILED_LOGIN_ATTEMPTS       3,          -- Stricter - 3 attempts
    PASSWORD_LOCK_TIME          1/12,       -- Lock for 2 hours

    SESSIONS_PER_USER           3,          -- Limit DBA sessions
    IDLE_TIME                   15,         -- Shorter idle timeout
    CONNECT_TIME                240;        -- Max 4 hours

-- -----------------------------------------------
-- PROFILE 3: Developer Profile (Dev/Test only)
-- -----------------------------------------------
CREATE PROFILE dev_profile LIMIT
    PASSWORD_VERIFY_FUNCTION    ora12c_strong_verify_function,
    PASSWORD_LENGTH             10,

    PASSWORD_LIFE_TIME          180,
    PASSWORD_GRACE_TIME         14,
    PASSWORD_REUSE_TIME         180,
    PASSWORD_REUSE_MAX          6,

    FAILED_LOGIN_ATTEMPTS       10,
    PASSWORD_LOCK_TIME          1/48,       -- Lock for 30 minutes

    SESSIONS_PER_USER           5,
    IDLE_TIME                   60,
    CONNECT_TIME                600;

-- -----------------------------------------------
-- Verify Profiles
-- -----------------------------------------------
SELECT
    PROFILE,
    RESOURCE_NAME,
    LIMIT
FROM DBA_PROFILES
WHERE PROFILE IN ('APP_PROFILE','DBA_PROFILE','DEV_PROFILE')
ORDER BY PROFILE, RESOURCE_NAME;

-- -----------------------------------------------
-- Lock Default Accounts That Are Not Needed
-- -----------------------------------------------
BEGIN
    FOR u IN (
        SELECT USERNAME
        FROM DBA_USERS
        WHERE USERNAME IN (
            'ANONYMOUS',
            'APEX_PUBLIC_USER',
            'FLOWS_FILES',
            'HR',
            'IX',
            'OE',
            'PM',
            'SCOTT',
            'SH'
        )
        AND ACCOUNT_STATUS = 'OPEN'
    )
    LOOP
        EXECUTE IMMEDIATE
            'ALTER USER ' || u.USERNAME || ' ACCOUNT LOCK';
        DBMS_OUTPUT.PUT_LINE('Locked: ' || u.USERNAME);
    END LOOP;
END;
/

-- -----------------------------------------------
-- Check for Users with Default Passwords
-- -----------------------------------------------
SELECT
    d.USERNAME,
    d.ACCOUNT_STATUS
FROM DBA_USERS_WITH_DEFPWD d
ORDER BY d.USERNAME;
