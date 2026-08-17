# Oracle PL/SQL Dynamic SQL Security & Injection Prevention

## 1. Oracle PL/SQL Dynamic Injection Vectors

### Unsafe Dynamic SQL with EXECUTE IMMEDIATE (VULNERABLE)
```sql
-- Vulnerable to PL/SQL Injection
PROCEDURE get_user_balance (
    p_user_id IN VARCHAR2,
    p_balance OUT NUMBER
) IS
    v_sql VARCHAR2(500);
BEGIN
    v_sql := 'SELECT balance FROM bank_accounts WHERE user_id = ''' || p_user_id || '''';
    EXECUTE IMMEDIATE v_sql INTO p_balance;
END get_user_balance;
```

### Remediated Oracle Bind Variables (SECURE)
```sql
-- Secure Parameterized PL/SQL
PROCEDURE get_user_balance (
    p_user_id IN VARCHAR2,
    p_balance OUT NUMBER
) IS
    v_sql VARCHAR2(500);
BEGIN
    v_sql := 'SELECT balance FROM bank_accounts WHERE user_id = :1';
    EXECUTE IMMEDIATE v_sql INTO p_balance USING p_user_id;
END get_user_balance;
```

## 2. Oracle DBMS_ASSERT Sanitization
```sql
-- Using DBMS_ASSERT for dynamic table or column names
v_clean_table := DBMS_ASSERT.ENQUOTE_NAME(DBMS_ASSERT.QUALIFIED_SQL_NAME(p_table_name));
```
