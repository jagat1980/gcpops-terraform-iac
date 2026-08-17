# Spring Security & JPA Query Parameterization Security Guide

## 1. SQL Injection Prevention in Java / Spring Boot

### Unsafe Dynamic Query Concatenation (VULNERABLE)
```java
// JAVA-S2077 / CWE-89 Vulnerability
public List<Account> findAccounts(String accountNumber) {
    String query = "SELECT a FROM Account a WHERE a.accountNumber = '" + accountNumber + "'";
    return entityManager.createQuery(query, Account.class).getResultList();
}
```

### Remediated Parameterized JPA Query (SECURE)
```java
// Parameterized Positional or Named Binding
public List<Account> findAccounts(String accountNumber) {
    TypedQuery<Account> query = entityManager.createQuery(
        "SELECT a FROM Account a WHERE a.accountNumber = :accountNumber", Account.class);
    query.setParameter("accountNumber", accountNumber);
    return query.getResultList();
}
```

## 2. Spring Security Authorization & Access Control

### Recommended Security Annotations
```java
@RestController
@RequestMapping("/api/v1/accounts")
public class AccountController {

    @PreAuthorize("hasRole('BANK_ADMIN') and hasPermission(#accountId, 'Account', 'READ')")
    @GetMapping("/{accountId}")
    public ResponseEntity<AccountDTO> getAccount(@PathVariable String accountId) {
        return ResponseEntity.ok(accountService.getAccountDetails(accountId));
    }
}
```
