# React & Angular Frontend Security & XSS Prevention Guide

## 1. React DOM Injection Prevention

### Unsafe dangerouslySetInnerHTML Usage (VULNERABLE)
```tsx
// Vulnerable to Reflected / Stored XSS
function UserBio({ userComment }: { userComment: string }) {
    return <div dangerouslySetInnerHTML={{ __html: userComment }} />;
}
```

### Remediated DOMPurify Sanitization in React (SECURE)
```tsx
import DOMPurify from 'dompurify';

function UserBio({ userComment }: { userComment: string }) {
    const cleanHTML = DOMPurify.sanitize(userComment, { ALLOWED_TAGS: ['b', 'i', 'em', 'strong'] });
    return <div dangerouslySetInnerHTML={{ __html: cleanHTML }} />;
}
```

## 2. Angular DomSanitizer Usage

### Remediated Angular Security Policy
```typescript
import { Component, SecurityContext } from '@angular/core';
import { DomSanitizer } from '@angular/platform-browser';

@Component({
  selector: 'app-user-profile',
  template: `<div [innerHTML]="safeContent"></div>`
})
public class UserProfileComponent {
    public safeContent: string;

    constructor(private sanitizer: DomSanitizer) {}

    public setBio(rawInput: string) {
        this.safeContent = this.sanitizer.sanitize(SecurityContext.HTML, rawInput) || '';
    }
}
```
