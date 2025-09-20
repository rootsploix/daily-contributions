// 🔒 Advanced Security Hardening for TypeScript Web Framework
// Comprehensive XSS protection, CSP enforcement, and browser security

/**
 * RootsploiX TypeScript Advanced Security Hardening Module
 * 
 * This module provides enterprise-grade security hardening for the TypeScript
 * Advanced Web Framework, including Content Security Policy enforcement,
 * advanced XSS protection, prototype pollution prevention, and real-time
 * security monitoring capabilities.
 * 
 * @author RootsploiX Security Team
 * @version 1.1.0
 * @license Educational and Research Purposes Only
 */

// Security configuration interfaces
interface SecurityConfig {
  enableCSP: boolean;
  enableXSSProtection: boolean;
  enablePrototypePollutionGuard: boolean;
  enableSecurityMonitoring: boolean;
  strictMode: boolean;
  logSecurityEvents: boolean;
}

interface CSPDirectives {
  'default-src': string[];
  'script-src': string[];
  'style-src': string[];
  'img-src': string[];
  'connect-src': string[];
  'font-src': string[];
  'object-src': string[];
  'media-src': string[];
  'frame-src': string[];
  'sandbox': string[];
  'report-uri': string[];
  'base-uri': string[];
  'form-action': string[];
}

interface SecurityEvent {
  type: SecurityEventType;
  severity: SecuritySeverity;
  description: string;
  timestamp: Date;
  userAgent: string;
  sourceIP?: string;
  payload?: string;
  blocked: boolean;
  mitigation: string;
}

interface TrustedTypePolicy {
  createHTML: (input: string) => TrustedHTML;
  createScript: (input: string) => TrustedScript;
  createScriptURL: (input: string) => TrustedScriptURL;
}

// Security enums
enum SecurityEventType {
  XSS_ATTEMPT = 'xss_attempt',
  PROTOTYPE_POLLUTION = 'prototype_pollution',
  CSP_VIOLATION = 'csp_violation',
  CLICKJACKING_ATTEMPT = 'clickjacking_attempt',
  SUSPICIOUS_FINGERPRINTING = 'suspicious_fingerprinting',
  MALICIOUS_PAYLOAD = 'malicious_payload',
  INJECTION_ATTEMPT = 'injection_attempt'
}

enum SecuritySeverity {
  INFO = 0,
  LOW = 1,
  MEDIUM = 2,
  HIGH = 3,
  CRITICAL = 4
}

// Security exception classes
class SecurityError extends Error {
  constructor(message: string, public eventType: SecurityEventType) {
    super(message);
    this.name = 'SecurityError';
  }
}

class XSSAttemptError extends SecurityError {
  constructor(message: string) {
    super(message, SecurityEventType.XSS_ATTEMPT);
    this.name = 'XSSAttemptError';
  }
}

class PrototypePollutionError extends SecurityError {
  constructor(message: string) {
    super(message, SecurityEventType.PROTOTYPE_POLLUTION);
    this.name = 'PrototypePollutionError';
  }
}

/**
 * Advanced Content Security Policy Manager
 * Implements strict CSP policies with dynamic nonce generation
 */
class ContentSecurityPolicyManager {
  private config: CSPDirectives;
  private nonce: string;
  private violationReports: SecurityEvent[] = [];

  constructor() {
    this.nonce = this.generateCSPNonce();
    this.config = this.getDefaultCSPConfig();
    this.setupCSPViolationReporting();
  }

  private getDefaultCSPConfig(): CSPDirectives {
    return {
      'default-src': ["'self'"],
      'script-src': ["'self'", `'nonce-${this.nonce}'`, "'strict-dynamic'"],
      'style-src': ["'self'", "'unsafe-inline'"],
      'img-src': ["'self'", "data:", "https:"],
      'connect-src': ["'self'"],
      'font-src': ["'self'", "https:", "data:"],
      'object-src': ["'none'"],
      'media-src': ["'self'"],
      'frame-src': ["'none'"],
      'sandbox': ["allow-forms", "allow-scripts", "allow-same-origin"],
      'report-uri': ["/csp-violation-report-endpoint/"],
      'base-uri': ["'self'"],
      'form-action': ["'self'"]
    };
  }

  private generateCSPNonce(): string {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  public enforceCSP(): void {
    const cspString = this.generateCSPString();
    
    // Set CSP via meta tag
    const meta = document.createElement('meta');
    meta.httpEquiv = 'Content-Security-Policy';
    meta.content = cspString;
    document.head.appendChild(meta);

    // Also set via HTTP header if possible (requires server support)
    console.log('🔒 CSP Enforced:', cspString);
  }

  private generateCSPString(): string {
    return Object.entries(this.config)
      .map(([directive, sources]) => {
        if (sources.length === 0) return '';
        return `${directive} ${sources.join(' ')}`;
      })
      .filter(directive => directive !== '')
      .join('; ');
  }

  private setupCSPViolationReporting(): void {
    document.addEventListener('securitypolicyviolation', (e) => {
      const violation: SecurityEvent = {
        type: SecurityEventType.CSP_VIOLATION,
        severity: SecuritySeverity.HIGH,
        description: `CSP violation: ${e.violatedDirective} - ${e.blockedURI}`,
        timestamp: new Date(),
        userAgent: navigator.userAgent,
        payload: e.originalPolicy,
        blocked: true,
        mitigation: 'Content blocked by CSP'
      };

      this.violationReports.push(violation);
      this.reportSecurityEvent(violation);
    });
  }

  public getCurrentNonce(): string {
    return this.nonce;
  }

  public refreshNonce(): string {
    this.nonce = this.generateCSPNonce();
    this.config['script-src'] = this.config['script-src'].map(src => 
      src.startsWith("'nonce-") ? `'nonce-${this.nonce}'` : src
    );
    return this.nonce;
  }

  private reportSecurityEvent(event: SecurityEvent): void {
    console.warn('🚨 CSP Violation:', event);
    
    // Send to security monitoring endpoint
    fetch('/api/security/report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(event)
    }).catch(err => console.error('Failed to report security event:', err));
  }
}

/**
 * Advanced XSS Protection System
 * Multi-layered defense against various XSS attack vectors
 */
class AdvancedXSSProtection {
  private trustedTypePolicy: TrustedTypePolicy;
  private xssDetectionPatterns: RegExp[];
  private sanitizationRules: Map<string, (input: string) => string>;

  constructor() {
    this.initializeTrustedTypes();
    this.setupXSSDetectionPatterns();
    this.initializeSanitizationRules();
  }

  private initializeTrustedTypes(): void {
    if ('trustedTypes' in window) {
      this.trustedTypePolicy = trustedTypes.createPolicy('rootsploix-security', {
        createHTML: (input: string) => this.sanitizeHTML(input),
        createScript: (input: string) => this.sanitizeScript(input),
        createScriptURL: (input: string) => this.sanitizeScriptURL(input)
      });
    }
  }

  private setupXSSDetectionPatterns(): void {
    this.xssDetectionPatterns = [
      // Script injection patterns
      /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
      /<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi,
      /<object\b[^<]*(?:(?!<\/object>)<[^<]*)*<\/object>/gi,
      /<embed\b[^<]*>/gi,
      
      // Event handler patterns
      /on\w+\s*=\s*["'][^"']*["']/gi,
      /javascript\s*:/gi,
      /vbscript\s*:/gi,
      /data\s*:\s*text\/html/gi,
      
      // DOM-based XSS patterns
      /document\.write\s*\(/gi,
      /innerHTML\s*=/gi,
      /outerHTML\s*=/gi,
      /document\.domain/gi,
      
      // Advanced XSS vectors
      /expression\s*\(/gi,
      /import\s*\(/gi,
      /eval\s*\(/gi,
      /Function\s*\(/gi,
      /setTimeout\s*\(/gi,
      /setInterval\s*\(/gi,
      
      // CSS injection patterns
      /expression\s*\(/gi,
      /@import/gi,
      /javascript\s*:/gi,
      
      // SVG-based XSS
      /<svg[^>]*onload\s*=/gi,
      /<svg[^>]*onerror\s*=/gi,
    ];
  }

  private initializeSanitizationRules(): void {
    this.sanitizationRules = new Map([
      ['script', (input: string) => input.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')],
      ['iframe', (input: string) => input.replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, '')],
      ['object', (input: string) => input.replace(/<object\b[^<]*(?:(?!<\/object>)<[^<]*)*<\/object>/gi, '')],
      ['embed', (input: string) => input.replace(/<embed\b[^<]*>/gi, '')],
      ['javascript', (input: string) => input.replace(/javascript\s*:/gi, '')],
      ['vbscript', (input: string) => input.replace(/vbscript\s*:/gi, '')],
      ['events', (input: string) => input.replace(/on\w+\s*=\s*["'][^"']*["']/gi, '')],
      ['eval', (input: string) => input.replace(/eval\s*\(/gi, 'eval_blocked(')],
      ['function', (input: string) => input.replace(/Function\s*\(/gi, 'Function_blocked(')],
    ]);
  }

  public sanitizeUserInput(input: unknown, context: 'html' | 'attribute' | 'script' = 'html'): string {
    if (typeof input !== 'string') {
      throw new XSSAttemptError('Input must be string type for sanitization');
    }

    // Detect potential XSS attempts
    const detectedPatterns = this.detectXSSPatterns(input);
    if (detectedPatterns.length > 0) {
      this.reportXSSAttempt(input, detectedPatterns);
    }

    // Apply context-specific sanitization
    let sanitized = input;
    
    switch (context) {
      case 'html':
        sanitized = this.sanitizeHTML(input);
        break;
      case 'attribute':
        sanitized = this.sanitizeAttribute(input);
        break;
      case 'script':
        sanitized = this.sanitizeScript(input);
        break;
    }

    return sanitized;
  }

  private detectXSSPatterns(input: string): string[] {
    const detectedPatterns: string[] = [];
    
    for (const pattern of this.xssDetectionPatterns) {
      if (pattern.test(input)) {
        detectedPatterns.push(pattern.source);
      }
    }

    return detectedPatterns;
  }

  private sanitizeHTML(input: string): string {
    let sanitized = input;

    // Apply all sanitization rules
    for (const [ruleName, sanitizeFunc] of this.sanitizationRules) {
      sanitized = sanitizeFunc(sanitized);
    }

    // Additional HTML-specific sanitization
    sanitized = sanitized
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;');

    return sanitized;
  }

  private sanitizeAttribute(input: string): string {
    return input
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }

  private sanitizeScript(input: string): string {
    // Very restrictive sanitization for script context
    return input.replace(/[^a-zA-Z0-9\s\-_.]/g, '');
  }

  private sanitizeScriptURL(input: string): string {
    // Only allow HTTPS URLs for script sources
    const url = new URL(input);
    if (url.protocol !== 'https:') {
      throw new XSSAttemptError('Script URLs must use HTTPS protocol');
    }
    return input;
  }

  private reportXSSAttempt(input: string, patterns: string[]): void {
    const event: SecurityEvent = {
      type: SecurityEventType.XSS_ATTEMPT,
      severity: SecuritySeverity.HIGH,
      description: `XSS attempt detected with patterns: ${patterns.join(', ')}`,
      timestamp: new Date(),
      userAgent: navigator.userAgent,
      payload: input.substring(0, 1000), // Limit payload size
      blocked: true,
      mitigation: 'Input sanitized and malicious content removed'
    };

    console.warn('🚨 XSS Attempt Blocked:', event);

    // Report to security monitoring
    this.sendSecurityAlert(event);
  }

  private sendSecurityAlert(event: SecurityEvent): void {
    // Send alert to security endpoint
    fetch('/api/security/xss-alert', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(event)
    }).catch(err => console.error('Failed to send XSS alert:', err));
  }
}

/**
 * Prototype Pollution Protection System
 * Prevents malicious modification of JavaScript object prototypes
 */
class PrototypePollutionGuard {
  private dangerousKeys: Set<string>;
  private protectedPrototypes: WeakSet<object>;
  private originalDefineProperty: typeof Object.defineProperty;

  constructor() {
    this.dangerousKeys = new Set([
      '__proto__',
      'constructor',
      'prototype',
      '__defineGetter__',
      '__defineSetter__',
      '__lookupGetter__',
      '__lookupSetter__'
    ]);

    this.protectedPrototypes = new WeakSet();
    this.originalDefineProperty = Object.defineProperty;
    
    this.initializeProtection();
  }

  public initializeProtection(): void {
    this.freezePrototypes();
    this.installPropertyGuards();
    this.protectJSON();
    this.monitorPrototypeAccess();

    console.log('🛡️ Prototype pollution protection activated');
  }

  private freezePrototypes(): void {
    // Freeze critical prototypes
    const criticalPrototypes = [
      Object.prototype,
      Array.prototype,
      Function.prototype,
      String.prototype,
      Number.prototype,
      Boolean.prototype,
      Date.prototype,
      RegExp.prototype
    ];

    for (const prototype of criticalPrototypes) {
      if (!Object.isFrozen(prototype)) {
        Object.freeze(prototype);
        this.protectedPrototypes.add(prototype);
      }
    }

    // Seal constructor properties
    Object.seal(Object.prototype.constructor);
    Object.seal(Array.prototype.constructor);
    Object.seal(Function.prototype.constructor);
  }

  private installPropertyGuards(): void {
    const self = this;

    // Override Object.defineProperty to prevent dangerous property definitions
    Object.defineProperty = function(obj: any, prop: string, descriptor: PropertyDescriptor) {
      if (self.isDangerousProperty(prop)) {
        const event: SecurityEvent = {
          type: SecurityEventType.PROTOTYPE_POLLUTION,
          severity: SecuritySeverity.CRITICAL,
          description: `Attempt to define dangerous property: ${prop}`,
          timestamp: new Date(),
          userAgent: navigator.userAgent,
          payload: JSON.stringify({ property: prop, descriptor }),
          blocked: true,
          mitigation: 'Property definition blocked'
        };

        self.reportPrototypePollution(event);
        throw new PrototypePollutionError(`Attempt to modify dangerous property: ${prop}`);
      }

      return self.originalDefineProperty.call(this, obj, prop, descriptor);
    };

    // Override Object.setPrototypeOf
    const originalSetPrototypeOf = Object.setPrototypeOf;
    Object.setPrototypeOf = function(obj: any, prototype: any) {
      if (self.protectedPrototypes.has(obj) || self.protectedPrototypes.has(prototype)) {
        throw new PrototypePollutionError('Attempt to modify protected prototype');
      }
      return originalSetPrototypeOf.call(this, obj, prototype);
    };
  }

  private protectJSON(): void {
    const originalParse = JSON.parse;
    const self = this;

    JSON.parse = function(text: string, reviver?: any) {
      const result = originalParse.call(this, text, reviver);
      self.validateObjectSafety(result);
      return result;
    };
  }

  private monitorPrototypeAccess(): void {
    // Monitor for suspicious prototype access patterns
    const handler = {
      get: (target: any, prop: string) => {
        if (this.isDangerousProperty(prop)) {
          console.warn(`🚨 Suspicious prototype access: ${prop}`);
        }
        return target[prop];
      },

      set: (target: any, prop: string, value: any) => {
        if (this.isDangerousProperty(prop)) {
          throw new PrototypePollutionError(`Blocked attempt to set dangerous property: ${prop}`);
        }
        target[prop] = value;
        return true;
      }
    };

    // Apply proxy monitoring to global objects (carefully)
    // Note: This is a simplified version - full implementation would be more complex
  }

  public validateObjectSafety<T extends object>(obj: T): T {
    if (obj === null || typeof obj !== 'object') {
      return obj;
    }

    const sanitized = this.deepCloneAndSanitize(obj);
    this.removePrototypePollution(sanitized);
    return sanitized as T;
  }

  private deepCloneAndSanitize(obj: any): any {
    if (obj === null || typeof obj !== 'object') {
      return obj;
    }

    if (obj instanceof Date) {
      return new Date(obj.getTime());
    }

    if (obj instanceof Array) {
      return obj.map(item => this.deepCloneAndSanitize(item));
    }

    const sanitized: any = {};
    for (const key in obj) {
      if (obj.hasOwnProperty(key) && !this.isDangerousProperty(key)) {
        sanitized[key] = this.deepCloneAndSanitize(obj[key]);
      }
    }

    return sanitized;
  }

  private removePrototypePollution(obj: any): void {
    if (obj === null || typeof obj !== 'object') {
      return;
    }

    for (const key of this.dangerousKeys) {
      if (key in obj) {
        delete obj[key];
        console.log(`🧹 Removed dangerous property: ${key}`);
      }
    }

    // Recursively clean nested objects
    for (const key in obj) {
      if (obj.hasOwnProperty(key) && typeof obj[key] === 'object') {
        this.removePrototypePollution(obj[key]);
      }
    }
  }

  private isDangerousProperty(prop: string): boolean {
    return this.dangerousKeys.has(prop);
  }

  private reportPrototypePollution(event: SecurityEvent): void {
    console.error('🚨 Prototype Pollution Attempt:', event);

    // Send to security monitoring
    fetch('/api/security/prototype-pollution', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(event)
    }).catch(err => console.error('Failed to report prototype pollution:', err));
  }
}

/**
 * Main Security Hardening Manager
 * Orchestrates all security components
 */
export class TypeScriptSecurityHardening {
  private config: SecurityConfig;
  private cspManager: ContentSecurityPolicyManager;
  private xssProtection: AdvancedXSSProtection;
  private prototypePollutionGuard: PrototypePollutionGuard;
  private securityEvents: SecurityEvent[] = [];
  private isInitialized: boolean = false;

  constructor(config: Partial<SecurityConfig> = {}) {
    this.config = {
      enableCSP: true,
      enableXSSProtection: true,
      enablePrototypePollutionGuard: true,
      enableSecurityMonitoring: true,
      strictMode: true,
      logSecurityEvents: true,
      ...config
    };

    this.initializeSecurity();
  }

  private initializeSecurity(): void {
    console.log('🔒 Initializing RootsploiX Advanced Security Hardening...');

    try {
      // Initialize security components
      if (this.config.enableCSP) {
        this.cspManager = new ContentSecurityPolicyManager();
        this.cspManager.enforceCSP();
        console.log('✅ Content Security Policy enforced');
      }

      if (this.config.enableXSSProtection) {
        this.xssProtection = new AdvancedXSSProtection();
        console.log('✅ Advanced XSS protection enabled');
      }

      if (this.config.enablePrototypePollutionGuard) {
        this.prototypePollutionGuard = new PrototypePollutionGuard();
        console.log('✅ Prototype pollution protection enabled');
      }

      if (this.config.enableSecurityMonitoring) {
        this.startSecurityMonitoring();
        console.log('✅ Security monitoring activated');
      }

      this.isInitialized = true;
      console.log('🛡️ TypeScript Security Hardening fully activated!');

    } catch (error) {
      console.error('❌ Security hardening initialization failed:', error);
      throw new SecurityError('Failed to initialize security hardening', SecurityEventType.INJECTION_ATTEMPT);
    }
  }

  public sanitizeInput(input: unknown, context: 'html' | 'attribute' | 'script' = 'html'): string {
    if (!this.isInitialized || !this.config.enableXSSProtection) {
      throw new SecurityError('XSS protection not initialized', SecurityEventType.XSS_ATTEMPT);
    }

    return this.xssProtection.sanitizeUserInput(input, context);
  }

  public validateObject<T extends object>(obj: T): T {
    if (!this.isInitialized || !this.config.enablePrototypePollutionGuard) {
      throw new SecurityError('Prototype pollution protection not initialized', SecurityEventType.PROTOTYPE_POLLUTION);
    }

    return this.prototypePollutionGuard.validateObjectSafety(obj);
  }

  public getCurrentCSPNonce(): string {
    if (!this.isInitialized || !this.config.enableCSP) {
      throw new SecurityError('CSP not initialized', SecurityEventType.CSP_VIOLATION);
    }

    return this.cspManager.getCurrentNonce();
  }

  public refreshCSPNonce(): string {
    if (!this.isInitialized || !this.config.enableCSP) {
      throw new SecurityError('CSP not initialized', SecurityEventType.CSP_VIOLATION);
    }

    return this.cspManager.refreshNonce();
  }

  private startSecurityMonitoring(): void {
    // Monitor for suspicious activities
    setInterval(() => {
      this.performSecurityHealthCheck();
    }, 30000); // Check every 30 seconds

    // Listen for unhandled security events
    window.addEventListener('error', (event) => {
      if (this.isSecurityRelatedError(event.error)) {
        this.handleSecurityError(event.error);
      }
    });

    window.addEventListener('unhandledrejection', (event) => {
      if (this.isSecurityRelatedError(event.reason)) {
        this.handleSecurityError(event.reason);
      }
    });
  }

  private performSecurityHealthCheck(): void {
    const healthCheck = {
      timestamp: new Date(),
      cspActive: !!this.cspManager,
      xssProtectionActive: !!this.xssProtection,
      prototypePollutionGuardActive: !!this.prototypePollutionGuard,
      securityEventsCount: this.securityEvents.length
    };

    if (this.config.logSecurityEvents) {
      console.log('🔍 Security Health Check:', healthCheck);
    }
  }

  private isSecurityRelatedError(error: any): boolean {
    if (!error) return false;
    
    const securityKeywords = [
      'script', 'eval', 'prototype', '__proto__', 'constructor',
      'innerHTML', 'outerHTML', 'javascript:', 'vbscript:',
      'onload', 'onerror', 'onclick'
    ];

    const errorString = error.toString().toLowerCase();
    return securityKeywords.some(keyword => errorString.includes(keyword));
  }

  private handleSecurityError(error: any): void {
    const securityEvent: SecurityEvent = {
      type: SecurityEventType.MALICIOUS_PAYLOAD,
      severity: SecuritySeverity.HIGH,
      description: `Security-related error detected: ${error.message || error}`,
      timestamp: new Date(),
      userAgent: navigator.userAgent,
      payload: error.stack || error.toString(),
      blocked: false,
      mitigation: 'Error logged for investigation'
    };

    this.securityEvents.push(securityEvent);
    console.warn('🚨 Security Error Detected:', securityEvent);
  }

  public getSecurityReport(): object {
    return {
      initializationStatus: this.isInitialized,
      configuration: this.config,
      securityEvents: this.securityEvents.length,
      recentEvents: this.securityEvents.slice(-10),
      systemHealth: {
        cspActive: !!this.cspManager,
        xssProtectionActive: !!this.xssProtection,
        prototypePollutionGuardActive: !!this.prototypePollutionGuard
      },
      lastHealthCheck: new Date()
    };
  }
}

// Initialize default security hardening when module loads
const defaultSecurityConfig: SecurityConfig = {
  enableCSP: true,
  enableXSSProtection: true,
  enablePrototypePollutionGuard: true,
  enableSecurityMonitoring: true,
  strictMode: true,
  logSecurityEvents: true
};

// Global security instance
export const rootsploixSecurity = new TypeScriptSecurityHardening(defaultSecurityConfig);

// Export security components for advanced usage
export {
  ContentSecurityPolicyManager,
  AdvancedXSSProtection,
  PrototypePollutionGuard,
  SecurityEventType,
  SecuritySeverity,
  SecurityError,
  XSSAttemptError,
  PrototypePollutionError
};

console.log('🔒 RootsploiX TypeScript Security Hardening Module Loaded');