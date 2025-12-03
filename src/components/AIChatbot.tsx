import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { Badge } from "./ui/badge";
import { ScrollArea } from "./ui/scroll-area";
import { Separator } from "./ui/separator";
import { Alert, AlertDescription } from "./ui/alert";
import { 
  Bot, 
  User, 
  Send, 
  Lightbulb, 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  Loader2,
  Terminal,
  Brain,
  Zap,
  Lock,
  Eye,
  Search,
  Database,
  Globe,
  MessageSquare
} from "lucide-react";

interface Message {
  id: string;
  content: string;
  sender: 'user' | 'ai';
  timestamp: Date;
  type?: 'text' | 'command' | 'analysis' | 'warning' | 'success';
  metadata?: {
    command?: string;
    confidence?: number;
    threat_level?: string;
  };
}

interface SecurityCommand {
  command: string;
  description: string;
  category: string;
  usage: string;
  example: string;
}

export function AIChatbot() {
  const [messages, setMessages] = useState<Message[]>([
    {
      id: "welcome",
      content: `🛡️ **PhishGuard AI Security Assistant v2.1** 🛡️

Welcome to your advanced cybersecurity command center! I'm equipped with AI-powered threat analysis and can help you with:

🔍 **Quick Commands:**
• \`/scan [url]\` - Instant URL threat analysis
• \`/analyze [text]\` - Content analysis for phishing
• \`/threat-intel [domain]\` - Domain reputation lookup
• \`/security-tips\` - Latest security recommendations
• \`/incident-response\` - Emergency response procedures

💡 **Expert Capabilities:**
• Real-time threat intelligence analysis
• Phishing detection and prevention
• Security incident guidance
• Best practice recommendations

Type \`/help\` for a complete command list or ask me anything about cybersecurity!`,
      sender: 'ai',
      timestamp: new Date(),
      type: 'text'
    }
  ]);
  const [inputMessage, setInputMessage] = useState("");
  const [isTyping, setIsTyping] = useState(false);

  const securityCommands: SecurityCommand[] = [
    {
      command: "/scan",
      description: "Analyze URLs for threats",
      category: "Analysis",
      usage: "/scan <url>",
      example: "/scan https://suspicious-site.com"
    },
    {
      command: "/analyze",
      description: "Analyze text content for phishing",
      category: "Analysis", 
      usage: "/analyze <text>",
      example: "/analyze Urgent: Your account will be suspended!"
    },
    {
      command: "/threat-intel",
      description: "Get threat intelligence on domains",
      category: "Intelligence",
      usage: "/threat-intel <domain>",
      example: "/threat-intel malicious-domain.com"
    },
    {
      command: "/security-tips",
      description: "Get latest security recommendations",
      category: "Education",
      usage: "/security-tips",
      example: "/security-tips"
    },
    {
      command: "/incident-response",
      description: "Emergency incident response guide",
      category: "Emergency",
      usage: "/incident-response",
      example: "/incident-response"
    },
    {
      command: "/vulnerability-check",
      description: "Check for common vulnerabilities",
      category: "Assessment",
      usage: "/vulnerability-check <target>",
      example: "/vulnerability-check email-server"
    },
    {
      command: "/phish-indicators",
      description: "List current phishing indicators",
      category: "Intelligence",
      usage: "/phish-indicators",
      example: "/phish-indicators"
    },
    {
      command: "/block-domain",
      description: "Add domain to blocklist",
      category: "Protection",
      usage: "/block-domain <domain>",
      example: "/block-domain phishing-site.com"
    }
  ];

  const suggestedQuestions = [
    "How can I identify advanced phishing attacks?",
    "What are the latest phishing trends?",
    "How to respond to a security incident?",
    "What makes a URL suspicious?",
    "How to train employees on phishing?",
    "Explain my recent scan results"
  ];

  useEffect(() => {
    // Auto-scroll to bottom when new messages arrive
    const scrollToBottom = () => {
      const chatContainer = document.getElementById('chat-messages-container');
      if (chatContainer) {
        setTimeout(() => {
          chatContainer.scrollTop = chatContainer.scrollHeight;
        }, 100);
      }
    };
    scrollToBottom();
  }, [messages]);

  const processCommand = (command: string, args: string[]): string => {
    switch (command) {
      case "/scan":
        if (args.length === 0) {
          return "❌ **Usage Error**\n\nPlease provide a URL to scan.\n**Example:** `/scan https://example.com`";
        }
        return analyzeURL(args.join(" "));
        
      case "/analyze":
        if (args.length === 0) {
          return "❌ **Usage Error**\n\nPlease provide text content to analyze.\n**Example:** `/analyze Your account will be suspended!`";
        }
        return analyzeContent(args.join(" "));
        
      case "/threat-intel":
        if (args.length === 0) {
          return "❌ **Usage Error**\n\nPlease provide a domain to check.\n**Example:** `/threat-intel suspicious-domain.com`";
        }
        return getThreatIntel(args[0]);
        
      case "/security-tips":
        return getSecurityTips();
        
      case "/incident-response":
        return getIncidentResponse();
        
      case "/vulnerability-check":
        if (args.length === 0) {
          return "❌ **Usage Error**\n\nPlease provide a target to check.\n**Example:** `/vulnerability-check email-server`";
        }
        return checkVulnerabilities(args.join(" "));
        
      case "/phish-indicators":
        return getPhishingIndicators();
        
      case "/block-domain":
        if (args.length === 0) {
          return "❌ **Usage Error**\n\nPlease provide a domain to block.\n**Example:** `/block-domain malicious-site.com`";
        }
        return blockDomain(args[0]);
        
      case "/help":
        return getHelpText();
        
      default:
        return `❌ **Unknown Command:** \`${command}\`\n\nType \`/help\` to see all available commands.`;
    }
  };

  const analyzeURL = (url: string): string => {
    // Simulate advanced URL analysis
    const suspiciousPatterns = ['bit.ly', 'tinyurl', 'secure-bank', 'paypal-verify', 'amazon-update'];
    const isSuspicious = suspiciousPatterns.some(pattern => url.toLowerCase().includes(pattern));
    const hasHTTPS = url.startsWith('https://');
    
    let threatLevel = 'LOW';
    let confidence = 75;
    let riskFactors = [];
    
    if (isSuspicious) {
      threatLevel = 'HIGH';
      confidence = 92;
      riskFactors.push('Suspicious domain pattern', 'Potential typosquatting');
    }
    
    if (!hasHTTPS) {
      threatLevel = threatLevel === 'LOW' ? 'MEDIUM' : threatLevel;
      confidence += 10;
      riskFactors.push('No HTTPS encryption');
    }
    
    try {
      const urlObj = new URL(url.startsWith('http') ? url : `https://${url}`);
      if (urlObj.hostname.split('.').length > 4) {
        riskFactors.push('Excessive subdomains');
      }
    } catch {
      riskFactors.push('Invalid URL format');
      threatLevel = 'HIGH';
    }

    return `🔍 **URL Threat Analysis Complete**

**Target:** \`${url}\`
**Threat Level:** ${threatLevel === 'HIGH' ? '🔴' : threatLevel === 'MEDIUM' ? '🟡' : '🟢'} **${threatLevel}**
**Confidence:** ${confidence}%

📊 **Analysis Results:**
${riskFactors.length > 0 ? riskFactors.map(factor => `• ⚠️ ${factor}`).join('\n') : '• ✅ No major threats detected'}

🛡️ **Recommendation:**
${threatLevel === 'HIGH' ? '**DO NOT VISIT** - Block this URL immediately' : 
  threatLevel === 'MEDIUM' ? 'Exercise caution - Verify legitimacy before proceeding' : 
  'URL appears safe but remain vigilant'}

📈 **Scan Details:**
• Database Version: v2024.1.1
• Processing Time: 1.2s
• Analysis Depth: Deep Scan`;
  };

  const analyzeContent = (content: string): string => {
    const urgencyWords = ['urgent', 'immediate', 'expires', 'suspended', 'verify now', 'act fast'];
    const phishingWords = ['click here', 'update payment', 'verify account', 'confirm identity'];
    const scamWords = ['congratulations', 'winner', 'prize', 'lottery', 'inheritance'];
    
    const urgencyCount = urgencyWords.filter(word => content.toLowerCase().includes(word)).length;
    const phishingCount = phishingWords.filter(word => content.toLowerCase().includes(word)).length;
    const scamCount = scamWords.filter(word => content.toLowerCase().includes(word)).length;
    
    const totalRisk = urgencyCount * 25 + phishingCount * 30 + scamCount * 35;
    let threatLevel = 'SAFE';
    let confidence = 85;
    
    if (totalRisk >= 60) {
      threatLevel = 'HIGH RISK';
      confidence = 94;
    } else if (totalRisk >= 30) {
      threatLevel = 'MEDIUM RISK'; 
      confidence = 88;
    } else if (totalRisk >= 15) {
      threatLevel = 'LOW RISK';
      confidence = 82;
    }

    return `📝 **Content Analysis Report**

**Content Length:** ${content.length} characters
**Threat Assessment:** ${threatLevel === 'HIGH RISK' ? '🔴' : threatLevel === 'MEDIUM RISK' ? '🟡' : threatLevel === 'LOW RISK' ? '🟠' : '🟢'} **${threatLevel}**
**Confidence Score:** ${confidence}%

🎯 **Detection Summary:**
• Urgency Indicators: ${urgencyCount} found
• Phishing Patterns: ${phishingCount} detected  
• Scam Language: ${scamCount} identified
• Risk Score: ${totalRisk}/100

⚡ **Key Findings:**
${urgencyCount > 0 ? '• ⚠️ Urgency language detected - common in phishing' : ''}
${phishingCount > 0 ? '• 🎣 Phishing indicators found - requests personal action' : ''}
${scamCount > 0 ? '• 💰 Scam terminology present - potential fraud attempt' : ''}
${totalRisk === 0 ? '• ✅ No suspicious patterns detected' : ''}

🛡️ **Security Recommendation:**
${threatLevel === 'HIGH RISK' ? '**BLOCK IMMEDIATELY** - This appears to be a phishing attempt' :
  threatLevel === 'MEDIUM RISK' ? 'Exercise extreme caution - Do not provide personal information' :
  threatLevel === 'LOW RISK' ? 'Minor concerns - Verify sender through official channels' :
  'Content appears legitimate but stay vigilant'}`;
  };

  const getThreatIntel = (domain: string): string => {
    // Simulate threat intelligence lookup
    const knownThreats = ['phishing-example.com', 'malware-site.net', 'scam-domain.org'];
    const isKnownThreat = knownThreats.includes(domain.toLowerCase());
    
    const reputation = isKnownThreat ? Math.floor(Math.random() * 30) + 10 : Math.floor(Math.random() * 30) + 70;
    const registrationAge = Math.floor(Math.random() * 2000) + 30;
    const geoLocation = ['United States', 'Russia', 'China', 'Netherlands', 'Germany'][Math.floor(Math.random() * 5)];

    return `🌐 **Threat Intelligence Report**

**Domain:** \`${domain}\`
**Overall Reputation:** ${reputation >= 70 ? '🟢 GOOD' : reputation >= 40 ? '🟡 SUSPICIOUS' : '🔴 MALICIOUS'} (${reputation}/100)

📍 **Domain Information:**
• Registration Age: ${registrationAge} days
• Geographic Location: ${geoLocation}
• SSL Certificate: ${Math.random() > 0.3 ? '✅ Valid' : '❌ Invalid/Missing'}
• WHOIS Privacy: ${Math.random() > 0.5 ? 'Enabled' : 'Disabled'}

🔍 **Threat Intelligence:**
${isKnownThreat ? 
  '• 🚨 **KNOWN MALICIOUS DOMAIN**\n• First reported: 12 days ago\n• Associated with: Phishing campaigns\n• Threat actors: APT-29, Lazarus Group' :
  '• No direct threat associations found\n• Domain appears in clean reputation databases\n• No recent malicious activity reported'}

📊 **Historical Analysis:**
• Blacklist Status: ${isKnownThreat ? '🔴 BLACKLISTED (3 sources)' : '🟢 Clean'}
• Malware Hosting: ${Math.random() > 0.7 ? '⚠️ Detected' : '✅ None detected'}
• Phishing Reports: ${isKnownThreat ? '🔴 Active (15 reports)' : '✅ No reports'}

⚡ **Real-time Status:**
• Current Status: ${isKnownThreat ? 'ACTIVE THREAT' : 'MONITORED'}
• Last Checked: Just now
• Next Scan: In 6 hours`;
  };

  const getSecurityTips = (): string => {
    return `🛡️ **Latest Security Recommendations**

**📊 Current Threat Landscape:**
• 47% increase in AI-generated phishing emails
• Business Email Compromise attacks up 81%
• Mobile phishing attempts increased 52%

**🔥 Today's Critical Tips:**

**1. Advanced Email Security**
• Enable DMARC, SPF, and DKIM authentication
• Use AI-powered email filters
• Implement zero-trust email policies
• Train staff on deepfake voice/video scams

**2. Mobile Device Protection**
• Enable remote wipe capabilities
• Use mobile threat detection apps
• Verify app store sources before downloads
• Implement mobile device management (MDM)

**3. AI-Era Phishing Defense**
• Be suspicious of "too perfect" messages
• Verify urgent requests through secondary channels
• Check for AI-generated image inconsistencies
• Use voice verification for sensitive requests

**4. Zero-Trust Implementation**
• Verify every user and device
• Implement conditional access policies
• Use privileged access management (PAM)
• Monitor all network traffic continuously

**⚡ Emergency Protocols:**
• Report suspicious activity within 5 minutes
• Isolate compromised systems immediately
• Contact incident response team: ext. 7777
• Document all actions taken

**📈 Your Security Score: 94% (Excellent)**`;
  };

  const getIncidentResponse = (): string => {
    return `🚨 **Emergency Incident Response Protocol**

**⚡ IMMEDIATE ACTIONS (First 5 Minutes):**

**1. Contain the Threat**
• Disconnect affected systems from network
• Preserve evidence - DO NOT shut down
• Isolate user accounts involved
• Block suspicious IP addresses/domains

**2. Alert Response Team**
• Security Team: ext. 7777 (24/7 hotline)
• IT Operations: ext. 5555
• Management: ext. 9999
• Legal/Compliance: ext. 3333

**3. Initial Assessment**
• Identify attack type and scope
• Document timeline of events
• Capture screenshots and logs
• Preserve system memory dumps

**📋 INCIDENT CLASSIFICATION:**

**🔴 CRITICAL (Code Red)**
• Active data exfiltration
• Ransomware deployment
• System compromise with admin access
• Customer data breach

**🟡 HIGH (Code Orange)** 
• Phishing campaign targeting employees
• Suspicious network activity
• Potential malware infection
• Unauthorized access attempts

**🟢 MEDIUM (Code Yellow)**
• Policy violations
• Minor security tool alerts
• Suspicious email reports
• Physical security incidents

**📞 External Contacts:**
• FBI Cyber Crime: 1-855-292-3937
• CISA: 1-888-282-0870
• Legal Counsel: [Your Legal Team]
• Cyber Insurance: [Your Provider]

**🔍 Evidence Collection:**
• Network logs and packet captures
• System event logs
• Email headers and attachments
• User activity logs
• Physical access logs

**Remember: Time is critical in incident response!**`;
  };

  const checkVulnerabilities = (target: string): string => {
    return `🔍 **Vulnerability Assessment: ${target}**

**📊 Scan Results:**
• **Critical:** 0 vulnerabilities
• **High:** 2 vulnerabilities  
• **Medium:** 5 vulnerabilities
• **Low:** 12 vulnerabilities
• **Info:** 8 findings

**🚨 High Priority Issues:**

**1. CVE-2024-1234 - Email Server**
• **Risk:** Remote Code Execution
• **CVSS:** 8.9 (High)
• **Status:** Patch available
• **Action:** Apply security update immediately

**2. CVE-2024-5678 - Web Application**
• **Risk:** SQL Injection
• **CVSS:** 7.8 (High)  
• **Status:** Mitigated by WAF
• **Action:** Code review and fix required

**⚠️ Medium Priority Issues:**
• Outdated SSL/TLS certificates (3 found)
• Missing security headers on web servers
• Weak password policies detected
• Unnecessary services running
• Missing endpoint protection on 2 systems

**📈 Security Recommendations:**
• Implement vulnerability scanning automation
• Establish patch management schedule
• Enable real-time threat monitoring
• Conduct quarterly penetration testing
• Update security awareness training

**📊 Overall Security Posture: 78% (Good)**
**Next Assessment:** Scheduled in 30 days`;
  };

  const getPhishingIndicators = (): string => {
    return `🎣 **Current Phishing Threat Indicators**

**🔥 Active Campaigns (Last 24 Hours):**

**1. Microsoft 365 Credential Harvesting**
• **Targets:** Office 365 users
• **Method:** Fake login pages
• **Indicators:** emails from "msft-security-team@outlook.com"
• **Status:** 🔴 Active (127 reports)

**2. Banking Trojan Distribution**
• **Targets:** Financial institutions
• **Method:** Malicious Excel attachments
• **Indicators:** Subject: "Account Statement - Action Required"
• **Status:** 🔴 Active (89 reports)

**3. CEO Fraud / BEC Attacks**
• **Targets:** Finance departments
• **Method:** Executive impersonation
• **Indicators:** Urgent wire transfer requests
• **Status:** 🟡 Moderate (34 reports)

**📊 Technical Indicators:**

**🌐 Malicious Domains (Auto-blocked):**
• secure-microsoft-login[.]net
• paypal-verification[.]org  
• amazon-security-alert[.]com
• bank-of-america-alerts[.]net

**📧 Email Indicators:**
• Sender reputation below 30%
• SPF/DKIM failures
• Suspicious attachment types: .scr, .pif, .exe
• URL redirects through 3+ hops

**🔗 URL Patterns:**
• bit.ly/[random] → malicious sites
• Short domains (less than 6 chars)
• Recently registered domains (<30 days)
• Free hosting services with suspicious content

**⚡ AI Detection Patterns:**
• Urgency language confidence: >85%
• Grammar inconsistencies
• Unusual send times (2-6 AM)
• Generic greetings with personal info requests

**🛡️ Protection Status:**
• Email filters: ✅ Active (99.7% effective)
• URL scanning: ✅ Real-time
• Attachment analysis: ✅ Deep inspection
• User reporting: ✅ 234 reports today

**📈 Threat Intelligence Updated:** 3 minutes ago`;
  };

  const blockDomain = (domain: string): string => {
    return `🚫 **Domain Blocked Successfully**

**Blocked Domain:** \`${domain}\`
**Timestamp:** ${new Date().toLocaleString()}
**Action:** Added to enterprise blocklist

**🛡️ Protection Applied:**
• ✅ DNS blackholing activated
• ✅ Email filtering updated
• ✅ Web proxy blocking enabled  
• ✅ Firewall rules deployed

**📊 Block Details:**
• **Scope:** Organization-wide
• **Propagation:** ~5 minutes
• **Duration:** Permanent (until manual removal)
• **Backup Systems:** Also updated

**🔍 Additional Actions Taken:**
• Domain added to threat intelligence feed
• Related IPs automatically scanned
• Similar domains queued for analysis
• Security team notified

**📈 Impact Assessment:**
• Users protected: 1,247
• Blocked access attempts: 0 (monitoring)
• False positive risk: Low
• Business impact: None expected

**⚡ Next Steps:**
• Monitor for evasion attempts
• Check for related domains
• Update threat signatures
• Review in 30 days for removal consideration

**Status:** 🟢 **ACTIVE PROTECTION**`;
  };

  const getHelpText = (): string => {
    const commandsByCategory = securityCommands.reduce((acc, cmd) => {
      if (!acc[cmd.category]) acc[cmd.category] = [];
      acc[cmd.category].push(cmd);
      return acc;
    }, {} as Record<string, SecurityCommand[]>);

    let helpText = "🤖 **PhishGuard AI Assistant - Command Reference**\n\n";
    
    Object.entries(commandsByCategory).forEach(([category, commands]) => {
      helpText += `**📂 ${category} Commands:**\n`;
      commands.forEach(cmd => {
        helpText += `• \`${cmd.command}\` - ${cmd.description}\n`;
        helpText += `  Usage: \`${cmd.usage}\`\n\n`;
      });
    });

    helpText += `**💡 Pro Tips:**
• Commands are case-insensitive
• Use quotes for multi-word arguments
• Type partial commands for auto-suggestions
• All actions are logged for security audit

**🔗 Quick Links:**
• Documentation: /docs
• API Reference: /api
• Security Portal: /security
• Training Materials: /training`;

    return helpText;
  };

  const getAIResponse = (userMessage: string): { content: string; type: Message['type']; metadata?: any } => {
    const message = userMessage.trim();
    
    // Check if it's a command
    if (message.startsWith('/')) {
      const parts = message.split(' ');
      const command = parts[0].toLowerCase();
      const args = parts.slice(1);
      
      return {
        content: processCommand(command, args),
        type: 'command',
        metadata: { command }
      };
    }

    // AI conversational responses for non-commands
    const lowerMessage = message.toLowerCase();
    
    if (lowerMessage.includes('latest') && lowerMessage.includes('threat')) {
      return {
        content: `🔥 **Latest Threat Intelligence Update**

**Current Global Threat Level:** 🟡 ELEVATED

**🚨 Breaking Threats (Last 6 Hours):**
• **Operation CloudStrike:** Large-scale credential harvesting targeting cloud services
• **PhishKit-2024:** New automated phishing framework detected
• **DeepFake CEO Scams:** AI-generated video calls requesting wire transfers

**📊 Real-Time Statistics:**
• Phishing attempts blocked: 15,247 today
• Malware downloads prevented: 2,891
• Suspicious domains identified: 4,156
• Active threat actors: 23 groups

**⚡ Immediate Actions Required:**
• Update email security rules
• Brief executives on deepfake risks  
• Enable enhanced MFA on cloud services
• Review vendor email authentication

Use \`/threat-intel\` for specific domain analysis or \`/phish-indicators\` for detailed IOCs.`,
        type: 'analysis',
        metadata: { threat_level: 'elevated' }
      };
    }

    if (lowerMessage.includes('train') && (lowerMessage.includes('employee') || lowerMessage.includes('staff'))) {
      return {
        content: `👥 **Security Awareness Training Guide**

**🎯 Essential Training Modules:**

**1. Phishing Recognition (Critical)**
• Real-world phishing examples
• Email header analysis
• URL inspection techniques
• Social engineering tactics

**2. Password Security**
• Password manager usage
• Multi-factor authentication setup
• Passkey implementation
• Credential hygiene best practices

**3. Mobile Security**
• App store safety
• Public Wi-Fi risks
• Device encryption
• Mobile phishing detection

**4. Incident Reporting**
• When to report
• How to report (ext. 7777)
• What information to provide
• Post-incident procedures

**📅 Training Schedule:**
• Monthly: Phishing simulation tests
• Quarterly: Security awareness updates
• Annually: Comprehensive security training
• Ad-hoc: Threat-specific briefings

**🏆 Gamification Elements:**
• Security champion badges
• Team competitions
• Phishing test leaderboards
• Reward programs for reporting

**📊 Success Metrics:**
• 95% phishing test pass rate
• 30-second average report time
• 99% training completion rate
• Zero successful phishing attacks

Would you like me to create a custom training program for your organization?`,
        type: 'success',
        metadata: { confidence: 95 }
      };
    }

    // Default intelligent response
    return {
      content: `🤖 **AI Security Assistant Ready**

I understand you're asking about: "${message}"

I can help you with advanced cybersecurity analysis and response. Here are some ways I can assist:

**🔍 Threat Analysis:**
• Use \`/scan [url]\` for instant URL threat assessment
• Use \`/analyze [text]\` for content analysis
• Use \`/threat-intel [domain]\` for reputation checks

**⚡ Quick Actions:**
• \`/security-tips\` - Latest security recommendations
• \`/incident-response\` - Emergency response procedures
• \`/phish-indicators\` - Current threat indicators

**🎯 Specialized Help:**
• AI-powered phishing detection
• Real-time threat intelligence
• Security awareness guidance
• Incident response coordination

Feel free to ask specific questions or use commands for immediate analysis. I'm here to keep your organization secure!

Type \`/help\` for a complete command reference.`,
      type: 'text'
    };
  };

  const handleSendMessage = async () => {
    if (!inputMessage.trim()) return;

    const userMessage: Message = {
      id: Date.now().toString(),
      content: inputMessage,
      sender: 'user',
      timestamp: new Date(),
      type: 'text'
    };

    setMessages(prev => [...prev, userMessage]);
    setInputMessage("");
    setIsTyping(true);

    // Simulate AI processing time
    setTimeout(() => {
      const aiResponseData = getAIResponse(inputMessage);
      const aiResponse: Message = {
        id: (Date.now() + 1).toString(),
        content: aiResponseData.content,
        sender: 'ai',
        timestamp: new Date(),
        type: aiResponseData.type,
        metadata: aiResponseData.metadata
      };
      
      setMessages(prev => [...prev, aiResponse]);
      setIsTyping(false);
    }, 800 + Math.random() * 1500);
  };

  const handleSuggestedQuestion = (question: string) => {
    setInputMessage(question);
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  const getMessageStyle = (type: Message['type']) => {
    switch (type) {
      case 'command': return 'bg-purple-50 dark:bg-purple-950/20 border-l-4 border-l-purple-500';
      case 'analysis': return 'bg-blue-50 dark:bg-blue-950/20 border-l-4 border-l-blue-500';
      case 'warning': return 'bg-orange-50 dark:bg-orange-950/20 border-l-4 border-l-orange-500';
      case 'success': return 'bg-green-50 dark:bg-green-950/20 border-l-4 border-l-green-500';
      default: return 'bg-muted';
    }
  };

  return (
    <div className="w-full max-w-full space-y-6">
      {/* Main Chat Interface */}
      <Card className="phish-card w-full">
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2">
            <Brain className="w-5 h-5 text-purple-500 animate-pulse-soft" />
            AI Security Command Center
            <Badge variant="outline" className="ml-2 ai-assistant-glow">
              v2.1 Enhanced
            </Badge>
          </CardTitle>
          <CardDescription>
            Advanced cybersecurity AI with command-line interface and real-time threat analysis
          </CardDescription>
        </CardHeader>
        
        <CardContent className="space-y-4">
          {/* Chat Messages Container with Fixed Height and Scroll */}
          <div className="border rounded-lg bg-muted/20 h-96 flex flex-col">
            <div 
              id="chat-messages-container"
              className="flex-1 overflow-y-auto p-4 space-y-4"
              style={{ maxHeight: '384px' }}
            >
              {messages.map((message) => (
                <div
                  key={message.id}
                  className={`flex gap-3 ${
                    message.sender === 'user' ? 'flex-row-reverse' : 'flex-row'
                  }`}
                >
                  <div className="flex-shrink-0">
                    <div className={`w-8 h-8 rounded-full flex items-center justify-center ${
                      message.sender === 'user' 
                        ? 'bg-primary text-primary-foreground' 
                        : message.type === 'command'
                        ? 'bg-purple-500 text-white'
                        : 'bg-muted-foreground text-background'
                    }`}>
                      {message.sender === 'user' ? (
                        <User className="w-4 h-4" />
                      ) : message.type === 'command' ? (
                        <Terminal className="w-4 h-4" />
                      ) : (
                        <Brain className="w-4 h-4" />
                      )}
                    </div>
                  </div>
                  <div className={`flex-1 max-w-[85%] ${
                    message.sender === 'user' ? 'text-right' : 'text-left'
                  }`}>
                    <div className={`inline-block p-4 rounded-lg ${
                      message.sender === 'user'
                        ? 'bg-primary text-primary-foreground'
                        : getMessageStyle(message.type)
                    }`}>
                      <div className="whitespace-pre-wrap text-sm font-mono break-words">
                        {message.content}
                      </div>
                      {message.metadata && (
                        <div className="mt-2 pt-2 border-t border-current/20">
                          <div className="text-xs opacity-75">
                            {message.metadata.command && `Command: ${message.metadata.command}`}
                            {message.metadata.confidence && ` | Confidence: ${message.metadata.confidence}%`}
                            {message.metadata.threat_level && ` | Threat Level: ${message.metadata.threat_level.toUpperCase()}`}
                          </div>
                        </div>
                      )}
                    </div>
                    <div className="text-xs text-muted-foreground mt-1 flex items-center gap-2">
                      <span>{message.timestamp.toLocaleTimeString()}</span>
                      {message.type === 'command' && <Terminal className="w-3 h-3" />}
                      {message.type === 'analysis' && <Search className="w-3 h-3" />}
                    </div>
                  </div>
                </div>
              ))}
              
              {/* Typing Indicator */}
              {isTyping && (
                <div className="flex gap-3">
                  <div className="flex-shrink-0">
                    <div className="w-8 h-8 rounded-full bg-purple-500 flex items-center justify-center">
                      <Brain className="w-4 h-4 text-white" />
                    </div>
                  </div>
                  <div className="flex-1">
                    <div className="inline-block p-3 rounded-lg bg-purple-50 dark:bg-purple-950/20">
                      <div className="flex items-center gap-2">
                        <Loader2 className="w-4 h-4 animate-spin text-purple-500" />
                        <span className="text-sm text-purple-700 dark:text-purple-300">AI analyzing and processing...</span>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>

          <Separator />

          {/* Quick Commands */}
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-muted-foreground" />
              <span className="text-sm font-medium">Quick Commands</span>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
              {['/scan', '/analyze', '/threat-intel', '/security-tips'].map((cmd) => (
                <Button
                  key={cmd}
                  variant="outline"
                  size="sm"
                  onClick={() => setInputMessage(cmd + ' ')}
                  className="text-xs font-mono justify-start security-button"
                >
                  {cmd}
                </Button>
              ))}
            </div>
          </div>

          <Separator />

          {/* Suggested Questions */}
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <Lightbulb className="w-4 h-4 text-muted-foreground" />
              <span className="text-sm font-medium">Expert Guidance</span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              {suggestedQuestions.map((question, index) => (
                <Button
                  key={index}
                  variant="outline"
                  size="sm"
                  onClick={() => handleSuggestedQuestion(question)}
                  className="text-xs justify-start h-auto py-2 px-3 whitespace-normal text-left"
                >
                  <MessageSquare className="w-3 h-3 mr-2 flex-shrink-0" />
                  {question}
                </Button>
              ))}
            </div>
          </div>

          <Separator />

          {/* Input Area */}
          <div className="flex gap-2">
            <div className="flex-1">
              <Input
                value={inputMessage}
                onChange={(e) => setInputMessage(e.target.value)}
                onKeyPress={handleKeyPress}
                placeholder="Ask about security or use /commands for analysis..."
                disabled={isTyping}
                className="font-mono bg-input-background backdrop-blur-sm"
              />
            </div>
            <Button 
              onClick={handleSendMessage} 
              disabled={!inputMessage.trim() || isTyping}
              size="icon"
              className="security-button"
            >
              <Send className="w-4 h-4" />
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Enhanced Status Dashboard */}
      <Card className="phish-card">
        <CardContent className="pt-6">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="flex items-center gap-3 p-3 border rounded-lg phish-card">
              <Shield className="w-8 h-8 text-green-500 animate-pulse-soft" />
              <div>
                <h4 className="font-medium">Protection Status</h4>
                <p className="text-sm text-muted-foreground">All systems secure</p>
              </div>
            </div>
            <div className="flex items-center gap-3 p-3 border rounded-lg phish-card">
              <Database className="w-8 h-8 text-blue-500" />
              <div>
                <h4 className="font-medium">Threat Database</h4>
                <p className="text-sm text-muted-foreground">Updated 3 min ago</p>
              </div>
            </div>
            <div className="flex items-center gap-3 p-3 border rounded-lg phish-card">
              <Zap className="w-8 h-8 text-purple-500" />
              <div>
                <h4 className="font-medium">AI Engine</h4>
                <p className="text-sm text-muted-foreground">99.7% accuracy</p>
              </div>
            </div>
            <div className="flex items-center gap-3 p-3 border rounded-lg phish-card">
              <Globe className="w-8 h-8 text-orange-500" />
              <div>
                <h4 className="font-medium">Global Threats</h4>
                <p className="text-sm text-muted-foreground">2,847 blocked today</p>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}