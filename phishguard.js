import React, { useState } from 'react';

const PhishingDetector = () => {
  const [emailContent, setEmailContent] = useState('');
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  
  // Phishing detection patterns
  const phishingPatterns = {
    // Urgency and pressure tactics
    urgencyPhrases: [
      'urgent action required', 'immediate attention', 'act now', 
      'limited time', 'expires', 'deadline', 'urgent notice',
      'immediate response required', '24 hours', 'account suspended'
    ],
    
    // Suspicious links and domains
    suspiciousLinkPatterns: [
      /https?:\/\/[^\s/$.?#].[^\s]*/i, // General URL pattern
      /bit\.ly/i, /tinyurl/i, /goo\.gl/i, // URL shorteners
      /\b(?!google\.com|microsoft\.com|apple\.com|amazon\.com|paypal\.com)\w+\.(xyz|tk|ml|ga|cf|gq|info)\b/i // Suspicious TLDs
    ],
    
    // Grammatical/spelling errors
    poorGrammarPatterns: [
      /(?:i|we) (needs|has|have been) to/i,
      /(?:please|kindly) (?:do|does|did) the/i,
      /(?:please|kindly) (?:clicks|clicking|clicked) on/i,
      /(?:please|kindly) (?:sends|sending|sent) the/i
    ],
    
    // Suspicious sender patterns
    suspiciousSenderPatterns: [
      /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{10,}@/i, // Random alphanumeric username
      /@(?!gmail\.com|yahoo\.com|outlook\.com|hotmail\.com|aol\.com).{20,}/i, // Unusually long domain
      /support@[\w-]+\.(?!com|org|net|edu|gov)/i // Suspicious support email domains
    ],
    
    // Request for sensitive information
    sensitiveInfoRequests: [
      'social security', 'ssn', 'password', 'credit card', 'bank account',
      'verify your account', 'confirm your information', 'update your details',
      'validate your account', 'account verification', 'security check'
    ],
    
    // Suspicious greeting patterns
    suspiciousGreetings: [
      'dear user', 'dear customer', 'dear account holder',
      'valued customer', 'attention', 'hello dear', 'greetings'
    ],
    
    // Impersonation patterns
    impersonationPatterns: [
      'paypal team', 'apple support', 'microsoft security',
      'amazon customer service', 'bank support', 'it department',
      'google security', 'facebook security', 'security team'
    ],
    
    // Attachment threats
    attachmentThreats: [
      'download attachment', 'open attachment', 'see attached file',
      'view attachment', 'attachment contains', 'in the attachment'
    ],
    
    // Fear and reward patterns
    fearRewardPatterns: [
      'your account has been', 'unauthorized login', 'suspicious activity',
      'won lottery', 'prize winner', 'you have won', 'inheritance',
      'million dollars', 'unclaimed funds', 'free gift'
    ]
  };

  const analyzeEmail = () => {
    setLoading(true);
    
    // Initialize results structure
    const detectionResults = {
      overallRisk: 0,
      detectedPatterns: [],
      riskFactors: {},
      explanations: []
    };
    
    // Normalize email content for case-insensitive matching
    const normalizedContent = emailContent.toLowerCase();
    let totalRiskScore = 0;
    
    // Check for urgency phrases
    const urgencyMatches = phishingPatterns.urgencyPhrases.filter(phrase => 
      normalizedContent.includes(phrase.toLowerCase())
    );
    
    if (urgencyMatches.length > 0) {
      const riskFactor = Math.min(urgencyMatches.length * 5, 25);
      totalRiskScore += riskFactor;
      detectionResults.riskFactors.urgency = riskFactor;
      detectionResults.detectedPatterns.push('Urgency tactics');
      detectionResults.explanations.push({
        type: 'Urgency and Pressure',
        details: `Found ${urgencyMatches.length} urgency phrases like: ${urgencyMatches.slice(0, 3).join(', ')}${urgencyMatches.length > 3 ? '...' : ''}`,
        severity: riskFactor > 15 ? 'High' : riskFactor > 5 ? 'Medium' : 'Low'
      });
    }
    
    // Check for suspicious links
    let linkMatches = 0;
    phishingPatterns.suspiciousLinkPatterns.forEach(pattern => {
      const matches = normalizedContent.match(pattern) || [];
      linkMatches += matches.length;
    });
    
    if (linkMatches > 0) {
      const riskFactor = Math.min(linkMatches * 10, 40);
      totalRiskScore += riskFactor;
      detectionResults.riskFactors.suspiciousLinks = riskFactor;
      detectionResults.detectedPatterns.push('Suspicious links');
      detectionResults.explanations.push({
        type: 'Suspicious Links',
        details: `Found ${linkMatches} potentially suspicious links or domains`,
        severity: riskFactor > 20 ? 'High' : riskFactor > 10 ? 'Medium' : 'Low'
      });
    }
    
    // Check for poor grammar
    let grammarMatches = 0;
    phishingPatterns.poorGrammarPatterns.forEach(pattern => {
      const matches = normalizedContent.match(pattern) || [];
      grammarMatches += matches.length;
    });
    
    if (grammarMatches > 0) {
      const riskFactor = Math.min(grammarMatches * 5, 15);
      totalRiskScore += riskFactor;
      detectionResults.riskFactors.poorGrammar = riskFactor;
      detectionResults.detectedPatterns.push('Grammar and spelling issues');
      detectionResults.explanations.push({
        type: 'Poor Grammar',
        details: `Found ${grammarMatches} grammar or spelling issues`,
        severity: riskFactor > 10 ? 'High' : riskFactor > 5 ? 'Medium' : 'Low'
      });
    }
    
    // Check for suspicious sender patterns
    let senderMatches = 0;
    phishingPatterns.suspiciousSenderPatterns.forEach(pattern => {
      const matches = normalizedContent.match(pattern) || [];
      senderMatches += matches.length;
    });
    
    if (senderMatches > 0) {
      const riskFactor = Math.min(senderMatches * 15, 30);
      totalRiskScore += riskFactor;
      detectionResults.riskFactors.suspiciousSender = riskFactor;
      detectionResults.detectedPatterns.push('Suspicious sender address');
      detectionResults.explanations.push({
        type: 'Suspicious Sender',
        details: `Email appears to come from a suspicious sender pattern`,
        severity: riskFactor > 20 ? 'High' : riskFactor > 10 ? 'Medium' : 'Low'
      });
    }
    
    // Check for requests for sensitive information
    const sensitiveMatches = phishingPatterns.sensitiveInfoRequests.filter(phrase => 
      normalizedContent.includes(phrase.toLowerCase())
    );
    
    if (sensitiveMatches.length > 0) {
      const riskFactor = Math.min(sensitiveMatches.length * 15, 45);
      totalRiskScore += riskFactor;
      detectionResults.riskFactors.sensitiveInfoRequests = riskFactor;
      detectionResults.detectedPatterns.push('Requests for sensitive information');
      detectionResults.explanations.push({
        type: 'Sensitive Information Request',
        details: `Found ${sensitiveMatches.length} requests for sensitive information like: ${sensitiveMatches.slice(0, 3).join(', ')}${sensitiveMatches.length > 3 ? '...' : ''}`,
        severity: riskFactor > 30 ? 'High' : riskFactor > 15 ? 'Medium' : 'Low'
      });
    }
    
    // Check for suspicious greetings
    const greetingMatches = phishingPatterns.suspiciousGreetings.filter(phrase => 
      normalizedContent.includes(phrase.toLowerCase())
    );
    
    if (greetingMatches.length > 0) {
      const riskFactor = Math.min(greetingMatches.length * 5, 10);
      totalRiskScore += riskFactor;
      detectionResults.riskFactors.suspiciousGreetings = riskFactor;
      detectionResults.detectedPatterns.push('Generic or suspicious greeting');
      detectionResults.explanations.push({
        type: 'Suspicious Greeting',
        details: `Email uses generic greetings like: ${greetingMatches.join(', ')}`,
        severity: 'Low'
      });
    }
    
    // Check for impersonation attempts
    const impersonationMatches = phishingPatterns.impersonationPatterns.filter(phrase => 
      normalizedContent.includes(phrase.toLowerCase())
    );
    
    if (impersonationMatches.length > 0) {
      const riskFactor = Math.min(impersonationMatches.length * 10, 30);
      totalRiskScore += riskFactor;
      detectionResults.riskFactors.impersonation = riskFactor;
      detectionResults.detectedPatterns.push('Brand/organization impersonation');
      detectionResults.explanations.push({
        type: 'Impersonation',
        details: `Email appears to impersonate: ${impersonationMatches.join(', ')}`,
        severity: riskFactor > 20 ? 'High' : riskFactor > 10 ? 'Medium' : 'Low'
      });
    }
    
    // Check for attachment references
    const attachmentMatches = phishingPatterns.attachmentThreats.filter(phrase => 
      normalizedContent.includes(phrase.toLowerCase())
    );
    
    if (attachmentMatches.length > 0) {
      const riskFactor = Math.min(attachmentMatches.length * 10, 20);
      totalRiskScore += riskFactor;
      detectionResults.riskFactors.attachmentThreats = riskFactor;
      detectionResults.detectedPatterns.push('Suspicious attachment references');
      detectionResults.explanations.push({
        type: 'Attachment Threats',
        details: `Email references suspicious attachments`,
        severity: riskFactor > 15 ? 'High' : riskFactor > 5 ? 'Medium' : 'Low'
      });
    }
    
    // Check for fear/reward manipulation
    const fearRewardMatches = phishingPatterns.fearRewardPatterns.filter(phrase => 
      normalizedContent.includes(phrase.toLowerCase())
    );
    
    if (fearRewardMatches.length > 0) {
      const riskFactor = Math.min(fearRewardMatches.length * 10, 25);
      totalRiskScore += riskFactor;
      detectionResults.riskFactors.fearReward = riskFactor;
      detectionResults.detectedPatterns.push('Fear or reward manipulation');
      detectionResults.explanations.push({
        type: 'Fear/Reward Manipulation',
        details: `Found ${fearRewardMatches.length} fear or reward manipulation phrases like: ${fearRewardMatches.slice(0, 3).join(', ')}${fearRewardMatches.length > 3 ? '...' : ''}`,
        severity: riskFactor > 15 ? 'High' : riskFactor > 5 ? 'Medium' : 'Low'
      });
    }
    
    // Calculate overall risk
    detectionResults.overallRisk = totalRiskScore;
    
    // Risk categorization
    let riskCategory = 'Low';
    if (totalRiskScore > 50) {
      riskCategory = 'High';
    } else if (totalRiskScore > 25) {
      riskCategory = 'Medium';
    }
    
    detectionResults.riskCategory = riskCategory;
    
    // Email length check
    if (emailContent.length < 100 && totalRiskScore > 0) {
      detectionResults.overallRisk += 10;
      detectionResults.explanations.push({
        type: 'Suspicious Email Length',
        details: 'Email is unusually short, which is common in phishing attempts',
        severity: 'Medium'
      });
    }
    
    // Final result
    setTimeout(() => {
      setResults(detectionResults);
      setLoading(false);
    }, 500);
  };

  const getRiskColor = (category) => {
    switch(category) {
      case 'High': return 'text-red-600';
      case 'Medium': return 'text-yellow-600';
      case 'Low': return 'text-green-600';
      default: return 'text-gray-600';
    }
  };

  const getRiskBgColor = (category) => {
    switch(category) {
      case 'High': return 'bg-red-100 border-red-300';
      case 'Medium': return 'bg-yellow-100 border-yellow-300';
      case 'Low': return 'bg-green-100 border-green-300';
      default: return 'bg-gray-100 border-gray-300';
    }
  };

  return (
    <div className="max-w-4xl mx-auto p-4">
      <h1 className="text-2xl font-bold mb-4 text-center">Phishing Email Detector</h1>
      <div className="mb-6">
        <label htmlFor="emailContent" className="block mb-2 font-medium">
          Paste the email content (including headers if available):
        </label>
        <textarea
          id="emailContent"
          className="w-full p-3 border border-gray-300 rounded min-h-64 mb-2"
          value={emailContent}
          onChange={(e) => setEmailContent(e.target.value)}
          placeholder="From: example@domain.com
Subject: Urgent Action Required - Your Account Will Be Suspended
          
Dear Customer,
          
We have detected suspicious activity on your account. Your account will be suspended within 24 hours unless you verify your information.
          
Click here to verify: http://suspicious-link.com"
        />
        <button
          onClick={analyzeEmail}
          disabled={loading || emailContent.trim().length === 0}
          className="w-full py-2 px-4 bg-blue-600 text-white font-medium rounded hover:bg-blue-700 disabled:bg-gray-400"
        >
          {loading ? 'Analyzing...' : 'Analyze Email'}
        </button>
      </div>

      {results && (
        <div className="border rounded p-4 mb-6">
          <h2 className="text-xl font-bold mb-4">Analysis Results</h2>
          
          <div className={`p-3 mb-4 rounded border ${getRiskBgColor(results.riskCategory)}`}>
            <div className="flex justify-between items-center">
              <h3 className="font-bold">Risk Assessment:</h3>
              <span className={`font-bold text-lg ${getRiskColor(results.riskCategory)}`}>
                {results.riskCategory} Risk
              </span>
            </div>
            <div className="mt-2">
              <div className="w-full bg-gray-200 rounded-full h-2.5">
                <div 
                  className={`h-2.5 rounded-full ${
                    results.riskCategory === 'High' ? 'bg-red-600' : 
                    results.riskCategory === 'Medium' ? 'bg-yellow-500' : 'bg-green-500'
                  }`} 
                  style={{ width: `${Math.min(results.overallRisk, 100)}%` }}
                ></div>
              </div>
              <div className="text-sm mt-1 text-gray-600">
                Risk Score: {results.overallRisk}/100
              </div>
            </div>
          </div>

          {results.detectedPatterns.length > 0 ? (
            <>
              <h3 className="font-bold mb-2">Detected Phishing Indicators:</h3>
              <ul className="list-disc pl-5 mb-4">
                {results.detectedPatterns.map((pattern, idx) => (
                  <li key={idx} className="mb-1">{pattern}</li>
                ))}
              </ul>
            </>
          ) : (
            <p className="mb-4 text-green-600">No phishing indicators detected.</p>
          )}

          {results.explanations.length > 0 && (
            <div>
              <h3 className="font-bold mb-2">Detailed Explanation:</h3>
              {results.explanations.map((explanation, idx) => (
                <div key={idx} className="mb-3 p-2 border-l-4 border-gray-300 pl-2">
                  <div className="flex justify-between">
                    <span className="font-semibold">{explanation.type}</span>
                    <span className={`${getRiskColor(explanation.severity)} font-medium`}>
                      {explanation.severity} Risk
                    </span>
                  </div>
                  <p className="text-gray-700 text-sm">{explanation.details}</p>
                </div>
              ))}
            </div>
          )}
          
          <div className="mt-4 p-3 bg-blue-50 border border-blue-200 rounded">
            <h3 className="font-bold mb-1">Recommendations:</h3>
            <ul className="list-disc pl-5">
              {results.riskCategory !== 'Low' && (
                <>
                  <li>Do not click on any links in the email</li>
                  <li>Do not download or open attachments</li>
                  <li>Do not reply with personal or financial information</li>
                  <li>If the email claims to be from a legitimate organization, contact them directly through their official website or phone number</li>
                  <li>Report the email as phishing to your email provider</li>
                </>
              )}
              {results.riskCategory === 'Low' && results.detectedPatterns.length === 0 && (
                <li>This email appears to be legitimate, but always remain vigilant</li>
              )}
              {results.riskCategory === 'Low' && results.detectedPatterns.length > 0 && (
                <>
                  <li>The email shows some minor suspicious indicators, but may be legitimate</li>
                  <li>Exercise caution when interacting with content in this email</li>
                </>
              )}
            </ul>
          </div>
        </div>
      )}
      
      <div className="bg-gray-50 p-4 rounded border border-gray-200">
        <h2 className="text-lg font-bold mb-2">About This Tool</h2>
        <p className="text-sm text-gray-700 mb-2">
          This phishing detector analyzes emails for common phishing patterns including:
        </p>
        <ul className="list-disc pl-5 text-sm text-gray-700">
          <li>Urgency tactics and pressure language</li>
          <li>Suspicious links and domains</li>
          <li>Grammar and spelling errors</li>
          <li>Suspicious sender addresses</li>
          <li>Requests for sensitive information</li>
          <li>Generic or suspicious greetings</li>
          <li>Brand or organization impersonation</li>
          <li>Attachment-based threats</li>
          <li>Fear or reward manipulation</li>
        </ul>
        <p className="text-sm text-gray-700 mt-2">
          Note: This tool provides an indication of phishing risk, but it's not 100% accurate. Always use your best judgment.
        </p>
      </div>
    </div>
  );
};

export default PhishingDetector;