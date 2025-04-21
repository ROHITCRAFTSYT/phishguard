# PhishGuard: Email Phishing Detection Tool

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Version](https://img.shields.io/badge/version-1.0.0-green.svg)

PhishGuard is a sophisticated web-based tool that helps users identify potential phishing emails through pattern recognition and content analysis. Built with React, it provides real-time analysis of email content to detect common phishing indicators.

## 🛡️ Features

- **Multi-factor analysis** - Examines emails using 9 different detection patterns
- **Risk categorization** - Classifies emails as High, Medium, or Low risk
- **Visual feedback** - Clear visual indicators of risk level
- **Detailed explanations** - Provides specific details about detected patterns
- **Actionable recommendations** - Offers context-specific security advice

## 🔍 Detection Capabilities

PhishGuard can identify:

- Urgency and pressure tactics
- Suspicious links and domains (including URL shorteners)
- Grammatical and spelling errors
- Suspicious sender patterns
- Requests for sensitive information
- Generic or suspicious greetings
- Brand/organization impersonation attempts
- Attachment-based threats
- Fear or reward manipulation tactics

## 🚀 Getting Started

### Prerequisites

- Node.js (v14.0.0 or higher)
- npm (v6.0.0 or higher)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/ROHITCRAFTSYT/phishguard.git
   cd phishguard
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Start the development server:
   ```bash
   npm start
   ```

4. Open your browser and navigate to `http://localhost:3000`

## 🔧 Usage

1. Copy the entire content of a suspicious email, including headers if available
2. Paste the content into the text area
3. Click "Analyze Email"
4. Review the detailed risk assessment and follow the recommendations

## 📂 Project Structure

```
src/
├── components/
│   ├── PhishingDetector.js   # Main detection component
│   └── ... 
├── utils/
│   ├── patternDetection.js   # Detection pattern logic
│   └── ...
├── App.js                    # App entry point
└── index.js                  # React entry point
```

## 🛠️ Technology Stack

- **React** - UI library
- **Tailwind CSS** - Styling
- **JavaScript** - Programming language

## 📊 Detection Algorithms

PhishGuard employs a comprehensive scoring system that:

1. Analyzes email content against known phishing patterns
2. Assigns weighted risk scores to different types of patterns
3. Calculates overall risk based on cumulative scoring
4. Provides category-specific explanations and severity levels

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

⚠️ **Disclaimer**: PhishGuard provides an indication of phishing risk through pattern analysis, but it's not 100% accurate. Always use your best judgment when dealing with suspicious emails. This tool is intended to supplement, not replace, good security practices.
