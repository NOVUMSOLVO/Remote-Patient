import React from 'react';

const Footer = () => {
  const currentYear = new Date().getFullYear();

  return (
    <footer className="bg-white border-t border-gray-200 py-4 px-4 lg:px-6">
      <div className="flex flex-col sm:flex-row justify-between items-center text-sm text-gray-600">
        <div className="flex items-center space-x-4 mb-2 sm:mb-0">
          <span>© {currentYear} NHS Digital Health Platform</span>
          <span className="hidden sm:inline">|</span>
          <a 
            href="/privacy" 
            className="hover:text-nhs-blue focus:outline-none focus:underline"
          >
            Privacy Policy
          </a>
          <span>|</span>
          <a 
            href="/accessibility" 
            className="hover:text-nhs-blue focus:outline-none focus:underline"
          >
            Accessibility
          </a>
          <span>|</span>
          <a 
            href="/support" 
            className="hover:text-nhs-blue focus:outline-none focus:underline"
          >
            Support
          </a>
        </div>
        <div className="flex items-center space-x-2">
          <span>Version 1.0.0</span>
          <span className="hidden sm:inline">|</span>
          <span className="text-green-600">System Status: ●</span>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
