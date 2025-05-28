import React, { useState } from 'react';
import { Outlet } from 'react-router-dom';
import clsx from 'clsx';
import Header from './Header';
import Sidebar from './Sidebar';
import Footer from './Footer';

const Layout = () => {
  const [sidebarOpen, setSidebarOpen] = useState(false);

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Skip to main content link for accessibility */}
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4 bg-nhs-blue text-white px-4 py-2 rounded-md z-50"
      >
        Skip to main content
      </a>

      {/* Header */}
      <Header 
        onMenuClick={() => setSidebarOpen(!sidebarOpen)}
        sidebarOpen={sidebarOpen}
      />

      <div className="flex h-[calc(100vh-4rem)]">
        {/* Sidebar */}
        <Sidebar 
          open={sidebarOpen} 
          onClose={() => setSidebarOpen(false)} 
        />

        {/* Main content */}
        <main 
          id="main-content"
          className={clsx(
            'flex-1 overflow-y-auto transition-all duration-300 ease-in-out',
            'focus:outline-none',
            sidebarOpen ? 'lg:ml-64' : 'lg:ml-16'
          )}
          tabIndex="-1"
        >
          <div className="p-4 lg:p-6">
            <Outlet />
          </div>
        </main>
      </div>

      {/* Footer */}
      <Footer />

      {/* Mobile overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 z-40 bg-black bg-opacity-50 lg:hidden"
          onClick={() => setSidebarOpen(false)}
          aria-hidden="true"
        />
      )}
    </div>
  );
};

export default Layout;
