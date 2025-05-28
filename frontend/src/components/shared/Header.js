import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { 
  Bars3Icon, 
  BellIcon, 
  UserIcon,
  Cog6ToothIcon,
  ArrowRightOnRectangleIcon,
  ChevronDownIcon
} from '@heroicons/react/24/outline';
import { Menu, Transition } from '@headlessui/react';
import { useAuth } from '../../contexts/AuthContext';
import { useTheme } from '../../contexts/ThemeContext';
import clsx from 'clsx';

const Header = ({ onMenuClick, sidebarOpen }) => {
  const { user, logout } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const [notificationCount] = useState(3); // This would come from a notifications context/hook

  const handleLogout = async () => {
    await logout();
  };

  return (
    <header className="bg-white shadow-sm border-b border-gray-200 h-16 fixed w-full top-0 z-30">
      <div className="flex items-center justify-between h-full px-4 lg:px-6">
        {/* Left side */}
        <div className="flex items-center space-x-4">
          {/* Mobile menu button */}
          <button
            type="button"
            className="lg:hidden p-2 rounded-md text-gray-600 hover:text-gray-900 hover:bg-gray-100 focus:outline-none focus:ring-2 focus:ring-nhs-blue"
            onClick={onMenuClick}
            aria-label="Toggle navigation menu"
          >
            <Bars3Icon className="h-6 w-6" />
          </button>

          {/* Desktop menu button */}
          <button
            type="button"
            className="hidden lg:block p-2 rounded-md text-gray-600 hover:text-gray-900 hover:bg-gray-100 focus:outline-none focus:ring-2 focus:ring-nhs-blue"
            onClick={onMenuClick}
            aria-label="Toggle sidebar"
          >
            <Bars3Icon className="h-6 w-6" />
          </button>

          {/* Logo and title */}
          <Link 
            to="/dashboard" 
            className="flex items-center space-x-3 focus:outline-none focus:ring-2 focus:ring-nhs-blue rounded-md"
          >
            <div className="w-8 h-8 bg-nhs-blue rounded-md flex items-center justify-center">
              <span className="text-white font-bold text-sm">RPM</span>
            </div>
            <div className="hidden sm:block">
              <h1 className="text-lg font-semibold text-gray-900">
                Remote Patient Monitoring
              </h1>
              <p className="text-xs text-gray-500">NHS Digital Health Platform</p>
            </div>
          </Link>
        </div>

        {/* Right side */}
        <div className="flex items-center space-x-4">
          {/* Theme toggle */}
          <button
            type="button"
            onClick={toggleTheme}
            className="p-2 rounded-md text-gray-600 hover:text-gray-900 hover:bg-gray-100 focus:outline-none focus:ring-2 focus:ring-nhs-blue"
            aria-label={`Switch to ${theme === 'light' ? 'dark' : 'light'} mode`}
          >
            {theme === 'light' ? '🌙' : '☀️'}
          </button>

          {/* Notifications */}
          <button
            type="button"
            className="relative p-2 rounded-md text-gray-600 hover:text-gray-900 hover:bg-gray-100 focus:outline-none focus:ring-2 focus:ring-nhs-blue"
            aria-label={`Notifications${notificationCount > 0 ? ` (${notificationCount} new)` : ''}`}
          >
            <BellIcon className="h-6 w-6" />
            {notificationCount > 0 && (
              <span className="absolute -top-1 -right-1 h-5 w-5 bg-red-500 text-white text-xs rounded-full flex items-center justify-center">
                {notificationCount > 9 ? '9+' : notificationCount}
                <span className="sr-only">new notifications</span>
              </span>
            )}
          </button>

          {/* User menu */}
          <Menu as="div" className="relative">
            <Menu.Button className="flex items-center space-x-2 p-2 rounded-md text-gray-600 hover:text-gray-900 hover:bg-gray-100 focus:outline-none focus:ring-2 focus:ring-nhs-blue">
              <div className="w-8 h-8 bg-gray-300 rounded-full flex items-center justify-center">
                {user?.avatar ? (
                  <img
                    src={user.avatar}
                    alt={`${user.first_name} ${user.last_name}`}
                    className="w-8 h-8 rounded-full object-cover"
                  />
                ) : (
                  <UserIcon className="h-5 w-5 text-gray-600" />
                )}
              </div>
              <div className="hidden md:block text-left">
                <p className="text-sm font-medium text-gray-900">
                  {user?.first_name} {user?.last_name}
                </p>
                <p className="text-xs text-gray-500 capitalize">
                  {user?.role?.name}
                </p>
              </div>
              <ChevronDownIcon className="h-4 w-4 text-gray-600" />
            </Menu.Button>

            <Transition
              enter="transition ease-out duration-100"
              enterFrom="transform opacity-0 scale-95"
              enterTo="transform opacity-100 scale-100"
              leave="transition ease-in duration-75"
              leaveFrom="transform opacity-100 scale-100"
              leaveTo="transform opacity-0 scale-95"
            >
              <Menu.Items className="absolute right-0 mt-2 w-48 bg-white rounded-md shadow-lg ring-1 ring-black ring-opacity-5 focus:outline-none">
                <div className="py-1">
                  <Menu.Item>
                    {({ active }) => (
                      <Link
                        to="/settings"
                        className={clsx(
                          'flex items-center px-4 py-2 text-sm',
                          active ? 'bg-gray-100 text-gray-900' : 'text-gray-700'
                        )}
                      >
                        <UserIcon className="h-4 w-4 mr-3" />
                        Profile
                      </Link>
                    )}
                  </Menu.Item>
                  <Menu.Item>
                    {({ active }) => (
                      <Link
                        to="/settings"
                        className={clsx(
                          'flex items-center px-4 py-2 text-sm',
                          active ? 'bg-gray-100 text-gray-900' : 'text-gray-700'
                        )}
                      >
                        <Cog6ToothIcon className="h-4 w-4 mr-3" />
                        Settings
                      </Link>
                    )}
                  </Menu.Item>
                  <div className="border-t border-gray-100" />
                  <Menu.Item>
                    {({ active }) => (
                      <button
                        onClick={handleLogout}
                        className={clsx(
                          'flex items-center w-full px-4 py-2 text-sm text-left',
                          active ? 'bg-gray-100 text-gray-900' : 'text-gray-700'
                        )}
                      >
                        <ArrowRightOnRectangleIcon className="h-4 w-4 mr-3" />
                        Sign out
                      </button>
                    )}
                  </Menu.Item>
                </div>
              </Menu.Items>
            </Transition>
          </Menu>
        </div>
      </div>
    </header>
  );
};

export default Header;
