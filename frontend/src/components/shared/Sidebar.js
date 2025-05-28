import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { 
  HomeIcon,
  UserGroupIcon,
  DevicePhoneMobileIcon,
  HeartIcon,
  BellIcon,
  ChatBubbleLeftRightIcon,
  DocumentChartBarIcon,
  Cog6ToothIcon,
  UserIcon,
  XMarkIcon
} from '@heroicons/react/24/outline';
import { useAuth } from '../../contexts/AuthContext';
import clsx from 'clsx';

const Sidebar = ({ open, onClose }) => {
  const location = useLocation();
  const { user, hasPermission } = useAuth();

  const navigation = [
    {
      name: 'Dashboard',
      href: '/dashboard',
      icon: HomeIcon,
      current: location.pathname === '/dashboard',
    },
    {
      name: 'Patients',
      href: '/patients',
      icon: UserGroupIcon,
      current: location.pathname.startsWith('/patients'),
      permission: 'view_patients',
    },
    {
      name: 'Devices',
      href: '/devices',
      icon: DevicePhoneMobileIcon,
      current: location.pathname === '/devices',
      permission: 'manage_devices',
    },
    {
      name: 'Monitoring',
      href: '/monitoring',
      icon: HeartIcon,
      current: location.pathname === '/monitoring',
      permission: 'view_health_data',
    },
    {
      name: 'Alerts',
      href: '/alerts',
      icon: BellIcon,
      current: location.pathname === '/alerts',
      permission: 'view_alerts',
    },
    {
      name: 'Communication',
      href: '/communication',
      icon: ChatBubbleLeftRightIcon,
      current: location.pathname === '/communication',
      permission: 'send_messages',
    },
    {
      name: 'Reports',
      href: '/reports',
      icon: DocumentChartBarIcon,
      current: location.pathname === '/reports',
      permission: 'view_reports',
    },
    {
      name: 'Admin',
      href: '/admin',
      icon: Cog6ToothIcon,
      current: location.pathname === '/admin',
      permission: 'admin_access',
    },
  ];

  // Filter navigation based on user permissions
  const filteredNavigation = navigation.filter(item => 
    !item.permission || hasPermission(item.permission)
  );

  return (
    <>
      {/* Mobile sidebar */}
      <div className={clsx(
        'fixed inset-y-0 left-0 z-50 w-64 bg-white shadow-lg transform transition-transform duration-300 ease-in-out lg:hidden',
        open ? 'translate-x-0' : '-translate-x-full'
      )}>
        <div className="flex items-center justify-between h-16 px-4 border-b border-gray-200">
          <div className="flex items-center space-x-2">
            <div className="w-8 h-8 bg-nhs-blue rounded-md flex items-center justify-center">
              <span className="text-white font-bold text-sm">RPM</span>
            </div>
            <span className="font-semibold text-gray-900">Menu</span>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-2 rounded-md text-gray-600 hover:text-gray-900 hover:bg-gray-100"
            aria-label="Close navigation menu"
          >
            <XMarkIcon className="h-6 w-6" />
          </button>
        </div>
        <nav className="mt-4 px-4 space-y-1">
          {filteredNavigation.map((item) => (
            <Link
              key={item.name}
              to={item.href}
              onClick={onClose}
              className={clsx(
                'group flex items-center px-3 py-2 text-sm font-medium rounded-md transition-colors duration-200',
                item.current
                  ? 'bg-nhs-blue text-white'
                  : 'text-gray-700 hover:bg-gray-100 hover:text-gray-900'
              )}
              aria-current={item.current ? 'page' : undefined}
            >
              <item.icon
                className={clsx(
                  'mr-3 h-5 w-5 flex-shrink-0',
                  item.current
                    ? 'text-white'
                    : 'text-gray-400 group-hover:text-gray-500'
                )}
              />
              {item.name}
            </Link>
          ))}
        </nav>

        {/* User info in mobile sidebar */}
        <div className="absolute bottom-0 left-0 right-0 p-4 border-t border-gray-200">
          <div className="flex items-center space-x-3">
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
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-gray-900 truncate">
                {user?.first_name} {user?.last_name}
              </p>
              <p className="text-xs text-gray-500 truncate capitalize">
                {user?.role?.name}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Desktop sidebar */}
      <div className={clsx(
        'hidden lg:flex lg:flex-col lg:fixed lg:inset-y-0 lg:bg-white lg:border-r lg:border-gray-200 lg:pt-16 transition-all duration-300 ease-in-out',
        open ? 'lg:w-64' : 'lg:w-16'
      )}>
        <div className="flex-1 flex flex-col overflow-y-auto">
          <nav className="flex-1 px-2 py-4 space-y-1">
            {filteredNavigation.map((item) => (
              <Link
                key={item.name}
                to={item.href}
                className={clsx(
                  'group flex items-center px-3 py-2 text-sm font-medium rounded-md transition-colors duration-200',
                  item.current
                    ? 'bg-nhs-blue text-white'
                    : 'text-gray-700 hover:bg-gray-100 hover:text-gray-900'
                )}
                aria-current={item.current ? 'page' : undefined}
                title={!open ? item.name : undefined}
              >
                <item.icon
                  className={clsx(
                    'flex-shrink-0 h-5 w-5',
                    open ? 'mr-3' : 'mx-auto',
                    item.current
                      ? 'text-white'
                      : 'text-gray-400 group-hover:text-gray-500'
                  )}
                />
                {open && (
                  <span className="truncate">{item.name}</span>
                )}
              </Link>
            ))}
          </nav>

          {/* User info in desktop sidebar */}
          {open && (
            <div className="flex-shrink-0 p-4 border-t border-gray-200">
              <div className="flex items-center space-x-3">
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
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-gray-900 truncate">
                    {user?.first_name} {user?.last_name}
                  </p>
                  <p className="text-xs text-gray-500 truncate capitalize">
                    {user?.role?.name}
                  </p>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </>
  );
};

export default Sidebar;
