import React from 'react';
import clsx from 'clsx';

const LoadingSpinner = ({ 
  size = 'medium', 
  color = 'primary', 
  className = '',
  text = 'Loading...' 
}) => {
  const sizeClasses = {
    small: 'w-4 h-4',
    medium: 'w-8 h-8',
    large: 'w-12 h-12',
    xlarge: 'w-16 h-16',
  };

  const colorClasses = {
    primary: 'border-nhs-blue',
    secondary: 'border-gray-400',
    white: 'border-white',
  };

  return (
    <div className={clsx('flex flex-col items-center justify-center', className)}>
      <div
        className={clsx(
          'animate-spin rounded-full border-4 border-gray-200',
          sizeClasses[size],
          colorClasses[color]
        )}
        style={{
          borderTopColor: 'var(--nhs-blue)',
        }}
        role="status"
        aria-label={text}
      />
      {text && (
        <span className="mt-2 text-sm text-gray-600 sr-only">
          {text}
        </span>
      )}
    </div>
  );
};

export default LoadingSpinner;
