import React, { createContext, useContext, useReducer, useEffect } from 'react';

const ThemeContext = createContext();

// Theme reducer
const themeReducer = (state, action) => {
  switch (action.type) {
    case 'SET_THEME':
      return { ...state, theme: action.payload };
    case 'TOGGLE_THEME':
      return { ...state, theme: state.theme === 'light' ? 'dark' : 'light' };
    case 'SET_HIGH_CONTRAST':
      return { ...state, highContrast: action.payload };
    case 'SET_FONT_SIZE':
      return { ...state, fontSize: action.payload };
    case 'SET_REDUCED_MOTION':
      return { ...state, reducedMotion: action.payload };
    default:
      return state;
  }
};

// Initial state
const initialState = {
  theme: localStorage.getItem('theme') || 'light',
  highContrast: localStorage.getItem('highContrast') === 'true',
  fontSize: localStorage.getItem('fontSize') || 'medium',
  reducedMotion: localStorage.getItem('reducedMotion') === 'true',
};

export const ThemeProvider = ({ children }) => {
  const [state, dispatch] = useReducer(themeReducer, initialState);

  // Apply theme to document
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', state.theme);
    localStorage.setItem('theme', state.theme);
  }, [state.theme]);

  // Apply high contrast
  useEffect(() => {
    if (state.highContrast) {
      document.documentElement.classList.add('high-contrast');
    } else {
      document.documentElement.classList.remove('high-contrast');
    }
    localStorage.setItem('highContrast', state.highContrast);
  }, [state.highContrast]);

  // Apply font size
  useEffect(() => {
    document.documentElement.setAttribute('data-font-size', state.fontSize);
    localStorage.setItem('fontSize', state.fontSize);
  }, [state.fontSize]);

  // Apply reduced motion
  useEffect(() => {
    if (state.reducedMotion) {
      document.documentElement.classList.add('reduce-motion');
    } else {
      document.documentElement.classList.remove('reduce-motion');
    }
    localStorage.setItem('reducedMotion', state.reducedMotion);
  }, [state.reducedMotion]);

  // Check system preferences on mount
  useEffect(() => {
    // Check for system dark mode preference
    if (!localStorage.getItem('theme')) {
      const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      if (prefersDark) {
        dispatch({ type: 'SET_THEME', payload: 'dark' });
      }
    }

    // Check for system high contrast preference
    if (!localStorage.getItem('highContrast')) {
      const prefersHighContrast = window.matchMedia('(prefers-contrast: high)').matches;
      if (prefersHighContrast) {
        dispatch({ type: 'SET_HIGH_CONTRAST', payload: true });
      }
    }

    // Check for system reduced motion preference
    if (!localStorage.getItem('reducedMotion')) {
      const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      if (prefersReducedMotion) {
        dispatch({ type: 'SET_REDUCED_MOTION', payload: true });
      }
    }

    // Listen for system preference changes
    const darkModeQuery = window.matchMedia('(prefers-color-scheme: dark)');
    const highContrastQuery = window.matchMedia('(prefers-contrast: high)');
    const reducedMotionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');

    const handleDarkModeChange = (e) => {
      if (!localStorage.getItem('theme')) {
        dispatch({ type: 'SET_THEME', payload: e.matches ? 'dark' : 'light' });
      }
    };

    const handleHighContrastChange = (e) => {
      if (!localStorage.getItem('highContrast')) {
        dispatch({ type: 'SET_HIGH_CONTRAST', payload: e.matches });
      }
    };

    const handleReducedMotionChange = (e) => {
      if (!localStorage.getItem('reducedMotion')) {
        dispatch({ type: 'SET_REDUCED_MOTION', payload: e.matches });
      }
    };

    darkModeQuery.addEventListener('change', handleDarkModeChange);
    highContrastQuery.addEventListener('change', handleHighContrastChange);
    reducedMotionQuery.addEventListener('change', handleReducedMotionChange);

    return () => {
      darkModeQuery.removeEventListener('change', handleDarkModeChange);
      highContrastQuery.removeEventListener('change', handleHighContrastChange);
      reducedMotionQuery.removeEventListener('change', handleReducedMotionChange);
    };
  }, []);

  // Theme actions
  const setTheme = (theme) => {
    dispatch({ type: 'SET_THEME', payload: theme });
  };

  const toggleTheme = () => {
    dispatch({ type: 'TOGGLE_THEME' });
  };

  const setHighContrast = (enabled) => {
    dispatch({ type: 'SET_HIGH_CONTRAST', payload: enabled });
  };

  const setFontSize = (size) => {
    dispatch({ type: 'SET_FONT_SIZE', payload: size });
  };

  const setReducedMotion = (enabled) => {
    dispatch({ type: 'SET_REDUCED_MOTION', payload: enabled });
  };

  const value = {
    theme: state.theme,
    highContrast: state.highContrast,
    fontSize: state.fontSize,
    reducedMotion: state.reducedMotion,
    setTheme,
    toggleTheme,
    setHighContrast,
    setFontSize,
    setReducedMotion,
  };

  return (
    <ThemeContext.Provider value={value}>
      {children}
    </ThemeContext.Provider>
  );
};

export const useTheme = () => {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }
  return context;
};
