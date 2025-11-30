#!/usr/bin/env python3
"""
Advanced Logging Module
A comprehensive logging solution for professional Python applications.
"""

import logging
import logging.handlers
import os
import sys
from typing import Dict, Optional, Any, List, Union
from pathlib import Path


class AdvancedLogger:
    """
    Advanced logging configuration with file rotation and multi-handler support.
    
    Features:
    - Console and file logging
    - Rotating log files with configurable size
    - Advanced log formatting with colors (console)
    - Log levels with custom filtering
    - Structured logging support
    """
    
    # Color codes for console output
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
        'RESET': '\033[0m'        # Reset
    }
    
    # Default log formats
    DEFAULT_FORMATS = {
        'verbose': '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(funcName)s - %(message)s',
        'standard': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        'simple': '%(levelname)s - %(message)s',
        'structured': '%(asctime)s | %(levelname)-8s | %(name)-15s | %(message)s'
    }
    
    def __init__(self):
        """Initialize the AdvancedLogger with default configurations."""
        self._configured_loggers = {}
    
    def _create_console_formatter(self, use_colors: bool = True) -> logging.Formatter:
        """
        Create a formatter for console output with optional colors.
        
        Args:
            use_colors: Whether to use colored output
            
        Returns:
            Configured logging formatter
        """
        if use_colors:
            class ColorFormatter(logging.Formatter):
                def format(self, record):
                    if record.levelname in AdvancedLogger.COLORS:
                        record.levelname = (f"{AdvancedLogger.COLORS[record.levelname]}"
                                          f"{record.levelname}"
                                          f"{AdvancedLogger.COLORS['RESET']}")
                        record.msg = (f"{AdvancedLogger.COLORS[record.levelname]}"
                                    f"{record.msg}"
                                    f"{AdvancedLogger.COLORS['RESET']}")
                    return super().format(record)
            
            return ColorFormatter(self.DEFAULT_FORMATS['structured'])
        else:
            return logging.Formatter(self.DEFAULT_FORMATS['structured'])
    
    def _create_file_formatter(self) -> logging.Formatter:
        """
        Create a formatter for file output.
        
        Returns:
            Configured logging formatter for files
        """
        return logging.Formatter(self.DEFAULT_FORMATS['verbose'])
    
    def setup_logger(self,
                    name: str,
                    log_file: Optional[str] = None,
                    console: bool = True,
                    level: Union[str, int] = logging.INFO,
                    max_bytes: int = 10 * 1024 * 1024,  # 10MB
                    backup_count: int = 5,
                    use_colors: bool = True,
                    format_type: str = 'standard',
                    custom_format: Optional[str] = None) -> logging.Logger:
        """
        Set up a comprehensive logger with console and file handlers.
        
        Args:
            name: Logger name (typically __name__)
            log_file: Path to log file (optional)
            console: Enable console output (default: True)
            level: Logging level (default: INFO)
            max_bytes: Maximum log file size before rotation (default: 10MB)
            backup_count: Number of backup log files to keep (default: 5)
            use_colors: Enable colored console output (default: True)
            format_type: Predefined format type ('verbose', 'standard', 'simple', 'structured')
            custom_format: Custom format string (overrides format_type)
            
        Returns:
            Configured logger instance
            
        Raises:
            ValueError: If invalid parameters are provided
        """
        # Validate inputs
        if not isinstance(name, str) or not name:
            raise ValueError("Logger name must be a non-empty string")
        
        if format_type not in self.DEFAULT_FORMATS and not custom_format:
            raise ValueError(f"Invalid format_type. Choose from {list(self.DEFAULT_FORMATS.keys())} or provide custom_format")
        
        # Get or create logger
        logger = logging.getLogger(name)
        
        # Avoid duplicate handlers
        if name in self._configured_loggers:
            return logger
        
        # Set log level
        if isinstance(level, str):
            level = getattr(logging, level.upper(), logging.INFO)
        logger.setLevel(level)
        
        # Clear existing handlers to avoid duplicates
        logger.handlers.clear()
        
        # Create formatters
        if custom_format:
            console_formatter = logging.Formatter(custom_format)
            file_formatter = logging.Formatter(custom_format)
        else:
            console_formatter = self._create_console_formatter(use_colors)
            file_formatter = logging.Formatter(self.DEFAULT_FORMATS[format_type])
        
        # Add console handler if requested
        if console:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(level)
            console_handler.setFormatter(console_formatter)
            logger.addHandler(console_handler)
        
        # Add file handler if log file specified
        if log_file:
            try:
                # Ensure directory exists
                log_path = Path(log_file)
                log_path.parent.mkdir(parents=True, exist_ok=True)
                
                # Create rotating file handler
                file_handler = logging.handlers.RotatingFileHandler(
                    filename=log_file,
                    maxBytes=max_bytes,
                    backupCount=backup_count,
                    encoding='utf-8'
                )
                file_handler.setLevel(level)
                file_handler.setFormatter(file_formatter)
                logger.addHandler(file_handler)
                
            except (OSError, IOError) as e:
                print(f"Warning: Could not create file handler for {log_file}: {e}", 
                      file=sys.stderr)
        
        # Prevent propagation to root logger to avoid duplicate messages
        logger.propagate = False
        
        # Store configured logger
        self._configured_loggers[name] = {
            'log_file': log_file,
            'console': console,
            'level': level
        }
        
        return logger
    
    def get_logger_config(self, name: str) -> Optional[Dict[str, Any]]:
        """
        Get configuration for a previously configured logger.
        
        Args:
            name: Logger name
            
        Returns:
            Logger configuration dictionary or None if not found
        """
        return self._configured_loggers.get(name)
    
    def list_configured_loggers(self) -> List[str]:
        """
        Get list of all configured logger names.
        
        Returns:
            List of configured logger names
        """
        return list(self._configured_loggers.keys())
    
    def shutdown(self) -> None:
        """Shutdown all logging handlers and clean up resources."""
        logging.shutdown()
        self._configured_loggers.clear()


# Global instance for easy access
_advanced_logger = AdvancedLogger()


def setup_logger(name: str,
                log_file: Optional[str] = None,
                console: bool = True,
                level: Union[str, int] = logging.INFO,
                **kwargs) -> logging.Logger:
    """
    Convenience function to set up a logger with advanced configuration.
    
    This is the main entry point for most use cases.
    
    Args:
        name: Logger name (typically __name__)
        log_file: Path to log file (optional)
        console: Enable console output (default: True)
        level: Logging level (default: INFO)
        **kwargs: Additional arguments for AdvancedLogger.setup_logger
        
    Returns:
        Configured logger instance
        
    Example:
        >>> logger = setup_logger(__name__, 'app.log', level='DEBUG')
        >>> logger.info('Application started')
    """
    return _advanced_logger.setup_logger(
        name=name,
        log_file=log_file,
        console=console,
        level=level,
        **kwargs
    )


def get_logger_config(name: str) -> Optional[Dict[str, Any]]:
    """
    Get configuration for a previously configured logger.
    
    Args:
        name: Logger name
        
    Returns:
        Logger configuration dictionary or None if not found
    """
    return _advanced_logger.get_logger_config(name)


def list_configured_loggers() -> List[str]:
    """
    Get list of all configured logger names.
    
    Returns:
        List of configured logger names
    """
    return _advanced_logger.list_configured_loggers()


def shutdown_logging() -> None:
    """Shutdown all logging handlers and clean up resources."""
    _advanced_logger.shutdown()


class StructuredLogger:
    """
    A wrapper for structured logging with consistent field support.
    """
    
    def __init__(self, logger: logging.Logger):
        """
        Initialize StructuredLogger.
        
        Args:
            logger: Base logger instance
        """
        self.logger = logger
    
    def debug(self, message: str, **kwargs) -> None:
        """Log debug message with structured data."""
        self._log_with_structure(logging.DEBUG, message, **kwargs)
    
    def info(self, message: str, **kwargs) -> None:
        """Log info message with structured data."""
        self._log_with_structure(logging.INFO, message, **kwargs)
    
    def warning(self, message: str, **kwargs) -> None:
        """Log warning message with structured data."""
        self._log_with_structure(logging.WARNING, message, **kwargs)
    
    def error(self, message: str, **kwargs) -> None:
        """Log error message with structured data."""
        self._log_with_structure(logging.ERROR, message, **kwargs)
    
    def critical(self, message: str, **kwargs) -> None:
        """Log critical message with structured data."""
        self._log_with_structure(logging.CRITICAL, message, **kwargs)
    
    def _log_with_structure(self, level: int, message: str, **kwargs) -> None:
        """
        Log message with structured data in JSON-like format.
        
        Args:
            level: Logging level
            message: Primary log message
            **kwargs: Structured data fields
        """
        if kwargs:
            structured_data = " | ".join(f"{k}={v}" for k, v in kwargs.items())
            full_message = f"{message} | {structured_data}"
        else:
            full_message = message
        
        self.logger.log(level, full_message)


def run_module(params_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main module entry point for integration with other systems.
    
    Args:
        params_dict: Dictionary containing module parameters:
            - name: Logger name (required)
            - log_file: Path to log file (optional)
            - console: Enable console output (optional, default: True)
            - level: Logging level (optional, default: 'INFO')
            - max_bytes: Max file size (optional, default: 10485760)
            - backup_count: Backup files count (optional, default: 5)
            - use_colors: Enable colors (optional, default: True)
            - format_type: Format type (optional, default: 'standard')
            - action: 'setup', 'config', 'list', or 'shutdown' (optional)
            
    Returns:
        Dictionary containing operation results
    """
    try:
        action = params_dict.get('action', 'setup')
        
        if action == 'setup':
            # Validate required parameters
            if 'name' not in params_dict:
                return {
                    "status": "error",
                    "error": "Missing required parameter: name"
                }
            
            # Set up logger
            logger = setup_logger(
                name=params_dict['name'],
                log_file=params_dict.get('log_file'),
                console=params_dict.get('console', True),
                level=params_dict.get('level', 'INFO'),
                max_bytes=params_dict.get('max_bytes', 10 * 1024 * 1024),
                backup_count=params_dict.get('backup_count', 5),
                use_colors=params_dict.get('use_colors', True),
                format_type=params_dict.get('format_type', 'standard')
            )
            
            return {
                "status": "success",
                "logger_name": params_dict['name'],
                "level": logging.getLevelName(logger.level),
                "handlers": [type(handler).__name__ for handler in logger.handlers]
            }
        
        elif action == 'config':
            name = params_dict.get('name')
            if not name:
                return {
                    "status": "error",
                    "error": "Missing required parameter: name for config action"
                }
            
            config = get_logger_config(name)
            if config:
                return {
                    "status": "success",
                    "logger_name": name,
                    "config": config
                }
            else:
                return {
                    "status": "error",
                    "error": f"Logger '{name}' not found"
                }
        
        elif action == 'list':
            loggers = list_configured_loggers()
            return {
                "status": "success",
                "configured_loggers": loggers,
                "count": len(loggers)
            }
        
        elif action == 'shutdown':
            shutdown_logging()
            return {
                "status": "success",
                "message": "Logging system shutdown complete"
            }
        
        else:
            return {
                "status": "error",
                "error": f"Unknown action: {action}"
            }
            
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }


def demonstrate_usage() -> None:
    """
    Demonstrate the logging module usage with various examples.
    """
    print("=== Advanced Logging Module Demonstration ===\n")
    
    # Example 1: Basic console logger
    print("1. Basic console logger:")
    basic_logger = setup_logger('basic_demo')
    basic_logger.info("This is a basic info message")
    basic_logger.warning("This is a warning message")
    
    # Example 2: File logger with rotation
    print("\n2. File logger with rotation:")
    file_logger = setup_logger(
        'file_demo',
        log_file='./logs/demo_application.log',
        level='DEBUG',
        max_bytes=1024 * 1024,  # 1MB
        backup_count=3
    )
    file_logger.debug("Debug message for file")
    file_logger.info("Info message for file")
    
    # Example 3: Structured logging
    print("\n3. Structured logging:")
    struct_logger = StructuredLogger(setup_logger('structured_demo'))
    struct_logger.info("User login successful", user_id=123, ip="192.168.1.100", duration_ms=45)
    struct_logger.error("Database connection failed", attempt=3, timeout=30, database="primary")
    
    # Example 4: Different format types
    print("\n4. Different format types:")
    verbose_logger = setup_logger('verbose_demo', format_type='verbose')
    verbose_logger.info("Verbose format message")
    
    simple_logger = setup_logger('simple_demo', format_type='simple')
    simple_logger.info("Simple format message")
    
    # Show configured loggers
    print(f"\n5. Configured loggers: {list_configured_loggers()}")
    
    # Cleanup demo files
    import shutil
    if os.path.exists('./logs'):
        shutil.rmtree('./logs')
    
    print("\n=== Demonstration Complete ===")


if __name__ == "__main__":
    # Run demonstration when executed directly
    demonstrate_usage()