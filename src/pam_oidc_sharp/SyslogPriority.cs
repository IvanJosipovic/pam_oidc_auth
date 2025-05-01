namespace pam_oidc_sharp;

/// <summary>
/// Syslog priority levels
/// </summary>
public enum SyslogPriority
{
    /// <summary>
    /// LOG_EMERG: system is unusable
    /// </summary>
    LOG_EMERG = 0,

    /// <summary>
    /// LOG_ALERT: action must be taken immediately
    /// </summary>
    LOG_ALERT = 1,

    /// <summary>
    /// LOG_CRIT: critical conditions
    /// </summary>
    LOG_CRIT = 2,

    /// <summary>
    /// LOG_ERR: error conditions
    /// </summary>
    LOG_ERR = 3,

    /// <summary>
    /// LOG_WARNING: warning conditions
    /// </summary>
    LOG_WARNING = 4,

    /// <summary>
    /// LOG_NOTICE: normal but significant condition
    /// </summary>
    LOG_NOTICE = 5,

    /// <summary>
    /// LOG_INFO: informational messages
    /// </summary>
    LOG_INFO = 6,

    /// <summary>
    /// LOG_DEBUG: debug-level messages
    /// </summary>
    LOG_DEBUG = 7
}