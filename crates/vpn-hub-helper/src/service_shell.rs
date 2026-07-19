use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// Coalesced signals shared by the SCM callback and the helper event loop.
#[derive(Debug, Default)]
pub struct ServiceSignals {
    stop: AtomicBool,
    resume: AtomicBool,
}

impl ServiceSignals {
    #[must_use]
    pub fn should_stop(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }

    pub fn request_resume(&self) {
        self.resume.store(true, Ordering::SeqCst);
    }

    pub fn take_resume(&self) -> bool {
        self.resume.swap(false, Ordering::SeqCst)
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceShellContract {
    pub target_account: &'static str,
    pub self_elevation_supported: bool,
    pub service_dispatcher_compiled: bool,
    pub default_enabled: bool,
    pub windows_target: bool,
}

pub type ServiceBody = fn(Arc<ServiceSignals>) -> Result<(), String>;

#[cfg(target_os = "windows")]
mod windows {
    use std::{
        ffi::OsString,
        sync::{Arc, OnceLock},
        time::Duration,
    };

    use windows_service::{
        define_windows_service,
        service::{
            PowerEventParam, ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState,
            ServiceStatus, ServiceType, SessionChangeReason,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };

    use super::{ServiceBody, ServiceSignals};

    const SERVICE_NAME: &str = "VpnHubHelper";
    static BODY: OnceLock<ServiceBody> = OnceLock::new();

    define_windows_service!(ffi_service_main, service_main);

    pub fn dispatch(body: ServiceBody) -> Result<(), String> {
        BODY.set(body)
            .map_err(|_| "service body already configured".to_owned())?;
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
            .map_err(|error| format!("service dispatcher unavailable: {error}"))
    }

    fn is_recovery_control(control: &ServiceControl) -> bool {
        matches!(
            control,
            ServiceControl::PowerEvent(
                PowerEventParam::ResumeAutomatic
                    | PowerEventParam::ResumeSuspend
                    | PowerEventParam::ResumeCritical
            )
        ) || matches!(
            control,
            ServiceControl::SessionChange(change)
                if matches!(
                    change.reason,
                    SessionChangeReason::SessionLogon | SessionChangeReason::SessionUnlock
                )
        )
    }

    fn service_main(_arguments: Vec<OsString>) {
        let signals = Arc::new(ServiceSignals::default());
        let signals_for_handler = Arc::clone(&signals);
        let event_handler = move |control_event| -> ServiceControlHandlerResult {
            match control_event {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    signals_for_handler.request_stop();
                    ServiceControlHandlerResult::NoError
                }
                control if is_recovery_control(&control) => {
                    signals_for_handler.request_resume();
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        };
        let Ok(status_handle) = service_control_handler::register(SERVICE_NAME, event_handler)
        else {
            return;
        };
        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP
                | ServiceControlAccept::SHUTDOWN
                | ServiceControlAccept::POWER_EVENT
                | ServiceControlAccept::SESSION_CHANGE,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::ZERO,
            process_id: None,
        });
        let service_result = BODY
            .get()
            .ok_or_else(|| "service body was not provisioned".to_owned())
            .and_then(|body| body(Arc::clone(&signals)));
        let exit_code = u32::from(service_result.is_err());
        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(exit_code),
            checkpoint: 0,
            wait_hint: Duration::ZERO,
            process_id: None,
        });
    }

    #[cfg(test)]
    pub(super) fn recovery_control_for_test(control: &ServiceControl) -> bool {
        is_recovery_control(control)
    }
}

/// Enters the SCM dispatcher on Windows. Interactive execution fails safely;
/// it never installs or elevates the process.
#[cfg(target_os = "windows")]
pub fn run_service_dispatcher(body: ServiceBody) -> Result<(), String> {
    windows::dispatch(body)
}

#[cfg(not(target_os = "windows"))]
pub fn run_service_dispatcher(_body: ServiceBody) -> Result<(), String> {
    Err("Windows service dispatcher is unavailable on this platform".into())
}

#[must_use]
pub const fn service_shell_contract() -> ServiceShellContract {
    ServiceShellContract {
        target_account: "NT AUTHORITY\\LOCAL SERVICE",
        self_elevation_supported: false,
        service_dispatcher_compiled: cfg!(target_os = "windows"),
        default_enabled: false,
        windows_target: cfg!(target_os = "windows"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_never_self_elevates_or_defaults_on() {
        let contract = service_shell_contract();
        assert_eq!(contract.target_account, "NT AUTHORITY\\LOCAL SERVICE");
        assert!(!contract.self_elevation_supported);
        assert!(!contract.default_enabled);
        assert_eq!(contract.service_dispatcher_compiled, cfg!(windows));
    }

    #[test]
    fn service_signals_coalesce_resume_and_latch_stop() {
        let signals = ServiceSignals::default();
        signals.request_resume();
        signals.request_resume();
        assert!(signals.take_resume());
        assert!(!signals.take_resume());
        signals.request_stop();
        assert!(signals.should_stop());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn power_resume_and_session_unlock_map_to_recovery_only() {
        use windows_service::service::{
            PowerEventParam, ServiceControl, SessionChangeParam, SessionChangeReason,
            SessionNotification,
        };

        assert!(windows::recovery_control_for_test(
            &ServiceControl::PowerEvent(PowerEventParam::ResumeAutomatic,)
        ));
        assert!(!windows::recovery_control_for_test(
            &ServiceControl::PowerEvent(PowerEventParam::Suspend,)
        ));
        let session = |reason| {
            ServiceControl::SessionChange(SessionChangeParam {
                reason,
                notification: SessionNotification {
                    size: 0,
                    session_id: 0,
                },
            })
        };
        assert!(windows::recovery_control_for_test(&session(
            SessionChangeReason::SessionUnlock,
        )));
        assert!(!windows::recovery_control_for_test(&session(
            SessionChangeReason::SessionLock,
        )));
    }
}
