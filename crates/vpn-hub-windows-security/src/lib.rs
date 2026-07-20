//! Audited Windows security adapter for named-pipe creation.
//!
//! The helper workspace forbids unsafe code. Tokio's only API for passing
//! `SECURITY_ATTRIBUTES` is unsafe, so this crate contains the single required
//! call and keeps the descriptor alive for the duration of `CreateNamedPipeW`.

#[cfg(target_os = "windows")]
mod windows {
    use std::{
        collections::{HashMap, HashSet},
        ffi::c_void,
        fs::OpenOptions,
        io,
        mem::size_of,
        os::windows::{
            fs::{MetadataExt, OpenOptionsExt},
            io::AsRawHandle,
        },
        path::{Path, PathBuf},
    };

    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
    use windows_permissions::{
        LocalBox, SecurityDescriptor, Sid, WindowsSecure,
        constants::{AccessRights, AceType, SecurityInformation},
        wrappers::LookupAccountName,
    };

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ProtectedPathPolicy {
        Root,
        StrictDirectory,
        MutableDirectory,
        Immutable,
        Executable,
        Mutable,
        SecretMaterial,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct FileIdentity {
        volume_serial_number: u32,
        file_index: u64,
    }
    use windows_sys::Win32::{
        Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_NO_DATA, FILETIME},
        NetworkManagement::IpHelper::{
            GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_UNICAST_ADDRESS_LH,
        },
        Security::SECURITY_ATTRIBUTES,
        Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_NAME_NORMALIZED, FILE_SHARE_READ,
            GetFileInformationByHandle, GetFinalPathNameByHandleW, VOLUME_NAME_DOS,
        },
        System::Threading::GetProcessTimes,
    };

    /// Validates installation root containment, reparse-point absence, owner,
    /// and every ACE trustee/mask using handles opened without following links.
    ///
    /// # Errors
    /// Returns an error when any path escapes the root or has a broad/unexpected ACL.
    pub fn validate_protected_installation(
        root: &Path,
        critical_paths: &[(PathBuf, ProtectedPathPolicy)],
        interactive_user_sid: &str,
    ) -> io::Result<()> {
        validate_sid(interactive_user_sid)?;
        let root_file = open_no_follow(root)?;
        let expected_root = normalize_final_path(&root_file)?;
        validate_secure_handle(&root_file, interactive_user_sid, ProtectedPathPolicy::Root)?;
        validate_component_chain(root, &expected_root, critical_paths, interactive_user_sid)
    }

    fn validate_component_chain(
        root: &Path,
        expected_root: &Path,
        critical_paths: &[(PathBuf, ProtectedPathPolicy)],
        interactive_user_sid: &str,
    ) -> io::Result<()> {
        let mut policies = HashMap::new();
        for (path, policy) in critical_paths {
            let relative = safe_relative_path(root, path)?;
            policies.insert(root.join(relative), *policy);
        }

        let mut checked = HashSet::new();
        for (path, _) in critical_paths {
            let relative = safe_relative_path(root, path)?;
            let components = relative.components().collect::<Vec<_>>();
            let mut current = root.to_path_buf();
            for (index, component) in components.iter().enumerate() {
                let std::path::Component::Normal(name) = component else {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "installation path contains unsafe component",
                    ));
                };
                current.push(name);
                if !checked.insert(current.clone()) {
                    continue;
                }
                let file = open_no_follow(&current)?;
                let final_path = normalize_final_path(&file)?;
                if !final_path.starts_with(expected_root) || final_path == expected_root {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "installation path escapes protected root",
                    ));
                }
                if index + 1 < components.len() && !file.metadata()?.is_dir() {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "installation parent component is not a directory",
                    ));
                }
                let policy = policies
                    .get(&current)
                    .copied()
                    .unwrap_or(ProtectedPathPolicy::StrictDirectory);
                validate_secure_handle(&file, interactive_user_sid, policy)?;
            }
        }
        Ok(())
    }

    fn safe_relative_path<'a>(root: &Path, path: &'a Path) -> io::Result<&'a Path> {
        let relative = path.strip_prefix(root).map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "installation path escapes protected root",
            )
        })?;
        if relative.as_os_str().is_empty()
            || relative
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "installation path contains unsafe component",
            ));
        }
        Ok(relative)
    }

    /// Opens a file without following reparse points and denies concurrent
    /// write/delete sharing. The returned handle can be held through process spawn.
    ///
    /// # Errors
    /// Returns an error for a reparse point or when stable file identity is unavailable.
    pub fn open_verified_file(path: &Path) -> io::Result<(std::fs::File, FileIdentity)> {
        let file = open_no_follow(path)?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "verified path is not a file",
            ));
        }
        let identity = file_identity(&file)?;
        Ok((file, identity))
    }

    /// Reopens a file under the same no-follow/share contract and reads its identity.
    ///
    /// # Errors
    /// Returns an error when the path is replaced, linked, or inaccessible.
    pub fn verified_file_identity(path: &Path) -> io::Result<FileIdentity> {
        let file = open_no_follow(path)?;
        file_identity(&file)
    }

    fn open_no_follow(path: &Path) -> io::Result<std::fs::File> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .share_mode(FILE_SHARE_READ)
            .open(path)?;
        if file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "reparse points are forbidden",
            ));
        }
        Ok(file)
    }

    fn file_identity(file: &std::fs::File) -> io::Result<FileIdentity> {
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: the File owns a valid handle and the output structure is live
        // and writable for the duration of the call.
        if unsafe {
            GetFileInformationByHandle(file.as_raw_handle().cast::<c_void>(), &raw mut information)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(FileIdentity {
            volume_serial_number: information.dwVolumeSerialNumber,
            file_index: (u64::from(information.nFileIndexHigh) << 32)
                | u64::from(information.nFileIndexLow),
        })
    }

    fn normalize_final_path(file: &std::fs::File) -> io::Result<PathBuf> {
        let handle = file.as_raw_handle().cast::<c_void>();
        // SAFETY: handle belongs to the live File and a null output buffer is
        // the documented sizing request.
        let required = unsafe {
            GetFinalPathNameByHandleW(
                handle,
                std::ptr::null_mut(),
                0,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            )
        };
        if required == 0 || required > 32_768 {
            return Err(io::Error::last_os_error());
        }
        let mut buffer = vec![0_u16; usize::try_from(required).map_err(io::Error::other)? + 1];
        // SAFETY: buffer is writable for the supplied capacity and the handle
        // remains valid throughout the call.
        let written = unsafe {
            GetFinalPathNameByHandleW(
                handle,
                buffer.as_mut_ptr(),
                u32::try_from(buffer.len()).map_err(io::Error::other)?,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            )
        };
        if written == 0 || usize::try_from(written).unwrap_or(usize::MAX) >= buffer.len() {
            return Err(io::Error::last_os_error());
        }
        let value =
            String::from_utf16(&buffer[..usize::try_from(written).map_err(io::Error::other)?])
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid final path"))?;
        let value = value.strip_prefix(r"\\?\").unwrap_or(&value);
        Ok(PathBuf::from(value))
    }

    fn validate_secure_handle(
        file: &std::fs::File,
        interactive_user_sid: &str,
        policy: ProtectedPathPolicy,
    ) -> io::Result<()> {
        let descriptor =
            file.security_descriptor(SecurityInformation::Owner | SecurityInformation::Dacl)?;
        let owner = descriptor
            .owner()
            .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "owner missing"))?
            .to_string();
        let owner = owner.trim_end_matches('\0');
        let allowed_owner = match policy {
            ProtectedPathPolicy::Root | ProtectedPathPolicy::StrictDirectory => {
                matches!(owner, "S-1-5-18" | "S-1-5-32-544")
            }
            ProtectedPathPolicy::Mutable | ProtectedPathPolicy::MutableDirectory => {
                matches!(owner, "S-1-5-18" | "S-1-5-19" | "S-1-5-32-544")
                    || owner == interactive_user_sid
            }
            ProtectedPathPolicy::Immutable
            | ProtectedPathPolicy::Executable
            | ProtectedPathPolicy::SecretMaterial => {
                matches!(owner, "S-1-5-18" | "S-1-5-19" | "S-1-5-32-544")
            }
        };
        if !allowed_owner {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unexpected installation owner",
            ));
        }
        let dacl = descriptor
            .dacl()
            .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "DACL missing"))?;
        validate_dacl(dacl, interactive_user_sid, policy)
    }

    fn validate_dacl(
        dacl: &windows_permissions::Acl,
        interactive_user_sid: &str,
        policy: ProtectedPathPolicy,
    ) -> io::Result<()> {
        if dacl.len() == 0 || dacl.len() > 16 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unexpected DACL size",
            ));
        }
        let mut has_system = false;
        let mut has_local_service = false;
        let mut has_user = false;
        for index in 0..dacl.len() {
            let ace = dacl
                .get_ace(index)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid DACL entry"))?;
            if ace.ace_type() != AceType::ACCESS_ALLOWED_ACE_TYPE || ace.mask().is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "unexpected DACL entry type or mask",
                ));
            }
            let trustee = ace
                .sid()
                .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "trustee missing"))?
                .to_string();
            let trustee = trustee.trim_end_matches('\0');
            if !matches!(trustee, "S-1-5-18" | "S-1-5-19" | "S-1-5-32-544")
                && trustee != interactive_user_sid
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "broad or unexpected DACL trustee",
                ));
            }
            has_system |= trustee == "S-1-5-18";
            has_local_service |= trustee == "S-1-5-19";
            if trustee == interactive_user_sid {
                if policy == ProtectedPathPolicy::SecretMaterial {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "interactive user cannot access service secret",
                    ));
                }
                has_user = true;
                validate_user_mask(ace.mask(), policy)?;
            }
        }
        if !has_system
            || (policy != ProtectedPathPolicy::Root && !has_local_service)
            || (policy != ProtectedPathPolicy::SecretMaterial && !has_user)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "required installation principal missing",
            ));
        }
        Ok(())
    }

    fn validate_user_mask(mask: AccessRights, policy: ProtectedPathPolicy) -> io::Result<()> {
        let administration = AccessRights::GenericAll
            | AccessRights::Delete
            | AccessRights::WriteDac
            | AccessRights::WriteOwner;
        let file_write = AccessRights::GenericWrite
            | AccessRights::Bit1
            | AccessRights::Bit2
            | AccessRights::Bit4
            | AccessRights::Bit8;
        let mutable = matches!(
            policy,
            ProtectedPathPolicy::Mutable | ProtectedPathPolicy::MutableDirectory
        );
        if mask.intersects(administration)
            || (!mutable && mask.intersects(file_write | AccessRights::Bit6))
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "interactive user has excessive installation rights",
            ));
        }
        let readable = mask.intersects(AccessRights::GenericRead | AccessRights::Bit0);
        let executable = mask.intersects(AccessRights::GenericExecute | AccessRights::Bit5);
        let requires_execute = matches!(
            policy,
            ProtectedPathPolicy::Root
                | ProtectedPathPolicy::StrictDirectory
                | ProtectedPathPolicy::MutableDirectory
                | ProtectedPathPolicy::Executable
        );
        if !readable || (requires_execute && !executable) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "interactive user lacks required installation rights",
            ));
        }
        Ok(())
    }

    /// Returns stable opaque records describing current IPv4 and IPv6 adapter state.
    /// Callers must hash these records in memory and must never log them.
    ///
    /// # Errors
    /// Returns an OS error when adapter enumeration fails or produces invalid bounds.
    pub fn network_state_records() -> io::Result<Vec<Vec<u8>>> {
        const AF_UNSPEC: u32 = 0;
        let mut size = 0_u32;
        // SAFETY: a null buffer with a writable size pointer is the documented
        // sizing call for GetAdaptersAddresses.
        let sizing = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC,
                0,
                std::ptr::null(),
                std::ptr::null_mut(),
                &raw mut size,
            )
        };
        if sizing == ERROR_NO_DATA {
            return Ok(Vec::new());
        }
        if sizing != ERROR_BUFFER_OVERFLOW || size == 0 || size > 16 * 1024 * 1024 {
            return Err(io::Error::from_raw_os_error(
                i32::try_from(sizing).unwrap_or(i32::MAX),
            ));
        }
        let requested = usize::try_from(size).map_err(io::Error::other)?;
        let word_size = size_of::<usize>();
        let words = requested
            .checked_add(word_size - 1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "adapter list too large"))?
            / word_size;
        let mut storage = vec![std::mem::MaybeUninit::<usize>::uninit(); words];
        let first = storage.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        // SAFETY: storage has exactly the capacity requested by the sizing call
        // and remains fixed while the returned in-buffer linked lists are read.
        let result =
            unsafe { GetAdaptersAddresses(AF_UNSPEC, 0, std::ptr::null(), first, &raw mut size) };
        if result != 0 {
            if result == ERROR_NO_DATA {
                return Ok(Vec::new());
            }
            return Err(io::Error::from_raw_os_error(
                i32::try_from(result).unwrap_or(i32::MAX),
            ));
        }
        let start = storage.as_ptr() as usize;
        let end = start.saturating_add(storage.len().saturating_mul(word_size));
        let mut records = Vec::new();
        let mut adapter = first;
        for _ in 0..1024 {
            if adapter.is_null() {
                break;
            }
            ensure_in_buffer(
                adapter.cast(),
                size_of::<IP_ADAPTER_ADDRESSES_LH>(),
                start,
                end,
            )?;
            // SAFETY: the pointer and complete structure were bounds checked.
            let item = unsafe { &*adapter };
            let mut base = Vec::new();
            // SAFETY: this union field is initialized by GetAdaptersAddresses.
            base.extend_from_slice(&unsafe { item.Anonymous1.Anonymous.IfIndex }.to_le_bytes());
            base.extend_from_slice(&item.Ipv6IfIndex.to_le_bytes());
            base.extend_from_slice(&item.IfType.to_le_bytes());
            base.extend_from_slice(&item.OperStatus.to_le_bytes());
            base.extend_from_slice(&item.Mtu.to_le_bytes());
            collect_ip_records(&mut records, &base, item.FirstUnicastAddress, start, end)?;
            if item.FirstUnicastAddress.is_null() {
                records.push(base);
            }
            adapter = item.Next;
        }
        if !adapter.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "adapter list exceeds bound",
            ));
        }
        records.sort();
        Ok(records)
    }

    fn collect_ip_records(
        records: &mut Vec<Vec<u8>>,
        base: &[u8],
        first: *mut IP_ADAPTER_UNICAST_ADDRESS_LH,
        start: usize,
        end: usize,
    ) -> io::Result<()> {
        let mut address = first;
        for _ in 0..1024 {
            if address.is_null() {
                break;
            }
            ensure_in_buffer(
                address.cast(),
                size_of::<IP_ADAPTER_UNICAST_ADDRESS_LH>(),
                start,
                end,
            )?;
            // SAFETY: the pointer and complete structure were bounds checked.
            let item = unsafe { &*address };
            let mut record = base.to_vec();
            let sockaddr_length = usize::try_from(item.Address.iSockaddrLength)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid address"))?;
            ensure_in_buffer(item.Address.lpSockaddr.cast(), sockaddr_length, start, end)?;
            // SAFETY: the address bytes were bounds checked against the owned buffer.
            let sockaddr = unsafe {
                std::slice::from_raw_parts(item.Address.lpSockaddr.cast::<u8>(), sockaddr_length)
            };
            record.extend_from_slice(sockaddr);
            record.push(item.OnLinkPrefixLength);
            record.extend_from_slice(&item.DadState.to_le_bytes());
            records.push(record);
            address = item.Next;
        }
        if !address.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "address list exceeds bound",
            ));
        }
        Ok(())
    }

    fn ensure_in_buffer(
        pointer: *const c_void,
        length: usize,
        start: usize,
        end: usize,
    ) -> io::Result<()> {
        let pointer = pointer as usize;
        if pointer < start || pointer.checked_add(length).is_none_or(|last| last > end) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid adapter list",
            ));
        }
        Ok(())
    }

    /// Creates a local named pipe with a protected DACL.
    ///
    /// # Errors
    /// Returns an error for an invalid SID, descriptor, or OS pipe creation failure.
    pub fn create_restricted_named_pipe(
        options: &ServerOptions,
        name: &str,
        interactive_user_sid: &str,
    ) -> io::Result<NamedPipeServer> {
        validate_sid(interactive_user_sid)?;
        let parsed_sid: LocalBox<Sid> = interactive_user_sid.parse()?;
        let canonical_sid = parsed_sid.to_string();
        let sddl = restricted_pipe_sddl(&canonical_sid);
        let descriptor: LocalBox<SecurityDescriptor> = sddl.parse()?;
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).map_err(io::Error::other)?,
            lpSecurityDescriptor: std::ptr::from_ref(&*descriptor).cast_mut().cast::<c_void>(),
            bInheritHandle: 0,
        };

        // SAFETY: `attributes` has the exact Windows layout, points to a valid
        // self-relative descriptor owned by `descriptor`, and both values stay
        // alive until CreateNamedPipeW returns. The handle is non-inheritable.
        unsafe {
            options.create_with_security_attributes_raw(
                name,
                std::ptr::from_mut(&mut attributes).cast::<c_void>(),
            )
        }
    }

    /// Resolves a local account to a canonical SID string.
    ///
    /// # Errors
    /// Returns an error when the account is invalid or cannot be resolved.
    pub fn lookup_local_account_sid(account_name: &str) -> io::Result<String> {
        if account_name.is_empty() || account_name.len() > 256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid account name",
            ));
        }
        let (sid, _, _) = LookupAccountName(Option::<&str>::None, account_name)?;
        let value = sid.to_string();
        let value = value.trim_end_matches('\0').to_owned();
        validate_sid(&value)?;
        Ok(value)
    }

    /// Reads the kernel process creation timestamp from a held child handle.
    ///
    /// # Errors
    /// Returns an error when the handle is invalid or lacks query rights.
    pub fn process_creation_identity(process_handle: usize) -> io::Result<u64> {
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        // SAFETY: the borrowed process handle remains valid for this call and
        // every output pointer refers to initialized, writable FILETIME storage.
        let result = unsafe {
            GetProcessTimes(
                process_handle as *mut c_void,
                &raw mut creation,
                &raw mut exit,
                &raw mut kernel,
                &raw mut user,
            )
        };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
    }

    fn validate_sid(value: &str) -> io::Result<()> {
        let suffix = value.strip_prefix("S-1-").ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid target user SID")
        })?;
        if value.len() > 184
            || suffix.is_empty()
            || !suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'-')
            || suffix.split('-').any(str::is_empty)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid target user SID",
            ));
        }
        Ok(())
    }

    fn restricted_pipe_sddl(canonical_sid: &str) -> String {
        format!("D:P(A;;GA;;;{canonical_sid})(A;;GA;;;LS)(A;;GA;;;SY)")
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[tokio::test]
        async fn created_pipe_dacl_contains_only_intended_principals() {
            let account = std::env::var("USERNAME").unwrap();
            let sid = lookup_local_account_sid(&account).unwrap();
            let name = format!(r"\\.\pipe\vpn-hub-acl-test-{}", std::process::id());
            let mut options = ServerOptions::new();
            options
                .first_pipe_instance(true)
                .reject_remote_clients(true);
            let server = create_restricted_named_pipe(&options, &name, &sid).unwrap();
            let sddl = restricted_pipe_sddl(&sid);
            assert!(sddl.contains(&sid));
            assert!(sddl.contains(";;;LS"));
            assert!(sddl.contains(";;;SY"));
            assert_eq!(sddl.matches("(A;;GA;;;").count(), 3);
            drop(server);
        }

        #[test]
        fn malformed_sid_is_rejected_before_ffi() {
            let options = ServerOptions::new();
            assert!(create_restricted_named_pipe(&options, r"\\.\pipe\test", "AU").is_err());
        }

        #[test]
        fn user_writable_executable_acl_is_rejected() {
            let account = std::env::var("USERNAME").unwrap();
            let sid = lookup_local_account_sid(&account).unwrap();
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("core.exe");
            std::fs::write(&path, b"test").unwrap();
            let file = OpenOptions::new().read(true).open(&path).unwrap();
            let descriptor: LocalBox<SecurityDescriptor> =
                format!("D:P(A;;GA;;;{sid})(A;;GA;;;LS)(A;;GA;;;SY)")
                    .parse()
                    .unwrap();
            assert!(
                validate_dacl(
                    descriptor.dacl().unwrap(),
                    &sid,
                    ProtectedPathPolicy::Executable,
                )
                .is_err()
            );
            assert!(validate_secure_handle(&file, &sid, ProtectedPathPolicy::Executable).is_err());
        }

        #[test]
        fn service_secret_acl_rejects_interactive_user_read_access() {
            let account = std::env::var("USERNAME").unwrap();
            let sid = lookup_local_account_sid(&account).unwrap();
            let descriptor: LocalBox<SecurityDescriptor> =
                format!("D:P(A;;FR;;;{sid})(A;;GA;;;LS)(A;;GA;;;SY)")
                    .parse()
                    .unwrap();
            assert!(
                validate_dacl(
                    descriptor.dacl().unwrap(),
                    &sid,
                    ProtectedPathPolicy::SecretMaterial,
                )
                .is_err()
            );
        }

        #[test]
        fn user_writable_intermediate_directory_is_rejected() {
            let sid = lookup_local_account_sid(&std::env::var("USERNAME").unwrap()).unwrap();
            let temp = tempfile::tempdir().unwrap();
            let writable_parent = temp.path().join("writable-parent");
            std::fs::create_dir(&writable_parent).unwrap();
            let target = writable_parent.join("core.exe");
            std::fs::write(&target, b"core").unwrap();
            let root = open_no_follow(temp.path()).unwrap();
            let expected_root = normalize_final_path(&root).unwrap();

            let result = validate_component_chain(
                temp.path(),
                &expected_root,
                &[(target, ProtectedPathPolicy::Executable)],
                &sid,
            );

            assert!(result.is_err());
        }

        #[test]
        fn intermediate_directory_reparse_point_is_rejected() {
            let sid = lookup_local_account_sid(&std::env::var("USERNAME").unwrap()).unwrap();
            let temp = tempfile::tempdir().unwrap();
            let outside = tempfile::tempdir().unwrap();
            std::fs::write(outside.path().join("core.exe"), b"core").unwrap();
            let linked_parent = temp.path().join("linked-parent");
            junction::create(outside.path(), &linked_parent).unwrap();
            let target = linked_parent.join("core.exe");
            let root = open_no_follow(temp.path()).unwrap();
            let expected_root = normalize_final_path(&root).unwrap();

            let result = validate_component_chain(
                temp.path(),
                &expected_root,
                &[(target, ProtectedPathPolicy::Executable)],
                &sid,
            );

            assert!(result.is_err());
        }

        #[test]
        fn verified_executable_handle_blocks_rename_until_released() {
            let temp = tempfile::tempdir().unwrap();
            let executable = temp.path().join("core.exe");
            let replacement = temp.path().join("replacement.exe");
            std::fs::write(&executable, b"core").unwrap();
            let (guard, identity) = open_verified_file(&executable).unwrap();
            assert_eq!(verified_file_identity(&executable).unwrap(), identity);

            assert!(std::fs::rename(&executable, &replacement).is_err());
            drop(guard);
            std::fs::rename(&executable, &replacement).unwrap();
        }
    }
}

#[cfg(target_os = "windows")]
pub use windows::{
    FileIdentity, ProtectedPathPolicy, create_restricted_named_pipe, lookup_local_account_sid,
    network_state_records, open_verified_file, process_creation_identity,
    validate_protected_installation, verified_file_identity,
};
