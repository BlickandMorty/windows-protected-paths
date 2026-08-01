# Windows Protected Paths

Choose files, folders, or ZIP archives and make them read-only to the normal interactive user while a SYSTEM guardian verifies permissions and, for files, can restore canonical content.

This project is the reusable version of the protected-file design used by the Windows Lockdown Guardian. It adds an honest security model and a safer two-stage workflow for arbitrary user-selected items.

## Important truth about “agent-only” editing

An AI agent is not automatically a separate Windows identity. If an agent runs under your account, Windows sees the same user token. This tool can make a path SYSTEM-managed, but it cannot prove that “only the AI” is acting. A true separate authority requires a dedicated service account, managed device policy, or credentials held by another person.

If you remain a local administrator, you can ultimately take ownership. The guardian adds strong friction and repairs ordinary drift; it is not mathematically irreversible.

## Modes

| Mode | Behavior |
|---|---|
| `IntegrityOnly` | Records hashes and reports changes. Does not change ACLs. |
| `ReadOnlyForUser` | SYSTEM owns the path; SYSTEM has full control; Administrators and Users receive read/execute. |
| `SystemManaged` | Adds the read-only ACL and restores protected file content from a canonical copy when drift is detected. Directories receive ACL enforcement; their full contents are not duplicated automatically. |

## Safe workflow

Audit first:

```powershell
.\src\Install-PathGuardian.ps1 -Path C:\Example\important.zip -Mode SystemManaged
```

Apply after reviewing the JSON plan:

```powershell
.\src\Install-PathGuardian.ps1 `
  -Path C:\Example\important.zip `
  -Mode SystemManaged `
  -Apply `
  -Acknowledgement 'PROTECT THESE PATHS'
```

Use the selection helper if you prefer a normal Windows picker:

```powershell
.\src\Select-ProtectedPaths.ps1
```

The helper creates a plan and prints the exact elevated command. It never changes permissions by itself.

## Built-in safety boundaries

- Rejects drive roots, profile roots, Windows, Program Files, ProgramData, and other broad system targets.
- Rejects known permanent-lockdown artifacts; this utility cannot be used to weaken them.
- Resolves every target to an absolute literal path before applying ACLs.
- Stores the original SDDL and creates a canonical copy for protected files.
- Refuses reparse points by default.
- Requires an exact acknowledgement and elevation.
- Writes reports outside protected roots.

## Recovery

`Restore-PathAccess.ps1` is for ordinary paths protected by this project. It validates a recovery phrase created during installation and restores the recorded original ACL. It refuses permanent-hard-gate targets. Keep the recovery phrase with a trusted person if self-lockout is the goal.

## License

MIT.

