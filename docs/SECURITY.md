# Security Notes

The strongest local configuration uses a standard daily account and a separate administrator credential held by a trusted person. When the protected user is also an administrator, NTFS ACLs are a delay and accountability mechanism, not an absolute barrier.

The guardian runs as SYSTEM because that is a real Windows security principal. It does not accept arbitrary commands, execute content from protected paths, or expose a general “agent write” endpoint. Those design choices prevent the guardian from becoming a privilege-escalation broker.

Canonical copies are available only for individual files. Mirroring arbitrary folders could silently double disk usage and overwrite legitimate changes; directory mode therefore enforces ACLs and reports content drift without automatic bulk restoration.

