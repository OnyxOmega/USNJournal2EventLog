The Update Sequence Number (USN) journal is designed to record that a change occurred and why
(e.g., USN_REASON_SECURITY_CHANGE), but it does not store the old and new Access Control Lists (ACLs)
within the record itself.The USN record simply provides the reason for the update, the Security ID
, and the File Reference Number.

## How to Get "Old to New" Changes
To actually see what changed in the permissions, you have to cross-reference the USN journal 
entry with other historical sources:

Volume Shadow Copies: You can mount a previous Volume Shadow Copy (VSC) and extract the previous 
security descriptor directly from the old Master File Table ($MFT).

Backups: Compare the current security descriptor of the file against the previous snapshot in your 
system backups.

Audit Logs: If Object Access Auditing (e.g., Event ID 4670) is enabled in your Local 
or Group Policy, Windows will explicitly log the specific permissions that were changed, detailing
the Old SD (Security Descriptor) and New SD in the Event Viewer.

##How to Analyze the Security Change
If you want to investigate the USN entry itself using forensic tools to confirm a permission 
change took place:

Acquire the log: Use triage tools like KAPE to pull the $UsnJrnl:$J Alternate Data Stream.

Parse the data: Parse the extracted data with MFTECmd or NTFS Journal Viewer to identify the exact
file and timestamp of the Security Change event.
