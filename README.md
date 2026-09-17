# SecureExamPaperSystem

## Secure Management of Competitive Examination Question Papers

SecureExamPaperSystem is a secure cloud-based system developed for managing competitive examination question papers. The system provides secure authentication, role-based access, encrypted storage, review and approval, scheduled release, and audit logging.

## Features

- User login with password authentication
- OTP-based verification
- Role-based access control
- Question paper upload
- Question paper review and approval
- Question paper rejection with reason
- Scheduled question paper release
- Encrypted question paper storage
- SHA-256 integrity verification
- RSA digital signature
- Audit logging
- Controlled question paper download

## User Roles

### Admin
- Monitor the system
- View question papers
- View paper status

### Question Setter
- Upload question papers
- Enter paper details
- Submit papers for review

### Reviewer
- View pending question papers
- Approve question papers
- Reject question papers with a reason

### Exam Officer
- View approved question papers
- Schedule the release date and time

## Technology Stack

| Component | Technology |
|---|---|
| Frontend | HTML, CSS, JavaScript |
| Backend | Python Flask |
| Database | Supabase PostgreSQL |
| Cloud Storage | Supabase Storage |
| Authentication | Flask Session + OTP |
| Encryption | AES-256 |
| Hashing | SHA-256 |
| Digital Signature | RSA |
| Scheduling | APScheduler |
| Deployment | Render |
| Version Control | GitHub |
| Development Tool | Visual Studio Code |

## System Workflow

