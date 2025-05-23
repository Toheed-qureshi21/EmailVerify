📧 Email Verification Flow – Node.js + MongoDB + MJML + Resend

This project implements a full-featured email verification flow for user signup in a Node.js application using Express, MongoDB, MJML email templates, and Resend email service.
🔧 Features
User signup with hashed passwords (bcrypt)

Email verification using token-based system

MJML templating for responsive emails

Resend integration for email delivery

Token expiry handling

Resend verification link if needed

Email verification status update

🔁 Email Verification Flow
1. User Signup
Route: /api/signup

Creates a new user and hashes password.

Generates a JWT token.

Redirects to /api/home.

2. Resend Verification Link
Route: /api/resend-verification

Deletes any existing token.

Generates a new token using crypto.randomInt.

Saves the token in the VerifyEmail collection.

Generates a link like:

perl
Copy
Edit
http://localhost:3000/api/verify-email-link?email=user@example.com&token=12345678
Compiles MJML email template using EJS.

Converts it to HTML and sends the email using Resend.

3. Email Template
Located at emails/verify-email.mjml

Uses placeholders for token and verification link:

mjml
Copy
Edit
<a href="<%= link %>">Verify your email</a>
4. Verify Email Link
Route: /api/verify-email-link?email=...&token=...

Validates token (checks expiration: 24 hours).

Updates user's isEmail_Verified to true.

Deletes the used token.

Redirects to /api/home.

🛠️ Technologies Used
Node.js + Express – backend server

MongoDB + Mongoose – database

bcryptjs – password hashing

crypto – secure token generation

EJS – dynamic email content rendering

MJML – responsive email design

Resend – email sending service

🔑 Password Reset Flow
1. Request Password Reset
Route: /api/request-password-reset

User submits their email

If email is valid and verified, generates a secure token

Stores token and expiry in a ResetToken collection

Sends a password reset link via email:

perl
Copy
Edit
http://localhost:3000/api/reset-password?email=user@example.com&token=12345678
Email template: emails/reset-password.mjml

mjml
Copy
Edit
<a href="<%= link %>">Reset your password</a>
2. Reset Password Page
Route: /api/reset-password?email=...&token=...

Validates token and expiration (typically 1 hour)

Displays password reset form

On submit, hashes new password and updates user record

Deletes used token

Redirects to /api/login or /api/home
