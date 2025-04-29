import nodemailer from "nodemailer"
import { config } from "dotenv";
config();
// ! This file is not used because we are using resend
// const testAccount = await nodemailer.createTestAccount();
// const transporter = nodemailer.createTransport({
//     host: "smtp.ethereal.email",
//     port: 587,
//     secure: false, // true for 465, false for other ports
//     auth: {
//       user: testAccount.user, // generated ethereal user
//       pass: testAccount.pass, // generated ethereal password
//     },
// });


// Ethreal example
// export const sendEmail =async({to,subject,html}) => {
//     const info = await transporter.sendMail({
//         from :`Backend app ${testAccount.user}`, // sender address
//         to, // list of receivers
//         subject, // Subject line
//         html
//     });
//      const testEmail = nodemailer.getTestMessageUrl(info);
//      console.log("Verify email link",testEmail);
//      return testEmail
// }

// Mailersend smtp service

const transporter = nodemailer.createTransport({
  host: 'smtp-relay.brevo.com',
  port: 587, // Use 465 for SSL or 2525 if 587 is blocked
  secure: false, // Set to true if using port 465
  auth: {
    user: process.env.BREVO_SMTP_LOGIN, // Your Brevo SMTP login (email address)
    pass: process.env.BREVO_SMTP_MASTER_PASSWORD, // Your Brevo SMTP password (API key)
  },
});
export const sendEmail = async ({ to, subject, html }) => {

  try {
    const info = await transporter.sendMail({
      from: `"Toheed developer" <${process.env.BREVO_SMTP_EMAIL}>`,
      to,
      subject,
      html,
    });
    console.log('Email sent:', info.messageId);
  } catch (error) {
    console.error('Error sending email:', error);
  }
};
