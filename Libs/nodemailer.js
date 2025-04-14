import nodemailer from "nodemailer"
// ! This file is not used because we are using resend
const testAccount = await nodemailer.createTestAccount();
const transporter = nodemailer.createTransport({
    host: "smtp.ethereal.email",
    port: 587,
    secure: false, // true for 465, false for other ports
    auth: {
      user: testAccount.user, // generated ethereal user
      pass: testAccount.pass, // generated ethereal password
    },
});

export const sendEmail =async({to,subject,html}) => {
    const info = await transporter.sendMail({
        from :`Backend app ${testAccount.user}`, // sender address
        to, // list of receivers
        subject, // Subject line
        html
    });
     const testEmail = nodemailer.getTestMessageUrl(info);
     console.log("Verify email link",testEmail);
     return testEmail
}